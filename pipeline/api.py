"""
Quart (async) REST API for the data-governance pipeline.

Exposes HTTP endpoints to trigger runs, check status, health, and metrics.
Pipeline execution happens in a background thread so the API stays responsive.

Layer 6 — imports from Layer 0 (constants), Layer 1 (governance_logger),
          Layer 2+ (extract, transform), loaders, monitoring.

Revision history
────────────────
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-08   Added API key authentication, rate limiting, input validation.
1.2   2026-06-09   Added OpenAPI/Swagger documentation routes (/docs, /openapi.json).
1.3   2026-06-09   Structured error responses (code, message, request_id),
                   progress tracking on /status, graceful SIGTERM shutdown.
1.4   2026-06-09   Run queue, history (/runs), cancel, webhook notifications.
1.5   2026-06-09   Replaced inline rate limiter with pluggable rate_limiter module.
1.6   2026-06-09   Added config validation via validate_loader_config on /run.
1.7   2026-06-09   JWT auth token rotation: /auth/token, /auth/revoke, bearer JWT support.
2.0   2026-06-09   Migrated Flask to Quart (ASGI) for async request handling.
2.1   2026-06-09   Fixed silent except in get_status, JWT header routing,
                   replaced _state dict with _RunStatus dataclass.
"""

import functools
import hmac
import logging
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    from quart import Quart, jsonify, request
    HAS_QUART = True
except ImportError:
    HAS_QUART = False


@dataclass
class _RunStatus:
    """In-memory status of the current/last pipeline run."""
    run_id: str | None = None
    status: str = "idle"
    started_at: str | None = None
    finished_at: str | None = None
    error: dict | None = None
    metrics: dict = field(default_factory=dict)


def _load_api_keys() -> set[str]:
    """Load allowed API keys from PIPELINE_API_KEYS env var (comma-separated)."""
    raw = os.environ.get("PIPELINE_API_KEYS", "")
    return {k.strip() for k in raw.split(",") if k.strip()}


def _error_response(code: str, message: str, status_code: int, **extra):
    """Build a structured error JSON response with a unique request ID."""
    body: dict = {
        "error": {
            "code": code,
            "message": message,
            "request_id": f"req_{uuid.uuid4().hex[:12]}",
        }
    }
    body["error"].update(extra)
    return jsonify(body), status_code


def _fire_webhook(url: str, payload: dict) -> None:
    """Best-effort POST to a webhook URL. Failures are logged, not raised."""
    try:
        import requests
        resp = requests.post(url, json=payload, timeout=10)
        logger.info("[API] Webhook fired to %s — status %d", url, resp.status_code)
    except Exception as exc:
        logger.warning("[API] Webhook to %s failed: %s", url, exc)


def create_app(pipeline_fn=None, max_queue_size: int | None = None) -> "Quart":
    """
    Create and configure the Quart application.

    Parameters
    ----------
    pipeline_fn : callable | None
        A function accepting ``(source, destination, config_dict)`` that
        executes the full pipeline.  If *None*, the /run endpoint returns
        501 Not Implemented.
    max_queue_size : int | None
        Maximum number of runs that can be queued while one is active.
        Defaults to ``PIPELINE_MAX_QUEUE_SIZE`` env var, or 0 (no queue).

    Returns
    -------
    Quart
        Configured Quart app instance.

    Raises
    ------
    RuntimeError
        If Quart is not installed.
    """
    if not HAS_QUART:
        raise RuntimeError(
            "Quart is required for the pipeline API. "
            "Install it with: pip install quart"
        )

    from pipeline.rate_limiter import create_rate_limiter

    app = Quart(__name__)
    api_keys = _load_api_keys()
    rate_limiter = create_rate_limiter(
        db_path=os.environ.get("PIPELINE_RATE_LIMIT_DB"),
    )

    if max_queue_size is None:
        max_queue_size = int(os.environ.get("PIPELINE_MAX_QUEUE_SIZE", "0"))

    if not api_keys:
        logger.warning("PIPELINE_API_KEYS not set — API is running WITHOUT authentication")

    # ── Authentication ──────────────────────────────────────────────────

    from pipeline.auth import jwt_available, validate_token as _validate_jwt

    def require_auth(fn):
        """Decorator: reject requests without a valid API key or JWT."""
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            api_key = (request.headers.get("X-API-Key") or "").strip()
            bearer = (
                request.headers.get("Authorization", "")
                .removeprefix("Bearer ")
                .strip()
            )
            credential = api_key or bearer
            is_bearer = bool(not api_key and bearer)

            rate_limit_id = credential or request.remote_addr
            if not rate_limiter.allow(rate_limit_id):
                return _error_response(
                    "rate_limit_exceeded",
                    "Rate limit exceeded. Try again later.",
                    429,
                )

            if not api_keys and not jwt_available():
                return await fn(*args, **kwargs)

            if credential and is_bearer and jwt_available():
                try:
                    _validate_jwt(credential)
                    return await fn(*args, **kwargs)
                except Exception as exc:
                    logger.debug("[API] JWT validation failed, trying static key: %s", exc)

            if api_keys and credential and any(
                hmac.compare_digest(credential, k) for k in api_keys
            ):
                return await fn(*args, **kwargs)

            logger.warning("[API] Unauthorized request to %s from %s",
                           request.path, request.remote_addr)
            return _error_response(
                "unauthorized",
                "Unauthorized. Provide a valid API key.",
                401,
            )

        return wrapper

    # ── Shared state ────────────────────────────────────────────────────
    _status = _RunStatus()
    _status_lock = threading.Lock()
    _queue: deque = deque()
    _cancel_events: dict[str, threading.Event] = {}

    # ── Run state persistence ──────────────────────────────────────────

    def _get_rsm():
        from pipeline.run_state import RunStateManager
        return RunStateManager()

    def _persist_start(run_id: str, source: str, destination: str) -> None:
        try:
            from pipeline.run_state import RunState
            rsm = _get_rsm()
            state = RunState(
                run_id=run_id, source=source,
                destination=destination, table="",
            )
            rsm.save_start(state)
        except Exception as exc:
            logger.warning("[API] Could not persist run start: %s", exc)

    def _persist_complete(run_id: str) -> None:
        try:
            _get_rsm().mark_complete(run_id)
        except Exception as exc:
            logger.warning("[API] Could not persist run completion: %s", exc)

    def _persist_failed(run_id: str, error: str) -> None:
        try:
            _get_rsm().mark_failed(run_id, error)
        except Exception as exc:
            logger.warning("[API] Could not persist run failure: %s", exc)

    # ── Background runner ───────────────────────────────────────────────

    def _run_pipeline(run_id: str, source: str, destination: str,
                      config: dict, webhook_url: str | None = None) -> None:
        """Execute pipeline_fn in a background thread and update _status."""
        logger.info("Pipeline run %s started — source=%s, dest=%s", run_id, source, destination)
        start = time.perf_counter()
        cancel_event = _cancel_events.get(run_id)

        try:
            if cancel_event and cancel_event.is_set():
                raise InterruptedError("Run cancelled before execution started")
            result = pipeline_fn(source, destination, config)
            elapsed = round(time.perf_counter() - start, 2)

            if cancel_event and cancel_event.is_set():
                with _status_lock:
                    _status.status = "cancelled"
                    _status.finished_at = datetime.now(timezone.utc).isoformat()
                    _status.metrics = {"duration_s": elapsed}
                _persist_failed(run_id, "Cancelled by user")
                logger.info("Pipeline run %s cancelled after %.2fs.", run_id, elapsed)
            else:
                with _status_lock:
                    _status.status = "completed"
                    _status.finished_at = datetime.now(timezone.utc).isoformat()
                    _status.metrics = {
                        "duration_s": elapsed,
                        "result": str(result) if result else None,
                    }
                _persist_complete(run_id)
                logger.info("Pipeline run %s completed in %.2fs.", run_id, elapsed)

        except Exception as exc:
            elapsed = round(time.perf_counter() - start, 2)
            error_detail: dict = {"message": str(exc), "type": type(exc).__name__}
            if hasattr(exc, "db_type"):
                error_detail["db_type"] = exc.db_type  # type: ignore[union-attr]
            if hasattr(exc, "table"):
                error_detail["table"] = exc.table  # type: ignore[union-attr]
            if hasattr(exc, "missing_keys"):
                error_detail["missing_keys"] = exc.missing_keys  # type: ignore[union-attr]
            with _status_lock:
                _status.status = "failed"
                _status.finished_at = datetime.now(timezone.utc).isoformat()
                _status.error = error_detail
                _status.metrics = {"duration_s": elapsed}
            _persist_failed(run_id, str(exc))
            logger.error("Pipeline run %s failed after %.2fs: %s", run_id, elapsed, exc)

        finally:
            with _status_lock:
                if _status.status == "running":
                    _status.status = "failed"
                    _status.error = {
                        "message": "Pipeline thread terminated unexpectedly",
                        "type": "unexpected_termination",
                    }
                    _status.finished_at = datetime.now(timezone.utc).isoformat()
                    _persist_failed(run_id, "Pipeline thread terminated unexpectedly")

            _cancel_events.pop(run_id, None)

            if webhook_url:
                with _status_lock:
                    payload = {
                        "run_id": run_id,
                        "status": _status.status,
                        "metrics": _status.metrics,
                        "error": _status.error,
                    }
                _fire_webhook(webhook_url, payload)

            _start_next_queued()

    def _start_next_queued() -> None:
        """Pop the next queued run and start it, if any."""
        with _status_lock:
            if not _queue:
                return
            item = _queue.popleft()
            _status.status = "running"
            _status.run_id = item["run_id"]
            _status.started_at = datetime.now(timezone.utc).isoformat()
            _status.finished_at = None
            _status.error = None
            _status.metrics = {}

        _persist_start(item["run_id"], item["source"], item["destination"])

        thread = threading.Thread(
            target=_run_pipeline,
            args=(item["run_id"], item["source"], item["destination"],
                  item["config"], item.get("webhook_url")),
            daemon=True,
        )
        thread.start()

    # ── Endpoints ───────────────────────────────────────────────────────

    @app.route("/run", methods=["POST"])
    @require_auth
    async def run_pipeline():
        """Trigger a pipeline run.  Expects JSON: {source, destination, config?, webhook_url?}."""
        if pipeline_fn is None:
            return _error_response(
                "not_configured",
                "No pipeline function configured.",
                501,
            )

        body = await request.get_json(silent=True) or {}
        source = body.get("source")
        destination = body.get("destination")
        config = body.get("config", {})
        webhook_url = body.get("webhook_url")

        if not source or not destination:
            return _error_response(
                "missing_fields",
                "Both 'source' and 'destination' are required.",
                400,
            )

        if not isinstance(source, str) or not isinstance(destination, str):
            return _error_response(
                "invalid_type",
                "'source' and 'destination' must be strings.",
                400,
            )

        if not isinstance(config, dict):
            return _error_response(
                "invalid_config",
                "'config' must be a JSON object.",
                400,
            )

        from pipeline.loaders import supported_db_types, validate_loader_config
        from pipeline.exceptions import ConfigValidationError

        known_destinations = supported_db_types()
        if destination.lower() not in known_destinations:
            return _error_response(
                "unknown_destination",
                f"Unknown destination '{destination}'.",
                400,
                valid_destinations=sorted(known_destinations),
            )

        try:
            validate_loader_config(destination, config, table=config.get("table", ""))
        except ConfigValidationError as exc:
            return _error_response(
                "invalid_config",
                str(exc),
                400,
                db_type=exc.db_type,
                missing_keys=exc.missing_keys,
            )

        run_id = str(uuid.uuid4())
        cancel_event = threading.Event()
        _cancel_events[run_id] = cancel_event

        with _status_lock:
            if _status.status == "running":
                if max_queue_size <= 0:
                    _cancel_events.pop(run_id, None)
                    return _error_response(
                        "already_running",
                        "A pipeline run is already in progress.",
                        409,
                        active_run_id=_status.run_id,
                    )
                if len(_queue) >= max_queue_size:
                    _cancel_events.pop(run_id, None)
                    return _error_response(
                        "queue_full",
                        f"Run queue is full ({max_queue_size} pending).",
                        429,
                    )
                _queue.append({
                    "run_id": run_id,
                    "source": source,
                    "destination": destination,
                    "config": config,
                    "webhook_url": webhook_url,
                })
                return jsonify({"run_id": run_id, "status": "queued",
                                "position": len(_queue)}), 202

            _status.status = "running"
            _status.run_id = run_id
            _status.started_at = datetime.now(timezone.utc).isoformat()
            _status.finished_at = None
            _status.error = None
            _status.metrics = {}

        _persist_start(run_id, source, destination)

        thread = threading.Thread(
            target=_run_pipeline,
            args=(run_id, source, destination, config, webhook_url),
            daemon=True,
        )
        thread.start()

        return jsonify({"run_id": run_id, "status": "started"}), 202

    @app.route("/status", methods=["GET"])
    @require_auth
    async def get_status():
        """Return the current pipeline run status with optional chunk progress."""
        with _status_lock:
            result = {
                "run_id": _status.run_id,
                "status": _status.status,
                "started_at": _status.started_at,
                "finished_at": _status.finished_at,
                "error": _status.error,
            }

        if result["run_id"] and result["status"] == "running":
            try:
                rsm = _get_rsm()
                run_state = rsm.get_state(str(result["run_id"]))
                if run_state and run_state.last_chunk_completed >= 0:
                    result["progress"] = {
                        "last_chunk_completed": run_state.last_chunk_completed,
                        "total_rows_processed": run_state.total_rows_processed,
                    }
            except Exception as exc:
                logger.debug("[API] Could not load run progress: %s", exc)

        return jsonify(result)

    @app.route("/runs", methods=["GET"])
    @require_auth
    async def list_runs():
        """List past pipeline runs with pagination."""
        limit = request.args.get("limit", 20, type=int)
        offset = request.args.get("offset", 0, type=int)
        status_filter = request.args.get("status")

        limit = max(1, min(limit, 100))
        offset = max(0, offset)

        try:
            rsm = _get_rsm()
            runs = rsm.list_runs(limit=limit, offset=offset, status_filter=status_filter)
            return jsonify({
                "runs": [asdict(r) for r in runs],
                "limit": limit,
                "offset": offset,
                "count": len(runs),
            })
        except Exception as exc:
            logger.warning("[API] Could not list runs: %s", exc)
            return jsonify({"runs": [], "limit": limit, "offset": offset, "count": 0})

    @app.route("/runs/<run_id>", methods=["GET"])
    @require_auth
    async def get_run(run_id: str):
        """Get details of a specific run by ID."""
        try:
            rsm = _get_rsm()
            state = rsm.get_state(run_id)
            if state is None:
                return _error_response("not_found", f"Run '{run_id}' not found.", 404)
            return jsonify(asdict(state))
        except Exception as exc:
            logger.warning("[API] Could not get run %s: %s", run_id, exc)
            return _error_response("not_found", f"Run '{run_id}' not found.", 404)

    @app.route("/runs/<run_id>/cancel", methods=["POST"])
    @require_auth
    async def cancel_run(run_id: str):
        """Cancel a queued or running pipeline run."""
        with _status_lock:
            for i, item in enumerate(_queue):
                if item["run_id"] == run_id:
                    _queue.remove(item)
                    _cancel_events.pop(run_id, None)
                    _persist_failed(run_id, "Cancelled before execution")
                    return jsonify({"run_id": run_id, "status": "cancelled",
                                    "detail": "Removed from queue"})

        cancel_event = _cancel_events.get(run_id)
        if cancel_event:
            cancel_event.set()
            return jsonify({"run_id": run_id, "status": "cancel_requested",
                            "detail": "Cancel signal sent to running pipeline"})

        return _error_response(
            "not_found",
            f"Run '{run_id}' is not active or queued.",
            404,
        )

    @app.route("/health", methods=["GET"])
    async def health():
        """Healthcheck endpoint — no auth required."""
        return jsonify({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

    @app.route("/metrics", methods=["GET"])
    @require_auth
    async def get_metrics():
        """Return the latest pipeline run metrics."""
        with _status_lock:
            return jsonify({
                "run_id": _status.run_id,
                "metrics": _status.metrics,
            })

    # ── Auth token endpoints ──────────────────────────────────────────

    @app.route("/auth/token", methods=["POST"])
    @require_auth
    async def create_auth_token():
        """Exchange an API key for a short-lived JWT."""
        if not jwt_available():
            return _error_response(
                "jwt_not_configured",
                "JWT auth is not enabled. Set PIPELINE_JWT_SECRET to enable.",
                501,
            )
        body = await request.get_json(silent=True) or {}
        subject = body.get("subject", "api-client")
        expiry = body.get("expiry_seconds", 3600)

        if not isinstance(expiry, int) or expiry < 60 or expiry > 86400:
            return _error_response(
                "invalid_expiry",
                "expiry_seconds must be an integer between 60 and 86400.",
                400,
            )

        from pipeline.auth import create_token
        result = create_token(subject, expiry)
        return jsonify(result), 201

    @app.route("/auth/revoke", methods=["POST"])
    @require_auth
    async def revoke_auth_token():
        """Revoke a JWT by its jti claim."""
        if not jwt_available():
            return _error_response(
                "jwt_not_configured",
                "JWT auth is not enabled. Set PIPELINE_JWT_SECRET to enable.",
                501,
            )
        body = await request.get_json(silent=True) or {}
        jti = body.get("jti")
        if not jti or not isinstance(jti, str):
            return _error_response(
                "missing_jti",
                "Request body must include a 'jti' string.",
                400,
            )

        from pipeline.auth import revoke_token
        revoke_token(jti)
        return jsonify({"jti": jti, "status": "revoked"})

    # ── Documentation ──────────────────────────────────────────────────
    try:
        from pipeline.openapi_spec import register_docs_routes
        register_docs_routes(app)
    except ImportError as exc:
        logger.warning("Could not register OpenAPI docs routes: %s", exc)

    logger.info("Pipeline Quart API created.")
    return app


if __name__ == "__main__":
    import asyncio

    from pipeline.logging_setup import auto_configure_logging
    auto_configure_logging()

    app = create_app()

    try:
        from hypercorn.asyncio import serve
        from hypercorn.config import Config as HypercornConfig

        config = HypercornConfig()
        config.bind = ["0.0.0.0:5000"]
        config.graceful_timeout = 10
        asyncio.run(serve(app, config))
    except ImportError:
        logger.warning("Hypercorn not installed — falling back to Quart dev server.")
        app.run(host="0.0.0.0", port=5000)
