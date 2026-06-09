"""
Flask REST API for the data-governance pipeline.

Exposes HTTP endpoints to trigger runs, check status, health, and metrics.
Pipeline execution happens in a background thread so the API stays responsive.

Layer 6 — imports from Layer 0 (constants), Layer 1 (governance_logger),
          Layer 2+ (extract, transform), loaders, monitoring.

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-08   Added API key authentication, rate limiting, input validation.
1.2   2026-06-09   Added OpenAPI/Swagger documentation routes (/docs, /openapi.json).
1.3   2026-06-09   Structured error responses (code, message, request_id),
                   progress tracking on /status, graceful SIGTERM shutdown.
"""

import functools
import hmac
import logging
import os
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    from flask import Flask, jsonify, request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


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


class _RateLimiter:
    """Simple in-memory token-bucket rate limiter keyed by API key."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._lock = threading.Lock()
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            self._buckets[key] = [t for t in bucket if now - t < self._window]
            if len(self._buckets[key]) >= self._max:
                return False
            self._buckets[key].append(now)
            return True


def create_app(pipeline_fn=None) -> "Flask":
    """
    Create and configure the Flask application.

    Parameters
    ----------
    pipeline_fn : callable | None
        A function accepting ``(source, destination, config_dict)`` that
        executes the full pipeline.  If *None*, the /run endpoint returns
        501 Not Implemented.

    Returns
    -------
    Flask
        Configured Flask app instance.

    Raises
    ------
    RuntimeError
        If Flask is not installed.
    """
    if not HAS_FLASK:
        raise RuntimeError(
            "Flask is required for the pipeline API. "
            "Install it with: pip install flask"
        )

    app = Flask(__name__)
    api_keys = _load_api_keys()
    rate_limiter = _RateLimiter()

    if not api_keys:
        logger.warning("PIPELINE_API_KEYS not set — API is running WITHOUT authentication")

    # ── Authentication ──────────────────────────────────────────────────

    def require_auth(fn):
        """Decorator: reject requests without a valid API key."""
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            key = (
                request.headers.get("X-API-Key")
                or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            )

            rate_limit_id = key or request.remote_addr
            if not rate_limiter.allow(rate_limit_id):
                return _error_response(
                    "rate_limit_exceeded",
                    "Rate limit exceeded. Try again later.",
                    429,
                )

            if not api_keys:
                return fn(*args, **kwargs)

            if not key or not any(hmac.compare_digest(key, k) for k in api_keys):
                logger.warning("[API] Unauthorized request to %s from %s",
                               request.path, request.remote_addr)
                return _error_response(
                    "unauthorized",
                    "Unauthorized. Provide a valid API key.",
                    401,
                )

            return fn(*args, **kwargs)
        return wrapper

    # ── Shared state ────────────────────────────────────────────────────
    _state: dict[str, object] = {
        "run_id": None,
        "status": "idle",
        "started_at": None,
        "finished_at": None,
        "error": None,
        "metrics": {},
    }
    _state_lock = threading.Lock()

    # ── Background runner ───────────────────────────────────────────────

    def _run_pipeline(run_id: str, source: str, destination: str, config: dict) -> None:
        """Execute pipeline_fn in a background thread and update _state."""
        logger.info("Pipeline run %s started — source=%s, dest=%s", run_id, source, destination)
        start = time.perf_counter()

        try:
            result = pipeline_fn(source, destination, config)
            elapsed = round(time.perf_counter() - start, 2)
            with _state_lock:
                _state["status"] = "completed"
                _state["finished_at"] = datetime.now(timezone.utc).isoformat()
                _state["metrics"] = {
                    "duration_s": elapsed,
                    "result": str(result) if result else None,
                }
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
            with _state_lock:
                _state["status"] = "failed"
                _state["finished_at"] = datetime.now(timezone.utc).isoformat()
                _state["error"] = error_detail
                _state["metrics"] = {"duration_s": elapsed}
            logger.error("Pipeline run %s failed after %.2fs: %s", run_id, elapsed, exc)
        finally:
            with _state_lock:
                if _state["status"] == "running":
                    _state["status"] = "failed"
                    _state["error"] = {
                        "message": "Pipeline thread terminated unexpectedly",
                        "type": "unexpected_termination",
                    }
                    _state["finished_at"] = datetime.now(timezone.utc).isoformat()

    # ── Endpoints ───────────────────────────────────────────────────────

    @app.route("/run", methods=["POST"])
    @require_auth
    def run_pipeline():
        """Trigger a pipeline run.  Expects JSON: {source, destination, config?}."""
        if pipeline_fn is None:
            return _error_response(
                "not_configured",
                "No pipeline function configured.",
                501,
            )

        body = request.get_json(silent=True) or {}
        source = body.get("source")
        destination = body.get("destination")
        config = body.get("config", {})

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

        from pipeline.loaders import supported_db_types
        known_destinations = supported_db_types()
        if destination.lower() not in known_destinations:
            return _error_response(
                "unknown_destination",
                f"Unknown destination '{destination}'.",
                400,
                valid_destinations=sorted(known_destinations),
            )

        run_id = str(uuid.uuid4())

        with _state_lock:
            if _state["status"] == "running":
                return _error_response(
                    "already_running",
                    "A pipeline run is already in progress.",
                    409,
                    active_run_id=_state["run_id"],
                )
            _state["status"] = "running"
            _state["run_id"] = run_id
            _state["started_at"] = datetime.now(timezone.utc).isoformat()
            _state["finished_at"] = None
            _state["error"] = None
            _state["metrics"] = {}

        thread = threading.Thread(
            target=_run_pipeline,
            args=(run_id, source, destination, config),
            daemon=True,
        )
        thread.start()

        return jsonify({"run_id": run_id, "status": "started"}), 202

    @app.route("/status", methods=["GET"])
    @require_auth
    def get_status():
        """Return the current pipeline run status with optional chunk progress."""
        with _state_lock:
            result = {
                "run_id": _state["run_id"],
                "status": _state["status"],
                "started_at": _state["started_at"],
                "finished_at": _state["finished_at"],
                "error": _state["error"],
            }

        if result["run_id"] and result["status"] == "running":
            try:
                from pipeline.run_state import RunStateManager
                rsm = RunStateManager()
                run_state = rsm.get_state(str(result["run_id"]))
                if run_state and run_state.last_chunk_completed >= 0:
                    result["progress"] = {
                        "last_chunk_completed": run_state.last_chunk_completed,
                        "total_rows_processed": run_state.total_rows_processed,
                    }
            except Exception:
                pass

        return jsonify(result)

    @app.route("/health", methods=["GET"])
    def health():
        """Healthcheck endpoint — no auth required."""
        return jsonify({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

    @app.route("/metrics", methods=["GET"])
    @require_auth
    def get_metrics():
        """Return the latest pipeline run metrics."""
        with _state_lock:
            return jsonify({
                "run_id": _state["run_id"],
                "metrics": _state["metrics"],
            })

    # ── Documentation ──────────────────────────────────────────────────
    try:
        from pipeline.openapi_spec import register_docs_routes
        register_docs_routes(app)
    except ImportError as exc:
        logger.warning("Could not register OpenAPI docs routes: %s", exc)

    logger.info("Pipeline Flask API created.")
    return app


if __name__ == "__main__":
    import signal

    from pipeline.logging_setup import auto_configure_logging
    auto_configure_logging()

    def _shutdown(signum, frame):
        logger.info("Received signal %s — shutting down.", signum)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _shutdown)

    app = create_app()
    app.run(host="0.0.0.0", port=5000)
