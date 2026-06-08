"""
Flask REST API for the data-governance pipeline.

Exposes HTTP endpoints to trigger runs, check status, health, and metrics.
Pipeline execution happens in a background thread so the API stays responsive.

Layer 6 — imports from Layer 0 (constants), Layer 1 (governance_logger),
          Layer 2+ (extract, transform), loaders, monitoring.

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
"""

import logging
import threading
import time
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    from flask import Flask, jsonify, request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


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

    # ── Shared state ────────────────────────────────────────────────────
    _state = {
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
        with _state_lock:
            _state["run_id"] = run_id
            _state["status"] = "running"
            _state["started_at"] = datetime.now(timezone.utc).isoformat()
            _state["finished_at"] = None
            _state["error"] = None

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
            with _state_lock:
                _state["status"] = "failed"
                _state["finished_at"] = datetime.now(timezone.utc).isoformat()
                _state["error"] = str(exc)
                _state["metrics"] = {"duration_s": elapsed}
            logger.error("Pipeline run %s failed after %.2fs: %s", run_id, elapsed, exc)

    # ── Endpoints ───────────────────────────────────────────────────────

    @app.route("/run", methods=["POST"])
    def run_pipeline():
        """Trigger a pipeline run.  Expects JSON: {source, destination, config?}."""
        if pipeline_fn is None:
            return jsonify({"error": "No pipeline function configured."}), 501

        with _state_lock:
            if _state["status"] == "running":
                return jsonify({
                    "error": "A pipeline run is already in progress.",
                    "run_id": _state["run_id"],
                }), 409

        body = request.get_json(silent=True) or {}
        source = body.get("source")
        destination = body.get("destination")
        config = body.get("config", {})

        if not source or not destination:
            return jsonify({"error": "Both 'source' and 'destination' are required."}), 400

        run_id = str(uuid.uuid4())
        thread = threading.Thread(
            target=_run_pipeline,
            args=(run_id, source, destination, config),
            daemon=True,
        )
        thread.start()

        return jsonify({"run_id": run_id, "status": "started"}), 202

    @app.route("/status", methods=["GET"])
    def get_status():
        """Return the current pipeline run status."""
        with _state_lock:
            return jsonify({
                "run_id": _state["run_id"],
                "status": _state["status"],
                "started_at": _state["started_at"],
                "finished_at": _state["finished_at"],
                "error": _state["error"],
            })

    @app.route("/health", methods=["GET"])
    def health():
        """Healthcheck endpoint."""
        return jsonify({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

    @app.route("/metrics", methods=["GET"])
    def get_metrics():
        """Return the latest pipeline run metrics."""
        with _state_lock:
            return jsonify({
                "run_id": _state["run_id"],
                "metrics": _state["metrics"],
            })

    logger.info("Pipeline Flask API created.")
    return app
