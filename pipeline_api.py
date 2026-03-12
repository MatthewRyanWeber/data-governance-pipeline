"""
pipeline_api.py  —  REST API Layer for pipeline_v3
===================================================
A Flask-based HTTP API that wraps pipeline_v3 so runs can be
triggered, monitored, and inspected via HTTP rather than the CLI.

Endpoints
---------
  POST  /run                  Trigger a pipeline run (async)
  GET   /run/<run_id>         Check status of a specific run
  GET   /runs                 List all runs with status
  GET   /runs/<run_id>/log    Fetch the governance audit log for a run
  GET   /scheduler/status     List all scheduled jobs + last-run info
  POST  /scheduler/trigger/<job_name>
                              Manually trigger a scheduled job
  GET   /health               Liveness probe
  GET   /formats              List all supported source file formats

Usage
-----
    # Run standalone (dev server):
    python pipeline_api.py

    # Or import and attach to an existing Flask app:
    from pipeline_api import create_app
    app = create_app()
    app.run(host="0.0.0.0", port=5000)

    # Trigger a run:
    curl -X POST http://localhost:5000/run \\
         -H "Content-Type: application/json" \\
         -d '{"source": "data.csv", "db_type": "sqlite", "db_name": "out"}'

    # Check status:
    curl http://localhost:5000/run/<run_id>

Authentication
--------------
Set the environment variable PIPELINE_API_KEY to enable bearer-token
authentication.  If unset, the API is open (suitable for localhost dev).

    export PIPELINE_API_KEY="your-secret-key"
"""

from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, abort


# ── In-memory run registry ────────────────────────────────────────────────────
_RUNS: dict[str, dict[str, Any]] = {}
_RUNS_LOCK = threading.Lock()


# ── Optional scheduler integration ────────────────────────────────────────────
_SCHEDULER = None   # Set by attach_scheduler()


# ═════════════════════════════════════════════════════════════════════════════
#  AUTH HELPER
# ═════════════════════════════════════════════════════════════════════════════

def _require_auth(f):
    """Decorator: enforce bearer-token auth when PIPELINE_API_KEY is set."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        api_key = os.environ.get("PIPELINE_API_KEY")
        if api_key:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer ") or auth_header[7:] != api_key:
                abort(401, description="Invalid or missing API key")
        return f(*args, **kwargs)
    return wrapper


# ═════════════════════════════════════════════════════════════════════════════
#  PIPELINE RUNNER (background thread)
# ═════════════════════════════════════════════════════════════════════════════

def _execute_run(run_id: str, source: str, cfg: dict) -> None:
    """Run the pipeline in a background thread and update _RUNS."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))

    from pipeline_v3 import (   # pylint: disable=import-outside-toplevel
        GovernanceLogger, Extractor, Transformer, _detect_pii,
        DataClassificationTagger, DeadLetterQueue, SchemaValidator, SQLLoader,
    )
    import io
    from contextlib import redirect_stdout, redirect_stderr

    with _RUNS_LOCK:
        _RUNS[run_id]["status"]   = "running"
        _RUNS[run_id]["started"]  = datetime.now(timezone.utc).isoformat()

    stdout_buf = io.StringIO()

    try:
        gov = GovernanceLogger(run_id)
        gov.pipeline_start(cfg)

        with redirect_stdout(stdout_buf), redirect_stderr(stdout_buf):
            df   = Extractor(gov).extract(source)
            pii  = _detect_pii(list(df.columns))
            df, _ = DataClassificationTagger(gov).classify(df, pii)
            dlq  = DeadLetterQueue(gov)
            val  = SchemaValidator(gov, dlq)
            exps = val.build_suite(df, interactive=False)
            df, _failed = val.validate(df, exps, on_failure="dlq")
            df   = Transformer(gov).transform(df, pii, cfg.get("pii_action","mask"), [])

            db_type  = cfg.get("db_type", "sqlite")
            db_name  = cfg.get("db_name", run_id)
            table    = cfg.get("table",   "data")
            SQLLoader(gov, db_type).load(df, {"db_name": db_name}, table)

        log_path = str(gov.ledger_file) if hasattr(gov, "ledger_file") else None

        with _RUNS_LOCK:
            _RUNS[run_id].update({
                "status":    "success",
                "finished":  datetime.now(timezone.utc).isoformat(),
                "rows_loaded": len(df),
                "pii_fields":  len(pii),
                "log_path":    log_path,
            })

    except Exception as exc:  # pylint: disable=broad-except
        with _RUNS_LOCK:
            _RUNS[run_id].update({
                "status":   "failed",
                "finished": datetime.now(timezone.utc).isoformat(),
                "error":    str(exc),
            })


# ═════════════════════════════════════════════════════════════════════════════
#  APP FACTORY
# ═════════════════════════════════════════════════════════════════════════════

def create_app(scheduler=None) -> Flask:
    """
    Create and return the Flask application.

    Parameters
    ----------
    scheduler : PipelineScheduler | None
        Optionally attach a PipelineScheduler instance to expose
        scheduler endpoints.
    """
    global _SCHEDULER  # pylint: disable=global-statement
    if scheduler:
        _SCHEDULER = scheduler

    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    # ── Health ─────────────────────────────────────────────────────────────
    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})

    # ── Supported formats ──────────────────────────────────────────────────
    @app.get("/formats")
    @_require_auth
    def formats():
        return jsonify({
            "file_formats": [
                ".csv", ".tsv", ".fwf",
                ".json", ".jsonl", ".ndjson",
                ".yaml", ".yml", ".xml",
                ".xlsx", ".xls",
                ".parquet", ".feather", ".arrow", ".orc", ".avro",
                ".sas7bdat", ".dta",
            ],
            "compression": [".gz", ".bz2", ".zip", ".zst", ".lz4", ".tgz"],
        })

    # ── Trigger a run ──────────────────────────────────────────────────────
    @app.post("/run")
    @_require_auth
    def trigger_run():
        """
        Trigger an async pipeline run.

        Request body (JSON)
        -------------------
        {
            "source":   "path/to/data.csv",   # required
            "db_type":  "sqlite",              # optional, default "sqlite"
            "db_name":  "output",              # optional
            "table":    "results",             # optional, default "data"
            "pii_action": "mask"               # optional: mask|pseudonymise|drop
        }

        Response
        --------
        {
            "run_id": "...",
            "status": "queued",
            "poll":   "/run/<run_id>"
        }
        """
        body   = request.get_json(force=True, silent=True) or {}
        source = body.get("source")
        if not source:
            abort(400, description="'source' field is required")

        run_id = str(uuid.uuid4())
        cfg    = {k: v for k, v in body.items() if k != "source"}

        with _RUNS_LOCK:
            _RUNS[run_id] = {
                "run_id":  run_id,
                "source":  source,
                "status":  "queued",
                "queued":  datetime.now(timezone.utc).isoformat(),
                "cfg":     cfg,
            }

        thread = threading.Thread(
            target=_execute_run, args=(run_id, source, cfg), daemon=True
        )
        thread.start()

        return jsonify({
            "run_id": run_id,
            "status": "queued",
            "poll":   f"/run/{run_id}",
        }), 202

    # ── Run status ─────────────────────────────────────────────────────────
    @app.get("/run/<run_id>")
    @_require_auth
    def run_status(run_id: str):
        with _RUNS_LOCK:
            run = _RUNS.get(run_id)
        if not run:
            abort(404, description=f"Run {run_id!r} not found")
        return jsonify(run)

    # ── List all runs ──────────────────────────────────────────────────────
    @app.get("/runs")
    @_require_auth
    def list_runs():
        with _RUNS_LOCK:
            runs = list(_RUNS.values())
        runs.sort(key=lambda r: r.get("queued", ""), reverse=True)
        return jsonify({"count": len(runs), "runs": runs})

    # ── Fetch audit log ────────────────────────────────────────────────────
    @app.get("/runs/<run_id>/log")
    @_require_auth
    def run_log(run_id: str):
        with _RUNS_LOCK:
            run = _RUNS.get(run_id)
        if not run:
            abort(404, description=f"Run {run_id!r} not found")

        log_path = run.get("log_path")
        if not log_path or not Path(log_path).exists():
            return jsonify({"run_id": run_id, "entries": [], "note": "log not yet available"})

        import json as _json
        entries = []
        for line in Path(log_path).read_text(encoding="utf-8").splitlines():
            try:
                entries.append(_json.loads(line))
            except _json.JSONDecodeError:
                pass
        return jsonify({"run_id": run_id, "entry_count": len(entries), "entries": entries})

    # ── Scheduler status ───────────────────────────────────────────────────
    @app.get("/scheduler/status")
    @_require_auth
    def scheduler_status():
        if not _SCHEDULER:
            return jsonify({"enabled": False, "message": "No scheduler attached"})
        return jsonify({"enabled": True, "jobs": _SCHEDULER.status()})

    # ── Manually trigger a scheduled job ───────────────────────────────────
    @app.post("/scheduler/trigger/<job_name>")
    @_require_auth
    def scheduler_trigger(job_name: str):
        if not _SCHEDULER:
            abort(503, description="No scheduler attached")
        if job_name not in _SCHEDULER._jobs:  # pylint: disable=protected-access
            abort(404, description=f"Job {job_name!r} not found")
        meta   = _SCHEDULER._jobs[job_name]   # pylint: disable=protected-access
        run_id = str(uuid.uuid4())
        thread = threading.Thread(
            target=_SCHEDULER._run_job,       # pylint: disable=protected-access
            args=(job_name,), daemon=True
        )
        thread.start()
        return jsonify({
            "message":   f"Job {job_name!r} triggered",
            "run_id":    run_id,
            "schedule":  meta.get("schedule"),
            "run_count": meta.get("run_count", 0),
            "last_run":  meta.get("last_run"),
        }), 202

    # ── Error handlers ─────────────────────────────────────────────────────
    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(404)
    @app.errorhandler(503)
    def error_handler(exc):
        return jsonify({"error": str(exc.description)}), exc.code

    return app


# ═════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="pipeline_v3 REST API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    application = create_app()
    print(f"pipeline_v3 API listening on http://{args.host}:{args.port}")
    print("Endpoints: /health  /run  /runs  /formats  /scheduler/status")
    application.run(host=args.host, port=args.port, debug=args.debug)
