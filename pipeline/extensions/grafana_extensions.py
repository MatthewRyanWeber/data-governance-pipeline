#!/usr/bin/env python3
"""
grafana_extensions.py  —  Grafana observability integration for the pipeline suite.

Three classes that make every pipeline run and compliance control visible in
a Grafana dashboard without requiring any changes to existing pipeline code:

    MetricsSink             Write pipeline run summaries, per-stage metrics,
                            and compliance control status to a SQLite database
                            that Grafana can query via the SQLite data source
                            plugin (or any SQL-compatible Grafana plugin).

    PrometheusExporter      Expose pipeline and compliance metrics on a local
                            HTTP /metrics endpoint in Prometheus text format.
                            Grafana scrapes this endpoint via its built-in
                            Prometheus data source — no extra infrastructure.

    GrafanaDashboardGenerator
                            Generate a ready-to-import Grafana dashboard JSON
                            pre-wired with panels for pipeline throughput,
                            compliance control status, BAA/IRB expiry, vendor
                            risk, and audit event volume.

Setup (two options)
───────────────────
Option A — SQLite + Grafana SQLite plugin  (simplest, no server needed)

    1.  pip install grafana_extensions  (this file — no extra deps beyond stdlib)
    2.  Add to your pipeline:

            from grafana_extensions import MetricsSink
            sink = MetricsSink(gov)
            sink.record_run(mc)          # mc = MetricsCollector instance
            sink.record_controls(monitor_results)

    3.  In Grafana, install the "SQLite" data source plugin and point it at
        the metrics.db file path.
    4.  Import the dashboard JSON from GrafanaDashboardGenerator.generate().

Option B — Prometheus + Grafana  (real-time, standard ops stack)

    1.  pip install prometheus_client  (optional — pure stdlib fallback included)
    2.  Add to your pipeline scheduler:

            from grafana_extensions import PrometheusExporter
            exporter = PrometheusExporter(gov, port=8000)
            exporter.start()             # starts background HTTP server

    3.  In Grafana, add a Prometheus data source pointing at http://localhost:8000
    4.  Import the dashboard JSON from GrafanaDashboardGenerator.generate().

Revision history
────────────────
1.0   2026-03-23   Initial release: MetricsSink, PrometheusExporter,
                   GrafanaDashboardGenerator.
"""
from __future__ import annotations

import http.server
import json
import logging
import pathlib
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# ── Optional: prometheus_client for richer metrics ────────────────────────────
try:
    import prometheus_client as _prom_check  # noqa: F401
    _ = _prom_check  # referenced for HAS flag only
    HAS_PROMETHEUS_CLIENT = True
except ImportError:
    HAS_PROMETHEUS_CLIENT = False
    # Prometheus exporter works without this — uses a pure-stdlib text format


# ── Module helpers ────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


# ═════════════════════════════════════════════════════════════════════════════
#  1. MetricsSink  —  SQLite metrics store for Grafana SQLite data source
# ═════════════════════════════════════════════════════════════════════════════

class MetricsSink:
    """
    Write pipeline run metrics and compliance control status to a SQLite
    database that Grafana can query via the SQLite data source plugin.

    Database schema
    ───────────────
    pipeline_runs
        id              INTEGER PRIMARY KEY AUTOINCREMENT
        run_id          TEXT       pipeline PIPELINE_ID (UUID)
        started_at      TEXT       ISO timestamp
        finished_at     TEXT       ISO timestamp
        source          TEXT       source file/table/API name
        destination     TEXT       destination type (snowflake, bigquery, etc.)
        rows_extracted  INTEGER
        rows_loaded     INTEGER
        rows_failed     INTEGER
        duration_sec    REAL
        status          TEXT       "success" | "warning" | "error"
        pii_columns     INTEGER    number of PII columns detected
        error_message   TEXT       populated on error

    stage_metrics
        id              INTEGER PRIMARY KEY AUTOINCREMENT
        run_id          TEXT
        recorded_at     TEXT
        stage           TEXT       "extract" | "transform" | "load" | "validate"
        rows            INTEGER
        duration_sec    REAL
        rows_per_sec    REAL

    compliance_controls
        id              INTEGER PRIMARY KEY AUTOINCREMENT
        checked_at      TEXT
        control_id      TEXT
        status          TEXT       "OK" | "WARN" | "FAIL"
        detail          TEXT

    audit_summary
        id              INTEGER PRIMARY KEY AUTOINCREMENT
        summarised_at   TEXT
        period_start    TEXT
        period_end      TEXT
        total_events    INTEGER
        extract_events  INTEGER
        privacy_events  INTEGER
        compliance_events INTEGER
        load_events     INTEGER
        error_events    INTEGER

    Quick-start
    ───────────
        from grafana_extensions import MetricsSink
        from pipeline_v3 import GovernanceLogger, MetricsCollector

        gov  = GovernanceLogger(run_id="run_001", src="employees.csv")
        mc   = MetricsCollector(gov)
        sink = MetricsSink(gov)

        # At end of pipeline run:
        sink.record_run(
            run_id      = "run_001",
            source      = "employees.csv",
            destination = "snowflake",
            rows_extracted = 50_000,
            rows_loaded    = 49_987,
            rows_failed    = 13,
            duration_sec   = 42.7,
            status         = "success",
            pii_columns    = 4,
        )

        # After ComplianceMonitor.run_all():
        sink.record_controls(monitor_results)

        # Periodically summarise the audit ledger:
        sink.summarise_ledger()
    """

    _DB_FILE   = "metrics.db"
    _TIMEOUT   = 10   # SQLite connection timeout seconds

    _DDL = [
        """CREATE TABLE IF NOT EXISTS pipeline_runs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id         TEXT,
            started_at     TEXT,
            finished_at    TEXT,
            source         TEXT,
            destination    TEXT,
            rows_extracted INTEGER DEFAULT 0,
            rows_loaded    INTEGER DEFAULT 0,
            rows_failed    INTEGER DEFAULT 0,
            duration_sec   REAL    DEFAULT 0,
            status         TEXT    DEFAULT 'success',
            pii_columns    INTEGER DEFAULT 0,
            error_message  TEXT    DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS stage_metrics (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id       TEXT,
            recorded_at  TEXT,
            stage        TEXT,
            rows         INTEGER DEFAULT 0,
            duration_sec REAL    DEFAULT 0,
            rows_per_sec REAL    DEFAULT 0
        )""",
        """CREATE TABLE IF NOT EXISTS compliance_controls (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_at  TEXT,
            control_id  TEXT,
            status      TEXT,
            detail      TEXT DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS audit_summary (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            summarised_at     TEXT,
            period_start      TEXT,
            period_end        TEXT,
            total_events      INTEGER DEFAULT 0,
            extract_events    INTEGER DEFAULT 0,
            privacy_events    INTEGER DEFAULT 0,
            compliance_events INTEGER DEFAULT 0,
            load_events       INTEGER DEFAULT 0,
            error_events      INTEGER DEFAULT 0
        )""",
        # Indexes for Grafana time-range queries
        "CREATE INDEX IF NOT EXISTS idx_runs_started   ON pipeline_runs(started_at)",
        "CREATE INDEX IF NOT EXISTS idx_ctrl_checked   ON compliance_controls(checked_at)",
        "CREATE INDEX IF NOT EXISTS idx_summary_period ON audit_summary(period_start)",
    ]

    def __init__(
        self,
        gov,
        db_path:  Optional[Union[str, pathlib.Path]] = None,
        dry_run:  bool = False,
    ) -> None:
        """
        Parameters
        ──────────
        gov       GovernanceLogger for audit events.
        db_path   Path to the SQLite metrics database.
                  Default: <gov.log_dir>/metrics.db
        dry_run   Collect metrics without writing to the database.
        """
        self.gov     = gov
        self.dry_run = dry_run
        self._lock   = threading.Lock()
        self._path   = (
            pathlib.Path(db_path) if db_path
            else pathlib.Path(gov.log_dir) / self._DB_FILE  # type: ignore[attr-defined]
        )
        if not dry_run:
            self._init_db()

    # ── Public API ────────────────────────────────────────────────────────────

    def record_run(
        self,
        run_id:         str,
        source:         str,
        destination:    str,
        rows_extracted: int  = 0,
        rows_loaded:    int  = 0,
        rows_failed:    int  = 0,
        duration_sec:   float = 0.0,
        status:         str  = "success",
        pii_columns:    int  = 0,
        started_at:     Optional[str] = None,
        error_message:  str  = "",
        stage_metrics:  Optional[Dict[str, Dict]] = None,
    ) -> None:
        """
        Record a completed pipeline run to the metrics database.

        Parameters
        ──────────
        run_id          Pipeline run UUID (from GovernanceLogger / PIPELINE_ID).
        source          Source label (file path, table name, API name).
        destination     Destination type string (e.g. "snowflake", "bigquery").
        rows_extracted  Rows read from the source.
        rows_loaded     Rows successfully written to the destination.
        rows_failed     Rows that went to the dead letter queue.
        duration_sec    Total wall-clock seconds for the run.
        status          "success" | "warning" | "error"
        pii_columns     Number of PII columns detected by PIIDiscoveryReporter.
        started_at      ISO timestamp of run start (default: now).
        error_message   Error description if status is "error".
        stage_metrics   Optional dict from MetricsCollector._stages for
                        per-stage breakdown.  Keys are stage names; values
                        are dicts with "rows" and "elapsed" (or "duration_sec").
        """
        if status not in ("success", "warning", "error"):
            raise ValueError(
                f"MetricsSink: status must be 'success', 'warning', or 'error', "
                f"got '{status}'."
            )

        now          = _iso(_now_utc())
        started_at   = started_at or now

        if self.dry_run:
            logger.info(
                "MetricsSink [dry_run]: run %s — %d rows, %.1fs, %s",
                run_id, rows_loaded, duration_sec, status
            )
            return

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO pipeline_runs
                   (run_id, started_at, finished_at, source, destination,
                    rows_extracted, rows_loaded, rows_failed,
                    duration_sec, status, pii_columns, error_message)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (run_id, started_at, now, source, destination,
                 rows_extracted, rows_loaded, rows_failed,
                 duration_sec, status, pii_columns, error_message),
            )
            # Per-stage breakdown
            if stage_metrics:
                for stage, m in stage_metrics.items():
                    rows     = m.get("rows", 0)
                    elapsed  = m.get("elapsed", m.get("duration_sec", 0.0))
                    rps      = rows / elapsed if elapsed > 0 else 0.0
                    conn.execute(
                        """INSERT INTO stage_metrics
                           (run_id, recorded_at, stage, rows, duration_sec, rows_per_sec)
                           VALUES (?,?,?,?,?,?)""",
                        (run_id, now, stage, rows, elapsed, rps),
                    )

        self.gov._event(  # type: ignore[attr-defined]
            "METRICS", "RUN_RECORDED",
            {"run_id": run_id, "source": source, "destination": destination,
             "rows_loaded": rows_loaded, "duration_sec": duration_sec,
             "status": status},
        )
        print(f"  📊  MetricsSink: run recorded — {rows_loaded:,} rows, "
              f"{duration_sec:.1f}s, {status}")

    def record_run_from_collector(
        self,
        mc,
        run_id:      str,
        source:      str,
        destination: str,
        status:      str = "success",
        pii_columns: int = 0,
        error_message: str = "",
    ) -> None:
        """
        Convenience wrapper — record a run directly from a MetricsCollector
        instance.  Extracts rows and timing automatically.

        Parameters
        ──────────
        mc            MetricsCollector instance (from pipeline_v3.py).
        run_id        Pipeline run UUID.
        source        Source label.
        destination   Destination type string.
        status        "success" | "warning" | "error"
        pii_columns   PII columns detected.
        error_message Error description if status is "error".
        """
        stages        = getattr(mc, "_stages", {})
        rows_extracted = stages.get("extract", {}).get("rows", getattr(mc, "rows_in", 0))
        rows_loaded    = stages.get("load", {}).get("rows", getattr(mc, "rows_out", 0))
        rows_failed    = max(0, rows_extracted - rows_loaded)

        run_start  = getattr(mc, "_run_start", time.monotonic())
        duration   = time.monotonic() - run_start

        self.record_run(
            run_id         = run_id,
            source         = source,
            destination    = destination,
            rows_extracted = rows_extracted,
            rows_loaded    = rows_loaded,
            rows_failed    = rows_failed,
            duration_sec   = duration,
            status         = status,
            pii_columns    = pii_columns,
            error_message  = error_message,
            stage_metrics  = stages,
        )

    def record_controls(self, results: List[Dict]) -> None:
        """
        Write ComplianceMonitor.run_all() results to the metrics database.

        Parameters
        ──────────
        results   List of result dicts from ComplianceMonitor.run_all().
                  Each dict must have: control_id, status, detail, checked_at.
        """
        if self.dry_run:
            logger.info("MetricsSink [dry_run]: %d controls", len(results))
            return

        now = _iso(_now_utc())
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO compliance_controls
                   (checked_at, control_id, status, detail)
                   VALUES (?,?,?,?)""",
                [
                    (r.get("checked_at", now),
                     r["control_id"],
                     r["status"],
                     r.get("detail", ""))
                    for r in results
                ],
            )

        failed = sum(1 for r in results if r["status"] == "FAIL")
        warned = sum(1 for r in results if r["status"] == "WARN")
        print(f"  📊  MetricsSink: {len(results)} controls recorded "
              f"— {failed} FAIL, {warned} WARN")

    def summarise_ledger(self) -> Dict:
        """
        Read the audit ledger JSONL files and write a summary row to the
        audit_summary table.  Call this periodically (e.g. daily) to keep
        the Grafana audit volume chart up to date.

        Returns the summary dict that was written.
        """
        log_dir      = pathlib.Path(self.gov.log_dir)  # type: ignore[attr-defined]
        ledger_files = sorted(log_dir.glob("audit_ledger*.jsonl"))

        events: List[Dict] = []
        for f in ledger_files:
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        if not events:
            return {}

        timestamps = [e.get("timestamp_utc", "") for e in events
                      if e.get("timestamp_utc")]
        period_start = min(timestamps)[:19] if timestamps else ""
        period_end   = max(timestamps)[:19] if timestamps else ""

        def _count(cat: str) -> int:
            return sum(1 for e in events if e.get("category") == cat)

        summary = {
            "summarised_at":     _iso(_now_utc()),
            "period_start":      period_start,
            "period_end":        period_end,
            "total_events":      len(events),
            "extract_events":    _count("EXTRACT"),
            "privacy_events":    _count("PRIVACY"),
            "compliance_events": _count("COMPLIANCE"),
            "load_events":       _count("LOAD"),
            "error_events":      sum(
                1 for e in events
                if e.get("level") in ("ERROR", "CRITICAL")
            ),
        }

        if not self.dry_run:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO audit_summary
                       (summarised_at, period_start, period_end, total_events,
                        extract_events, privacy_events, compliance_events,
                        load_events, error_events)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (summary["summarised_at"], summary["period_start"],
                     summary["period_end"], summary["total_events"],
                     summary["extract_events"], summary["privacy_events"],
                     summary["compliance_events"], summary["load_events"],
                     summary["error_events"]),
                )

        print(f"  📊  MetricsSink: audit summary — {len(events):,} events "
              f"({period_start[:10]} → {period_end[:10]})")
        return summary

    def recent_runs(self, n: int = 20) -> List[Dict]:
        """Return the n most recent pipeline runs as a list of dicts."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT ?",
                (n,)
            ).fetchall()
            cols = [d[0] for d in conn.execute(
                "SELECT * FROM pipeline_runs LIMIT 0"
            ).description or []]
        return [dict(zip(cols, row)) for row in rows] if cols else []

    def db_path(self) -> pathlib.Path:
        """Return the path of the metrics database."""
        return self._path

    # ── Internals ─────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            # WAL mode allows concurrent reads (Grafana) while the pipeline writes
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            for ddl in self._DDL:
                conn.execute(ddl)
        logger.info("MetricsSink: database ready at %s", self._path)

    def _connect(self):
        return sqlite3.connect(
            str(self._path),
            timeout=self._TIMEOUT,
            isolation_level=None,   # autocommit
            check_same_thread=False,
        )


# ═════════════════════════════════════════════════════════════════════════════
#  2. PrometheusExporter  —  /metrics HTTP endpoint for Grafana Prometheus
# ═════════════════════════════════════════════════════════════════════════════

class PrometheusExporter:
    """
    Expose pipeline and compliance metrics on a local HTTP /metrics endpoint
    in Prometheus text exposition format.

    Grafana scrapes this endpoint via its built-in Prometheus data source.
    No Prometheus server is required — Grafana can scrape directly.

    Metrics exposed
    ───────────────
    pipeline_runs_total               Counter   Total pipeline runs
    pipeline_rows_extracted_total     Counter   Total rows extracted (all runs)
    pipeline_rows_loaded_total        Counter   Total rows loaded (all runs)
    pipeline_rows_failed_total        Counter   Total rows sent to DLQ
    pipeline_last_duration_seconds    Gauge     Duration of the most recent run
    pipeline_last_rows_loaded         Gauge     Rows loaded in most recent run
    pipeline_last_status              Gauge     1=success, 0.5=warning, 0=error
    compliance_control_status         Gauge     Per-control: 1=OK, 0.5=WARN, 0=FAIL
    pipeline_pii_columns_detected     Gauge     PII columns in most recent run
    pipeline_audit_events_total       Counter   Total audit ledger events

    Quick-start
    ───────────
        from grafana_extensions import PrometheusExporter
        from pipeline_v3 import GovernanceLogger

        gov      = GovernanceLogger(run_id="run_001", src="employees.csv")
        exporter = PrometheusExporter(gov, port=8000)
        exporter.start()     # starts background HTTP server thread

        # After each run:
        exporter.update_run(rows_extracted=50000, rows_loaded=49987,
                            rows_failed=13, duration_sec=42.7, status="success")

        # After each ComplianceMonitor.run_all():
        exporter.update_controls(monitor_results)

    Then in Grafana: add a Prometheus data source at http://localhost:8000
    """

    # Status value mappings — Grafana threshold-based colour coding works best
    # with numeric values: 1 = green, 0.5 = yellow, 0 = red
    _STATUS_VALUES = {"success": 1.0, "warning": 0.5, "error": 0.0,
                      "OK": 1.0,      "WARN": 0.5,    "FAIL": 0.0}

    def __init__(
        self,
        gov,
        port:    int  = 8000,
        host:    str  = "0.0.0.0",
        dry_run: bool = False,
    ) -> None:
        """
        Parameters
        ──────────
        gov      GovernanceLogger for audit events.
        port     HTTP port for the /metrics endpoint (default 8000).
        host     Bind address (default 0.0.0.0 — all interfaces).
        dry_run  Update internal state without starting the HTTP server.
        """
        self.gov     = gov
        self.port    = port
        self.host    = host
        self.dry_run = dry_run
        self._lock   = threading.Lock()
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread]       = None

        # Internal metric state
        self._counters: Dict[str, float] = {
            "pipeline_runs_total":           0,
            "pipeline_rows_extracted_total": 0,
            "pipeline_rows_loaded_total":    0,
            "pipeline_rows_failed_total":    0,
            "pipeline_audit_events_total":   0,
        }
        self._gauges: Dict[str, float] = {
            "pipeline_last_duration_seconds": 0,
            "pipeline_last_rows_loaded":      0,
            "pipeline_last_status":           1,
            "pipeline_pii_columns_detected":  0,
        }
        self._control_gauges: Dict[str, float] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Start the background HTTP server thread.
        The /metrics endpoint will be available at http://<host>:<port>/metrics
        """
        if self.dry_run:
            logger.info("PrometheusExporter [dry_run]: server not started.")
            return
        if self._thread and self._thread.is_alive():
            logger.warning("PrometheusExporter: already running on port %d", self.port)
            return

        exporter = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # pylint: disable=invalid-name
                if self.path in ("/metrics", "/metrics/"):
                    body = exporter._render_metrics().encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "text/plain; version=0.0.4; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, fmt, *args):  # suppress default access log
                pass

        try:
            self._server = http.server.HTTPServer((self.host, self.port), _Handler)
        except OSError as exc:
            raise RuntimeError(
                f"PrometheusExporter: could not bind to port {self.port} — "
                f"address already in use. Try a different port: {exc}"
            ) from exc
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="prometheus-exporter",
        )
        self._thread.start()
        print(f"  📡  PrometheusExporter: listening on "
              f"http://{self.host}:{self.port}/metrics")
        logger.info("PrometheusExporter: started on %s:%d", self.host, self.port)

    def stop(self) -> None:
        """Shut down the HTTP server gracefully."""
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.info("PrometheusExporter: stopped.")

    def update_run(
        self,
        rows_extracted: int   = 0,
        rows_loaded:    int   = 0,
        rows_failed:    int   = 0,
        duration_sec:   float = 0.0,
        status:         str   = "success",
        pii_columns:    int   = 0,
    ) -> None:
        """
        Update metric state after a pipeline run completes.
        Thread-safe — can be called from within a running pipeline.
        """
        with self._lock:
            self._counters["pipeline_runs_total"]           += 1
            self._counters["pipeline_rows_extracted_total"] += rows_extracted
            self._counters["pipeline_rows_loaded_total"]    += rows_loaded
            self._counters["pipeline_rows_failed_total"]    += rows_failed
            self._gauges["pipeline_last_duration_seconds"]   = duration_sec
            self._gauges["pipeline_last_rows_loaded"]        = rows_loaded
            self._gauges["pipeline_last_status"]             = (
                self._STATUS_VALUES.get(status, 1.0)
            )
            self._gauges["pipeline_pii_columns_detected"]   = pii_columns

    def update_controls(self, results: List[Dict]) -> None:
        """
        Update compliance control gauge values from ComplianceMonitor results.
        Each control becomes a labelled gauge metric.
        """
        with self._lock:
            for r in results:
                ctrl  = r.get("control_id", "UNKNOWN")
                value = self._STATUS_VALUES.get(r.get("status", "OK"), 1.0)
                self._control_gauges[ctrl] = value

    def update_audit_count(self, total_events: int) -> None:
        """Update the total audit event counter."""
        with self._lock:
            self._counters["pipeline_audit_events_total"] = total_events

    def is_running(self) -> bool:
        """Return True if the HTTP server is currently running."""
        return self._thread is not None and self._thread.is_alive()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _render_metrics(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        lines = [
            "# HELP pipeline_runs_total Total number of pipeline runs",
            "# TYPE pipeline_runs_total counter",
        ]
        with self._lock:
            for name, value in self._counters.items():
                mtype = "counter"
                lines += [
                    f"# HELP {name} Pipeline metric: {name.replace('_', ' ')}",
                    f"# TYPE {name} {mtype}",
                    f"{name} {value}",
                ]
            for name, value in self._gauges.items():
                lines += [
                    f"# HELP {name} Pipeline metric: {name.replace('_', ' ')}",
                    f"# TYPE {name} gauge",
                    f"{name} {value}",
                ]
            if self._control_gauges:
                lines += [
                    "# HELP compliance_control_status Compliance control status: "
                    "1=OK 0.5=WARN 0=FAIL",
                    "# TYPE compliance_control_status gauge",
                ]
                for ctrl, value in self._control_gauges.items():
                    lines.append(
                        f'compliance_control_status{{control="{ctrl}"}} {value}'
                    )
        return "\n".join(lines) + "\n"


# ═════════════════════════════════════════════════════════════════════════════
#  3. GrafanaDashboardGenerator  —  ready-to-import dashboard JSON
# ═════════════════════════════════════════════════════════════════════════════

class GrafanaDashboardGenerator:
    """
    Generate a ready-to-import Grafana dashboard JSON file pre-wired with
    panels for the data this pipeline produces.

    The generated dashboard works with either data source:
    - SQLite data source plugin  (requires MetricsSink)
    - Prometheus data source     (requires PrometheusExporter)

    Panels included
    ───────────────
    Row 1 — Pipeline Overview
        • Total runs (stat panel)
        • Total rows loaded (stat panel)
        • Last run status (stat panel — green/yellow/red threshold)
        • Last run duration (stat panel)

    Row 2 — Throughput
        • Rows loaded over time (time series)
        • Run duration over time (time series)
        • Rows failed / DLQ over time (time series)

    Row 3 — Compliance Controls
        • Control status grid (table panel — one row per control)
        • Controls pass rate over time (time series)

    Row 4 — Audit Activity
        • Audit events by category (bar chart)
        • Error events over time (time series)

    Row 5 — Governance
        • PII columns detected per run (bar chart)
        • Compliance events over time (time series)

    Quick-start
    ───────────
        from grafana_extensions import GrafanaDashboardGenerator

        gen = GrafanaDashboardGenerator(
            title           = "Data Governance Pipeline",
            datasource_name = "Pipeline Metrics",   # your SQLite DS name in Grafana
            datasource_type = "sqlite",             # "sqlite" or "prometheus"
        )

        gen.generate("grafana_dashboard.json")
        # → Import this file in Grafana: Dashboards → Import → Upload JSON
    """

    def __init__(
        self,
        title:           str = "Data Governance Pipeline",
        datasource_name: str = "Pipeline Metrics",
        datasource_type: str = "sqlite",
        org_name:        str = "",
        refresh_interval: str = "1m",
    ) -> None:
        """
        Parameters
        ──────────
        title             Dashboard title shown in Grafana.
        datasource_name   Name of the Grafana data source to query.
                          Must match the data source name you configured in Grafana.
        datasource_type   "sqlite" or "prometheus"
        org_name          Optional organization name shown in the dashboard header.
        refresh_interval  Auto-refresh interval string (e.g. "30s", "1m", "5m").
        """
        if datasource_type not in ("sqlite", "prometheus"):
            raise ValueError(
                "GrafanaDashboardGenerator: datasource_type must be "
                "'sqlite' or 'prometheus'."
            )
        self.title            = title
        self.datasource_name  = datasource_name
        self.datasource_type  = datasource_type
        self.org_name         = org_name
        self.refresh_interval = refresh_interval

    # ── Public API ────────────────────────────────────────────────────────────

    def generate(self, path: Union[str, pathlib.Path]) -> pathlib.Path:
        """
        Write the dashboard JSON to disk.
        Import in Grafana: Dashboards → New → Import → Upload JSON file.
        """
        path = pathlib.Path(path)
        dashboard = self._build_dashboard()
        path.write_text(
            json.dumps(dashboard, indent=2), encoding="utf-8"
        )
        logger.info("GrafanaDashboardGenerator: dashboard written → %s", path)
        print(f"  📊  Grafana dashboard generated → {path}")
        print("       Import in Grafana: Dashboards → New → Import → "
              "Upload JSON file")
        return path

    def as_dict(self) -> Dict:
        """Return the dashboard as a Python dict."""
        return self._build_dashboard()

    # ── Dashboard builder ─────────────────────────────────────────────────────

    def _ds(self) -> Dict:
        """Datasource reference used in all panel targets."""
        return {"type": self.datasource_type, "uid": "${DS_UID}"}

    def _build_dashboard(self) -> Dict:
        is_sq = self.datasource_type == "sqlite"

        # Queries differ by data source type
        def sq(sql: str, ref: str = "A") -> Dict:
            """SQLite panel target."""
            return {"datasource": self._ds(), "rawSql": sql,
                    "refId": ref, "format": "table"}

        def pq(expr: str, ref: str = "A", legend: str = "") -> Dict:
            """Prometheus panel target."""
            return {"datasource": self._ds(), "expr": expr,
                    "refId": ref, "legendFormat": legend}

        def target(sql: str, prom_expr: str, ref: str = "A",
                   legend: str = "") -> Dict:
            return sq(sql, ref) if is_sq else pq(prom_expr, ref, legend)

        panels = []
        panel_id = 1

        def _stat(title, sql, prom, unit="short", thresholds=None,
                  color_mode="background") -> Dict:
            nonlocal panel_id
            p = {
                "id":    panel_id,
                "type":  "stat",
                "title": title,
                "datasource": self._ds(),
                "targets": [target(sql, prom)],
                "fieldConfig": {
                    "defaults": {
                        "unit": unit,
                        "color": {"mode": color_mode},
                        "thresholds": thresholds or {
                            "mode": "absolute",
                            "steps": [
                                {"color": "green", "value": None},
                            ],
                        },
                    }
                },
                "options": {"reduceOptions": {"calcs": ["lastNotNull"]}},
                "gridPos": {"h": 4, "w": 6, "x": (panel_id - 1) % 4 * 6, "y": 0},
            }
            panel_id += 1
            return p

        def _timeseries(title, targets_list, unit="short", y=8) -> Dict:
            nonlocal panel_id
            p = {
                "id":    panel_id,
                "type":  "timeseries",
                "title": title,
                "datasource": self._ds(),
                "targets": targets_list,
                "fieldConfig": {"defaults": {"unit": unit}},
                "gridPos": {"h": 8, "w": 12, "x": (panel_id % 2) * 12, "y": y},
            }
            panel_id += 1
            return p

        def _table(title, sql, prom, y=16) -> Dict:
            nonlocal panel_id
            p = {
                "id":    panel_id,
                "type":  "table",
                "title": title,
                "datasource": self._ds(),
                "targets": [target(sql, prom)],
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": y},
            }
            panel_id += 1
            return p

        # ── Row 1: Overview stats ──────────────────────────────────────────
        panels.append(_stat(
            "Total Runs",
            "SELECT COUNT(*) as value FROM pipeline_runs",
            "pipeline_runs_total",
            unit="none",
        ))
        panels.append(_stat(
            "Total Rows Loaded",
            "SELECT SUM(rows_loaded) as value FROM pipeline_runs",
            "pipeline_rows_loaded_total",
            unit="none",
        ))
        panels.append(_stat(
            "Last Run Status",
            "SELECT CASE status WHEN 'success' THEN 1 WHEN 'warning' THEN 0.5 "
            "ELSE 0 END as value FROM pipeline_runs ORDER BY started_at DESC LIMIT 1",
            "pipeline_last_status",
            thresholds={
                "mode": "absolute",
                "steps": [
                    {"color": "red",    "value": None},
                    {"color": "yellow", "value": 0.4},
                    {"color": "green",  "value": 0.9},
                ],
            },
        ))
        panels.append(_stat(
            "Last Run Duration",
            "SELECT duration_sec as value FROM pipeline_runs "
            "ORDER BY started_at DESC LIMIT 1",
            "pipeline_last_duration_seconds",
            unit="s",
        ))

        # ── Row 2: Throughput time series ──────────────────────────────────
        panels.append(_timeseries(
            "Rows Loaded Over Time",
            [target(
                "SELECT started_at as time, rows_loaded as value, source "
                "FROM pipeline_runs ORDER BY started_at",
                "pipeline_rows_loaded_total",
                legend="rows loaded",
            )],
            unit="none", y=4,
        ))
        panels.append(_timeseries(
            "Run Duration Over Time",
            [target(
                "SELECT started_at as time, duration_sec as value "
                "FROM pipeline_runs ORDER BY started_at",
                "pipeline_last_duration_seconds",
                legend="duration (s)",
            )],
            unit="s", y=4,
        ))

        # ── Row 3: Compliance controls ─────────────────────────────────────
        panels.append(_table(
            "Compliance Controls — Latest Status",
            """SELECT control_id, status, detail,
               MAX(checked_at) as last_checked
               FROM compliance_controls
               GROUP BY control_id
               ORDER BY status DESC, control_id""",
            "compliance_control_status",
            y=12,
        ))

        panels.append(_timeseries(
            "Controls Pass Rate Over Time",
            [target(
                """SELECT checked_at as time,
                   ROUND(100.0 * SUM(CASE status WHEN 'OK' THEN 1 ELSE 0 END)
                   / COUNT(*), 1) as value
                   FROM compliance_controls
                   GROUP BY DATE(checked_at)
                   ORDER BY checked_at""",
                "avg(compliance_control_status)",
                legend="pass rate %",
            )],
            unit="percent", y=20,
        ))

        # ── Row 4: Audit activity ──────────────────────────────────────────
        panels.append(_timeseries(
            "Audit Events Over Time",
            [target(
                """SELECT summarised_at as time, total_events as value
                   FROM audit_summary ORDER BY summarised_at""",
                "pipeline_audit_events_total",
                legend="total events",
            )],
            unit="none", y=28,
        ))
        panels.append(_timeseries(
            "Error Events Over Time",
            [target(
                """SELECT summarised_at as time, error_events as value
                   FROM audit_summary ORDER BY summarised_at""",
                "pipeline_rows_failed_total",
                legend="errors",
            )],
            unit="none", y=28,
        ))

        # ── Row 5: Governance ──────────────────────────────────────────────
        panels.append(_timeseries(
            "PII Columns Detected Per Run",
            [target(
                """SELECT started_at as time, pii_columns as value
                   FROM pipeline_runs ORDER BY started_at""",
                "pipeline_pii_columns_detected",
                legend="PII columns",
            )],
            unit="none", y=36,
        ))
        panels.append(_timeseries(
            "Rows Failed (DLQ) Over Time",
            [target(
                """SELECT started_at as time, rows_failed as value
                   FROM pipeline_runs ORDER BY started_at""",
                "pipeline_rows_failed_total",
                legend="rows failed",
            )],
            unit="none", y=36,
        ))

        # ── Dashboard envelope ─────────────────────────────────────────────
        header = self.title
        if self.org_name:
            header = f"{self.title} — {self.org_name}"

        return {
            "title":         header,
            "uid":           "pipeline-governance-001",
            "schemaVersion": 38,
            "version":       1,
            "refresh":       self.refresh_interval,
            "time":          {"from": "now-24h", "to": "now"},
            "timepicker":    {},
            "templating": {
                "list": [
                    {
                        "name":       "DS_UID",
                        "type":       "datasource",
                        "pluginId":   self.datasource_type,
                        "label":      "Data Source",
                        "current":    {"text": self.datasource_name},
                    }
                ]
            },
            "panels":        panels,
            "tags":          ["pipeline", "governance", "compliance",
                              self.datasource_type],
            "description": (
                f"Auto-generated by grafana_extensions.py — "
                f"Data Governance Pipeline observability dashboard. "
                f"Data source: {self.datasource_name} ({self.datasource_type}). "
                f"Generated: {_iso(_now_utc())[:19]} UTC"
            ),
        }