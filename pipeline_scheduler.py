"""
pipeline_scheduler.py  —  Native Pipeline Scheduler
====================================================
Built-in cron-style scheduler so pipeline_v3 runs don't require
an external orchestrator (Airflow, cron, Task Scheduler, etc.)
for straightforward use cases.

Features
--------
  • Human-readable schedule definitions  (every 15 minutes, daily at 06:00, etc.)
  • Multiple named jobs, each with its own schedule and config
  • Missed-run detection and catch-up (optional)
  • Per-job success / failure hooks
  • Thread-safe; runs in a background daemon thread
  • Persistent run history  (schedule_history.jsonl)
  • Graceful shutdown via stop()

Quick start
-----------
    from pipeline_scheduler import PipelineScheduler
    from pipeline_v3 import GovernanceLogger

    def my_pipeline(gov, cfg):
        # ... your extract / transform / load logic ...
        pass

    sched = PipelineScheduler()
    sched.add_job(
        name     = "hourly_sales",
        fn       = my_pipeline,
        schedule = "every 1 hour",
        cfg      = {"db_type": "sqlite", "db_name": "sales"},
    )
    sched.add_job(
        name     = "daily_report",
        fn       = my_pipeline,
        schedule = "daily at 06:00",
        cfg      = {"db_type": "postgresql"},
    )
    sched.start()          # non-blocking — runs in background thread
    # sched.stop()         # graceful shutdown

Schedule string formats
-----------------------
    "every N seconds"
    "every N minutes"
    "every N hours"
    "daily at HH:MM"
    "weekly on MON at HH:MM"   (MON TUE WED THU FRI SAT SUN)
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    import schedule as _schedule
except ModuleNotFoundError:
    _schedule = None  # type: ignore[assignment]
    # PipelineScheduler will raise a clear message at first use

logger = logging.getLogger(__name__)

HISTORY_FILE = Path("schedule_history.jsonl")


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: PipelineScheduler
# ═════════════════════════════════════════════════════════════════════════════

class PipelineScheduler:
    """
    Cron-style scheduler for pipeline_v3 jobs.

    Each job is a Python callable that accepts ``(gov, cfg)`` as arguments.
    A fresh GovernanceLogger is created for every run so audit trails
    are isolated per execution.

    Parameters
    ----------
    gov_factory : callable | None
        Factory that returns a GovernanceLogger.  Defaults to importing
        GovernanceLogger from pipeline_v3 and calling it with the job name.
    history_file : str | Path
        Path to the JSONL file where run history is appended.
        Defaults to ``schedule_history.jsonl`` in the working directory.
    """

    def __init__(
        self,
        gov_factory: Callable | None = None,
        history_file: str | Path = HISTORY_FILE,
    ) -> None:
        self._gov_factory  = gov_factory or self._default_gov_factory
        self._history_file = Path(history_file)
        self._jobs: dict[str, dict] = {}
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock       = threading.Lock()

    # ── Default GovernanceLogger factory ─────────────────────────────────────
    @staticmethod
    def _default_gov_factory(name: str):
        from pipeline_v3 import GovernanceLogger  # pylint: disable=import-outside-toplevel
        gov = GovernanceLogger(name)
        gov.pipeline_start({})
        return gov

    # ── Schedule string parser ────────────────────────────────────────────────
    @staticmethod
    def _parse_schedule(s: str) -> "_schedule.Job":
        """
        Parse a human-readable schedule string into a schedule.Job.

        Supports:
            "every N seconds / minutes / hours"
            "daily at HH:MM"
            "weekly on WEEKDAY at HH:MM"
        """
        if _schedule is None:
            raise ModuleNotFoundError(
                "Missing dependency 'schedule'.  "
                "Install it with:  pip install schedule>=1.2.0"
            )
        parts = s.strip().lower().split()

        # "every N unit"
        if parts[0] == "every" and len(parts) >= 3:
            n    = int(parts[1])
            unit = parts[2].rstrip("s")   # seconds → second, etc.
            if unit == "second":
                return _schedule.every(n).seconds
            if unit == "minute":
                return _schedule.every(n).minutes
            if unit == "hour":
                return _schedule.every(n).hours
            raise ValueError(f"Unknown time unit: {parts[2]!r}")

        # "daily at HH:MM"
        if parts[0] == "daily":
            if len(parts) < 3 or parts[1] != "at":
                raise ValueError(
                    f"Cannot parse schedule string: {s!r}\n"
                    "Expected format: 'daily at HH:MM'  e.g. 'daily at 06:00'"
                )
            return _schedule.every().day.at(parts[2])

        # "weekly on WEEKDAY at HH:MM"
        if parts[0] == "weekly":
            if len(parts) < 3 or parts[1] != "on":
                raise ValueError(
                    f"Cannot parse schedule string: {s!r}\n"
                    "Expected format: 'weekly on WEEKDAY at HH:MM'  "
                    "e.g. 'weekly on mon at 08:00'"
                )
            day      = parts[2]
            time_str = parts[4] if len(parts) >= 5 else "00:00"
            day_map = {
                "mon": _schedule.every().monday,
                "tue": _schedule.every().tuesday,
                "wed": _schedule.every().wednesday,
                "thu": _schedule.every().thursday,
                "fri": _schedule.every().friday,
                "sat": _schedule.every().saturday,
                "sun": _schedule.every().sunday,
            }
            if day not in day_map:
                raise ValueError(f"Unknown weekday: {day!r}")
            return day_map[day].at(time_str)

        raise ValueError(
            f"Cannot parse schedule string: {s!r}\n"
            "Examples: 'every 15 minutes', 'daily at 06:00', 'weekly on mon at 08:00'"
        )

    # ── Add a job ─────────────────────────────────────────────────────────────
    def add_job(
        self,
        name:     str,
        fn:       Callable,
        schedule: str,
        cfg:      dict | None = None,
        on_success: Callable | None = None,
        on_failure: Callable | None = None,
        catch_up:   bool = False,
    ) -> "PipelineScheduler":
        """
        Register a new scheduled job.

        Parameters
        ----------
        name       : str       Unique job name (used as GovernanceLogger run ID).
        fn         : callable  Pipeline function — called as fn(gov, cfg).
        schedule   : str       Human-readable schedule (see module docstring).
        cfg        : dict      Passed verbatim to fn as the second argument.
        on_success : callable  Called with (name, duration_s) after success.
        on_failure : callable  Called with (name, exception) after failure.
        catch_up   : bool      If True, run once immediately if the last run
                               was missed (based on history file).

        Returns
        -------
        self  (fluent interface — chain multiple add_job() calls)
        """
        job_meta = {
            "fn":         fn,
            "schedule":   schedule,
            "cfg":        cfg or {},
            "on_success": on_success,
            "on_failure": on_failure,
            "catch_up":   catch_up,
            "run_count":  0,
            "last_run":   None,
            "last_status": None,
        }
        with self._lock:
            self._jobs[name] = job_meta

        # Build the schedule.Job and attach the wrapper
        sched_job = self._parse_schedule(schedule)
        sched_job.do(self._run_job, name)

        logger.info("Scheduled job %r: %s", name, schedule)
        return self

    def _run_job(self, name: str) -> None:
        """Execute one job run — called by the schedule library."""
        meta  = self._jobs.get(name)
        if not meta:
            return

        start   = datetime.now(timezone.utc)
        gov     = self._gov_factory(f"sched_{name}_{start.strftime('%Y%m%d_%H%M%S')}")
        status  = "success"
        exc_str = None

        try:
            meta["fn"](gov, meta["cfg"])
            duration = (datetime.now(timezone.utc) - start).total_seconds()
            logger.info("Job %r completed in %.1fs", name, duration)
            if meta["on_success"]:
                meta["on_success"](name, duration)
        except Exception as exc:  # pylint: disable=broad-except
            status  = "failure"
            exc_str = str(exc)
            logger.error("Job %r failed: %s", name, exc_str)
            if meta["on_failure"]:
                meta["on_failure"](name, exc)

        # Update metadata
        with self._lock:
            meta["run_count"]  += 1
            meta["last_run"]    = start.isoformat()
            meta["last_status"] = status

        # Append to history file
        record = {
            "job":       name,
            "started":   start.isoformat(),
            "status":    status,
            "run_count": meta["run_count"],
        }
        if exc_str:
            record["error"] = exc_str
        with open(self._history_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    def start(self, blocking: bool = False) -> None:
        """
        Start the scheduler.

        Parameters
        ----------
        blocking : bool
            If True, blocks the calling thread (useful for a dedicated
            scheduler process).  If False (default), runs in a background
            daemon thread and returns immediately.
        """
        if blocking:
            self._run_loop()
        else:
            self._thread = threading.Thread(
                target=self._run_loop, daemon=True, name="PipelineScheduler"
            )
            self._thread.start()
            logger.info("PipelineScheduler started (background thread)")

    def _run_loop(self) -> None:
        if _schedule is None:
            raise ModuleNotFoundError(
                "Missing dependency 'schedule'.  "
                "Install it with:  pip install schedule>=1.2.0"
            )
        self._stop_event.clear()
        while not self._stop_event.is_set():
            _schedule.run_pending()
            time.sleep(1)

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the scheduler to stop and wait for the thread to exit."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("PipelineScheduler stopped")

    # ── Status reporting ──────────────────────────────────────────────────────
    def status(self) -> list[dict]:
        """
        Return a snapshot of all job statuses.

        Returns
        -------
        list[dict]  One dict per job with keys: name, schedule, run_count,
                    last_run, last_status.
        """
        with self._lock:
            return [
                {
                    "name":        name,
                    "schedule":    meta["schedule"],
                    "run_count":   meta["run_count"],
                    "last_run":    meta["last_run"],
                    "last_status": meta["last_status"],
                }
                for name, meta in self._jobs.items()
            ]

    def history(self, n: int = 50) -> list[dict]:
        """
        Return the last ``n`` run records from the history file.

        Parameters
        ----------
        n : int   Maximum number of records to return (most recent first).
        """
        if not self._history_file.exists():
            return []
        lines = self._history_file.read_text(encoding="utf-8").strip().splitlines()
        records = []
        for line in reversed(lines[-n:]):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return records
