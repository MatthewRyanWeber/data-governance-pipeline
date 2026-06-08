"""
Cron-style scheduler for pipeline runs.

Runs a pipeline function on a repeating cron schedule. Uses the ``schedule``
package when available; falls back to a simple minute-level time matcher.

Layer 6 — imports from Layer 0 (constants).

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Callable

logger = logging.getLogger(__name__)

from importlib.util import find_spec as _fs

HAS_SCHEDULE = _fs("schedule") is not None


class PipelineScheduler:
    """
    Schedule pipeline runs on a cron-like interval.

    Quick-start
    -----------
        from pipeline.scheduler import PipelineScheduler
        sched = PipelineScheduler(my_pipeline_fn, cron_expr="0 * * * *")
        sched.start()   # non-blocking — runs in a background thread
        # ... later ...
        sched.stop()
    """

    def __init__(
        self,
        pipeline_fn: Callable,
        cron_expr: str = "0 * * * *",
        timezone_name: str = "UTC",
    ) -> None:
        self.pipeline_fn = pipeline_fn
        self.cron_expr = cron_expr
        self.timezone_name = timezone_name
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._cron_parts = self._parse_cron(self.cron_expr)
        logger.info("PipelineScheduler initialised — cron=%s, tz=%s", self.cron_expr, self.timezone_name)

    @staticmethod
    def _parse_cron(expr: str) -> dict:
        """
        Parse a five-field cron expression into a dict of sets.

        Supports: integers, wildcards (*), ranges (1-5), steps (*/10),
        comma-separated lists (1,15,30).
        """
        fields = expr.strip().split()
        if len(fields) != 5:
            raise ValueError(f"Cron expression must have 5 fields, got {len(fields)}: {expr!r}")

        names = ["minute", "hour", "day", "month", "weekday"]
        ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]
        result: dict[str, set[int]] = {}

        for name, field, (low, high) in zip(names, fields, ranges):
            values: set[int] = set()
            for part in field.split(","):
                if part == "*":
                    values.update(range(low, high + 1))
                elif "/" in part:
                    base, step_str = part.split("/", 1)
                    step = int(step_str)
                    start = low if base == "*" else int(base)
                    values.update(range(start, high + 1, step))
                elif "-" in part:
                    range_start, range_end = part.split("-", 1)
                    values.update(range(int(range_start), int(range_end) + 1))
                else:
                    values.add(int(part))
            result[name] = values

        return result

    def _matches_now(self) -> bool:
        """Check whether the current UTC time matches the cron expression."""
        now = datetime.now(timezone.utc)
        return (
            now.minute in self._cron_parts["minute"]
            and now.hour in self._cron_parts["hour"]
            and now.day in self._cron_parts["day"]
            and now.month in self._cron_parts["month"]
            and now.weekday() in self._cron_parts["weekday"]
        )

    def _run_loop(self) -> None:
        """Background loop — checks the cron expression every 60 seconds."""
        logger.info("Scheduler loop started.")
        last_fire_minute: int | None = None

        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)
            current_minute = now.hour * 60 + now.minute

            if self._matches_now() and current_minute != last_fire_minute:
                last_fire_minute = current_minute
                logger.info("Cron match at %s — firing pipeline.", now.isoformat())
                try:
                    self.pipeline_fn()
                except Exception as exc:
                    logger.error("Scheduled pipeline run failed: %s", exc)

            self._stop_event.wait(timeout=60)

        logger.info("Scheduler loop stopped.")

    def start(self) -> None:
        """Start the scheduler in a background daemon thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Scheduler is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="pipeline-scheduler")
        self._thread.start()
        logger.info("Scheduler started.")

    def stop(self) -> None:
        """Signal the scheduler to stop and wait for the thread to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=120)
            self._thread = None
        logger.info("Scheduler stopped.")
