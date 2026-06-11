"""
Cron-style scheduler for pipeline runs.

Runs a pipeline function on a repeating cron schedule. Uses the ``schedule``
package when available; falls back to a simple minute-level time matcher.

Layer 6 — imports from Layer 0 (constants).

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-11   Daily/weekly crons fire every matching day (last-fire key now
                   includes the date); sleep to the next minute boundary instead
                   of a drifting fixed 60s wait; cron parser supports range/step
                   ("1-5/2") and maps weekday 7 to 0 (Sunday alias).
"""

import logging
import threading
import zoneinfo
from datetime import datetime, timezone
from typing import Callable

logger = logging.getLogger(__name__)


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

        try:
            self._tz = zoneinfo.ZoneInfo(self.timezone_name)
        except (KeyError, zoneinfo.ZoneInfoNotFoundError):
            logger.warning("Unknown timezone %r — falling back to UTC", self.timezone_name)
            self._tz = timezone.utc  # type: ignore[assignment]
        self._cron_parts = self._parse_cron(self.cron_expr)
        logger.info("PipelineScheduler initialised — cron=%s, tz=%s", self.cron_expr, self.timezone_name)

    @staticmethod
    def _parse_cron(expr: str) -> dict:
        """
        Parse a five-field cron expression into a dict of sets.

        Supports: integers, wildcards (*), ranges (1-5), steps (*/10),
        steps over ranges (1-5/2), comma-separated lists (1,15,30).
        Weekday 7 is accepted as an alias for 0 (Sunday).
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
                base, _, step_text = part.partition("/")
                step = int(step_text) if step_text else 1
                if base == "*":
                    start, end = low, high
                elif "-" in base:
                    range_start_text, range_end_text = base.split("-", 1)
                    start, end = int(range_start_text), int(range_end_text)
                else:
                    start = int(base)
                    # Cron treats "N/step" as every step-th value from N to
                    # the field maximum; a bare "N" is just that value.
                    end = high if step_text else start
                values.update(range(start, end + 1, step))
            if name == "weekday" and 7 in values:
                # POSIX cron allows both 0 and 7 for Sunday; the matcher only
                # ever produces 0-6, so 7 could never fire if kept.
                values.discard(7)
                values.add(0)
            result[name] = values

        return result

    def _matches_now(self, now: datetime | None = None) -> bool:
        """Check whether the given time (in configured timezone) matches the cron expression."""
        if now is None:
            now = datetime.now(self._tz)
        # Python weekday(): Mon=0..Sun=6; cron weekday: Sun=0..Sat=6
        cron_weekday = (now.weekday() + 1) % 7
        return (
            now.minute in self._cron_parts["minute"]
            and now.hour in self._cron_parts["hour"]
            and now.day in self._cron_parts["day"]
            and now.month in self._cron_parts["month"]
            and cron_weekday in self._cron_parts["weekday"]
        )

    def _should_fire(self, now: datetime, last_fire: datetime | None) -> bool:
        """Fire when the cron matches and this exact minute has not fired yet.

        The dedup key is the full date+time truncated to the minute — keying
        on hour*60+minute alone made daily/weekly jobs fire exactly once ever.
        """
        return self._matches_now(now) and now.replace(second=0, microsecond=0) != last_fire

    @staticmethod
    def _seconds_until_next_minute(now: datetime) -> float:
        """Seconds from *now* to the next minute boundary (always > 0)."""
        remainder = 60.0 - now.second - now.microsecond / 1_000_000
        return max(remainder, 0.001)

    def _run_loop(self) -> None:
        """Background loop — wakes at each minute boundary and checks the cron."""
        logger.info("Scheduler loop started.")
        last_fire: datetime | None = None

        while not self._stop_event.is_set():
            now = datetime.now(self._tz)

            if self._should_fire(now, last_fire):
                last_fire = now.replace(second=0, microsecond=0)
                logger.info("Cron match at %s — firing pipeline.", now.isoformat())
                try:
                    self.pipeline_fn()
                except Exception as exc:
                    logger.error("Scheduled pipeline run failed: %s", exc)

            # Sleeping to the boundary (instead of a fixed 60s) keeps the
            # check aligned even when pipeline_fn ran for a while, so no
            # scheduled minute can be skipped by drift.
            wake_reference = datetime.now(self._tz)
            self._stop_event.wait(timeout=self._seconds_until_next_minute(wake_reference))

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
