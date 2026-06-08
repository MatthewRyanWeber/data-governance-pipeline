"""
SLA monitor — tracks pipeline wall-clock time against a deadline.

Fires WARNING audit events when 80% of the SLA budget is consumed,
and BREACH events when the deadline is exceeded.

Layer 3 — imports from Layer 1 (governance_logger).
"""

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SLAMonitor:
    """
    Tracks pipeline runtime against a configurable SLA deadline.

    Quick-start
    -----------
        from pipeline.monitoring import SLAMonitor
        sla = SLAMonitor(gov, sla_seconds=7200)
        sla.start()
        # ... pipeline work ...
        elapsed = sla.final_check()
    """

    def __init__(self, gov: "GovernanceLogger", sla_seconds: int = 0) -> None:
        self.gov = gov
        self.sla_seconds = sla_seconds
        self._start: float | None = None
        self.breached: bool = False

    def start(self) -> None:
        self._start = time.monotonic()
        if self.sla_seconds:
            logger.info(
                "[SLA] Monitoring active — deadline: %ds (%.1f minutes)",
                self.sla_seconds, self.sla_seconds / 60,
            )

    def check(self, label: str = "") -> float:
        """Check elapsed time and fire audit events if SLA is breached."""
        if self._start is None:
            return 0.0
        elapsed = time.monotonic() - self._start
        if not self.sla_seconds:
            return elapsed

        if elapsed > self.sla_seconds:
            self.breached = True
            self.gov.sla_event("BREACH", elapsed, self.sla_seconds)
            logger.warning(
                "[SLA BREACH] Pipeline has run for %.0fs (limit: %ds) %s",
                elapsed, self.sla_seconds, label,
            )
        elif elapsed > self.sla_seconds * 0.8:
            self.gov.sla_event("WARNING", elapsed, self.sla_seconds)
        return elapsed

    def final_check(self) -> float:
        elapsed = self.check("final")
        if self.sla_seconds and not self.breached:
            self.gov.sla_event("OK", elapsed, self.sla_seconds)
            logger.info(
                "[SLA] Completed in %.1fs (limit: %ds, %d%% used)",
                elapsed, self.sla_seconds,
                int(100 * elapsed / self.sla_seconds),
            )
        return elapsed
