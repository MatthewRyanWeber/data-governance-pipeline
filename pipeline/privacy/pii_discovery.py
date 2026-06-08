"""
PII discovery reporter — wraps helpers.detect_pii with governance logging.

Layer 3 — imports from Layer 0 (helpers), Layer 1 (governance_logger).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.helpers import detect_pii

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class PIIDiscoveryReporter:
    """
    Scans DataFrame columns for PII and logs findings.

    Quick-start
    -----------
        from pipeline.privacy import PIIDiscoveryReporter
        reporter = PIIDiscoveryReporter(gov)
        findings = reporter.scan(df)
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def scan(self, df) -> list[dict]:
        """Scan DataFrame columns for PII patterns and log findings."""
        findings = detect_pii(list(df.columns))
        if findings:
            self.gov.pii_detected(findings)
            logger.info("[PII] Found %d PII field(s): %s",
                        len(findings), [f["field"] for f in findings])
        else:
            logger.info("[PII] No PII fields detected.")
        return findings
