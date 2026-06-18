"""
PII discovery reporter — scans a DataFrame for PII by column NAME and, by
default, by cell VALUE, logging the combined findings through governance.

Layer 3 — imports from Layer 0 (helpers), Layer 1 (governance_logger),
Layer 3 (nlp_pii_detector, same layer — imported lazily inside the method).

Revision history
────────────────
1.0   2026-06-08   Initial release: column-name scan via helpers.detect_pii.
1.1   2026-06-17   scan() also runs a value-level scan by default (the
                   NLPPIIDetector regex path, which needs no spaCy), so PII
                   hiding in a non-PII-named column is caught. Value findings
                   are normalised into the name-scan finding schema and tagged
                   with a `detection` field ("name" or "value").
"""

import logging
from typing import TYPE_CHECKING

from pipeline.helpers import detect_pii

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

# Value-detected types that are GDPR Art. 9 special category / high-sensitivity,
# matching the name-based scan's treatment of ssn/passport.
_SPECIAL_VALUE_TYPES = {"SSN", "US_PASSPORT"}


class PIIDiscoveryReporter:
    """
    Scans DataFrame columns for PII — by name and (by default) by value.

    Column-name detection alone misses PII in a generically-named column
    (a 'comment' field full of SSNs). The value scan closes that gap using
    the regex detectors in NLPPIIDetector, which run without spaCy installed.

    Quick-start
    -----------
        from pipeline.privacy import PIIDiscoveryReporter
        reporter = PIIDiscoveryReporter(gov)
        findings = reporter.scan(df)
    """

    def __init__(self, gov: "GovernanceLogger", scan_values: bool = True) -> None:
        self.gov = gov
        self.scan_values = scan_values

    def scan(self, df, text_columns: list[str] | None = None) -> list[dict]:
        """Scan columns (by name and value) for PII and log the findings.

        ``text_columns`` limits the value scan to specific columns; None
        auto-detects text-like columns. Returns the combined finding list;
        every finding carries a ``field`` and a ``detection`` ("name"/"value").
        """
        findings = [dict(f, detection="name") for f in detect_pii(list(df.columns))]

        if self.scan_values:
            findings.extend(self._scan_values(df, text_columns))

        if findings:
            self.gov.pii_detected(findings)
            located = sorted({f["field"] for f in findings})
            logger.info("[PII] Found %d PII finding(s) across %d field(s): %s",
                        len(findings), len(located), located)
        else:
            logger.info("[PII] No PII detected by name or value.")
        return findings

    def _scan_values(self, df, text_columns: list[str] | None) -> list[dict]:
        """Value-level scan via the NLPPIIDetector regex path (spaCy optional).

        Findings are normalised into the name-scan schema so callers see one
        uniform finding shape.
        """
        from pipeline.privacy.nlp_pii_detector import NLPPIIDetector

        # Regex-only: deterministic and independent of spaCy. NER stays opt-in
        # via NLPPIIDetector directly, where its cost/nondeterminism is expected.
        detector = NLPPIIDetector(self.gov)
        raw_findings = detector.scan(
            df, text_columns=text_columns, include_regex=True, include_ner=False,
        )

        normalised = []
        for finding in raw_findings:
            entity_type = finding["entity_type"]
            special = entity_type in _SPECIAL_VALUE_TYPES
            normalised.append({
                "field": finding["column"],
                "matched_pattern": f"value:{entity_type}",
                "special_category": special,
                "gdpr_reference": "Article 9" if special else "Article 4(1)",
                "ccpa_reference": "§1798.140(o)",
                "detection": "value",
                "count": finding["count"],
            })
        return normalised
