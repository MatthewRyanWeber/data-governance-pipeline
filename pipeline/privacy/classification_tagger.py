"""
Data sensitivity classification tagger.

Assigns RESTRICTED / CONFIDENTIAL / INTERNAL / PUBLIC based on PII findings.
Drives downstream row-level and column-level security policies.

Layer 3 — imports from Layer 1 (governance_logger).
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DataClassificationTagger:
    """
    Tags DataFrames with a sensitivity classification level.

    Quick-start
    -----------
        from pipeline.privacy import DataClassificationTagger
        tagger = DataClassificationTagger(gov)
        df, level = tagger.classify(df, pii_findings)
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def classify(self, df, pii_findings: list[dict]) -> tuple:
        """Determine classification level and add _data_classification column."""
        special_count = sum(1 for f in pii_findings if f.get("special_category"))
        pii_count = len(pii_findings)

        if special_count > 0:
            level = "RESTRICTED"
        elif pii_count > 0:
            level = "CONFIDENTIAL"
        elif any(
            kw in " ".join(df.columns).lower()
            for kw in ("internal", "confidential", "private", "budget", "forecast")
        ):
            level = "INTERNAL"
        else:
            level = "PUBLIC"

        df["_data_classification"] = level
        self.gov.classification_tagged(level, pii_count, special_count)
        logger.info(
            "[CLASSIFY] Dataset classified as: %s (PII fields: %d, special category: %d)",
            level, pii_count, special_count,
        )
        return df, level
