"""
Left-joins a lookup/reference table onto the main dataset.

Supports CSV, JSON, Excel lookup formats. Unmatched rows receive NaN
(left join — never drops rows from the main dataset).

Layer 2 — imports from Layer 1 (governance_logger).
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DataEnricher:
    """
    Enriches a DataFrame by joining lookup/reference data.

    Quick-start
    -----------
        from pipeline.data_enricher import DataEnricher
        enricher = DataEnricher(gov)
        df = enricher.enrich(df, "dept_id", "departments.csv", "department_id")
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def enrich(
        self,
        df: "pd.DataFrame",
        join_col: str,
        lookup_path: str,
        lookup_key: str,
        lookup_cols: list[str] | None = None,
    ) -> "pd.DataFrame":
        """Left-join a lookup table onto the main DataFrame."""
        import pandas as pd

        if join_col not in df.columns:
            logger.warning("[ENRICHMENT] Join column '%s' not found — skipping.", join_col)
            return df

        ext = Path(lookup_path).suffix.lower()
        if ext == ".csv":
            lookup_df = pd.read_csv(lookup_path)
        elif ext == ".json":
            lookup_df = pd.read_json(lookup_path)
        elif ext in (".xlsx", ".xls"):
            lookup_df = pd.read_excel(lookup_path)
        else:
            logger.warning("[ENRICHMENT] Unsupported lookup format: %s", ext)
            return df

        if lookup_cols:
            keep = [lookup_key] + [c for c in lookup_cols if c in lookup_df.columns]
            lookup_df = lookup_df[keep]

        before_cols = set(df.columns)
        df = df.merge(
            lookup_df, left_on=join_col, right_on=lookup_key,
            how="left", suffixes=("", "_lookup"),
        )

        if lookup_key != join_col and lookup_key in df.columns:
            df.drop(columns=[lookup_key], inplace=True, errors="ignore")

        new_cols = set(df.columns) - before_cols
        rows_matched = int(df[list(new_cols)[0]].notna().sum()) if new_cols else 0

        self.gov.enrichment_applied(join_col, lookup_path, rows_matched, len(df))
        logger.info(
            "[ENRICH] Joined '%s' on '%s' → %d/%d rows matched | new columns: %s",
            lookup_path, join_col, rows_matched, len(df), list(new_cols),
        )
        return df
