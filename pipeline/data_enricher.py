"""
Left-joins a lookup/reference table onto the main dataset.

Supports CSV, JSON, Excel lookup formats. Unmatched rows receive NaN
(left join — never drops rows from the main dataset).

Layer 2 — imports from Layer 0 (helpers), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-11   Key-collision fix: drop the lookup's key column, never the
                   main table's; duplicate lookup keys are deduplicated with a
                   warning so row counts are preserved; lookup files cached by
                   (path, mtime) so chunked runs parse each file once.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.helpers import load_file_cached

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

    @staticmethod
    def _read_lookup_file(lookup_path: str):
        """Read a CSV/JSON/Excel lookup file, or None for unsupported formats."""
        import pandas as pd

        ext = Path(lookup_path).suffix.lower()
        if ext == ".csv":
            return pd.read_csv(lookup_path, encoding="utf-8")
        if ext == ".json":
            return pd.read_json(lookup_path, encoding="utf-8")
        if ext in (".xlsx", ".xls"):
            return pd.read_excel(lookup_path)
        logger.warning("[ENRICHMENT] Unsupported lookup format: %s", ext)
        return None

    def enrich(
        self,
        df: "pd.DataFrame",
        join_col: str,
        lookup_path: str,
        lookup_key: str,
        lookup_cols: list[str] | None = None,
    ) -> "pd.DataFrame":
        """Left-join a lookup table onto the main DataFrame."""
        if join_col not in df.columns:
            logger.warning("[ENRICHMENT] Join column '%s' not found — skipping.", join_col)
            return df

        # Cached by (path, mtime) so chunked runs parse each lookup once
        # instead of once per chunk. The cached frame is never mutated.
        lookup_df = load_file_cached(lookup_path, self._read_lookup_file)
        if lookup_df is None:
            return df

        if lookup_cols:
            keep = [lookup_key] + [c for c in lookup_cols if c in lookup_df.columns]
            lookup_df = lookup_df[keep]

        duplicate_key_count = int(lookup_df.duplicated(subset=[lookup_key]).sum())
        if duplicate_key_count:
            # Duplicate join keys would fan out the left join and silently
            # multiply main-table rows; keep the first occurrence instead.
            logger.warning(
                "[ENRICHMENT] Lookup '%s' has %d duplicate value(s) in key '%s' — "
                "keeping the first occurrence of each to preserve row counts.",
                lookup_path, duplicate_key_count, lookup_key,
            )
            lookup_df = lookup_df.drop_duplicates(subset=[lookup_key], keep="first")

        before_cols = set(df.columns)
        df = df.merge(
            lookup_df, left_on=join_col, right_on=lookup_key,
            how="left", suffixes=("", "_lookup"),
        )

        if lookup_key != join_col:
            # When the lookup key name collides with an existing main-table
            # column, the merge suffixes the lookup's copy — drop that one,
            # never the main table's column.
            if lookup_key in before_cols:
                redundant_key_column = f"{lookup_key}_lookup"
            else:
                redundant_key_column = lookup_key
            df = df.drop(columns=[redundant_key_column], errors="ignore")

        new_cols = set(df.columns) - before_cols
        rows_matched = int(df[list(new_cols)].notna().any(axis=1).sum()) if new_cols else 0

        self.gov.enrichment_applied(join_col, lookup_path, rows_matched, len(df))
        logger.info(
            "[ENRICH] Joined '%s' on '%s' → %d/%d rows matched | new columns: %s",
            lookup_path, join_col, rows_matched, len(df), list(new_cols),
        )
        return df
