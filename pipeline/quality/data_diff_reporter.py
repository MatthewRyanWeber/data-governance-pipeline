"""
Data diff reporter — compares two DataFrames and produces a structured diff report.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DataDiffReporter:
    """
    Compares two DataFrames (or snapshots from consecutive runs) and
    produces a structured diff report showing exactly what changed.

    Reports include:
      - New rows added since the last run
      - Rows deleted since the last run
      - Rows with one or more column values changed
      - A per-column change summary (count of cells modified)
      - A JSON diff report written to the governance log directory

    Quick-start
    -----------
        from pipeline.quality import DataDiffReporter
        reporter = DataDiffReporter(gov)
        diff     = reporter.compare(df_old, df_new, key_columns=["id"])
        reporter.save(diff)

    Parameters
    ----------
    gov : GovernanceLogger
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def compare(
        self,
        df_old: "pd.DataFrame",
        df_new: "pd.DataFrame",
        key_columns: list[str] | None = None,
    ) -> dict:
        """
        Diff two DataFrames.

        Parameters
        ----------
        df_old      : pd.DataFrame   Snapshot from the previous run.
        df_new      : pd.DataFrame   Snapshot from the current run.
        key_columns : list[str] | None
            Columns that uniquely identify a row (used to match rows
            across snapshots).  If None, the integer index is used.

        Returns
        -------
        dict  Structured diff report.
        """
        old = df_old.copy().reset_index(drop=True)
        new = df_new.copy().reset_index(drop=True)

        if key_columns:
            old = old.drop_duplicates(subset=key_columns).set_index(key_columns)
            new = new.drop_duplicates(subset=key_columns).set_index(key_columns)

        old_idx = set(old.index.tolist())
        new_idx = set(new.index.tolist())

        added_keys   = sorted(new_idx - old_idx, key=str)
        deleted_keys = sorted(old_idx - new_idx, key=str)
        common_keys  = list(old_idx & new_idx)

        # Find changed rows among common keys — vectorized comparison
        shared_cols = [c for c in old.columns if c in new.columns]
        changed_rows = []
        col_change_counts: dict[str, int] = {c: 0 for c in shared_cols}

        if common_keys and shared_cols:
            old_common = old.loc[old.index.isin(set(common_keys)), shared_cols].astype(str)
            new_common = new.loc[new.index.isin(set(common_keys)), shared_cols].astype(str)
            old_common, new_common = old_common.align(new_common, join="inner")

            diff_mask = old_common != new_common
            changed_idx = diff_mask.any(axis=1)

            for col in shared_cols:
                col_change_counts[col] = int(diff_mask[col].sum())

            for key in changed_idx[changed_idx].index:
                row_diff = diff_mask.loc[key]
                changed_cols = row_diff[row_diff].index
                diffs = {
                    col: {"before": old_common.at[key, col], "after": new_common.at[key, col]}
                    for col in changed_cols
                }
                changed_rows.append({"key": str(key), "changes": diffs})

        report = {
            "generated_utc":         datetime.now(timezone.utc).isoformat(),
            "rows_before":           len(df_old),
            "rows_after":            len(df_new),
            "rows_added":            len(added_keys),
            "rows_deleted":          len(deleted_keys),
            "rows_changed":          len(changed_rows),
            "added_keys":            [str(k) for k in added_keys],
            "deleted_keys":          [str(k) for k in deleted_keys],
            "changed_rows":          changed_rows,
            "column_change_counts":  col_change_counts,
        }

        self.gov.transformation_applied("DIFF_COMPLETE", {
            "rows_added":   len(added_keys),
            "rows_deleted": len(deleted_keys),
            "rows_changed": len(changed_rows),
        })
        logger.info(
            "[Diff] +%d added, -%d deleted, ~%d changed",
            len(added_keys), len(deleted_keys), len(changed_rows),
        )
        return report

    def save(self, diff: dict) -> Path:
        """Write the diff report to the governance log directory."""
        ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.gov.log_dir / f"diff_report_{ts}.json"
        path.write_text(json.dumps(diff, indent=2, default=str), encoding="utf-8")
        self.gov.transformation_applied("DIFF_REPORT_SAVED", {"path": str(path)})
        logger.info("[Diff] Report saved to %s", path)
        return path
