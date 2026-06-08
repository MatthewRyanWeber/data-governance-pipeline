"""
Verifies foreign-key values exist in a reference set before loading.

Invalid FK rows are routed to the Dead Letter Queue to prevent
silently loading orphaned records.

Layer 2 — imports from Layer 1 (governance_logger).
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.dead_letter_queue import DeadLetterQueue
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class ReferentialIntegrityChecker:
    """
    Checks foreign-key columns against a reference dataset.

    Quick-start
    -----------
        from pipeline.referential_integrity import ReferentialIntegrityChecker
        checker = ReferentialIntegrityChecker(gov, dlq)
        df = checker.check(df, "department_id", "departments.csv", "department_id")
    """

    def __init__(self, gov: "GovernanceLogger", dlq: "DeadLetterQueue") -> None:
        self.gov = gov
        self.dlq = dlq

    def check(
        self,
        df: "pd.DataFrame",
        fk_col: str,
        reference_path: str,
        reference_col: str,
        on_violation: str = "dlq",
    ) -> "pd.DataFrame":
        """Check FK column and route violations to DLQ or warn."""
        import pandas as pd

        if fk_col not in df.columns:
            logger.warning("[RI] Foreign key column '%s' not found — skipping.", fk_col)
            return df

        ext = Path(reference_path).suffix.lower()
        if ext == ".csv":
            ref_df = pd.read_csv(reference_path, encoding="utf-8")
        elif ext in (".xlsx", ".xls"):
            ref_df = pd.read_excel(reference_path)
        elif ext == ".json":
            ref_df = pd.read_json(reference_path)
        else:
            logger.warning("[RI] Unsupported reference format: %s", ext)
            return df

        valid_keys = set(ref_df[reference_col].dropna().astype(str))

        fk_as_str = df[fk_col].astype(str)
        valid_mask = fk_as_str.isin(valid_keys)
        invalid_count = int((~valid_mask).sum())
        valid_count = int(valid_mask.sum())

        self.gov.referential_integrity_checked(
            fk_col, reference_path, valid_count, invalid_count,
        )

        if invalid_count > 0:
            invalid_vals = df.loc[~valid_mask, fk_col].unique().tolist()
            logger.warning(
                "[RI CHECK] '%s': %d invalid FK value(s): %s%s",
                fk_col, invalid_count,
                invalid_vals[:5], "…" if len(invalid_vals) > 5 else "",
            )

            if on_violation == "dlq":
                bad_indices = df.index[~valid_mask].tolist()
                reason = (
                    f"REFERENTIAL_INTEGRITY: '{fk_col}' value not found "
                    f"in '{reference_path}':'{reference_col}'"
                )
                df = self.dlq.write(df, bad_indices, reason)
        else:
            logger.info("[RI CHECK] '%s': all %d values valid.", fk_col, valid_count)

        return df
