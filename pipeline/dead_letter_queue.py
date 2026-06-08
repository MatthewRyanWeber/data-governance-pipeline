"""
Routes rejected rows to a DLQ CSV file for investigation.

Rows that fail validation, referential integrity, or schema checks
are written here instead of being silently dropped.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).
"""

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import DEFAULT_RUN_CONTEXT

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DeadLetterQueue:
    """
    Writes rejected rows to a CSV file with rejection metadata.

    Quick-start
    -----------
        from pipeline.dead_letter_queue import DeadLetterQueue
        dlq = DeadLetterQueue(gov)
        df = dlq.write(df, bad_indices, "VALIDATION_FAILED")
    """

    def __init__(self, gov: "GovernanceLogger", run_context=None) -> None:
        self.gov = gov
        self.run_context = run_context or DEFAULT_RUN_CONTEXT
        self.dlq_path = Path(gov.dlq_file)
        self._lock = threading.Lock()

    def write(self, df: "pd.DataFrame", bad_indices: list[int],
              reason: str) -> "pd.DataFrame":
        """Remove bad rows from df, append them to DLQ CSV, return clean df."""
        if not bad_indices:
            return df

        bad_mask = df.index.isin(bad_indices)
        rejected_df = df[bad_mask].copy()
        clean_df = df[~bad_mask].copy()

        rejected_df["_dlq_pipeline_id"] = self.run_context.pipeline_id
        rejected_df["_dlq_reason"] = reason
        rejected_df["_dlq_timestamp"] = datetime.now(timezone.utc).isoformat()

        with self._lock:
            write_header = not self.dlq_path.exists() or self.dlq_path.stat().st_size == 0
            rejected_df.to_csv(
                self.dlq_path, mode="a",
                header=write_header, index=False,
                encoding="utf-8",
            )
        self.gov.dlq_written(len(rejected_df), reason)
        return clean_df
