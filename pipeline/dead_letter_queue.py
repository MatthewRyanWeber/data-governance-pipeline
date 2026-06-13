"""
Routes rejected rows to a DLQ CSV file for investigation.

Rows that fail validation, referential integrity, or schema checks
are written here instead of being silently dropped.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-11   Appends align to the existing CSV header: missing keys are
                   written empty, and genuinely new keys trigger a rewrite with
                   an expanded header so columns never misalign.
"""

import csv
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import default_run_context

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
        self.run_context = run_context or default_run_context()
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
            file_is_empty = not self.dlq_path.exists() or self.dlq_path.stat().st_size == 0
            if file_is_empty:
                rejected_df.to_csv(
                    self.dlq_path, mode="w",
                    header=True, index=False,
                    encoding="utf-8",
                )
            else:
                self._append_aligned_to_existing_header(rejected_df)
        self.gov.dlq_written(len(rejected_df), reason)
        return clean_df

    def _read_existing_header(self) -> list[str]:
        """Return the column names from the DLQ CSV's first line."""
        with open(self.dlq_path, encoding="utf-8", newline="") as f:
            return next(csv.reader(f), [])

    def _append_aligned_to_existing_header(self, rejected_df: "pd.DataFrame") -> None:
        """Append rows so every value lands under the correct existing column.

        A raw mode="a" to_csv writes positionally: a later write with a
        different column set silently misaligns every row. Missing keys are
        written empty; genuinely new keys force a one-off rewrite with the
        expanded header so the file stays rectangular.
        """
        import pandas as pd

        existing_header = self._read_existing_header()
        new_keys = [c for c in rejected_df.columns if c not in existing_header]

        if new_keys:
            logger.warning(
                "[DLQ] %d new column(s) %s not in the existing DLQ header — "
                "rewriting %s with an expanded header.",
                len(new_keys), new_keys, self.dlq_path,
            )
            combined_header = existing_header + new_keys
            existing_df = pd.read_csv(self.dlq_path, encoding="utf-8")
            existing_df = existing_df.reindex(columns=combined_header)
            aligned_df = rejected_df.reindex(columns=combined_header)
            # Atomic rewrite: a plain mode="w" crash mid-write would
            # truncate the DLQ and lose every previously-rejected row.
            # Write a sibling temp file, then os.replace (atomic on the
            # same filesystem).
            import os
            import tempfile
            combined = pd.concat(
                [existing_df, aligned_df], ignore_index=True)
            dlq_dir = os.path.dirname(self.dlq_path) or "."
            fd, tmp_path = tempfile.mkstemp(
                dir=dlq_dir, prefix=".dlq_", suffix=".tmp")
            os.close(fd)
            try:
                combined.to_csv(
                    tmp_path, header=True, index=False, encoding="utf-8")
                os.replace(tmp_path, self.dlq_path)
            except BaseException:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise
        else:
            rejected_df.reindex(columns=existing_header).to_csv(
                self.dlq_path, mode="a",
                header=False, index=False,
                encoding="utf-8",
            )
