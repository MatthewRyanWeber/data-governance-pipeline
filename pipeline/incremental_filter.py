"""
Watermark-based incremental loading.

Tracks the maximum value of a watermark column (e.g. updated_at) so
subsequent runs only process new/changed rows.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).
"""

import json
import logging
from typing import TYPE_CHECKING

from pipeline.constants import WATERMARK_FILE, STATE_FILE_LOCK

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class IncrementalFilter:
    """
    Filters DataFrames to only new rows based on a stored watermark.

    Quick-start
    -----------
        from pipeline.incremental_filter import IncrementalFilter
        inc = IncrementalFilter(gov)
        wm = inc.read_watermark("data.csv", "updated_at")
        df = inc.filter(df, "updated_at", wm, "data.csv")
        inc.update_watermark(df, "updated_at", "data.csv")
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        self.state_file = WATERMARK_FILE

    def _key(self, source: str, col: str) -> str:
        return f"{source}::{col}"

    def read_watermark(self, source: str, col: str):
        key = self._key(source, col)
        if not self.state_file.exists():
            return None
        with open(self.state_file, encoding="utf-8") as f:
            state = json.load(f)
        wm = state.get(key)
        if wm:
            self.gov.watermark_event("READ", col, wm)
        return wm

    def filter(self, df, col: str, last_wm, source: str):
        """Filter df to rows where col > last_wm."""
        import pandas as pd

        if last_wm is None:
            return df
        before = len(df)
        try:
            ws = pd.to_datetime(df[col], errors="coerce")
            wv = pd.to_datetime(last_wm)
            df = df[ws > wv].copy()
        except Exception as exc:
            logger.debug("Datetime comparison failed for %s: %s, falling back to raw comparison", col, exc)
            df = df[df[col] > last_wm].copy()
        self.gov.watermark_event("READ", col, last_wm, filtered=before - len(df))
        logger.info("[INCR] Filtered %d rows | %d new", before - len(df), len(df))
        return df

    def update_watermark(self, df, col: str, source: str) -> None:
        if col not in df.columns or df.empty:
            return
        import pandas as pd
        raw_max = df[col].max()
        if pd.api.types.is_datetime64_any_dtype(df[col]):
            new_wm = pd.Timestamp(raw_max).isoformat()
        else:
            new_wm = str(raw_max)
        key = self._key(source, col)
        with STATE_FILE_LOCK:
            state: dict = {}
            if self.state_file.exists():
                with open(self.state_file, encoding="utf-8") as f:
                    state = json.load(f)
            state[key] = new_wm
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        self.gov.watermark_event("WRITE", col, new_wm)
