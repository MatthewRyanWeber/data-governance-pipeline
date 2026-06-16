"""
Watermark-based incremental loading.

Tracks the maximum value of a watermark column (e.g. updated_at) so
subsequent runs only process new/changed rows.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-11   Numeric watermark columns compare numerically and persist
                   as native JSON numbers; rows that coerce to NaT are now
                   included in the output with a logged warning instead of
                   being silently dropped forever.
1.2   2026-06-13   Atomic watermark write (temp-file-then-rename) and
                   corruption-tolerant read — a crash mid-write or a
                   truncated file no longer corrupts the watermark or
                   crashes the next run.
1.3   2026-06-15   Late-arriving data is no longer dropped silently: rows below
                   the watermark are counted in the ledger every run, and an
                   optional dlq= routes them for recovery (a delayed event or
                   backfill arriving after the watermark moved on).
1.4   2026-06-16   Numeric branch keeps rows with a null watermark value (logged)
                   instead of dropping them forever — matches the datetime
                   branch's unparseable-row handling.
"""

import json
import logging
from typing import TYPE_CHECKING

from pipeline.constants import WATERMARK_FILE, STATE_FILE_LOCK
from pipeline.helpers import atomic_json_write

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

    def _load_state(self) -> dict:
        """Read the watermark state, tolerating a missing or corrupt file.

        A truncated/garbled file (e.g. from a crash mid-write before this
        module wrote atomically) must not crash the run — treat it as
        empty and log, like run_state does.
        """
        if not self.state_file.exists():
            return {}
        try:
            with open(self.state_file, encoding="utf-8") as f:
                return dict(json.load(f))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Watermark file %s is unreadable (%s) — treating as empty; "
                "the next run may reprocess from the start.",
                self.state_file, exc,
            )
            return {}

    def read_watermark(self, source: str, col: str):
        key = self._key(source, col)
        wm = self._load_state().get(key)
        if wm:
            self.gov.watermark_event("READ", col, wm)
        return wm

    def filter(self, df, col: str, last_wm, source: str, dlq=None):
        """Filter df to rows where col > last_wm.

        Rows whose watermark value is strictly OLDER than ``last_wm`` are
        excluded — but they are no longer dropped silently: their count is
        recorded in the ledger every run, and if a ``dlq`` is supplied the
        late/out-of-order rows are routed there for recovery (a delayed event
        or backfill arriving after the watermark moved on would otherwise
        vanish with no trace — the late-arriving-data failure mode).
        """
        import pandas as pd

        if last_wm is None:
            return df
        before = len(df)

        if pd.api.types.is_numeric_dtype(df[col]):
            # Numeric watermarks must compare numerically — coercing a
            # version/sequence column through to_datetime is meaningless.
            try:
                numeric_watermark = float(last_wm)
            except (TypeError, ValueError):
                logger.warning(
                    "[INCREMENTAL] Watermark %r is not numeric but column '%s' is — "
                    "processing all rows rather than dropping any.",
                    last_wm, col,
                )
                return df
            # A null watermark value makes every comparison False, so the row
            # would be dropped on every run forever with no trace — process it
            # instead, mirroring the datetime branch's unparseable handling.
            null_mask = df[col].isna()
            null_count = int(null_mask.sum())
            if null_count:
                logger.warning(
                    "[INCREMENTAL] %d row(s) in '%s' have a null watermark value "
                    "— including them in this run rather than dropping them.",
                    null_count, col,
                )
            self._handle_late_arrivals(df, df[col] < numeric_watermark, col, last_wm, dlq)
            df = df[(df[col] > numeric_watermark) | null_mask].copy()
        else:
            try:
                watermark_value = pd.to_datetime(last_wm)
            except (TypeError, ValueError) as exc:
                logger.debug(
                    "Watermark %r for '%s' is not datetime-like: %s — raw comparison.",
                    last_wm, col, exc,
                )
                self._handle_late_arrivals(df, df[col] < last_wm, col, last_wm, dlq)
                df = df[df[col] > last_wm].copy()
            else:
                parsed = pd.to_datetime(df[col], errors="coerce")
                unparseable_mask = parsed.isna()
                unparseable_count = int(unparseable_mask.sum())
                if unparseable_count:
                    # Rows that cannot be parsed would otherwise be excluded
                    # on every run forever — process them instead.
                    logger.warning(
                        "[INCREMENTAL] %d row(s) in '%s' could not be parsed as "
                        "datetime — including them in this run.",
                        unparseable_count, col,
                    )
                self._handle_late_arrivals(df, parsed < watermark_value, col, last_wm, dlq)
                df = df[(parsed > watermark_value) | unparseable_mask].copy()

        self.gov.watermark_event("READ", col, last_wm, filtered=before - len(df))
        logger.info("[INCREMENTAL] Filtered %d rows | %d new", before - len(df), len(df))
        return df

    def _handle_late_arrivals(self, df, late_mask, col: str, last_wm, dlq) -> None:
        """Surface rows below the watermark instead of dropping them silently.

        For a source that re-reads its full history every run, these are simply
        already-processed rows; for an incremental-at-source feed they are
        late/out-of-order arrivals. The filter can't tell which, so it records
        the count in the ledger every run (durable, never silent) and — only
        when a DLQ is provided — routes the rows there so a genuine late arrival
        is recoverable rather than lost.
        """
        late_count = int(late_mask.sum())
        if late_count == 0:
            return
        self.gov.watermark_event("LATE_ARRIVAL", col, last_wm, filtered=late_count)
        if dlq is not None:
            late_indices = df.index[late_mask].tolist()
            dlq.write(df, late_indices,
                      reason=f"late_arrival: {col} older than watermark {last_wm}")
            logger.warning(
                "[INCREMENTAL] %d row(s) in '%s' are older than the watermark %r "
                "(late/out-of-order) — routed to the DLQ for recovery instead of "
                "being dropped.", late_count, col, last_wm,
            )
        else:
            logger.info(
                "[INCREMENTAL] %d row(s) in '%s' are older than the watermark %r "
                "and were excluded (already processed, or late/out-of-order — pass "
                "dlq= to capture late arrivals for recovery).",
                late_count, col, last_wm,
            )

    def update_watermark(self, df, col: str, source: str) -> None:
        if col not in df.columns or df.empty:
            return
        import pandas as pd
        raw_max = df[col].max()
        if pd.api.types.is_datetime64_any_dtype(df[col]):
            new_wm = pd.Timestamp(raw_max).isoformat()
        elif pd.api.types.is_numeric_dtype(df[col]):
            # Stored as a native JSON number so the next run can compare
            # numerically instead of round-tripping through str/to_datetime.
            new_wm = raw_max.item() if hasattr(raw_max, "item") else raw_max
        else:
            new_wm = str(raw_max)
        key = self._key(source, col)
        with STATE_FILE_LOCK:
            state = self._load_state()
            state[key] = new_wm
            # Atomic write: a crash mid-write previously corrupted the
            # watermark and crashed the next run.
            atomic_json_write(self.state_file, json.dumps(state, indent=2))
        self.gov.watermark_event("WRITE", col, new_wm)
