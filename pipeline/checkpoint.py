"""
Backward-compatibility shim — delegates to RunStateManager.

All checkpoint logic now lives in pipeline.run_state.RunStateManager.
This module exists so that existing imports continue to work.

Layer 2 — imports from Layer 2 (run_state), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial release.
1.1   2026-06-08   Delegated to RunStateManager.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.run_state import RunStateManager

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class CheckpointManager:
    """Thin wrapper around RunStateManager checkpoint methods."""

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        self._rsm = RunStateManager()

    def load_checkpoint(self, source: str, table: str) -> int:
        return self._rsm.load_checkpoint(self.gov, source, table)

    def save_checkpoint(self, source: str, table: str,
                        chunk_idx: int, rows: int) -> None:
        self._rsm.save_checkpoint(self.gov, source, table, chunk_idx, rows)

    def clear_checkpoint(self, source: str, table: str) -> None:
        self._rsm.clear_checkpoint(source, table)
