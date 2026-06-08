"""
Chunk-level checkpoint manager for resumable pipeline runs.

Saves progress after each loaded chunk so a crashed pipeline resumes
from the last successful chunk rather than restarting.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).
"""

import json
import logging
from typing import TYPE_CHECKING

from pipeline.constants import CHECKPOINT_FILE, STATE_FILE_LOCK

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class CheckpointManager:
    """
    Saves and restores chunk-level pipeline progress.

    Quick-start
    -----------
        from pipeline.checkpoint import CheckpointManager
        cp = CheckpointManager(gov)
        last = cp.load_checkpoint("data.csv", "employees")
        # ... process chunks starting from last+1 ...
        cp.save_checkpoint("data.csv", "employees", chunk_idx, rows)
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        self.state_file = CHECKPOINT_FILE

    def _key(self, source: str, table: str) -> str:
        return f"{source}::{table}"

    def load_checkpoint(self, source: str, table: str) -> int:
        """Return the last completed chunk index, or -1 if none."""
        key = self._key(source, table)
        with STATE_FILE_LOCK:
            if not self.state_file.exists():
                return -1
            with open(self.state_file, encoding="utf-8") as f:
                state = json.load(f)
        last = state.get(key, -1)
        if last >= 0:
            self.gov.checkpoint_event("RESTORED", last, 0)
            logger.info(
                "[CHECKPOINT] Resuming from chunk %d (skipping %d already-completed chunks)",
                last + 1, last + 1,
            )
        return last

    def save_checkpoint(self, source: str, table: str,
                        chunk_idx: int, rows: int) -> None:
        """Persist the index of the last successfully loaded chunk."""
        key = self._key(source, table)
        with STATE_FILE_LOCK:
            state: dict = {}
            if self.state_file.exists():
                with open(self.state_file, encoding="utf-8") as f:
                    state = json.load(f)
            state[key] = chunk_idx
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        self.gov.checkpoint_event("SAVED", chunk_idx, rows)

    def clear_checkpoint(self, source: str, table: str) -> None:
        """Remove the checkpoint for a completed, successful run."""
        key = self._key(source, table)
        with STATE_FILE_LOCK:
            if not self.state_file.exists():
                return
            with open(self.state_file, encoding="utf-8") as f:
                state = json.load(f)
            state.pop(key, None)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
