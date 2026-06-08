"""
Persistent run-state tracking for crash recovery.

Writes a JSON state file for each active pipeline run. If the process dies
mid-run, the state file stays in 'running' status — crash_recovery.py
detects this on the next startup and resumes from the last checkpoint.

Layer 2 — imports from Layer 0 (constants).

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import RUN_STATE_DIR, STATE_FILE_LOCK

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class RunState:
    """Serialisable snapshot of a pipeline run's progress."""
    run_id: str
    source: str
    destination: str
    table: str
    config_path: str = ""
    status: str = "running"
    last_chunk_completed: int = -1
    total_rows_processed: int = 0
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    args_json: str = "{}"
    error_message: str = ""


class RunStateManager:
    """
    Persists run state to disk so incomplete runs survive process death.

    Quick-start
    -----------
        from pipeline.run_state import RunStateManager
        rsm = RunStateManager()
        rsm.save_start(run_state)
        rsm.update_chunk(run_id, chunk_idx=5, rows=50_000)
        rsm.mark_complete(run_id)
    """

    def __init__(self, state_dir: Path | None = None) -> None:
        self.state_dir = state_dir or RUN_STATE_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, run_id: str) -> Path:
        return self.state_dir / f"{run_id}.json"

    def _write(self, state: RunState) -> None:
        path = self._path(state.run_id)
        with STATE_FILE_LOCK:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(asdict(state), f, indent=2)

    def _read(self, run_id: str) -> RunState | None:
        path = self._path(run_id)
        if not path.exists():
            return None
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return RunState(**data)

    def save_start(self, state: RunState) -> None:
        """Write the initial run state before processing begins."""
        state.status = "running"
        self._write(state)
        logger.info("[RUN_STATE] Saved start state for run %s", state.run_id)

    def update_chunk(self, run_id: str, chunk_idx: int, rows_so_far: int) -> None:
        """Update progress after each chunk completes."""
        state = self._read(run_id)
        if state is None:
            logger.warning("[RUN_STATE] No state found for run %s — skipping update.", run_id)
            return
        state.last_chunk_completed = chunk_idx
        state.total_rows_processed = rows_so_far
        self._write(state)

    def mark_complete(self, run_id: str) -> None:
        """Mark a run as successfully completed."""
        state = self._read(run_id)
        if state is None:
            return
        state.status = "complete"
        self._write(state)
        logger.info("[RUN_STATE] Run %s marked complete (%d rows).",
                    run_id, state.total_rows_processed)

    def mark_failed(self, run_id: str, error: str) -> None:
        """Mark a run as failed with an error message."""
        state = self._read(run_id)
        if state is None:
            return
        state.status = "failed"
        state.error_message = error
        self._write(state)
        logger.warning("[RUN_STATE] Run %s marked failed: %s", run_id, error)

    def get_incomplete_runs(self) -> list[RunState]:
        """Find all runs in 'running' state — these are crash candidates."""
        incomplete = []
        if not self.state_dir.exists():
            return incomplete

        for path in sorted(self.state_dir.glob("*.json")):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("status") == "running":
                    incomplete.append(RunState(**data))
            except (json.JSONDecodeError, TypeError, KeyError) as exc:
                logger.warning("[RUN_STATE] Corrupt state file %s: %s", path, exc)

        return incomplete

    def cleanup_old_runs(self, keep_days: int = 7) -> int:
        """Remove completed/failed state files older than keep_days."""
        if not self.state_dir.exists():
            return 0

        cutoff = datetime.now(timezone.utc).timestamp() - (keep_days * 86400)
        removed = 0

        for path in self.state_dir.glob("*.json"):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("status") in ("complete", "failed"):
                    started = datetime.fromisoformat(data["started_at"]).timestamp()
                    if started < cutoff:
                        path.unlink()
                        removed += 1
            except (json.JSONDecodeError, KeyError, OSError):
                pass

        if removed:
            logger.info("[RUN_STATE] Cleaned up %d old state files.", removed)
        return removed
