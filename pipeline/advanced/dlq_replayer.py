"""
DLQ replayer — replays dead-letter-queue rows through the pipeline after fixes.

Layer 5 — imports from Layer 0-4.

Revision history
────────────────
1.0   2026-06-07   Initial release: replay, replay_all, archive on success.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

# Columns injected by the dead-letter-queue writer — stripped before replay
_DLQ_META_COLUMNS = {"_dlq_pipeline_id", "_dlq_reason", "_dlq_timestamp"}


class DLQReplayer:
    """
    Replays dead-letter-queue CSV files back through the pipeline.

    After a root cause is fixed, DLQ rows can be re-transformed and
    re-loaded instead of being lost.  Successfully replayed files are
    archived with a ``.replayed`` suffix so they are not processed again.

    Quick-start
    -----------
        from pipeline.advanced import DLQReplayer
        replayer = DLQReplayer(gov)
        replayer.replay_all(transformer=tx, loader=ldr, cfg=db_cfg, table="t")

    Parameters
    ----------
    gov      : GovernanceLogger
    dlq_dir  : Path | None   Directory containing DLQ CSV files.
    dry_run  : bool          If True, log what would happen without modifying anything.
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        dlq_dir: Path | None = None,
        dry_run: bool = False,
    ) -> None:
        self.gov = gov
        self.dlq_dir = Path(dlq_dir) if dlq_dir else (gov.log_dir / "dlq")
        self.dry_run = dry_run

    # ── Discovery ────────────────────────────────────────────────────────

    def list_dlq_files(self) -> list[Path]:
        """Return all un-replayed DLQ CSV files in dlq_dir, sorted by name."""
        if not self.dlq_dir.exists():
            return []
        return sorted(self.dlq_dir.glob("*.csv"))

    # ── Single file replay ───────────────────────────────────────────────

    def replay(
        self,
        dlq_file: Path | str,
        transformer=None,
        loader=None,
        cfg: dict | None = None,
        table: str | None = None,
    ) -> int:
        """
        Replay a single DLQ CSV file.

        Steps:
        1. Read the DLQ CSV.
        2. Strip DLQ metadata columns.
        3. Optionally re-transform via ``transformer.transform(df)``.
        4. Optionally re-load via ``loader.load(df, cfg, table)``.
        5. Log a governance event.
        6. Archive the file with a ``.replayed`` suffix.

        Parameters
        ----------
        dlq_file    : Path | str   Path to the DLQ CSV file.
        transformer : object | None  Must have a ``.transform(df)`` method.
        loader      : object | None  Must have a ``.load(df, cfg, table)`` method.
        cfg         : dict | None    Database config (required if loader is given).
        table       : str | None     Target table (required if loader is given).

        Returns
        -------
        int  Number of rows replayed.
        """
        dlq_file = Path(dlq_file)
        if not dlq_file.exists():
            raise FileNotFoundError(f"DLQ file not found: {dlq_file}")

        df = pd.read_csv(dlq_file, encoding="utf-8")
        original_count = len(df)

        if original_count == 0:
            logger.info("DLQ file %s is empty — nothing to replay.", dlq_file.name)
            self._archive(dlq_file)
            return 0

        # Strip DLQ metadata columns
        meta_present = [c for c in df.columns if c in _DLQ_META_COLUMNS]
        if meta_present:
            df = df.drop(columns=meta_present)
            logger.info("Stripped %d DLQ metadata column(s): %s", len(meta_present), meta_present)

        # Re-transform
        if transformer is not None:
            try:
                df = transformer.transform(df)
                logger.info("Re-transformed %d rows via %s.", len(df), type(transformer).__name__)
            except Exception as exc:
                logger.error("Re-transform failed for %s: %s", dlq_file.name, exc)
                self.gov.error(f"DLQ replay transform failed: {dlq_file.name}", exc)
                raise

        # Re-load
        if loader is not None:
            if cfg is None or table is None:
                raise ValueError("cfg and table are required when a loader is provided.")
            if self.dry_run:
                logger.info(
                    "[DRY RUN] Would load %d rows from %s into %s — skipping.",
                    len(df), dlq_file.name, table,
                )
            else:
                try:
                    loader.load(df, cfg, table)
                    logger.info("Re-loaded %d rows into %s.", len(df), table)
                except Exception as exc:
                    logger.error("Re-load failed for %s: %s", dlq_file.name, exc)
                    self.gov.error(f"DLQ replay load failed: {dlq_file.name}", exc)
                    raise

        # Governance event
        self.gov.transformation_applied("DLQ_REPLAY", {
            "dlq_file": str(dlq_file),
            "rows_replayed": len(df),
            "rows_original": original_count,
            "meta_columns_stripped": meta_present,
            "re_transformed": transformer is not None,
            "re_loaded": loader is not None,
            "dry_run": self.dry_run,
        })

        # Archive
        if not self.dry_run:
            self._archive(dlq_file)

        return len(df)

    # ── Bulk replay ──────────────────────────────────────────────────────

    def replay_all(
        self,
        transformer=None,
        loader=None,
        cfg: dict | None = None,
        table: str | None = None,
    ) -> dict:
        """
        Replay every un-replayed DLQ file in the dlq_dir.

        Returns a summary dict with files_replayed, total_rows, and any errors.
        """
        files = self.list_dlq_files()
        if not files:
            logger.info("No DLQ files found in %s.", self.dlq_dir)
            return {"files_replayed": 0, "total_rows": 0, "errors": []}

        total_rows = 0
        errors: list[dict] = []
        replayed = 0

        for dlq_file in files:
            try:
                rows = self.replay(
                    dlq_file, transformer=transformer,
                    loader=loader, cfg=cfg, table=table,
                )
                total_rows += rows
                replayed += 1
            except Exception as exc:
                logger.error("Failed to replay %s: %s", dlq_file.name, exc)
                errors.append({"file": str(dlq_file), "error": str(exc)})

        summary = {
            "files_replayed": replayed,
            "total_rows": total_rows,
            "errors": errors,
        }
        logger.info(
            "DLQ replay complete: %d file(s), %d rows, %d error(s).",
            replayed, total_rows, len(errors),
        )
        return summary

    # ── Internal helpers ─────────────────────────────────────────────────

    @staticmethod
    def _archive(dlq_file: Path) -> None:
        """Rename a DLQ file with a .replayed suffix so it is not replayed again."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        archived = dlq_file.with_suffix(f".replayed_{ts}.csv")
        dlq_file.rename(archived)
        logger.info("Archived DLQ file: %s -> %s", dlq_file.name, archived.name)
