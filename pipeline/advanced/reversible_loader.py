"""
Reversible loader — wraps any loader to make loads reversible via Parquet snapshots.

Layer 5 — imports from Layer 0-4.

Revision history
────────────────
1.0   2026-06-07   Initial release: snapshot, rollback, manifest, purge.
"""

import hashlib
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_MANIFEST_FILE = "snapshot_manifest.jsonl"


class ReversibleLoader:
    """
    Wraps any loader to make loads reversible via Parquet snapshots.

    Before every load, the current state of the target table is captured
    as a Parquet file.  If the load goes wrong, ``rollback()`` restores
    the table to that snapshot.  A JSONL manifest tracks every snapshot
    for auditability.

    Strategies
    ----------
    parquet   Save a Parquet file of the table before each load (default).
    shadow    Write a ``_shadow`` copy of the table inside the database.
    both      Do both.

    Quick-start
    -----------
        from pipeline.advanced import ReversibleLoader
        rl = ReversibleLoader(gov, sql_loader)
        run_id = rl.load(df, cfg, "employees")
        # something went wrong:
        rl.rollback("employees", run_id, cfg)

    Parameters
    ----------
    gov             : GovernanceLogger
    loader          : Any loader that has a .load(df, cfg, table, ...) method.
    db_type         : str   Database flavour for SQLAlchemy engine building.
    snapshot_dir    : Path | None   Where to write Parquet snapshots.
    strategy        : str   "parquet", "shadow", or "both".
    retention_days  : int   Auto-purge snapshots older than this.
    compression     : str   Parquet compression codec.
    warn_size_mb    : float Log a warning if snapshot exceeds this size.
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        loader,
        db_type: str = "sqlite",
        snapshot_dir: Path | None = None,
        strategy: str = "parquet",
        retention_days: int = 30,
        compression: str = "snappy",
        warn_size_mb: float = 500.0,
    ) -> None:
        self.gov = gov
        self.loader = loader
        self.db_type = db_type
        self.snapshot_dir = Path(snapshot_dir) if snapshot_dir else (gov.log_dir / "snapshots")
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.strategy = strategy
        self.retention_days = retention_days
        self.compression = compression
        self.warn_size_mb = warn_size_mb

    # ── Identifiers ──────────────────────────────────────────────────────

    @staticmethod
    def _run_id() -> str:
        """Generate a unique run identifier: YYYYMMDD_HHMMSS_<6hex>."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{ts}_{secrets.token_hex(3)}"

    @staticmethod
    def _checksum(path: Path) -> str:
        """SHA-256 hex digest of a file, read in 64 KB chunks."""
        hasher = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65_536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    # ── Manifest ─────────────────────────────────────────────────────────

    def _manifest_path(self) -> Path:
        return self.snapshot_dir / _MANIFEST_FILE

    def _manifest_append(self, record: dict) -> None:
        """Append a single record to the JSONL manifest."""
        with open(self._manifest_path(), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    def _manifest_records(self) -> list[dict]:
        """Read all manifest records."""
        manifest = self._manifest_path()
        if not manifest.exists():
            return []
        records: list[dict] = []
        for line in manifest.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("Corrupt manifest line skipped.")
        return records

    # ── Engine helpers ───────────────────────────────────────────────────

    @staticmethod
    def _engine(cfg: dict, db_type: str = "sqlite"):
        """Build a SQLAlchemy engine from a config dict."""
        from sqlalchemy import create_engine

        if db_type == "sqlite":
            return create_engine(f"sqlite:///{cfg['db_name']}.db")
        if db_type == "postgresql":
            return create_engine(
                f"postgresql+psycopg2://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 5432)}/{cfg['db_name']}"
            )
        if db_type == "mysql":
            return create_engine(
                f"mysql+pymysql://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 3306)}/{cfg['db_name']}"
            )
        if db_type == "mssql":
            return create_engine(
                f"mssql+pyodbc://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 1433)}/{cfg['db_name']}"
                f"?driver={cfg.get('driver', 'ODBC+Driver+17+for+SQL+Server')}"
            )
        if db_type == "snowflake":
            from snowflake.sqlalchemy import URL as _sfurl
            return create_engine(_sfurl(
                account=cfg["account"], user=cfg["user"],
                password=cfg["password"], database=cfg["database"],
                schema=cfg.get("schema", "PUBLIC"),
                warehouse=cfg["warehouse"], role=cfg.get("role", ""),
            ))
        raise ValueError(f"Unsupported db_type for ReversibleLoader: {db_type}")

    @staticmethod
    def _table_exists(engine, table: str) -> bool:
        """Check whether a table exists in the connected database."""
        from sqlalchemy import inspect as sa_inspect
        return table in sa_inspect(engine).get_table_names()

    def _read_table(self, cfg: dict, table: str) -> pd.DataFrame | None:
        """Read the full contents of a table, or None if it does not exist."""
        engine = self._engine(cfg, self.db_type)
        if not self._table_exists(engine, table):
            return None
        with engine.connect() as conn:
            return pd.read_sql_table(table, conn)

    # ── Core operations ──────────────────────────────────────────────────

    def load(
        self,
        df: pd.DataFrame,
        cfg: dict,
        table: str,
        if_exists: str = "append",
        natural_keys: list[str] | None = None,
    ) -> str:
        """
        Snapshot the current table state, then delegate to the wrapped loader.

        Returns the run_id that can be used for rollback.
        """
        run_id = self._run_id()
        snapshot_path: Path | None = None

        # 1. Read current table state
        existing = self._read_table(cfg, table)

        # 2. Save Parquet snapshot
        if "parquet" in self.strategy and existing is not None and len(existing) > 0:
            filename = f"{table}_{run_id}.parquet"
            snapshot_path = self.snapshot_dir / filename
            existing.to_parquet(snapshot_path, compression=self.compression, index=False)
            size_mb = snapshot_path.stat().st_size / (1024 * 1024)
            if size_mb > self.warn_size_mb:
                logger.warning(
                    "Snapshot %s is %.1f MB — exceeds warn threshold of %.1f MB.",
                    filename, size_mb, self.warn_size_mb,
                )
            logger.info("Parquet snapshot saved: %s (%.2f MB)", filename, size_mb)

        # 3. Write shadow table
        if "shadow" in self.strategy and existing is not None and len(existing) > 0:
            shadow_table = f"{table}_shadow_{run_id}"
            engine = self._engine(cfg, self.db_type)
            with engine.begin() as conn:
                existing.to_sql(shadow_table, conn, if_exists="replace", index=False)
            logger.info("Shadow table written: %s", shadow_table)

        # 4. Append manifest record
        record = {
            "run_id": run_id,
            "table": table,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "strategy": self.strategy,
            "snapshot_file": str(snapshot_path) if snapshot_path else None,
            "snapshot_checksum": self._checksum(snapshot_path) if snapshot_path else None,
            "rows_before": len(existing) if existing is not None else 0,
            "rows_incoming": len(df),
        }
        self._manifest_append(record)

        # 5. Delegate to wrapped loader
        self.loader.load(df, cfg, table, if_exists=if_exists, natural_keys=natural_keys)

        # 6. Governance event
        self.gov.transformation_applied("REVERSIBLE_LOAD", {
            "run_id": run_id,
            "table": table,
            "strategy": self.strategy,
            "rows_before": record["rows_before"],
            "rows_incoming": record["rows_incoming"],
            "snapshot_file": record["snapshot_file"],
        })

        logger.info("Reversible load complete — run_id=%s, table=%s", run_id, table)
        return run_id

    def rollback(self, table: str, run_id: str, cfg: dict) -> None:
        """
        Restore a table to its state before a specific load run.

        Reads the Parquet snapshot identified by run_id and replaces the
        table contents.
        """
        records = self._manifest_records()
        match = [r for r in records if r["run_id"] == run_id and r["table"] == table]
        if not match:
            raise ValueError(f"No snapshot found for table={table}, run_id={run_id}")

        entry = match[0]
        snapshot_file = entry.get("snapshot_file")
        if not snapshot_file or not Path(snapshot_file).exists():
            raise FileNotFoundError(
                f"Snapshot file missing: {snapshot_file} — rollback not possible."
            )

        snapshot_path = Path(snapshot_file)

        # Verify checksum integrity before restoring
        stored_checksum = entry.get("snapshot_checksum")
        if stored_checksum:
            actual_checksum = self._checksum(snapshot_path)
            if actual_checksum != stored_checksum:
                raise RuntimeError(
                    f"Snapshot checksum mismatch for {snapshot_path.name} — "
                    "file may have been tampered with."
                )

        restored_df = pd.read_parquet(snapshot_path)
        engine = self._engine(cfg, self.db_type)
        with engine.begin() as conn:
            restored_df.to_sql(table, conn, if_exists="replace", index=False)

        self.gov.transformation_applied("ROLLBACK_EXECUTED", {
            "run_id": run_id,
            "table": table,
            "rows_restored": len(restored_df),
            "snapshot_file": str(snapshot_path),
        })
        logger.info(
            "Rollback complete — table=%s restored to run_id=%s (%d rows).",
            table, run_id, len(restored_df),
        )

    def rollback_latest(self, table: str, cfg: dict) -> None:
        """Roll back the most recent load for a given table."""
        records = self._manifest_records()
        table_records = [r for r in records if r["table"] == table]
        if not table_records:
            raise ValueError(f"No snapshot history found for table={table}")
        latest = table_records[-1]
        self.rollback(table, latest["run_id"], cfg)

    # ── History and maintenance ──────────────────────────────────────────

    def snapshot_history(self, table: str) -> list[dict]:
        """Return all manifest entries for a given table."""
        return [r for r in self._manifest_records() if r["table"] == table]

    def purge_old_snapshots(self) -> int:
        """
        Delete Parquet snapshot files older than retention_days.

        Returns the number of files purged.
        """
        cutoff = time.time() - (self.retention_days * 86_400)
        purged = 0
        for path in self.snapshot_dir.glob("*.parquet"):
            if path.stat().st_mtime < cutoff:
                path.unlink()
                purged += 1
                logger.info("Purged old snapshot: %s", path.name)

        if purged:
            self.gov.transformation_applied("SNAPSHOTS_PURGED", {
                "purged_count": purged,
                "retention_days": self.retention_days,
            })
        return purged
