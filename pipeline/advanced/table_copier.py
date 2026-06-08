"""
Table copier — copies tables between databases with governance logging.

Layer 5 — imports from Layer 0-4.

Revision history
────────────────
1.0   2026-06-07   Initial release: cross-database table copy with chunked writes.
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class TableCopier:
    """
    Copies tables between databases with full governance logging.

    Reads the source table in one shot, then writes to the destination
    in chunks to avoid memory spikes on large tables.  Logs lineage
    events for both source and destination.

    Quick-start
    -----------
        from pipeline.advanced import TableCopier
        copier = TableCopier(gov)
        copier.copy(src_cfg, "users", dst_cfg, "users_backup", "postgresql")

    Parameters
    ----------
    gov      : GovernanceLogger
    dry_run  : bool   If True, log what would happen without writing.
    """

    _SQLALCHEMY_PLATFORMS = {"sqlite", "postgresql", "mysql", "mssql", "snowflake"}

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        self.gov = gov
        self.dry_run = dry_run

    # ── Engine builder ───────────────────────────────────────────────────

    @staticmethod
    def _engine(cfg: dict, db_type: str = "sqlite"):
        """Build a SQLAlchemy engine from a config dict."""
        from sqlalchemy import create_engine
        from urllib.parse import quote_plus as _qp

        if db_type == "sqlite":
            return create_engine(f"sqlite:///{cfg['db_name']}.db")
        if db_type == "postgresql":
            return create_engine(
                f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port', 5432)}/{cfg['db_name']}"
            )
        if db_type == "mysql":
            return create_engine(
                f"mysql+pymysql://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port', 3306)}/{cfg['db_name']}"
            )
        if db_type == "mssql":
            return create_engine(
                f"mssql+pyodbc://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port', 1433)}/{cfg['db_name']}"
                f"?driver={cfg.get('driver', 'ODBC+Driver+17+for+SQL+Server')}"
            )
        raise ValueError(f"Unsupported db_type for TableCopier: {db_type}")

    # ── Public API ───────────────────────────────────────────────────────

    def copy(
        self,
        src_cfg: dict,
        src_table: str,
        dst_cfg: dict,
        dst_table: str,
        dst_type: str,
        chunk_size: int = 10_000,
    ) -> int:
        """
        Copy a table from one database to another.

        Reads the full source table, then writes to the destination in
        chunks of ``chunk_size`` rows.  Governance events are logged for
        source registration, load completion, and destination registration.

        Parameters
        ----------
        src_cfg     : dict   Source database connection config.
        src_table   : str    Source table name.
        dst_cfg     : dict   Destination database connection config.
        dst_table   : str    Destination table name.
        dst_type    : str    Destination database type (sqlite/postgresql/mysql/mssql).
        chunk_size  : int    Rows per write chunk.

        Returns
        -------
        int  Total rows copied.
        """
        # Read source
        src_engine = self._engine(src_cfg, src_cfg.get("db_type", "sqlite"))
        with src_engine.connect() as conn:
            df = pd.read_sql_table(src_table, conn)

        row_count = len(df)
        logger.info(
            "Read %d rows from %s.%s",
            row_count, src_cfg.get("db_name", "?"), src_table,
        )

        self.gov.source_registered(
            path=f"{src_cfg.get('db_name', '?')}/{src_table}",
            file_type="database_table",
            rows=row_count,
            cols=len(df.columns),
        )

        if self.dry_run:
            logger.info(
                "[DRY RUN] Would copy %d rows to %s.%s — skipping write.",
                row_count, dst_cfg.get("db_name", "?"), dst_table,
            )
            return row_count

        # Write to destination in chunks
        dst_engine = self._engine(dst_cfg, dst_type)
        rows_written = 0
        for start in range(0, row_count, chunk_size):
            chunk = df.iloc[start : start + chunk_size]
            mode = "replace" if start == 0 else "append"
            with dst_engine.begin() as conn:
                chunk.to_sql(dst_table, conn, if_exists=mode, index=False)
            rows_written += len(chunk)
            logger.info(
                "Wrote chunk %d-%d (%d rows) to %s.%s",
                start, start + len(chunk) - 1, len(chunk),
                dst_cfg.get("db_name", "?"), dst_table,
            )

        self.gov.load_complete(rows_written, dst_table)
        self.gov.destination_registered(
            db=dst_type,
            name=dst_cfg.get("db_name", ""),
            table=dst_table,
        )

        logger.info(
            "Table copy complete: %s -> %s (%d rows).",
            src_table, dst_table, rows_written,
        )
        return rows_written
