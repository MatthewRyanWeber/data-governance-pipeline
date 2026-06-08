"""
SQL loader with retry and upsert — supports sqlite, postgresql, mysql, mssql,
and snowflake via SQLAlchemy.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class SQLLoader).
1.1   2026-06-08   Upsert uses staging table + DELETE/INSERT instead of loading
                   entire target table into memory.
"""

import time
import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_SNOWFLAKE
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SQLLoader(BaseLoader):
    """SQL loader with retry and upsert (v2.0)."""

    def __init__(self, gov: "GovernanceLogger", db_type: str, dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        self.db_type = db_type

    def _engine(self, cfg):
        from sqlalchemy import create_engine
        from urllib.parse import quote_plus as _qp
        t = self.db_type
        if t == "sqlite":
            return create_engine(f"sqlite:///{cfg['db_name']}.db")
        if t == "postgresql":
            return create_engine(
                f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port', 5432)}/{cfg['db_name']}")
        if t == "mysql":
            return create_engine(
                f"mysql+pymysql://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port', 3306)}/{cfg['db_name']}")
        if t == "mssql":
            return create_engine(
                f"mssql+pyodbc://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port', 1433)}/{cfg['db_name']}"
                f"?driver={cfg.get('driver', 'ODBC+Driver+17+for+SQL+Server')}")
        if t == "snowflake":
            if not HAS_SNOWFLAKE:
                raise RuntimeError("snowflake-connector-python not installed")
            from snowflake.sqlalchemy import URL as _sfurl
            return create_engine(_sfurl(
                account=cfg["account"],
                user=cfg["user"],
                password=cfg["password"],
                database=cfg["database"],
                schema=cfg.get("schema", "PUBLIC"),
                warehouse=cfg["warehouse"],
                role=cfg.get("role", ""),
            ))
        raise ValueError(f"Unknown db type: {t}")

    def load(self, df, cfg, table, if_exists="append", natural_keys=None):
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return
        with self._engine_scope(cfg) as engine:
            if natural_keys:
                self._upsert(df, engine, table, natural_keys)
            else:
                self._load_with_retry(df, engine, table, if_exists)
        self.gov.load_complete(len(df), table)
        db_identifier = cfg.get("database") or cfg.get("db_name", "")
        self.gov.destination_registered(self.db_type, db_identifier, table)

    def _load_with_retry(self, df, engine, table, if_exists):
        for attempt in range(1, 4):
            try:
                with engine.begin() as _conn:
                    df.to_sql(table, _conn, if_exists=if_exists, index=False,
                              chunksize=500)
                return
            except Exception as exc:
                if attempt == 3:
                    raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                logger.warning("Attempt %d/3 failed. Retrying in %ds...",
                               attempt, wait)
                time.sleep(wait)

    def _upsert(self, new_df, engine, table, natural_keys):
        """Database-native upsert via staging table — never loads target into memory."""
        from sqlalchemy import inspect as sai, text

        if table not in sai(engine).get_table_names():
            self._load_with_retry(new_df, engine, table, "replace")
            return

        staging = f"_upsert_staging_{table}"
        validate_sql_identifier(staging, "staging table")

        def q(name):
            return f"`{name}`" if self.db_type == "mysql" else f'"{name}"'

        all_cols = list(new_df.columns)
        cols_str = ", ".join(q(c) for c in all_cols)
        key_match = " AND ".join(
            f"{q(table)}.{q(k)} = {q(staging)}.{q(k)}" for k in natural_keys
        )

        with engine.begin() as conn:
            new_df.to_sql(staging, conn, if_exists="replace", index=False,
                          chunksize=500)

        try:
            with engine.begin() as conn:
                conn.execute(text(
                    f"DELETE FROM {q(table)} WHERE EXISTS "
                    f"(SELECT 1 FROM {q(staging)} WHERE {key_match})"
                ))
                conn.execute(text(
                    f"INSERT INTO {q(table)} ({cols_str}) "
                    f"SELECT {cols_str} FROM {q(staging)}"
                ))
        finally:
            with engine.begin() as conn:
                conn.execute(text(f"DROP TABLE IF EXISTS {q(staging)}"))

        self.gov.transformation_applied(
            "UPSERT_COMPLETE",
            {"table": table, "final_rows": len(new_df)},
        )
