"""
SQL loader with retry and upsert — supports sqlite, postgresql, mysql, mssql,
and snowflake via SQLAlchemy.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class SQLLoader).
"""

import time
import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_SNOWFLAKE

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SQLLoader:
    """SQL loader with retry and upsert (v2.0)."""

    def __init__(self, gov: "GovernanceLogger", db_type: str) -> None:
        self.gov = gov
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
        engine = self._engine(cfg)
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
        from sqlalchemy import inspect as sai
        if table not in sai(engine).get_table_names():
            self._load_with_retry(new_df, engine, table, "replace")
            return
        with engine.connect() as _conn:
            existing = pd.read_sql_table(table, _conn)
        merged = new_df.merge(existing, on=natural_keys, how="outer",
                              suffixes=("", "_old"), indicator=True)
        merged.drop(
            columns=[c for c in merged.columns if c.endswith("_old")]
            + ["_merge"],
            inplace=True, errors="ignore",
        )
        self._load_with_retry(merged, engine, table, "replace")
        self.gov.transformation_applied(
            "UPSERT_COMPLETE",
            {"table": table, "final_rows": len(merged)},
        )
