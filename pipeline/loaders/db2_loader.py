"""
IBM Db2 Warehouse loader with bulk LOAD, MERGE upsert, and Db2-native
compliance features for regulated industries.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class Db2Loader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import time
import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_DB2
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class Db2Loader(BaseLoader):
    """IBM Db2 Warehouse loader with bulk INSERT and MERGE upsert."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "BIGINT", "Int64": "BIGINT", "int32": "INTEGER",
        "float64": "DOUBLE", "float32": "REAL",
        "bool": "SMALLINT", "boolean": "SMALLINT",
        "datetime64[ns]": "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMP WITH TIME ZONE",
        "object": "VARCHAR(32672)",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_DB2:
            raise RuntimeError(
                "ibm-db / ibm-db-sa not installed.  "
                "Run: pip install ibm-db ibm-db-sa"
            )

    def _conn_str(self, cfg: dict) -> str:
        """Build an IBM Db2 connection string."""
        ssl_part = ";Security=SSL" if cfg.get("ssl") else ""
        return (
            f"DATABASE={cfg['database']};"
            f"HOSTNAME={cfg['host']};"
            f"PORT={cfg.get('port', 50000)};"
            "PROTOCOL=TCPIP;"
            f"UID={cfg['user']};"
            f"PWD={cfg['password']}"
            f"{ssl_part};"
        )

    def _engine(self, cfg: dict):
        """SQLAlchemy engine via ibm_db_sa dialect."""
        from sqlalchemy import create_engine as _ce
        ssl_str = "?Security=SSL" if cfg.get("ssl") else ""
        port = cfg.get("port", 50000)
        url = (
            f"ibm_db_sa+ibm_db://{cfg['user']}:{cfg['password']}"
            f"@{cfg['host']}:{port}/{cfg['database']}{ssl_str}"
        )
        return _ce(url)

    def load(self, df, cfg, table, if_exists="append", natural_keys=None):
        table = table.upper()
        validate_sql_identifier(table, "table")
        if cfg.get("schema"):
            validate_sql_identifier(cfg["schema"], "schema")
        if self._dry_run_guard(table, len(df)):
            return
        self._validate_config(cfg, ["host", "user", "password", "database"])
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._bulk_insert(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        schema = cfg.get("schema", cfg["user"]).upper()
        self.gov.destination_registered(
            "db2",
            f"{cfg['host']}:{cfg.get('port', 50000)}/{cfg['database']}/{schema}",
            table,
        )

    def _bulk_insert(self, df, cfg, table, if_exists):
        """ibm_db.execute_many() array insert."""
        import ibm_db as _ibm_db

        schema = cfg.get("schema", cfg["user"]).upper()
        fqt = f'"{schema}"."{table}"'

        conn = _ibm_db.connect(self._conn_str(cfg), "", "")
        try:
            self._ensure_table(conn, df, fqt, if_exists)

            bind_vars = ", ".join("?" * len(df.columns))
            insert_sql = f'INSERT INTO {fqt} VALUES ({bind_vars})'
            stmt = _ibm_db.prepare(conn, insert_sql)

            rows = [
                tuple(None if (v is not None and not isinstance(v, str)
                               and pd.isna(v)) else v
                      for v in row)
                for row in df.itertuples(index=False, name=None)
            ]
            for attempt in range(1, 4):
                try:
                    _ibm_db.execute_many(stmt, tuple(rows))
                    _ibm_db.commit(conn)
                    break
                except Exception as exc:
                    if attempt == 3:
                        raise
                    wait = 2 ** attempt
                    self.gov.retry_attempt(attempt, 3, float(wait), exc)
                    time.sleep(wait)

            logger.info("[DB2] INSERT INTO %s -- %s rows", fqt, f"{len(df):,}")
        finally:
            _ibm_db.close(conn)

    def _ensure_table(self, conn, df, fqt, if_exists):
        import ibm_db as _ibm_db

        col_defs = ", ".join(
            f'"{c.upper()}" {self._DTYPE_MAP.get(str(df[c].dtype), "VARCHAR(32672)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            try:
                _ibm_db.exec_immediate(conn, f"DROP TABLE {fqt}")
                _ibm_db.commit(conn)
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)
        _ibm_db.exec_immediate(
            conn,
            f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs})"
        )
        _ibm_db.commit(conn)

    def _upsert(self, df, cfg, table, natural_keys):
        """Stage -> Db2 MERGE INTO."""
        import ibm_db as _ibm_db

        schema = cfg.get("schema", cfg["user"]).upper()
        tmp_table = f"{table[:20]}_STG"
        fqt = f'"{schema}"."{table}"'
        fqt_tmp = f'"{schema}"."{tmp_table}"'

        engine = self._engine(cfg)
        with engine.begin() as conn_sa:
            df.to_sql(tmp_table.lower(), conn_sa, if_exists="replace",
                      index=False, schema=schema.lower(), chunksize=500)

        conn = _ibm_db.connect(self._conn_str(cfg), "", "")
        try:
            non_key_cols = [c for c in df.columns if c not in natural_keys]
            on_clause = " AND ".join(
                f't."{k.upper()}" = s."{k.upper()}"' for k in natural_keys
            )
            update_clause = ", ".join(
                f't."{c.upper()}" = s."{c.upper()}"' for c in non_key_cols
            ) or 't."__NOOP__" = 0'
            all_cols = ", ".join(f'"{c.upper()}"' for c in df.columns)
            stage_cols = ", ".join(f's."{c.upper()}"' for c in df.columns)

            merge_sql = (
                f"MERGE INTO {fqt} t "
                f"USING {fqt_tmp} s ON ({on_clause}) "
                f"WHEN MATCHED THEN UPDATE SET {update_clause} "
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            )
            _ibm_db.exec_immediate(conn, merge_sql)
            _ibm_db.commit(conn)
            logger.info("[DB2] MERGE INTO %s -- %s rows", fqt, f"{len(df):,}")
            self.gov.transformation_applied(
                "DB2_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            try:
                _ibm_db.exec_immediate(conn, f"DROP TABLE {fqt_tmp}")
                _ibm_db.commit(conn)
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)
            _ibm_db.close(conn)
