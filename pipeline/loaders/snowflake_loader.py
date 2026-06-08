"""
Snowflake loader with bulk staging (PUT -> COPY INTO), MERGE upsert, and
GDPR-safe truncation.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class SnowflakeLoader).
"""

import time
import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_SNOWFLAKE
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SnowflakeLoader(BaseLoader):
    """
    Snowflake loader with bulk staging, MERGE upsert, and GDPR-safe truncation.

    Uses snowflake-connector-python for DDL/DML and snowflake-sqlalchemy
    for pandas .to_sql() compatibility.
    """

    _DTYPE_MAP: dict[str, str] = {
        "int64":               "NUMBER(19,0)",
        "Int64":               "NUMBER(19,0)",
        "int32":               "NUMBER(10,0)",
        "float64":             "FLOAT",
        "float32":             "FLOAT",
        "bool":                "BOOLEAN",
        "boolean":             "BOOLEAN",
        "datetime64[ns]":      "TIMESTAMP_NTZ",
        "datetime64[ns, UTC]": "TIMESTAMP_TZ",
        "object":              "VARCHAR(16777216)",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_SNOWFLAKE:
            raise RuntimeError(
                "Snowflake packages not installed. "
                "Run: pip install snowflake-connector-python snowflake-sqlalchemy"
            )

    # ── Connection helpers ────────────────────────────────────────────────

    def _connect(self, cfg: dict):
        """Return a raw snowflake.connector connection."""
        import snowflake.connector as _sf_connector
        conn_args = {
            "account":   cfg["account"],
            "user":      cfg["user"],
            "password":  cfg["password"],
            "database":  cfg["database"],
            "schema":    cfg.get("schema", "PUBLIC"),
            "warehouse": cfg["warehouse"],
        }
        if cfg.get("role"):
            conn_args["role"] = cfg["role"]
        return _sf_connector.connect(**conn_args)

    def _engine(self, cfg: dict):
        """Return a SQLAlchemy engine for pandas I/O."""
        from snowflake.sqlalchemy import URL as _sf_url
        from sqlalchemy import create_engine as _sf_create_engine
        url = _sf_url(
            account=cfg["account"],
            user=cfg["user"],
            password=cfg["password"],
            database=cfg["database"],
            schema=cfg.get("schema", "PUBLIC"),
            warehouse=cfg["warehouse"],
            role=cfg.get("role", ""),
        )
        return _sf_create_engine(url)

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        validate_sql_identifier(table, "table")
        if cfg.get("schema"):
            validate_sql_identifier(cfg["schema"], "schema")
        if self._dry_run_guard(table, len(df)):
            return
        self._validate_config(cfg, ["account", "user", "password", "database", "warehouse"])
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._bulk_load(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "snowflake",
            f"{cfg['account']}/{cfg['database']}/{cfg.get('schema', 'PUBLIC')}",
            table,
        )

    # ── Bulk load (PUT -> internal stage -> COPY INTO) ────────────────────

    def _bulk_load(self, df, cfg, table, if_exists):
        import tempfile
        import os
        import pathlib

        with tempfile.NamedTemporaryFile(
            suffix=".csv.gz", delete=False, mode="wb"
        ) as tmp:
            tmp_path = tmp.name

        df.to_csv(tmp_path, index=False, compression="gzip")
        stage_file = pathlib.Path(tmp_path).name

        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            schema = cfg.get("schema", "PUBLIC")
            fqt = f'"{cfg["database"]}"."{schema}"."{table.upper()}"'

            self._ensure_table(cur, df, fqt, if_exists)

            stage = f"@%{table.upper()}"
            cur.execute(
                f"PUT file://{tmp_path} {stage} "
                "AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
            )
            logger.info("[SNOWFLAKE] PUT %s -> %s", stage_file, stage)

            col_list = ", ".join(f'"{c}"' for c in df.columns)
            file_fmt = (
                "FILE_FORMAT = (TYPE=CSV SKIP_HEADER=1 "
                "FIELD_OPTIONALLY_ENCLOSED_BY='\"' "
                "NULL_IF=('') EMPTY_FIELD_AS_NULL=TRUE COMPRESSION=GZIP)"
            )
            copy_sql = (
                f"COPY INTO {fqt} ({col_list}) "
                f"FROM {stage}/{stage_file} " + file_fmt
            )
            cur.execute(copy_sql)
            result = cur.fetchone()
            rows = result[3] if result else len(df)
            logger.info("[SNOWFLAKE] COPY INTO %s -- %s rows loaded",
                        table.upper(), f"{rows:,}")

            cur.execute(f"REMOVE {stage}/{stage_file}")
            conn.commit()
        except Exception as exc:
            logger.warning("[SNOWFLAKE] COPY INTO failed -- falling back to to_sql(): %s", exc)
            self._sql_fallback(df, cfg, table, if_exists)
        finally:
            cur.close()
            conn.close()
            try:
                os.unlink(tmp_path)
            except OSError as exc:
                logger.debug("Cleanup failed: %s", exc)

    def _ensure_table(self, cur, df, fqt, if_exists):
        type_map = {
            "int64":               "NUMBER(38,0)",
            "Int64":               "NUMBER(38,0)",
            "float64":             "FLOAT",
            "bool":                "BOOLEAN",
            "boolean":             "BOOLEAN",
            "datetime64[ns]":      "TIMESTAMP_NTZ",
            "datetime64[ns, UTC]": "TIMESTAMP_TZ",
            "object":              "VARCHAR(16777216)",
        }
        col_defs = ", ".join(
            f'"{c}" {type_map.get(str(df[c].dtype), "VARCHAR(16777216)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f"CREATE OR REPLACE TABLE {fqt} ({col_defs})")
        else:
            cur.execute(f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs})")

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(self, df, cfg, table, natural_keys):
        tmp_table = f"{table.upper()}__STAGE__{int(time.time())}"
        schema = cfg.get("schema", "PUBLIC")
        fqt = f'"{cfg["database"]}"."{schema}"."{table.upper()}"'
        fqt_tmp = f'"{cfg["database"]}"."{schema}"."{tmp_table}"'

        engine = self._engine(cfg)
        for attempt in range(1, 4):
            try:
                with engine.begin() as _conn:
                    df.to_sql(
                        tmp_table.lower(), _conn,
                        if_exists="replace", index=False, chunksize=500,
                        method="multi",
                    )
                break
            except Exception as exc:
                if attempt == 3:
                    raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                time.sleep(wait)

        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            non_key_cols = [c for c in df.columns if c not in natural_keys]
            on_clause = " AND ".join(
                f't."{k}" = s."{k}"' for k in natural_keys
            )
            update_clause = ", ".join(
                f't."{c}" = s."{c}"' for c in non_key_cols
            ) or "t.__NOOP__ = 0"
            all_cols = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols = ", ".join(f's."{c}"' for c in df.columns)

            merge_sql = f"""
                MERGE INTO {fqt} AS t
                USING {fqt_tmp} AS s
                ON ({on_clause})
                WHEN MATCHED THEN
                    UPDATE SET {update_clause}
                WHEN NOT MATCHED THEN
                    INSERT ({all_cols}) VALUES ({stage_cols})
            """
            cur.execute(merge_sql)
            conn.commit()
            cur.execute(f"DROP TABLE IF EXISTS {fqt_tmp}")
            conn.commit()
            logger.info("[SNOWFLAKE] MERGE INTO %s complete.", table.upper())

            self.gov.transformation_applied(
                "SNOWFLAKE_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys,
                 "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()

    # ── SQLAlchemy fallback ───────────────────────────────────────────────

    def _sql_fallback(self, df, cfg, table, if_exists):
        engine = self._engine(cfg)
        for attempt in range(1, 4):
            try:
                with engine.begin() as conn:
                    df.to_sql(
                        table.lower(), conn,
                        if_exists=if_exists, index=False,
                        chunksize=500, method="multi",
                    )
                return
            except Exception as exc:
                if attempt == 3:
                    raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                logger.warning("Attempt %d/3 failed. Retrying in %ds...",
                               attempt, wait)
                time.sleep(wait)
