"""
Databricks / Delta Lake loader with MERGE upsert, time-travel audit support,
and schema evolution.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class DatabricksLoader).
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_DATABRICKS
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DatabricksLoader(BaseLoader):
    """Databricks / Delta Lake loader with MERGE upsert and time-travel audit."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "BIGINT", "Int64": "BIGINT", "int32": "INT",
        "float64": "DOUBLE", "float32": "FLOAT",
        "bool": "BOOLEAN", "boolean": "BOOLEAN",
        "datetime64[ns]": "TIMESTAMP", "datetime64[ns, UTC]": "TIMESTAMP",
        "object": "STRING",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_DATABRICKS:
            raise RuntimeError(
                "databricks-sql-connector not installed.  "
                "Run: pip install databricks-sql-connector"
            )

    def _connect(self, cfg: dict):
        import databricks.sql as _databricks_sql
        conn_kwargs: dict = {
            "server_hostname": cfg["server_hostname"],
            "http_path": cfg["http_path"],
        }
        if cfg.get("access_token"):
            conn_kwargs["access_token"] = cfg["access_token"]
        elif cfg.get("oauth_client_id"):
            conn_kwargs["credentials_provider"] = self._oauth_provider(cfg)
        if cfg.get("catalog") and cfg["catalog"] != "hive_metastore":
            conn_kwargs["catalog"] = cfg["catalog"]
        return _databricks_sql.connect(**conn_kwargs)

    @staticmethod
    def _oauth_provider(cfg: dict):
        try:
            from databricks.sdk.oauth import ClientCredentials
            return ClientCredentials(
                client_id=cfg["oauth_client_id"],
                client_secret=cfg["oauth_client_secret"],
                token_url=f"https://{cfg['server_hostname']}/oidc/v1/token",
                scopes=["all-apis"],
            )
        except ImportError as exc:
            raise RuntimeError(
                "databricks-sdk is required for OAuth M2M auth.  "
                "Run: pip install databricks-sdk"
            ) from exc

    def _fqt(self, cfg: dict, table: str) -> str:
        catalog = cfg.get("catalog", "hive_metastore")
        schema = cfg.get("schema", "default")
        if catalog == "hive_metastore":
            return f"`{schema}`.`{table}`"
        return f"`{catalog}`.`{schema}`.`{table}`"

    def load(self, df, cfg, table, if_exists="append", natural_keys=None,
             schema_evolution=True):
        validate_sql_identifier(table, "table")
        if cfg.get("catalog"):
            validate_sql_identifier(cfg["catalog"], "catalog")
        if cfg.get("schema"):
            validate_sql_identifier(cfg["schema"], "schema")
        if self._dry_run_guard(table, len(df)):
            return
        self._validate_config(cfg, ["server_hostname", "http_path"])
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys, schema_evolution)
        else:
            self._bulk_insert(df, cfg, table, if_exists, schema_evolution)
        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "databricks",
            f"{cfg['server_hostname']}/{cfg.get('catalog', 'hive_metastore')}"
            f"/{cfg.get('schema', 'default')}",
            table,
        )

    def _bulk_insert(self, df, cfg, table, if_exists, schema_evolution):
        fqt = self._fqt(cfg, table)
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            if schema_evolution:
                cur.execute(
                    "SET spark.databricks.delta.schema.autoMerge.enabled = true"
                )
            self._ensure_table(cur, df, fqt, if_exists)
            col_list = ", ".join(f"`{c}`" for c in df.columns)
            placeholders = ", ".join("?" * len(df.columns))
            insert_sql = f"INSERT INTO {fqt} ({col_list}) VALUES ({placeholders})"
            rows = list(df.where(df.notna(), None).itertuples(index=False, name=None))
            batch_size = 1_000
            for i in range(0, len(rows), batch_size):
                cur.executemany(insert_sql, rows[i:i + batch_size])
            version = self._table_version(cur, fqt)
            logger.info("[DB] INSERT INTO %s -- %s rows (Delta version %s)",
                        fqt, f"{len(df):,}", version)
            self._log_delta_version(table, version, "INSERT")
            conn.commit()
        finally:
            cur.close()
            conn.close()

    def _ensure_table(self, cur, df, fqt, if_exists):
        col_defs = ", ".join(
            f"`{c}` {self._DTYPE_MAP.get(str(df[c].dtype), 'STRING')}"
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f"CREATE OR REPLACE TABLE {fqt} ({col_defs}) USING DELTA")
        else:
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs}) USING DELTA"
            )

    def _upsert(self, df, cfg, table, natural_keys, schema_evolution):
        fqt = self._fqt(cfg, table)
        import uuid
        tmp_view = f"_pipeline_stage_{table}_{uuid.uuid4().hex[:8]}"
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            if schema_evolution:
                cur.execute(
                    "SET spark.databricks.delta.schema.autoMerge.enabled = true"
                )
            self._ensure_table(cur, df, fqt, "append")
            col_list = ", ".join(f"`{c}`" for c in df.columns)
            non_key_cols = [c for c in df.columns if c not in natural_keys]

            def _fmt(v):
                if v is None or (not isinstance(v, str) and pd.isna(v)):
                    return "NULL"
                if isinstance(v, bool):
                    return "TRUE" if v else "FALSE"
                if isinstance(v, (int, float)):
                    return str(v)
                return "'" + str(v).replace("'", "''") + "'"

            value_rows = ", ".join(
                "(" + ", ".join(_fmt(v) for v in row) + ")"
                for row in df.itertuples(index=False, name=None)
            )
            on_clause = " AND ".join(
                f"t.`{k}` = s.`{k}`" for k in natural_keys
            )
            update_clause = ", ".join(
                f"t.`{c}` = s.`{c}`" for c in non_key_cols
            ) or "`__noop__` = 0"
            all_cols = ", ".join(f"`{c}`" for c in df.columns)
            stage_cols = ", ".join(f"s.`{c}`" for c in df.columns)
            col_typed = ", ".join(
                f"`{c}` {self._DTYPE_MAP.get(str(df[c].dtype), 'STRING')}"
                for c in df.columns
            )
            cur.execute(
                f"CREATE OR REPLACE TEMPORARY VIEW `{tmp_view}` ({col_typed}) "
                f"AS SELECT * FROM (VALUES {value_rows}) AS t({col_list})"
            )
            merge_sql = f"""
                MERGE INTO {fqt} AS t
                USING `{tmp_view}` AS s
                ON ({on_clause})
                WHEN MATCHED THEN UPDATE SET {update_clause}
                WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})
            """
            cur.execute(merge_sql)
            version = self._table_version(cur, fqt)
            logger.info("[DB] MERGE INTO %s -- %s rows (Delta version %s)",
                        fqt, f"{len(df):,}", version)
            self._log_delta_version(table, version, "MERGE")
            conn.commit()
        finally:
            try:
                cur.execute(f"DROP VIEW IF EXISTS `{tmp_view}`")
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)
            cur.close()
            conn.close()

    def _table_version(self, cur, fqt) -> int | None:
        try:
            cur.execute(f"DESCRIBE HISTORY {fqt} LIMIT 1")
            row = cur.fetchone()
            return int(row[0]) if row else None
        except Exception as exc:
            logger.debug("Version query failed for %s: %s", fqt, exc)
            return None

    def _log_delta_version(self, table, version, operation):
        self.gov.transformation_applied(
            "DELTA_VERSION_RECORDED",
            {
                "table": table,
                "operation": operation,
                "version": version,
                "time_travel_query":
                    f"SELECT * FROM {table} VERSION AS OF {version}"
                    if version is not None else "N/A",
            },
        )
