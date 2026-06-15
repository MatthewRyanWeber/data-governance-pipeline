"""
Databricks / Delta Lake loader with MERGE upsert, time-travel audit support,
and schema evolution.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class DatabricksLoader).
1.1   2026-06-11   Bulk insert batches many rows per parameterized INSERT
                   (executemany was one HTTP round-trip per row); upsert
                   rewritten to stage into a real Delta staging table and
                   MERGE from it (the VALUES-literal temp view was an
                   injection risk, a Spark parse error, and unbounded in
                   size); all-key MERGE omits WHEN MATCHED.
1.2   2026-06-12   Loader contract: dry-run returns 0 (was None); keyless upsert raises via _require_upsert_keys (was silent append).
1.3   2026-06-14   Staging name bounds the table portion so a long table name
                   cannot exceed the identifier length limit.
"""

import logging
from typing import TYPE_CHECKING

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
        import time
        import databricks.sql as _databricks_sql
        conn_kwargs: dict = {
            "server_hostname": cfg["server_hostname"],
            "http_path": cfg["http_path"],
            # A serverless warehouse that has auto-stopped can take 30-60s+
            # to resume; the default socket timeout is too short to wait it
            # out, so the first connection after idle fails.
            "_socket_timeout": int(cfg.get("connect_timeout", 180)),
        }
        if cfg.get("access_token"):
            conn_kwargs["access_token"] = cfg["access_token"]
        elif cfg.get("oauth_client_id"):
            conn_kwargs["credentials_provider"] = self._oauth_provider(cfg)
        if cfg.get("catalog") and cfg["catalog"] != "hive_metastore":
            conn_kwargs["catalog"] = cfg["catalog"]

        # Retry the connect itself: a cold serverless warehouse often
        # rejects the very first request while it is still starting.
        # A TypeError means a bad/renamed kwarg (e.g. connector API drift on
        # the private _socket_timeout) — that will never succeed, so fail
        # fast instead of masking it as a 30s "warehouse starting" retry.
        attempts = int(cfg.get("connect_attempts", 3))
        last_exc: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                return _databricks_sql.connect(**conn_kwargs)
            except TypeError:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt == attempts:
                    break
                wait = 10 * attempt
                logger.warning(
                    "[DATABRICKS] Connect attempt %d/%d failed (warehouse "
                    "still starting?) — retrying in %ds: %s",
                    attempt, attempts, wait, exc,
                )
                time.sleep(wait)
        raise last_exc  # type: ignore[misc]

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
             schema_evolution=True) -> int:
        validate_sql_identifier(table, "table")
        if cfg.get("catalog"):
            validate_sql_identifier(cfg["catalog"], "catalog")
        if cfg.get("schema"):
            validate_sql_identifier(cfg["schema"], "schema")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._require_upsert_keys(if_exists, natural_keys)
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
        return len(df)

    # Parameter budget per INSERT statement; keeps each request well under
    # connector/endpoint limits while still batching hundreds of rows.
    _PARAM_BUDGET = 2_000

    def _insert_rows(self, cur, df, fqt) -> None:
        """Insert df into fqt with multi-row parameterized INSERT statements.

        executemany on this connector issues one HTTP round-trip per row;
        packing many rows per statement turns N round-trips into
        ceil(N / rows_per_statement).
        """
        col_list = ", ".join(f"`{c}`" for c in df.columns)
        column_count = max(1, len(df.columns))
        rows_per_statement = max(1, self._PARAM_BUDGET // column_count)
        row_placeholder = "(" + ", ".join("?" * len(df.columns)) + ")"
        rows = list(df.where(df.notna(), None).itertuples(index=False, name=None))
        for i in range(0, len(rows), rows_per_statement):
            chunk = rows[i:i + rows_per_statement]
            placeholders = ", ".join([row_placeholder] * len(chunk))
            insert_sql = (
                f"INSERT INTO {fqt} ({col_list}) VALUES {placeholders}"
            )
            flat_params = [value for row in chunk for value in row]
            cur.execute(insert_sql, flat_params)

    @staticmethod
    def _try_enable_auto_merge(cur) -> None:
        """Best-effort schema auto-merge.

        Serverless / Free Edition warehouses reject SET of this config
        (CONFIG_NOT_AVAILABLE); the explicit CREATE TABLE already defines
        the schema, so a rejected SET is a warning, not a load failure.
        """
        try:
            cur.execute(
                "SET spark.databricks.delta.schema.autoMerge.enabled = true"
            )
        except Exception as exc:
            logger.warning(
                "[DATABRICKS] Could not enable delta.schema.autoMerge "
                "(serverless/Free Edition restricts it) — continuing "
                "without schema auto-merge: %s", exc,
            )

    def _bulk_insert(self, df, cfg, table, if_exists, schema_evolution):
        fqt = self._fqt(cfg, table)
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            if schema_evolution:
                self._try_enable_auto_merge(cur)
            self._ensure_table(cur, df, fqt, if_exists)
            self._insert_rows(cur, df, fqt)
            version = self._table_version(cur, fqt)
            logger.info("[DATABRICKS] INSERT INTO %s -- %s rows (Delta version %s)",
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
        # Stage into a real Delta table, not a VALUES-literal temp view:
        # literals are an injection/escaping hazard, serialize the whole frame
        # into one statement, and the typed temp-view DDL was a Spark parse
        # error in the first place.
        # Bound the table portion of the staging name so a long source table
        # cannot push the identifier past the platform's length limit.
        stage_table = f"_pipeline_stage_{table[:100]}_{uuid.uuid4().hex[:8]}"
        fqt_stage = self._fqt(cfg, stage_table)
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            if schema_evolution:
                self._try_enable_auto_merge(cur)
            self._ensure_table(cur, df, fqt, "append")
            self._ensure_table(cur, df, fqt_stage, "replace")
            self._insert_rows(cur, df, fqt_stage)

            non_key_cols = [c for c in df.columns if c not in natural_keys]
            on_clause = " AND ".join(
                f"t.`{k}` = s.`{k}`" for k in natural_keys
            )
            all_cols = ", ".join(f"`{c}`" for c in df.columns)
            stage_cols = ", ".join(f"s.`{c}`" for c in df.columns)
            # When every column is a key there is nothing to update: omit
            # WHEN MATCHED instead of referencing a non-existent __noop__.
            if non_key_cols:
                update_clause = ", ".join(
                    f"t.`{c}` = s.`{c}`" for c in non_key_cols
                )
                matched_part = f"WHEN MATCHED THEN UPDATE SET {update_clause}"
            else:
                matched_part = ""
            merge_sql = f"""
                MERGE INTO {fqt} AS t
                USING {fqt_stage} AS s
                ON ({on_clause})
                {matched_part}
                WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})
            """
            # Delta has no multi-statement transaction, so a MERGE that fails
            # part-way can leave partial state in the target — this is inherent
            # to the platform and not recoverable here. The staging table is
            # still dropped in finally regardless of outcome.
            cur.execute(merge_sql)
            version = self._table_version(cur, fqt)
            logger.info("[DATABRICKS] MERGE INTO %s -- %s rows (Delta version %s)",
                        fqt, f"{len(df):,}", version)
            self._log_delta_version(table, version, "MERGE")
            conn.commit()
        finally:
            try:
                cur.execute(f"DROP TABLE IF EXISTS {fqt_stage}")
            except Exception as exc:
                logger.warning("[DATABRICKS] Staging table cleanup failed: %s", exc)
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
