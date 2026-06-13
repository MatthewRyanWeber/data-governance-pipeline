"""
ClickHouse loader with native bulk insert, ReplacingMergeTree upsert, and
high-concurrency OLAP optimisations.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class ClickHouseLoader).
1.1   2026-06-11   Nullable integer columns no longer cast to float64 (which
                   silently corrupted values above 2^53); upsert refuses to
                   run against a pre-existing table whose engine is not
                   ReplacingMergeTree (plain MergeTree would duplicate rows).
1.2   2026-06-12   Loader contract: dry-run returns 0 (was None); keyless upsert raises via _require_upsert_keys (was silent append).
"""

import time
import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_CLICKHOUSE
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class ClickHouseLoader(BaseLoader):
    """ClickHouse loader with native bulk insert and ReplacingMergeTree upsert."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "Int64", "Int64": "Nullable(Int64)", "int32": "Int32",
        "float64": "Float64", "float32": "Float32",
        "bool": "UInt8", "boolean": "Nullable(UInt8)",
        "datetime64[ns]": "DateTime64(9)",
        "datetime64[ns, UTC]": "DateTime64(9, 'UTC')",
        "object": "Nullable(String)",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_CLICKHOUSE:
            raise RuntimeError(
                "clickhouse-connect not installed.  "
                "Run: pip install clickhouse-connect"
            )

    def _client(self, cfg: dict):
        import clickhouse_connect
        return clickhouse_connect.get_client(
            host=cfg.get("host", "localhost"),
            port=int(cfg.get("port", 8443 if cfg.get("secure") else 8123)),
            username=cfg.get("username", "default"),
            password=cfg.get("password", ""),
            database=cfg.get("database", "default"),
            secure=bool(cfg.get("secure", False)),
        )

    def load(self, df, cfg, table, if_exists="append", natural_keys=None) -> int:
        validate_sql_identifier(table, "table")
        if cfg.get("database"):
            validate_sql_identifier(cfg["database"], "database")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._require_upsert_keys(if_exists, natural_keys)
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._bulk_insert(df, cfg, table, if_exists)
        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "clickhouse",
            f"{cfg.get('host', 'localhost')}:{cfg.get('port', 8123)}"
            f"/{cfg.get('database', 'default')}",
            table,
        )
        return len(df)

    def _bulk_insert(self, df, cfg, table, if_exists):
        client = self._client(cfg)
        database = cfg.get("database", "default")
        self._ensure_table(client, df, database, table, if_exists)
        df_ch = self._prepare_df(df)
        for attempt in range(1, 4):
            try:
                client.insert_df(table, df_ch, database=database)
                logger.info("[CLICKHOUSE] INSERT INTO %s.%s -- %s rows",
                            database, table, f"{len(df):,}")
                return
            except Exception as exc:
                if attempt == 3:
                    raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                logger.warning("Attempt %d/3 failed. Retrying in %ds...",
                               attempt, wait)
                time.sleep(wait)

    def _ensure_table(self, client, df, database, table, if_exists,
                      order_by=None, engine="MergeTree()"):
        col_defs = ", ".join(
            f"`{c}` {self._DTYPE_MAP.get(str(df[c].dtype), 'Nullable(String)')}"
            for c in df.columns
        )
        order_clause = (
            f"ORDER BY ({', '.join(f'`{k}`' for k in order_by)})"
            if order_by else "ORDER BY tuple()"
        )
        if if_exists == "replace":
            client.command(f"DROP TABLE IF EXISTS `{database}`.`{table}`")
        create_sql = (
            f"CREATE TABLE IF NOT EXISTS `{database}`.`{table}` "
            f"({col_defs}) ENGINE = {engine} {order_clause}"
        )
        client.command(create_sql)

    def _upsert(self, df, cfg, table, natural_keys):
        client = self._client(cfg)
        database = cfg.get("database", "default")
        # Dedup-on-merge only works on ReplacingMergeTree; inserting into a
        # pre-existing plain MergeTree would silently duplicate every row.
        # query() not command(): command() returns a QuerySummary object on
        # newer clickhouse-connect, which would defeat the string check.
        engine_rows = client.query(
            "SELECT engine FROM system.tables "
            "WHERE database = {db:String} AND name = {tbl:String}",
            parameters={"db": database, "tbl": table},
        ).result_rows
        existing_engine = engine_rows[0][0] if engine_rows else ""
        if existing_engine and "ReplacingMergeTree" not in str(existing_engine):
            raise ValueError(
                f"ClickHouseLoader: cannot upsert into '{database}.{table}' — "
                f"existing table engine is '{existing_engine}', but upsert "
                "requires ReplacingMergeTree. Recreate the table with "
                "ENGINE = ReplacingMergeTree or load with if_exists='append'."
            )
        df_with_ts = df.copy()
        df_with_ts["_updated_at"] = int(time.time())
        self._ensure_table(
            client, df_with_ts, database, table, "append",
            order_by=natural_keys,
            engine="ReplacingMergeTree(_updated_at)",
        )
        df_ch = self._prepare_df(df_with_ts)
        client.insert_df(table, df_ch, database=database)
        client.command(f"OPTIMIZE TABLE `{database}`.`{table}` FINAL")
        logger.info("[CLICKHOUSE] UPSERT -> %s.%s -- %s rows "
                    "(ReplacingMergeTree + OPTIMIZE FINAL)",
                    database, table, f"{len(df):,}")
        self.gov.transformation_applied(
            "CLICKHOUSE_UPSERT_COMPLETE",
            {"table": table, "natural_keys": natural_keys,
             "rows": len(df), "engine": "ReplacingMergeTree",
             "note": "OPTIMIZE FINAL issued"},
        )

    @staticmethod
    def _prepare_df(df):
        import pandas as pd

        out = df.copy()
        for col in out.columns:
            dtype_str = str(out[col].dtype)
            if dtype_str in ("Int64", "Int32", "boolean"):
                # Nullable extension dtypes: a float64 cast silently corrupts
                # integers above 2^53, so keep exact ints in an object column
                # with None for nulls.
                out[col] = [
                    None if pd.isna(value) else int(value)
                    for value in out[col]
                ]
            elif dtype_str == "bool":
                out[col] = out[col].astype("uint8")
            elif dtype_str == "float64":
                # A float64 column of whole numbers is almost always an
                # integer column pandas widened because of nulls.  Values
                # >2^53 are NOT exactly representable in float64, so they
                # are already corrupted before reaching this loader — warn
                # so the caller passes the column as pandas 'Int64' to keep
                # full precision.  (We do not silently re-type genuine
                # floats here.)
                series = out[col].dropna()
                if len(series) and (series == series.round()).all():
                    over = series.abs() > 2 ** 53
                    if over.any():
                        logger.warning(
                            "[CLICKHOUSE] Column %r holds integer values "
                            "above 2^53 as float64 — precision is already "
                            "lost upstream. Pass it as pandas 'Int64' to "
                            "preserve exact values.", col,
                        )
        return out
