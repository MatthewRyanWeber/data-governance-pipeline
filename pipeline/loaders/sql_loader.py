"""
SQL loader with retry and upsert — supports sqlite, postgresql, mysql, mssql,
and snowflake via SQLAlchemy.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class SQLLoader).
1.1   2026-06-08   Upsert uses staging table + DELETE/INSERT instead of loading
                   entire target table into memory.
1.2   2026-06-11   Dotted table names are split into schema + table (passed as
                   schema= to to_sql and quoted separately in upsert SQL)
                   instead of creating a literal "schema.table" table.
1.3   2026-06-12   Loader contract: dry-run returns 0 (was None); keyless upsert raises via _require_upsert_keys (was silent append).
1.4   2026-06-14   Upsert staging table name is now unique per run+thread (run id +
                   uuid4) so parallel workers targeting the same destination no
                   longer clobber each other's staging table; engine is cached per
                   connection identity so streaming chunk loads reuse one pool.
1.5   2026-06-17   Write chunk size is byte-aware (_adaptive_chunksize) instead of
                   a fixed 500 rows, so wide or large-cell frames don't blow the
                   driver packet limit / memory.
"""

import time
import uuid
import logging
import threading
from pathlib import Path
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
        # load() runs once per streaming chunk; caching the engine here keeps the
        # connection pool alive across chunks instead of rebuilding it each call.
        self._engine_cache: dict = {}
        self._engine_cache_lock = threading.Lock()

    @staticmethod
    def _cfg_identity(cfg) -> tuple:
        """Stable, hashable key over the connection-defining cfg fields.

        Engines differ only by where they connect, so two cfgs that resolve to
        the same target share one pooled engine.  Credentials are part of the
        identity but are never logged from here.
        """
        fields = (
            "db_name", "database", "host", "port", "user", "password",
            "driver", "encrypt", "trust_server_certificate",
            "account", "warehouse", "role", "schema",
        )
        return tuple((f, cfg.get(f)) for f in fields)

    def _engine_for(self, cfg):
        """Return a cached engine for cfg's connection identity, building once.

        Replaces _engine_scope's per-call create/dispose: in streaming mode that
        rebuilt the whole pool every chunk.  Disposed via close().
        """
        key = self._cfg_identity(cfg)
        with self._engine_cache_lock:
            engine = self._engine_cache.get(key)
            if engine is None:
                engine = self._engine(cfg)
                self._engine_cache[key] = engine
            return engine

    def close(self) -> None:
        """Dispose every cached engine and its connection pool."""
        with self._engine_cache_lock:
            for engine in self._engine_cache.values():
                try:
                    engine.dispose()
                except Exception as exc:
                    # Disposal is best-effort cleanup; a failure here must not
                    # mask the real work the loader already completed.
                    logger.warning("Could not dispose engine: %s", exc)
            self._engine_cache.clear()

    def _engine(self, cfg):
        from sqlalchemy import create_engine
        from urllib.parse import quote_plus as _qp
        t = self.db_type
        if t == "sqlite":
            db_name = str(cfg["db_name"])
            # Append .db only when no extension was given — silently
            # rewriting an explicit path like "data.db" to "data.db.db"
            # writes somewhere the caller never asked for.
            if "." not in Path(db_name).name:
                db_name += ".db"
            return create_engine(f"sqlite:///{db_name}")
        if t == "postgresql":
            return create_engine(
                f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port', 5432)}/{cfg['db_name']}")
        if t == "mysql":
            return create_engine(
                f"mysql+pymysql://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port', 3306)}/{cfg['db_name']}")
        if t == "mssql":
            # host may carry "server,port" (SQL Server convention) — don't
            # append :port twice in that case
            host = str(cfg["host"])
            host_part = host if "," in host else f"{host}:{cfg.get('port', 1433)}"
            url = (
                f"mssql+pyodbc://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{host_part}/{cfg['db_name']}"
                f"?driver={cfg.get('driver', 'ODBC+Driver+17+for+SQL+Server')}")
            # Modern MS drivers encrypt by default; allow reaching servers
            # with self-signed certificates (test containers, dev boxes).
            if cfg.get("encrypt"):
                url += f"&Encrypt={cfg['encrypt']}"
            if cfg.get("trust_server_certificate"):
                url += f"&TrustServerCertificate={cfg['trust_server_certificate']}"
            return create_engine(url)
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

    @staticmethod
    def _split_table_name(table: str) -> tuple[str | None, str]:
        """Split 'schema.table' into (schema, table); plain names get None.

        Passing the dotted string straight to to_sql would create a single
        table literally named "schema.table" instead of using the schema.
        """
        if "." in table:
            schema, table_name = table.split(".", 1)
            return schema, table_name
        return None, table

    def load(self, df, cfg, table, if_exists="append", natural_keys=None) -> int:
        validate_sql_identifier(table, "table")
        schema, table_name = self._split_table_name(table)
        if self._dry_run_guard(table, len(df)):
            return 0
        self._require_upsert_keys(if_exists, natural_keys)
        engine = self._engine_for(cfg)
        if natural_keys:
            self._upsert(df, engine, table_name, natural_keys, schema)
        else:
            self._load_with_retry(df, engine, table_name, if_exists,
                                  schema)
        self.gov.load_complete(len(df), table)
        db_identifier = cfg.get("database") or cfg.get("db_name", "")
        self.gov.destination_registered(self.db_type, db_identifier, table)
        return len(df)

    def _load_with_retry(self, df, engine, table, if_exists, schema=None):
        for attempt in range(1, 4):
            try:
                with engine.begin() as _conn:
                    df.to_sql(table, _conn, if_exists=if_exists, index=False,
                              chunksize=self._adaptive_chunksize(df), schema=schema)
                return
            except Exception as exc:
                if attempt == 3:
                    raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                logger.warning("Attempt %d/3 failed. Retrying in %ds...",
                               attempt, wait)
                time.sleep(wait)

    def _upsert(self, new_df, engine, table, natural_keys, schema=None):
        """Database-native upsert via staging table — never loads target into memory."""
        from sqlalchemy import inspect as sai, text

        if table not in sai(engine).get_table_names(schema=schema):
            self._load_with_retry(new_df, engine, table, "replace", schema)
            return

        # Unique per call (a fresh uuid fragment) so two parallel workers
        # upserting into the same destination table never share (and clobber)
        # one staging table mid DELETE/INSERT. Keep the target table name
        # (truncated) for readability, and bound the whole identifier well
        # under the 63-char limit (Postgres/MySQL) for ANY table name.
        staging = f"_stg_{table[:40]}_{uuid.uuid4().hex[:10]}"
        validate_sql_identifier(staging, "staging table")

        def q(name):
            return f"`{name}`" if self.db_type == "mysql" else f'"{name}"'

        def qualified(name):
            return f"{q(schema)}.{q(name)}" if schema else q(name)

        all_cols = list(new_df.columns)
        cols_str = ", ".join(q(c) for c in all_cols)
        key_match = " AND ".join(
            f"{qualified(table)}.{q(k)} = {qualified(staging)}.{q(k)}"
            for k in natural_keys
        )

        # Staging creation is inside the try so a mid-create failure still hits
        # the finally and drops whatever partial table was left behind.
        try:
            with engine.begin() as conn:
                new_df.to_sql(staging, conn, if_exists="replace", index=False,
                              chunksize=self._adaptive_chunksize(new_df), schema=schema)
            with engine.begin() as conn:
                conn.execute(text(
                    f"DELETE FROM {qualified(table)} WHERE EXISTS "
                    f"(SELECT 1 FROM {qualified(staging)} WHERE {key_match})"
                ))
                conn.execute(text(
                    f"INSERT INTO {qualified(table)} ({cols_str}) "
                    f"SELECT {cols_str} FROM {qualified(staging)}"
                ))
        finally:
            with engine.begin() as conn:
                conn.execute(text(
                    f"DROP TABLE IF EXISTS {qualified(staging)}"
                ))

        self.gov.transformation_applied(
            "UPSERT_COMPLETE",
            {"table": table, "final_rows": len(new_df)},
        )
