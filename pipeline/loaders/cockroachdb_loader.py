"""
CockroachDB loader -- writes governed DataFrames to CockroachDB (distributed
PostgreSQL) with ON CONFLICT upsert support.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class CockroachDBLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   if_exists='upsert' without natural_keys now raises instead
                   of silently appending.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_COCKROACH
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class CockroachDBLoader(BaseLoader):
    """CockroachDB loader with INSERT and ON CONFLICT DO UPDATE upsert."""

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a CockroachDB table."""
        if if_exists not in ("append", "replace", "upsert"):
            raise ValueError(
                f"CockroachDBLoader: if_exists must be 'append', 'replace', "
                f"or 'upsert', got '{if_exists}'."
            )
        if not table:
            raise ValueError("CockroachDBLoader: table name is required.")
        if not cfg.get("host"):
            raise ValueError("CockroachDBLoader: cfg must contain 'host'.")
        if not cfg.get("db_name"):
            raise ValueError("CockroachDBLoader: cfg must contain 'db_name'.")
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._validate_config(cfg, ["host", "user", "db_name"])

        if if_exists == "upsert" and not natural_keys:
            # Silently appending here would duplicate rows the caller
            # expected to be merged.
            raise ValueError(
                "CockroachDBLoader: if_exists='upsert' requires natural_keys."
            )

        if df.empty:
            return 0

        with self._engine_scope(cfg) as engine:
            if if_exists == "upsert":
                rows = self._upsert(df, engine, table, natural_keys)
            else:
                pg_if_exists = "replace" if if_exists == "replace" else "append"
                df.to_sql(table, engine, if_exists=pg_if_exists,
                          index=False, method="multi", chunksize=500)
                rows = len(df)

        self.gov._event(
            "LOAD", "COCKROACHDB_WRITE_COMPLETE",
            {
                "host": cfg["host"],
                "db_name": cfg["db_name"],
                "table": table,
                "rows": rows,
                "if_exists": if_exists,
                "driver": "cockroachdb" if HAS_COCKROACH else "psycopg2",
            },
        )
        return rows

    def table_info(self, cfg: dict, table: str) -> dict:
        """Return basic metadata about a CockroachDB table."""
        from sqlalchemy import inspect as sa_inspect, text as sa_text

        validate_sql_identifier(table, "table")
        with self._engine_scope(cfg) as engine:
            insp = sa_inspect(engine)
            cols = [c["name"] for c in insp.get_columns(table)]
            with engine.connect() as conn:
                count = conn.execute(
                    sa_text(f"SELECT COUNT(*) FROM {table}")
                ).scalar()
            url_repr = repr(engine.url.render_as_string(hide_password=True))
        return {
            "table": table,
            "columns": cols,
            "row_count": count,
            "engine_url": url_repr,
        }

    def _engine(self, cfg: dict):
        """Build a SQLAlchemy engine for CockroachDB."""
        from sqlalchemy import create_engine
        from urllib.parse import quote_plus as _qp

        host = cfg["host"]
        port = cfg.get("port", 26257)
        db_name = cfg["db_name"]
        user = _qp(cfg.get("user", "root"))
        password = _qp(cfg.get("password", ""))
        sslmode = cfg.get("sslmode", "verify-full")
        sslcert = cfg.get("sslrootcert", "")
        cluster = cfg.get("cluster_name", "")
        options = cfg.get("options", "")

        if cluster:
            host = f"{cluster}.{host}"

        if HAS_COCKROACH:
            url = f"cockroachdb://{user}:{password}@{host}:{port}/{db_name}"
            params = [f"sslmode={sslmode}"]
            if sslcert:
                params.append(f"sslrootcert={sslcert}")
            if options:
                params.append(options)
            url += "?" + "&".join(params)
        else:
            url = (f"postgresql+psycopg2://{user}:{password}"
                   f"@{host}:{port}/{db_name}")
            params = [f"sslmode={sslmode}"]
            if sslcert:
                params.append(f"sslrootcert={sslcert}")
            if options:
                params.append(options)
            url += "?" + "&".join(params)

        return create_engine(url, pool_pre_ping=True)

    def _upsert(self, df, engine, table, natural_keys) -> int:
        """INSERT ... ON CONFLICT DO UPDATE SET."""
        from sqlalchemy import text as sa_text

        missing = [k for k in natural_keys if k not in df.columns]
        if missing:
            raise ValueError(
                f"CockroachDBLoader: upsert key column(s) not in DataFrame: "
                f"{missing}"
            )

        cols = list(df.columns)
        non_keys = [c for c in cols if c not in natural_keys]
        for col in cols:
            validate_sql_identifier(col, "column")
        for key in natural_keys:
            validate_sql_identifier(key, "natural_key")
        key_str = ", ".join(natural_keys)
        col_str = ", ".join(cols)
        val_str = ", ".join(f":{c}" for c in cols)
        update_str = ", ".join(f"{c} = EXCLUDED.{c}" for c in non_keys)

        sql = sa_text(
            f"INSERT INTO {table} ({col_str}) VALUES ({val_str}) "
            f"ON CONFLICT ({key_str}) DO UPDATE SET {update_str}"
        )

        # ON CONFLICT requires a unique constraint on the key columns,
        # which tables created by our own append path (to_sql) lack —
        # without this the loader's upsert can never work on tables the
        # loader itself created.  Separate transaction: CockroachDB
        # cannot use an index created inside the same transaction.
        #
        # Postgres/Cockroach truncate identifiers at 63 bytes, so a long
        # table+keys name would silently truncate and could collide across
        # different upsert targets.  A short content hash keeps the name
        # unique-per-(table,keys) and always under the limit.
        import hashlib
        digest = hashlib.sha1(
            f"{table}\0{','.join(natural_keys)}".encode("utf-8")
        ).hexdigest()[:12]
        safe_name = validate_sql_identifier(f"uq_dgp_{digest}", "index")
        with engine.begin() as conn:
            conn.execute(sa_text(
                f"CREATE UNIQUE INDEX IF NOT EXISTS {safe_name} "
                f"ON {table} ({key_str})"
            ))

        rows = 0
        with engine.begin() as conn:
            for batch_start in range(0, len(df), 500):
                batch = df.iloc[batch_start:batch_start + 500]
                conn.execute(sql, batch.to_dict(orient="records"))
                rows += len(batch)
        return rows
