"""
DuckDB loader -- writes governed DataFrames to DuckDB (embedded analytical
database) with MotherDuck cloud support.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class DuckDBLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-08   Fixed SQL injection: query() now rejects mutating statements.
1.3   2026-06-09   Fix broken upsert: create a unique index on the natural keys
                   so ON CONFLICT has a target; DO NOTHING when no non-key cols.
"""

import logging
import re
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_DUCKDB
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

# Statements that mutate data or schema -- rejected by query().
_MUTATING_SQL_RE = re.compile(
    r"^\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE)\b",
    re.IGNORECASE,
)

# Allowed statement prefixes for the read-only query() method.
_READONLY_SQL_RE = re.compile(
    r"^\s*(?:SELECT|WITH|EXPLAIN)\b",
    re.IGNORECASE,
)


class DuckDBLoader(BaseLoader):
    """DuckDB loader with INSERT, REPLACE, and ON CONFLICT upsert."""

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_DUCKDB:
            raise RuntimeError(
                "DuckDBLoader requires the duckdb package.\n"
                "Install with:  pip install duckdb"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a DuckDB table."""
        import duckdb

        if if_exists not in ("append", "replace", "upsert"):
            raise ValueError(
                f"DuckDBLoader: if_exists must be 'append', 'replace', or "
                f"'upsert', got '{if_exists}'."
            )
        if not table:
            raise ValueError("DuckDBLoader: table name is required.")
        if not cfg.get("db_path"):
            raise ValueError("DuckDBLoader: cfg must contain 'db_path'.")
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._validate_config(cfg, ["db_path"])

        if df.empty:
            return 0

        db_path = cfg["db_path"]
        token = cfg.get("motherduck_token")

        if token and db_path.startswith("md:"):
            import os
            os.environ.setdefault("MOTHERDUCK_TOKEN", token)

        kwargs: dict = {"read_only": cfg.get("read_only", False)}
        if cfg.get("threads"):
            kwargs["threads"] = int(cfg["threads"])

        conn = duckdb.connect(db_path, **kwargs)
        try:
            if if_exists == "replace":
                conn.execute(f"DROP TABLE IF EXISTS {table}")
                conn.execute(f"CREATE TABLE {table} AS SELECT * FROM df")
            elif if_exists == "upsert" and natural_keys:
                for k in natural_keys:
                    validate_sql_identifier(k, "natural_key")
                missing = [k for k in natural_keys if k not in df.columns]
                if missing:
                    raise ValueError(
                        f"DuckDBLoader: upsert key(s) not in DataFrame: "
                        f"{missing}"
                    )
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} AS "
                    f"SELECT * FROM df WHERE 1=0"
                )
                key_str = ", ".join(natural_keys)
                # DuckDB's ON CONFLICT requires the conflict target to be backed
                # by a UNIQUE/PK constraint or index; the CTAS above creates
                # none, so add a unique index on the keys before the upsert.
                index_name = "idx_" + table.replace(".", "_") + "_upsert_keys"
                validate_sql_identifier(index_name, "index")
                conn.execute(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} "
                    f"ON {table} ({key_str})"
                )
                non_keys = [c for c in df.columns if c not in natural_keys]
                if non_keys:
                    update_str = ", ".join(
                        f"{c} = excluded.{c}" for c in non_keys
                    )
                    conflict_action = f"DO UPDATE SET {update_str}"
                else:
                    # No non-key columns to update — fall back to ignore-on-conflict.
                    conflict_action = "DO NOTHING"
                conn.execute(
                    f"INSERT INTO {table} SELECT * FROM df "
                    f"ON CONFLICT ({key_str}) {conflict_action}"
                )
            else:
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} AS "
                    f"SELECT * FROM df WHERE 1=0"
                )
                conn.execute(f"INSERT INTO {table} SELECT * FROM df")
        finally:
            conn.close()

        self.gov._event(
            "LOAD", "DUCKDB_WRITE_COMPLETE",
            {
                "db_path": db_path,
                "table": table,
                "rows": len(df),
                "if_exists": if_exists,
                "motherduck": db_path.startswith("md:"),
            },
        )
        return len(df)

    def query(self, cfg: dict, sql: str) -> "pd.DataFrame":
        """Run a read-only SQL query against a DuckDB database.

        Only SELECT, WITH, and EXPLAIN statements are permitted.
        Mutating statements (DROP, DELETE, INSERT, UPDATE, ALTER, CREATE,
        TRUNCATE) are rejected before execution.
        """
        import duckdb

        if _MUTATING_SQL_RE.search(sql):
            raise ValueError(
                "DuckDBLoader.query(): mutating statements are not allowed. "
                f"Got statement starting with: {sql.strip()[:40]!r}"
            )
        if not _READONLY_SQL_RE.match(sql):
            raise ValueError(
                "DuckDBLoader.query(): only SELECT, WITH, and EXPLAIN "
                f"statements are allowed. Got: {sql.strip()[:40]!r}"
            )
        logger.warning(
            "DuckDBLoader.query(): executing caller-supplied SQL. "
            "This method is for read-only analytical queries only."
        )
        conn = duckdb.connect(cfg["db_path"], read_only=True)
        try:
            return conn.execute(sql).df()
        finally:
            conn.close()
