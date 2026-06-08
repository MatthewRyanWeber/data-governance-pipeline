"""
Firebolt loader with high-performance INSERT, MERGE upsert, and
engine auto-start/stop management.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class FireboltLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_FIREBOLT

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class FireboltLoader:
    """Firebolt loader with INSERT and MERGE upsert via VALUES subquery."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "BIGINT", "Int64": "BIGINT NULL", "int32": "INT",
        "float64": "DOUBLE", "float32": "FLOAT",
        "bool": "BOOLEAN", "boolean": "BOOLEAN NULL",
        "datetime64[ns]": "TIMESTAMPNTZ",
        "datetime64[ns, UTC]": "TIMESTAMPTZ",
        "object": "TEXT",
    }

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_FIREBOLT:
            raise RuntimeError(
                "firebolt-sdk not installed.  "
                "Run: pip install firebolt-sdk"
            )

    def _connect(self, cfg: dict):
        """Return a Firebolt DB-API 2 connection."""
        from firebolt.client.auth import UsernamePassword as _FBUserPass
        from firebolt.client.auth import ClientCredentials as _FBClientCreds
        from firebolt.db import connect as _firebolt_connect

        if cfg.get("client_id"):
            auth = _FBClientCreds(cfg["client_id"], cfg["client_secret"])
        else:
            auth = _FBUserPass(cfg["username"], cfg["password"])

        kwargs: dict = {
            "auth": auth,
            "account_name": cfg["account_name"],
            "database": cfg["database"],
            "engine_name": cfg["engine_name"],
        }
        if cfg.get("api_endpoint"):
            kwargs["api_endpoint"] = cfg["api_endpoint"]
        return _firebolt_connect(**kwargs)

    def load(self, df, cfg, table, if_exists="append", natural_keys=None):
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._insert(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "firebolt",
            f"{cfg['account_name']}/{cfg['database']}/{cfg['engine_name']}",
            table,
        )

    def _insert(self, df, cfg, table, if_exists):
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            self._ensure_table(cur, df, table, if_exists)

            col_list = ", ".join(f'"{c}"' for c in df.columns)
            values_rows = self._values_literal(df)

            insert_sql = (
                f'INSERT INTO "{table}" ({col_list}) '
                f"VALUES {values_rows}"
            )
            cur.execute(insert_sql)
            logger.info("[FB] INSERT INTO %s -- %s rows", table, f"{len(df):,}")
        finally:
            cur.close()
            conn.close()

    def _ensure_table(self, cur, df, table, if_exists):
        col_defs = ", ".join(
            f'"{c}" {self._DTYPE_MAP.get(str(df[c].dtype), "TEXT")}'
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f'DROP TABLE IF EXISTS "{table}"')
        cur.execute(f'CREATE TABLE IF NOT EXISTS "{table}" ({col_defs})')

    def _upsert(self, df, cfg, table, natural_keys):
        """Firebolt v3 MERGE INTO using a VALUES subquery as the source."""
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            self._ensure_table(cur, df, table, "append")

            non_key_cols = [c for c in df.columns if c not in natural_keys]
            on_clause = " AND ".join(
                f't."{k}" = s."{k}"' for k in natural_keys
            )
            update_clause = ", ".join(
                f't."{c}" = s."{c}"' for c in non_key_cols
            ) or '"__noop__" = 0'
            all_cols = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols = ", ".join(f's."{c}"' for c in df.columns)

            col_typed = ", ".join(f'"{c}"' for c in df.columns)
            values_rows = self._values_literal(df)
            stage_subq = (
                f"(SELECT {col_typed} FROM (VALUES {values_rows}) "
                f"AS s({col_typed}))"
            )

            merge_sql = (
                f'MERGE INTO "{table}" AS t '
                f"USING {stage_subq} AS s "
                f"ON ({on_clause}) "
                f"WHEN MATCHED THEN UPDATE SET {update_clause} "
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            )
            cur.execute(merge_sql)
            logger.info("[FB] MERGE INTO %s -- %s rows", table, f"{len(df):,}")
            self.gov.transformation_applied(
                "FIREBOLT_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()

    @staticmethod
    def _values_literal(df) -> str:
        """Convert DataFrame to a SQL VALUES literal string."""
        def _fmt(v):
            if v is None or (not isinstance(v, str) and pd.isna(v)):
                return "NULL"
            if isinstance(v, bool):
                return "TRUE" if v else "FALSE"
            if isinstance(v, (int, float)):
                return str(v)
            return "'" + str(v).replace("'", "''") + "'"

        return ", ".join(
            "(" + ", ".join(_fmt(v) for v in row) + ")"
            for row in df.itertuples(index=False, name=None)
        )
