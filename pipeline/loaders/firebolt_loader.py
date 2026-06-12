"""
Firebolt loader with high-performance INSERT, MERGE upsert, and
engine auto-start/stop management.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class FireboltLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   INSERT path uses chunked parameterized executemany instead
                   of a whole-DataFrame VALUES literal; literal formatting
                   (still used by the MERGE source) now handles numpy scalars;
                   config validation accepts client_id/client_secret as an
                   alternative to username/password; all-key MERGE omits
                   WHEN MATCHED instead of referencing __noop__.
1.3   2026-06-12   Loader contract: dry-run returns 0 (was None); keyless upsert raises via _require_upsert_keys (was silent append).
"""

import logging
import numbers
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_FIREBOLT
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class FireboltLoader(BaseLoader):
    """Firebolt loader with INSERT and MERGE upsert via VALUES subquery."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "BIGINT", "Int64": "BIGINT NULL", "int32": "INT",
        "float64": "DOUBLE", "float32": "FLOAT",
        "bool": "BOOLEAN", "boolean": "BOOLEAN NULL",
        "datetime64[ns]": "TIMESTAMPNTZ",
        "datetime64[ns, UTC]": "TIMESTAMPTZ",
        "object": "TEXT",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
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

    def load(self, df, cfg, table, if_exists="append", natural_keys=None) -> int:
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._require_upsert_keys(if_exists, natural_keys)
        # Firebolt supports two auth schemes; either satisfies validation.
        self._validate_config(
            cfg,
            ["username|client_id", "database", "account_name", "engine_name"],
        )
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
        return len(df)

    _INSERT_CHUNK = 1_000

    def _insert(self, df, cfg, table, if_exists):
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            self._ensure_table(cur, df, table, if_exists)

            # Parameterized executemany: a whole-DataFrame VALUES literal
            # serialized every value into one statement and mis-quoted
            # numpy scalars.
            col_list = ", ".join(f'"{c}"' for c in df.columns)
            placeholders = ", ".join("?" * len(df.columns))
            insert_sql = (
                f'INSERT INTO "{table}" ({col_list}) '
                f"VALUES ({placeholders})"
            )
            rows = list(
                df.where(df.notna(), None).itertuples(index=False, name=None)
            )
            for i in range(0, len(rows), self._INSERT_CHUNK):
                cur.executemany(insert_sql, rows[i:i + self._INSERT_CHUNK])
            logger.info("[FIREBOLT] INSERT INTO %s -- %s rows", table, f"{len(df):,}")
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
            all_cols = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols = ", ".join(f's."{c}"' for c in df.columns)

            col_typed = ", ".join(f'"{c}"' for c in df.columns)
            values_rows = self._values_literal(df)
            stage_subq = (
                f"(SELECT {col_typed} FROM (VALUES {values_rows}) "
                f"AS s({col_typed}))"
            )

            # When every column is a key there is nothing to update: omit
            # WHEN MATCHED instead of referencing a non-existent __noop__.
            if non_key_cols:
                update_clause = ", ".join(
                    f't."{c}" = s."{c}"' for c in non_key_cols
                )
                matched_part = f"WHEN MATCHED THEN UPDATE SET {update_clause} "
            else:
                matched_part = ""

            merge_sql = (
                f'MERGE INTO "{table}" AS t '
                f"USING {stage_subq} AS s "
                f"ON ({on_clause}) "
                f"{matched_part}"
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            )
            cur.execute(merge_sql)
            logger.info("[FIREBOLT] MERGE INTO %s -- %s rows", table, f"{len(df):,}")
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
            # pandas type check catches numpy.bool_, which is not a Python
            # bool; without it booleans would fall through and be quoted.
            if pd.api.types.is_bool(v):
                return "TRUE" if v else "FALSE"
            # numbers.Integral/Real cover numpy scalars (int64, float64...)
            # that fail a plain isinstance(int/float) check and would
            # otherwise be emitted as quoted strings.
            if isinstance(v, numbers.Integral):
                return str(int(v))
            if isinstance(v, numbers.Real):
                import math
                value = float(v)
                if math.isnan(value) or math.isinf(value):
                    return "NULL"
                return repr(value)
            return "'" + str(v).replace("'", "''") + "'"

        return ", ".join(
            "(" + ", ".join(_fmt(v) for v in row) + ")"
            for row in df.itertuples(index=False, name=None)
        )
