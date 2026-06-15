"""
SAP HANA loader -- writes DataFrames to SAP HANA Cloud or on-premise HANA (2.0+).
SAP Analytics Cloud (SAC) can connect to HANA tables as a live data source.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class HanaLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   Upsert staging table is dropped in a finally block so a
                   failed MERGE no longer leaks the stage table.
1.3   2026-06-12   Loader contract: dry-run returns 0 (was None); keyless upsert raises via _require_upsert_keys (was silent append).
1.4   2026-06-14   Write path forces autocommit=False so drop/create/insert/merge
                   commit atomically (a failed step after the replace-drop no
                   longer loses the target table); rollback on error; staging
                   name bounded to HANA's 127-char limit; CREATE SCHEMA runs
                   once per load, not for the stage table.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_HANA
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class HanaLoader(BaseLoader):
    """SAP HANA loader with chunked INSERT and MERGE upsert."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "BIGINT", "Int64": "BIGINT", "int32": "INTEGER",
        "float64": "DOUBLE", "float32": "REAL",
        "bool": "BOOLEAN", "boolean": "BOOLEAN",
        "datetime64[ns]": "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMP",
        "object": "NVARCHAR(5000)",
    }

    _CHUNK = 5_000

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_HANA:
            raise RuntimeError(
                "hdbcli not installed.  "
                "Run: pip install hdbcli"
            )

    def _connect(self, cfg: dict, for_write: bool = False):
        """Return a live hdbcli connection.

        for_write forces autocommit off regardless of cfg: the load/upsert path
        spans a drop + create + insert + merge that must commit as one unit, or
        a failure after the replace-drop would leave the target table gone with
        nothing recreated.
        """
        import hdbcli.dbapi as _hdb
        autocommit = False if for_write else cfg.get("autocommit", True)
        return _hdb.connect(
            address=cfg["host"],
            port=int(cfg.get("port", 443)),
            user=cfg["user"],
            password=cfg["password"],
            encrypt=cfg.get("encrypt", True),
            autocommit=autocommit,
        )

    def _col_def(self, col: str, dtype: str) -> str:
        sql_type = self._DTYPE_MAP.get(dtype, "NVARCHAR(5000)")
        return f'"{col}" {sql_type}'

    def _ensure_table(self, cur, schema, table, df, ensure_schema: bool = True):
        """CREATE TABLE IF NOT EXISTS in the target schema.

        ensure_schema is skipped for the stage table: the schema is already
        guaranteed by the target-table call earlier in the same load.
        """
        cols = ", ".join(
            self._col_def(c, str(df[c].dtype)) for c in df.columns
        )
        if ensure_schema:
            cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        cur.execute(
            f'CREATE TABLE IF NOT EXISTS "{schema}"."{table}" ({cols})'
        )

    def _drop_table(self, cur, schema, table):
        cur.execute(f'DROP TABLE IF EXISTS "{schema}"."{table}"')

    def _insert(self, cur, schema, table, df):
        """Chunked executemany INSERT."""
        cols = ", ".join(f'"{c}"' for c in df.columns)
        params = ", ".join("?" * len(df.columns))
        sql = f'INSERT INTO "{schema}"."{table}" ({cols}) VALUES ({params})'
        rows = list(df.where(df.notna(), None).itertuples(index=False, name=None))
        for i in range(0, len(rows), self._CHUNK):
            cur.executemany(sql, rows[i: i + self._CHUNK])

    def _upsert(self, cur, schema, table, df, natural_keys):
        """HANA MERGE INTO via staging table."""
        import uuid
        # Bound the table portion: HANA caps identifiers at 127 chars and the
        # "__stage_" + 8-hex-char suffix must fit alongside it.
        stage = f"{table[:100]}__stage_{uuid.uuid4().hex[:8]}"
        self._ensure_table(cur, schema, stage, df, ensure_schema=False)
        self._insert(cur, schema, stage, df)

        non_keys = [c for c in df.columns if c not in natural_keys]
        key_cond = " AND ".join(
            f'T."{k}" = S."{k}"' for k in natural_keys
        )
        if non_keys:
            update_clause = ", ".join(
                f'T."{c}" = S."{c}"' for c in non_keys
            )
            update_part = f"WHEN MATCHED THEN UPDATE SET {update_clause}"
        else:
            update_part = ""

        insert_cols = ", ".join(f'"{c}"' for c in df.columns)
        insert_vals = ", ".join(f'S."{c}"' for c in df.columns)

        merge_sql = f"""
            MERGE INTO "{schema}"."{table}" AS T
            USING "{schema}"."{stage}" AS S
            ON ({key_cond})
            {update_part}
            WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({insert_vals})
        """
        # Drop in finally: a failed MERGE must not leak the stage table.
        try:
            cur.execute(merge_sql)
        finally:
            self._drop_table(cur, schema, stage)

    def load(self, df, cfg, table, if_exists="append", natural_keys=None) -> int:
        schema = cfg.get("schema", "PIPELINE")
        validate_sql_identifier(table, "table")
        validate_sql_identifier(schema, "schema")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._require_upsert_keys(if_exists, natural_keys)
        self._validate_config(cfg, ["host", "user", "password"])
        # for_write forces autocommit off: the replace-drop, create, insert and
        # merge must commit as one unit so a mid-sequence failure cannot leave
        # the target table dropped with nothing recreated.
        conn = self._connect(cfg, for_write=True)
        cur = conn.cursor()

        try:
            if if_exists == "replace":
                self._drop_table(cur, schema, table)
            self._ensure_table(cur, schema, table, df)

            if natural_keys:
                self._upsert(cur, schema, table, df, natural_keys)
            else:
                self._insert(cur, schema, table, df)

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "hana",
            f"{cfg['host']}:{cfg.get('port', 443)}/{schema}",
            table,
        )
        self.gov.transformation_applied("HANA_LOAD_COMPLETE", {
            "schema": schema, "table": table, "rows": len(df),
            "mode": "upsert" if natural_keys else if_exists,
        })
        return len(df)

