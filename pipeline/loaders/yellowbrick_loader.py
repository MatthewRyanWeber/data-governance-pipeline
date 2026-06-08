"""
Yellowbrick Data Warehouse loader with bulk COPY FROM STDIN, MERGE upsert,
and PostgreSQL-compatible wire protocol.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class YellowbrickLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import time
import logging
from typing import TYPE_CHECKING
from urllib.parse import quote_plus as _qp

from pipeline.constants import HAS_YELLOWBRICK
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class YellowbrickLoader(BaseLoader):
    """Yellowbrick loader with COPY FROM STDIN and MERGE upsert."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "BIGINT", "Int64": "BIGINT", "int32": "INTEGER",
        "float64": "DOUBLE PRECISION", "float32": "REAL",
        "bool": "BOOLEAN", "boolean": "BOOLEAN",
        "datetime64[ns]": "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMPTZ",
        "object": "VARCHAR(65535)",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_YELLOWBRICK:
            raise RuntimeError(
                "psycopg2 not installed.  "
                "Run: pip install psycopg2-binary"
            )

    def _connect(self, cfg: dict):
        """Return a psycopg2 connection to Yellowbrick."""
        import psycopg2
        return psycopg2.connect(
            host=cfg["host"],
            port=int(cfg.get("port", 5432)),
            dbname=cfg["database"],
            user=cfg["user"],
            password=cfg["password"],
            sslmode=cfg.get("sslmode", "require"),
        )

    def _engine(self, cfg: dict):
        """SQLAlchemy engine for upsert staging."""
        from sqlalchemy import create_engine as _ce
        port = cfg.get("port", 5432)
        return _ce(
            f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
            f"@{cfg['host']}:{port}/{cfg['database']}"
        )

    def load(self, df, cfg, table, if_exists="append", natural_keys=None):
        validate_sql_identifier(table, "table")
        if cfg.get("schema"):
            validate_sql_identifier(cfg["schema"], "schema")
        if self._dry_run_guard(table, len(df)):
            return
        self._validate_config(cfg, ["host", "database", "user", "password"])
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._copy_from_stdin(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "yellowbrick",
            f"{cfg['host']}:{cfg.get('port', 5432)}/{cfg['database']}"
            f"/{cfg.get('schema', 'public')}",
            table,
        )

    def _copy_from_stdin(self, df, cfg, table, if_exists):
        """Stream CSV to Yellowbrick via copy_expert()."""
        import io as _io

        schema = cfg.get("schema", "public")
        fqt = f'"{schema}"."{table}"'
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            self._ensure_table(cur, df, fqt, if_exists)
            conn.commit()

            csv_buf = _io.StringIO()
            df.to_csv(csv_buf, index=False, header=False, na_rep="\\N")
            csv_buf.seek(0)

            col_list = ", ".join(f'"{c}"' for c in df.columns)
            copy_sql = (
                f"COPY {fqt} ({col_list}) FROM STDIN "
                "WITH (FORMAT CSV, NULL '\\N')"
            )
            cur.copy_expert(copy_sql, csv_buf)
            conn.commit()
            logger.info("[YB] COPY FROM STDIN -> %s -- %s rows",
                        fqt, f"{len(df):,}")
        finally:
            cur.close()
            conn.close()

    def _ensure_table(self, cur, df, fqt, if_exists):
        col_defs = ", ".join(
            f'"{c}" {self._DTYPE_MAP.get(str(df[c].dtype), "VARCHAR(65535)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f"DROP TABLE IF EXISTS {fqt}")
        cur.execute(f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs})")

    def _upsert(self, df, cfg, table, natural_keys):
        """Stage -> PostgreSQL-compatible MERGE INTO."""
        schema = cfg.get("schema", "public")
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt = f'"{schema}"."{table}"'
        fqt_tmp = f'"{schema}"."{tmp_table}"'

        self._copy_from_stdin(df, cfg, tmp_table, "replace")

        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            self._ensure_table(cur, df, fqt, "append")
            conn.commit()

            non_key_cols = [c for c in df.columns if c not in natural_keys]
            on_clause = " AND ".join(
                f't."{k}" = s."{k}"' for k in natural_keys
            )
            all_cols = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols = ", ".join(f's."{c}"' for c in df.columns)

            merge_sql = f"MERGE INTO {fqt} AS t USING {fqt_tmp} AS s ON ({on_clause}) "
            if non_key_cols:
                update_clause = ", ".join(
                    f'"{c}" = s."{c}"' for c in non_key_cols
                )
                merge_sql += f"WHEN MATCHED THEN UPDATE SET {update_clause} "
            merge_sql += f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            cur.execute(merge_sql)
            cur.execute(f"DROP TABLE IF EXISTS {fqt_tmp}")
            conn.commit()
            logger.info("[YB] MERGE INTO %s -- %s rows", fqt, f"{len(df):,}")
            self.gov.transformation_applied(
                "YELLOWBRICK_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()
