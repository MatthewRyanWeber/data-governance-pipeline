"""
Oracle ADW loader with bulk array insert, MERGE upsert, and Thin-mode operation.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class OracleLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   Rollback before each executemany retry so partial batches
                   are not duplicated; INSERTs emit an explicit column list;
                   load_complete reports rows actually inserted (excluding
                   batcherrors quarantine); table-existence check honours
                   cfg['schema'] via all_tables; all-key MERGE omits
                   WHEN MATCHED instead of the non-updatable ROWID trick.
1.3   2026-06-12   Loader contract: dry-run returns 0 (was None); keyless upsert raises via _require_upsert_keys (was silent append).
"""

import time
import logging
from typing import TYPE_CHECKING
from urllib.parse import quote_plus as _qp

from pipeline.constants import HAS_ORACLE
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class OracleLoader(BaseLoader):
    """Oracle loader with array INSERT (batcherrors) and MERGE upsert."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "NUMBER(19)", "Int64": "NUMBER(19)", "int32": "NUMBER(10)",
        "float64": "BINARY_DOUBLE", "float32": "BINARY_FLOAT",
        "bool": "NUMBER(1)", "boolean": "NUMBER(1)",
        "datetime64[ns]": "TIMESTAMP(6)",
        "datetime64[ns, UTC]": "TIMESTAMP(6) WITH TIME ZONE",
        "object": "VARCHAR2(4000)",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_ORACLE:
            raise RuntimeError("python-oracledb not installed.  Run: pip install oracledb")

    def _connect(self, cfg: dict):
        import oracledb as _oracledb
        conn_kwargs: dict = {
            "user": cfg["user"], "password": cfg["password"], "dsn": cfg["dsn"],
        }
        if cfg.get("wallet_location"):
            conn_kwargs["wallet_location"] = cfg["wallet_location"]
            conn_kwargs["wallet_password"] = cfg.get("wallet_password", "")
        if cfg.get("tns_admin"):
            _oracledb.init_oracle_client()
            conn_kwargs["config_dir"] = cfg["tns_admin"]
        return _oracledb.connect(**conn_kwargs)

    def _engine(self, cfg: dict):
        from sqlalchemy import create_engine as _ce
        user, password, dsn = _qp(cfg["user"]), _qp(cfg["password"]), cfg["dsn"]
        wallet = cfg.get("wallet_location", "")
        if wallet:
            return _ce(
                f"oracle+oracledb://{user}:{password}@",
                connect_args={"dsn": dsn, "wallet_location": wallet,
                              "wallet_password": cfg.get("wallet_password", "")},
            )
        return _ce(f"oracle+oracledb://{user}:{password}@{dsn}")

    def load(self, df, cfg, table, if_exists="append", natural_keys=None):
        table = table.upper()
        validate_sql_identifier(table, "table")
        if cfg.get("schema"):
            validate_sql_identifier(cfg["schema"], "schema")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._require_upsert_keys(if_exists, natural_keys)
        self._validate_config(cfg, ["user", "password", "dsn"])
        if natural_keys:
            inserted = self._upsert(df, cfg, table, natural_keys)
        else:
            inserted = self._array_insert(df, cfg, table, if_exists)
        self.gov.load_complete(inserted, table)
        self.gov.destination_registered(
            "oracle", f"{cfg['dsn']}/{cfg.get('schema', cfg['user'])}", table,
        )

    def _array_insert(self, df, cfg, table, if_exists) -> int:
        schema = cfg.get("schema", "").upper()
        fqt = f'"{schema}"."{table}"' if schema else f'"{table}"'
        conn = self._connect(cfg)
        cur = conn.cursor()
        inserted = len(df)
        try:
            self._ensure_table(cur, df, fqt, if_exists)
            conn.commit()
            # Explicit column list: positional VALUES against a pre-existing
            # table with a different column order would land values in the
            # wrong columns.
            col_list = ", ".join(f'"{c.upper()}"' for c in df.columns)
            bind_vars = ", ".join(f":{i+1}" for i in range(len(df.columns)))
            insert_sql = f"INSERT INTO {fqt} ({col_list}) VALUES ({bind_vars})"
            rows = list(df.where(df.notna(), None).itertuples(index=False, name=None))
            for attempt in range(1, 4):
                try:
                    cur.executemany(insert_sql, rows, batcherrors=True)
                    batch_errors = cur.getbatcherrors()
                    if batch_errors:
                        logger.warning("[ORACLE] %d batch error(s) during INSERT",
                                       len(batch_errors))
                        for err in batch_errors[:5]:
                            logger.warning("[ORACLE] Row %d: %s",
                                           err.offset, err.message)
                    conn.commit()
                    inserted = len(df) - len(batch_errors)
                    logger.info("[ORACLE] INSERT INTO %s -- %s rows OK, %d quarantined",
                                fqt, f"{inserted:,}", len(batch_errors))
                    break
                except Exception as exc:
                    if attempt == 3:
                        raise
                    # Discard any partially-executed batch before retrying,
                    # otherwise the retry re-inserts rows that already landed.
                    conn.rollback()
                    wait = 2 ** attempt
                    self.gov.retry_attempt(attempt, 3, float(wait), exc)
                    time.sleep(wait)
        finally:
            cur.close()
            conn.close()
        return inserted

    def _ensure_table(self, cur, df, fqt, if_exists):
        col_defs = ", ".join(
            f'"{c.upper()}" {self._DTYPE_MAP.get(str(df[c].dtype), "VARCHAR2(4000)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            try:
                cur.execute(f"DROP TABLE {fqt} PURGE")
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)
        table_name_raw = fqt.split(".")[-1].strip('"')
        fqt_parts = fqt.split(".")
        owner = fqt_parts[0].strip('"') if len(fqt_parts) == 2 else ""
        if owner:
            # user_tables only sees the connected user's tables; with an
            # explicit schema the check must go through all_tables + owner.
            cur.execute(
                "DECLARE v_cnt NUMBER; BEGIN "
                "SELECT COUNT(*) INTO v_cnt FROM all_tables "
                "WHERE table_name = :tname AND owner = :towner; "
                "IF v_cnt = 0 THEN "
                f"EXECUTE IMMEDIATE 'CREATE TABLE {fqt} ({col_defs})'; "
                "END IF; END;",
                {"tname": table_name_raw, "towner": owner},
            )
        else:
            cur.execute(
                "DECLARE v_cnt NUMBER; BEGIN "
                "SELECT COUNT(*) INTO v_cnt FROM user_tables "
                "WHERE table_name = :tname; "
                "IF v_cnt = 0 THEN "
                f"EXECUTE IMMEDIATE 'CREATE TABLE {fqt} ({col_defs})'; "
                "END IF; END;",
                {"tname": table_name_raw},
            )

    def _upsert(self, df, cfg, table, natural_keys):
        schema = cfg.get("schema", "").upper()
        import uuid
        tmp_table = f"{table[:20]}_STG_{uuid.uuid4().hex[:8]}"
        fqt = f'"{schema}"."{table}"' if schema else f'"{table}"'
        fqt_tmp = f'"{schema}"."{tmp_table}"' if schema else f'"{tmp_table}"'
        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            self._ensure_table(cur, df, fqt, "append")
            self._ensure_table(cur, df, fqt_tmp, "replace")
            conn.commit()
            col_list = ", ".join(f'"{c.upper()}"' for c in df.columns)
            bind_vars = ", ".join(f":{i+1}" for i in range(len(df.columns)))
            insert_sql = f"INSERT INTO {fqt_tmp} ({col_list}) VALUES ({bind_vars})"
            rows = list(df.where(df.notna(), None).itertuples(index=False, name=None))
            cur.executemany(insert_sql, rows)
            conn.commit()
            non_key_cols = [c for c in df.columns if c not in natural_keys]
            on_clause = " AND ".join(
                f't."{k.upper()}" = s."{k.upper()}"' for k in natural_keys
            )
            all_cols = ", ".join(f'"{c.upper()}"' for c in df.columns)
            stage_cols = ", ".join(f's."{c.upper()}"' for c in df.columns)
            # When every column is a key there is nothing to update: omit
            # WHEN MATCHED (ROWID is not updatable, so the old no-op trick
            # raised ORA-38104).
            if non_key_cols:
                update_clause = ", ".join(
                    f't."{c.upper()}" = s."{c.upper()}"' for c in non_key_cols
                )
                matched_part = f"WHEN MATCHED THEN UPDATE SET {update_clause} "
            else:
                matched_part = ""
            merge_sql = (
                f"MERGE INTO {fqt} t USING {fqt_tmp} s ON ({on_clause}) "
                f"{matched_part}"
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            )
            cur.execute(merge_sql)
            conn.commit()
            logger.info("[ORACLE] MERGE INTO %s -- %s rows", fqt, f"{len(df):,}")
            self.gov.transformation_applied(
                "ORACLE_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
            return len(df)
        finally:
            try:
                cur.execute(f"DROP TABLE {fqt_tmp} PURGE")
                conn.commit()
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)
            cur.close()
            conn.close()
