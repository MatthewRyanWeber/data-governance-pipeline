"""
Azure Synapse Analytics loader with Azure Blob-staged COPY, MERGE upsert,
and Entra ID (AAD) authentication support.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class SynapseLoader).
1.1   2026-06-11   to_sql chunksize now derived from SQL Server's 2,100
                   bind-parameter limit so wide frames no longer fail;
                   all-key MERGE omits WHEN MATCHED instead of referencing
                   __noop__; SQLAlchemy engines disposed via _engine_scope.
1.2   2026-06-12   Loader contract: dry-run returns 0 (was None); keyless upsert raises via _require_upsert_keys (was silent append).
"""

import time
import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_SYNAPSE
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SynapseLoader(BaseLoader):
    """Azure Synapse Analytics loader with Blob COPY, MERGE, and Entra ID auth."""

    _DTYPE_MAP: dict[str, str] = {
        "int64": "BIGINT", "Int64": "BIGINT", "int32": "INT",
        "float64": "FLOAT", "float32": "REAL",
        "bool": "BIT", "boolean": "BIT",
        "datetime64[ns]": "DATETIME2", "datetime64[ns, UTC]": "DATETIMEOFFSET",
        "object": "NVARCHAR(MAX)",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_SYNAPSE:
            raise RuntimeError(
                "Synapse dependencies not installed.  "
                "Run: pip install pyodbc azure-storage-blob azure-identity"
            )

    def _connection_string(self, cfg: dict) -> str:
        driver = cfg.get("driver", "ODBC Driver 17 for SQL Server")
        host = cfg["host"]
        port = cfg.get("port", 1433)
        db = cfg["database"]
        # Encrypt-by-default stays, but both knobs are configurable so the
        # loader can reach test servers with self-signed certificates.
        encrypt = cfg.get("encrypt", "yes")
        trust_cert = cfg.get("trust_server_certificate", "no")
        tls = f"Encrypt={encrypt};TrustServerCertificate={trust_cert}"
        if cfg.get("tenant_id"):
            return (
                f"DRIVER={{{driver}}};SERVER={host},{port};DATABASE={db};"
                "Authentication=ActiveDirectoryServicePrincipal;"
                f"UID={cfg['client_id']};PWD={cfg['client_secret']};{tls}"
            )
        return (
            f"DRIVER={{{driver}}};SERVER={host},{port};DATABASE={db};"
            f"UID={cfg['user']};PWD={cfg['password']};{tls}"
        )

    def _engine(self, cfg: dict):
        from sqlalchemy import create_engine as _ce
        import urllib.parse
        conn_str = self._connection_string(cfg)
        return _ce(
            f"mssql+pyodbc:///?odbc_connect="
            f"{urllib.parse.quote_plus(conn_str)}"
        )

    @staticmethod
    def _safe_chunksize(df) -> int:
        # SQL Server caps a statement at 2,100 bind parameters; with
        # method="multi" each row consumes len(columns) parameters, so the
        # chunk size must shrink as the frame gets wider (2000 leaves headroom).
        return max(1, 2000 // max(1, len(df.columns)))

    def load(self, df, cfg, table, if_exists="append", natural_keys=None) -> int:
        validate_sql_identifier(table, "table")
        if cfg.get("schema"):
            validate_sql_identifier(cfg["schema"], "schema")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._require_upsert_keys(if_exists, natural_keys)
        self._validate_config(cfg, ["host", "database"])
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        elif cfg.get("storage_account"):
            self._blob_copy(df, cfg, table, if_exists)
        else:
            self._sql_fallback(df, cfg, table, if_exists)
        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "synapse",
            f"{cfg['host']}/{cfg['database']}/{cfg.get('schema', 'dbo')}",
            table,
        )
        return len(df)

    def _blob_copy(self, df, cfg, table, if_exists):
        import tempfile
        import os
        import pyodbc as _pyodbc
        from azure.storage.blob import BlobServiceClient as _BlobServiceClient

        account = cfg["storage_account"]
        container = cfg["storage_container"]
        sas_token = cfg["storage_sas_token"]
        schema = cfg.get("schema", "dbo")
        blob_name = f"synapse_stage/{table}_{int(time.time())}.csv.gz"
        blob_url = (
            f"https://{account}.blob.core.windows.net/{container}/{blob_name}"
        )
        with tempfile.NamedTemporaryFile(suffix=".csv.gz", delete=False) as tmp:
            tmp_path = tmp.name
        df.to_csv(tmp_path, index=False, compression="gzip")
        blob_client = _BlobServiceClient(
            account_url=f"https://{account}.blob.core.windows.net",
            credential=sas_token,
        ).get_blob_client(container, blob_name)
        with open(tmp_path, "rb") as data:
            blob_client.upload_blob(data, overwrite=True)
        logger.info("[SYNAPSE] Uploaded blob: %s...", blob_url[:60])
        conn_str = self._connection_string(cfg)
        conn = _pyodbc.connect(conn_str, autocommit=False)
        cur = conn.cursor()
        fqt = f"[{schema}].[{table}]"
        try:
            self._ensure_table(cur, df, fqt, if_exists)
            col_list = ", ".join(f"[{c}]" for c in df.columns)
            copy_sql = (
                f"COPY INTO {fqt} ({col_list}) "
                f"FROM '{blob_url}?{sas_token}' "
                "WITH (FILE_TYPE='CSV', FIRSTROW=2, FIELDTERMINATOR=',', "
                "ROWTERMINATOR='\\n', COMPRESSION='GZIP')"
            )
            cur.execute(copy_sql)
            conn.commit()
            logger.info("[SYNAPSE] COPY INTO %s -- %s rows", fqt, f"{len(df):,}")
        except Exception as exc:
            logger.warning("[SYNAPSE] COPY INTO failed -- falling back to to_sql(): %s", exc)
            self._sql_fallback(df, cfg, table, if_exists)
        finally:
            cur.close()
            conn.close()
            try:
                os.unlink(tmp_path)
                blob_client.delete_blob()
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)

    def _ensure_table(self, cur, df, fqt, if_exists):
        col_defs = ", ".join(
            f"[{c}] {self._DTYPE_MAP.get(str(df[c].dtype), 'NVARCHAR(MAX)')}"
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(
                f"IF OBJECT_ID('{fqt}', 'U') IS NOT NULL DROP TABLE {fqt}"
            )
            cur.execute(f"CREATE TABLE {fqt} ({col_defs})")
            cur.connection.commit()
        else:
            # OBJECT_ID resolves the bracketed identifier correctly,
            # including names containing dots — the old
            # TABLE_SCHEMA+'.'+TABLE_NAME string compare broke on those.
            cur.execute(
                f"IF OBJECT_ID('{fqt}', 'U') IS NULL "
                f"CREATE TABLE {fqt} ({col_defs})"
            )
            cur.connection.commit()

    def _upsert(self, df, cfg, table, natural_keys):
        import pyodbc as _pyodbc
        schema = cfg.get("schema", "dbo")
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt = f"[{schema}].[{table}]"
        fqt_tmp = f"[{schema}].[{tmp_table}]"
        with self._engine_scope(cfg) as engine:
            with engine.begin() as _conn:
                df.to_sql(tmp_table, _conn, if_exists="replace", index=False,
                          schema=schema, chunksize=self._safe_chunksize(df),
                          method="multi")
        conn_str = self._connection_string(cfg)
        conn = _pyodbc.connect(conn_str, autocommit=False)
        cur = conn.cursor()
        try:
            non_key_cols = [c for c in df.columns if c not in natural_keys]
            on_clause = " AND ".join(
                f"t.[{k}] = s.[{k}]" for k in natural_keys
            )
            all_cols = ", ".join(f"[{c}]" for c in df.columns)
            stage_cols = ", ".join(f"s.[{c}]" for c in df.columns)
            self._ensure_table(cur, df, fqt, "append")
            # When every column is a key there is nothing to update: omit
            # WHEN MATCHED instead of referencing a non-existent __noop__.
            if non_key_cols:
                update_clause = ", ".join(
                    f"t.[{c}] = s.[{c}]" for c in non_key_cols
                )
                matched_part = f"WHEN MATCHED THEN UPDATE SET {update_clause} "
            else:
                matched_part = ""
            merge_sql = (
                f"MERGE {fqt} AS t "
                f"USING {fqt_tmp} AS s ON ({on_clause}) "
                f"{matched_part}"
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) "
                f"VALUES ({stage_cols});"
            )
            cur.execute(merge_sql)
            cur.execute(f"DROP TABLE IF EXISTS {fqt_tmp}")
            conn.commit()
            logger.info("[SYNAPSE] MERGE INTO %s -- %s rows", fqt, f"{len(df):,}")
            self.gov.transformation_applied(
                "SYNAPSE_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys,
                 "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()

    def _sql_fallback(self, df, cfg, table, if_exists):
        schema = cfg.get("schema", "dbo")
        with self._engine_scope(cfg) as engine:
            for attempt in range(1, 4):
                try:
                    with engine.begin() as _conn:
                        df.to_sql(table, _conn, if_exists=if_exists,
                                  index=False, schema=schema,
                                  chunksize=self._safe_chunksize(df),
                                  method="multi")
                    return
                except Exception as exc:
                    if attempt == 3:
                        raise
                    wait = 2 ** attempt
                    self.gov.retry_attempt(attempt, 3, float(wait), exc)
                    time.sleep(wait)
