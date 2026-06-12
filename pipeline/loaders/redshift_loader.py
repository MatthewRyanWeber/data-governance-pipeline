"""
Amazon Redshift loader with S3-staged COPY, MERGE upsert, and retry.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class RedshiftLoader).
1.1   2026-06-11   Upsert stages via the S3 COPY path when s3_bucket is
                   configured; all-key MERGE omits WHEN MATCHED instead of
                   referencing __noop__; SQLAlchemy engines disposed via
                   _engine_scope.
1.2   2026-06-12   Loader contract: dry-run returns 0 (was None); keyless upsert raises via _require_upsert_keys (was silent append).
"""

import os
import time
import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_REDSHIFT
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class RedshiftLoader(BaseLoader):
    """
    Amazon Redshift loader with S3-staged COPY, MERGE upsert, and retry.

    Uses redshift_connector for DDL/DML and sqlalchemy-redshift for
    pandas .to_sql() compatibility.
    """

    _DTYPE_MAP: dict[str, str] = {
        "int64":               "BIGINT",
        "Int64":               "BIGINT",
        "int32":               "INTEGER",
        "float64":             "DOUBLE PRECISION",
        "float32":             "REAL",
        "bool":                "BOOLEAN",
        "boolean":             "BOOLEAN",
        "datetime64[ns]":      "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMPTZ",
        "object":              "VARCHAR(65535)",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_REDSHIFT:
            raise RuntimeError(
                "redshift-connector not installed.  "
                "Run: pip install redshift-connector sqlalchemy-redshift"
            )

    def _connect(self, cfg: dict):
        import redshift_connector
        return redshift_connector.connect(
            host=cfg["host"],
            port=int(cfg.get("port", 5439)),
            database=cfg["database"],
            user=cfg["user"],
            password=cfg["password"],
        )

    def _engine(self, cfg: dict):
        from sqlalchemy import create_engine as _ce
        from urllib.parse import quote_plus as _qp
        schema = cfg.get("schema", "public")
        port = cfg.get("port", 5439)
        url = (
            f"redshift+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
            f"@{cfg['host']}:{port}/{cfg['database']}"
        )
        return _ce(url, connect_args={"options": f"-csearch_path={schema}"})

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str = "append",
        natural_keys: list[str] | None = None,
    ) -> int:
        table = table.lower()
        validate_sql_identifier(table, "table")
        if cfg.get("schema"):
            validate_sql_identifier(cfg["schema"], "schema")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._require_upsert_keys(if_exists, natural_keys)
        self._validate_config(cfg, ["host", "database", "user", "password"])
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        elif cfg.get("s3_bucket"):
            self._s3_copy(df, cfg, table, if_exists)
        else:
            self._sql_fallback(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "redshift",
            f"{cfg['host']}/{cfg['database']}/{cfg.get('schema', 'public')}",
            table,
        )
        return len(df)

    def _s3_copy(self, df, cfg, table, if_exists):
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is required for Redshift S3 COPY.  "
                "Run: pip install boto3"
            ) from exc

        import tempfile

        bucket = cfg["s3_bucket"]
        prefix = cfg.get("s3_prefix", "redshift_stage/")
        region = cfg.get("aws_region", "us-east-1")
        key = f"{prefix}{table}_{int(time.time())}.csv.gz"

        with tempfile.NamedTemporaryFile(suffix=".csv.gz", delete=False) as tmp:
            tmp_path = tmp.name
        df.to_csv(tmp_path, index=False, compression="gzip")

        s3 = boto3.client(
            "s3",
            region_name=region,
            aws_access_key_id=cfg.get("aws_access_key_id"),
            aws_secret_access_key=cfg.get("aws_secret_access_key"),
        )
        s3.upload_file(tmp_path, bucket, key)
        logger.info("[REDSHIFT] Uploaded s3://%s/%s", bucket, key)

        conn = self._connect(cfg)
        cur = conn.cursor()
        schema = cfg.get("schema", "public")
        fqt = f'"{schema}"."{table}"'

        try:
            self._ensure_table(cur, df, fqt, if_exists)

            col_list = ", ".join(f'"{c}"' for c in df.columns)
            iam_role = cfg.get("iam_role", os.environ.get("REDSHIFT_IAM_ROLE", ""))
            if iam_role:
                auth_clause = f"IAM_ROLE '{iam_role}'"
            else:
                access_key = cfg.get(
                    "aws_access_key_id",
                    os.environ.get("AWS_ACCESS_KEY_ID", ""),
                )
                secret_key = cfg.get(
                    "aws_secret_access_key",
                    os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
                )
                if not access_key or not secret_key:
                    raise ValueError(
                        "Redshift COPY requires iam_role or AWS credentials"
                    )
                auth_clause = (
                    f"ACCESS_KEY_ID '{access_key}' "
                    f"SECRET_ACCESS_KEY '{secret_key}'"
                )
                logger.warning(
                    "[REDSHIFT] Using inline credentials for COPY "
                    "-- prefer IAM_ROLE for production"
                )
            copy_sql = (
                f"COPY {fqt} ({col_list}) "
                f"FROM 's3://{bucket}/{key}' "
                f"{auth_clause} "
                f"REGION '{region}' "
                "CSV IGNOREHEADER 1 GZIP EMPTYASNULL BLANKSASNULL"
            )
            cur.execute(copy_sql)
            conn.commit()
            logger.info("[REDSHIFT] COPY INTO %s -- %s rows", fqt, f"{len(df):,}")

        except Exception as exc:
            logger.warning("[REDSHIFT] S3 COPY failed -- falling back to to_sql(): %s", exc)
            self._sql_fallback(df, cfg, table, if_exists)
        finally:
            cur.close()
            conn.close()
            try:
                os.unlink(tmp_path)
                s3.delete_object(Bucket=bucket, Key=key)
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)

    def _ensure_table(self, cur, df, fqt, if_exists):
        col_defs = ", ".join(
            f'"{c}" {self._DTYPE_MAP.get(str(df[c].dtype), "VARCHAR(65535)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f"DROP TABLE IF EXISTS {fqt}")
            cur.execute(f"CREATE TABLE {fqt} ({col_defs})")
        else:
            cur.execute(f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs})")

    def _upsert(self, df, cfg, table, natural_keys):
        schema = cfg.get("schema", "public")
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt = f'"{schema}"."{table}"'
        fqt_tmp = f'"{schema}"."{tmp_table}"'

        # Stage through S3 COPY when configured — to_sql row-by-row staging
        # is orders of magnitude slower for warehouse-sized frames.
        if cfg.get("s3_bucket"):
            self._s3_copy(df, cfg, tmp_table, "replace")
        else:
            with self._engine_scope(cfg) as engine:
                with engine.begin() as _conn:
                    df.to_sql(tmp_table, _conn, if_exists="replace",
                              index=False, schema=schema, chunksize=500,
                              method="multi")

        conn = self._connect(cfg)
        cur = conn.cursor()
        try:
            non_key_cols = [c for c in df.columns if c not in natural_keys]
            on_clause = " AND ".join(
                f't."{k}" = s."{k}"' for k in natural_keys
            )
            all_cols = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols = ", ".join(f's."{c}"' for c in df.columns)

            self._ensure_table(cur, df, fqt, "append")

            # When every column is a key there is nothing to update: omit
            # WHEN MATCHED instead of referencing a non-existent __noop__.
            if non_key_cols:
                update_clause = ", ".join(
                    f't."{c}" = s."{c}"' for c in non_key_cols
                )
                matched_part = f"WHEN MATCHED THEN UPDATE SET {update_clause}"
            else:
                matched_part = ""

            merge_sql = f"""
                MERGE INTO {fqt} AS t
                USING {fqt_tmp} AS s ON ({on_clause})
                {matched_part}
                WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})
            """
            cur.execute(merge_sql)
            cur.execute(f"DROP TABLE IF EXISTS {fqt_tmp}")
            conn.commit()
            logger.info("[REDSHIFT] MERGE INTO %s -- %s rows", fqt, f"{len(df):,}")
            self.gov.transformation_applied(
                "REDSHIFT_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys,
                 "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()

    def _sql_fallback(self, df, cfg, table, if_exists):
        schema = cfg.get("schema", "public")
        with self._engine_scope(cfg) as engine:
            for attempt in range(1, 4):
                try:
                    with engine.begin() as _conn:
                        df.to_sql(table, _conn, if_exists=if_exists,
                                  index=False, schema=schema, chunksize=500,
                                  method="multi")
                    return
                except Exception as exc:
                    if attempt == 3:
                        raise
                    wait = 2 ** attempt
                    self.gov.retry_attempt(attempt, 3, float(wait), exc)
                    time.sleep(wait)
