"""
AWS Athena loader -- writes governed DataFrames to Athena via S3 Parquet
staging and MSCK REPAIR TABLE metadata refresh.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class AthenaLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import time
import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_S3
from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class AthenaLoader(BaseLoader):
    """AWS Athena loader with S3 Parquet staging."""

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_S3:
            raise RuntimeError(
                "AthenaLoader requires boto3.\n"
                "Install with:  pip install boto3 pyarrow s3fs"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to an Athena table via S3 Parquet staging."""
        import boto3
        import io
        import pyarrow as pa
        import pyarrow.parquet as pq

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"AthenaLoader: if_exists must be 'append' or 'replace', "
                f"got '{if_exists}'."
            )
        if not table:
            raise ValueError("AthenaLoader: table name is required.")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._validate_config(cfg, ["database", "s3_data_dir", "s3_staging_dir"])

        database = cfg.get("database")
        s3_data_dir = cfg.get("s3_data_dir", "")
        s3_staging = cfg.get("s3_staging_dir", "")
        region = cfg.get("region", "us-east-1")
        workgroup = cfg.get("workgroup", "primary")
        compression = cfg.get("compression", "snappy")

        if not database:
            raise ValueError("AthenaLoader: cfg must contain 'database'.")
        if not s3_data_dir:
            raise ValueError("AthenaLoader: cfg must contain 's3_data_dir'.")
        if not s3_staging:
            raise ValueError(
                "AthenaLoader: cfg must contain 's3_staging_dir'."
            )

        if df.empty:
            return 0

        s3_kwargs: dict = {"region_name": region}
        if cfg.get("aws_access_key"):
            s3_kwargs["aws_access_key_id"] = cfg["aws_access_key"]
            s3_kwargs["aws_secret_access_key"] = cfg["aws_secret_key"]
        s3_client = boto3.client("s3", **s3_kwargs)

        buf = io.BytesIO()
        pq.write_table(pa.Table.from_pandas(df, preserve_index=False),
                       buf, compression=compression)
        buf.seek(0)

        import uuid as _uuid
        object_key = s3_data_dir.split("s3://", 1)[-1]
        bucket_name = object_key.split("/")[0]
        prefix = "/".join(object_key.split("/")[1:]).rstrip("/")
        file_key = f"{prefix}/{_uuid.uuid4()}.parquet"

        s3_client.put_object(Bucket=bucket_name, Key=file_key,
                             Body=buf.getvalue())

        athena = boto3.client("athena", **s3_kwargs)
        query = f"MSCK REPAIR TABLE `{database}`.`{table}`"
        resp = athena.start_query_execution(
            QueryString=query,
            QueryExecutionContext={"Database": database},
            ResultConfiguration={"OutputLocation": s3_staging},
            WorkGroup=workgroup,
        )
        exec_id = resp["QueryExecutionId"]

        for _ in range(60):
            status = athena.get_query_execution(
                QueryExecutionId=exec_id
            )["QueryExecution"]["Status"]["State"]
            if status in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(2)

        self.gov._event(
            "LOAD", "ATHENA_WRITE_COMPLETE",
            {
                "database": database,
                "table": table,
                "rows": len(df),
                "region": region,
                "if_exists": if_exists,
            },
        )
        return len(df)
