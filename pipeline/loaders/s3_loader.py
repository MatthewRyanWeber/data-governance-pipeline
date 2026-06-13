"""
S3/GCS/Azure Blob loader -- writes governed DataFrames to object storage
as CSV, JSON, JSONL, or Parquet files.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class S3Loader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class S3Loader(BaseLoader):
    """Write DataFrames to S3, GCS, or Azure Blob as flat files."""

    _FORMATS = ("parquet", "csv", "json", "jsonl")

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)

    def load(self, df, cfg, table="", if_exists="replace",
             natural_keys=None) -> int:
        """Write df to object storage."""
        provider = cfg.get("provider", "s3").lower()
        bucket = cfg.get("bucket")
        key = cfg.get("key") or (f"{table}.parquet" if table else "")
        fmt = cfg.get("format", "parquet").lower()

        if not bucket:
            raise ValueError("S3Loader: cfg must contain 'bucket'.")
        if not key:
            raise ValueError(
                "S3Loader: supply object key via cfg['key'] or the "
                "table parameter."
            )
        if fmt not in self._FORMATS:
            raise ValueError(
                f"S3Loader: format must be one of {self._FORMATS}, "
                f"got '{fmt}'."
            )
        if self._dry_run_guard(f"{bucket}/{key}", len(df)):
            return 0
        self._validate_config(cfg, ["bucket"])

        if df.empty:
            return 0

        body = self._serialise(df, fmt, cfg)
        self._upload(body, provider, bucket, key, cfg)

        self.gov._event(
            "LOAD", "S3_WRITE_COMPLETE",
            {
                "provider": provider,
                "bucket": bucket,
                "key": key,
                "rows": len(df),
                "format": fmt,
            },
        )
        return len(df)

    @staticmethod
    def _serialise(df, fmt, cfg) -> bytes:
        import io
        if fmt == "parquet":
            import pyarrow as pa
            import pyarrow.parquet as pq
            buf = io.BytesIO()
            pq.write_table(pa.Table.from_pandas(df, preserve_index=False),
                           buf, compression=cfg.get("compression", "snappy"))
            return buf.getvalue()
        if fmt == "csv":
            return bytes(df.to_csv(index=False).encode("utf-8"))
        if fmt == "json":
            return bytes(df.to_json(orient="records", indent=2).encode("utf-8"))
        if fmt == "jsonl":
            return bytes(df.to_json(orient="records", lines=True).encode("utf-8"))
        raise ValueError(f"S3Loader: unknown format '{fmt}'")

    @staticmethod
    def _upload(body, provider, bucket, key, cfg):
        if provider == "s3":
            import boto3 as _b3
            kwargs: dict = {}
            if cfg.get("region"):
                kwargs["region_name"] = cfg["region"]
            if cfg.get("aws_access_key"):
                kwargs["aws_access_key_id"] = cfg["aws_access_key"]
                kwargs["aws_secret_access_key"] = cfg["aws_secret_key"]
            # S3-compatible stores (MinIO, Cloudflare R2, Ceph) and local
            # test servers are reached via a custom endpoint.  Reject a
            # plaintext endpoint for a non-local host: signing real AWS
            # credentials toward an arbitrary http:// host would leak the
            # signed request (and the data) over the wire.
            endpoint_url = cfg.get("endpoint_url")
            if endpoint_url:
                from urllib.parse import urlparse
                parsed = urlparse(endpoint_url)
                hostname = parsed.hostname or ""
                is_local = hostname in ("localhost", "127.0.0.1", "::1")
                if parsed.scheme != "https" and not is_local:
                    raise ValueError(
                        "S3Loader: endpoint_url must use https for non-local "
                        f"hosts (got {endpoint_url!r}). Use https:// or a "
                        "localhost endpoint for testing."
                    )
                kwargs["endpoint_url"] = endpoint_url
            client = _b3.client("s3", **kwargs)
            client.put_object(Bucket=bucket, Key=key, Body=body)

        elif provider == "gcs":
            try:
                import gcsfs
            except ImportError as exc:
                raise RuntimeError(
                    "S3Loader GCS: install gcsfs -- pip install gcsfs"
                ) from exc
            opts = cfg.get("storage_options", {})
            if cfg.get("gcs_credentials"):
                opts["token"] = cfg["gcs_credentials"]
            fs = gcsfs.GCSFileSystem(**opts)
            with fs.open(f"{bucket}/{key}", "wb") as f:
                f.write(body)

        elif provider == "azure":
            try:
                import adlfs
            except ImportError as exc:
                raise RuntimeError(
                    "S3Loader Azure: install adlfs -- pip install adlfs"
                ) from exc
            opts = cfg.get("storage_options", {})
            if cfg.get("azure_account"):
                opts["account_name"] = cfg["azure_account"]
                opts["account_key"] = cfg.get("azure_key", "")
            fs = adlfs.AzureBlobFileSystem(**opts)
            with fs.open(f"{bucket}/{key}", "wb") as f:
                f.write(body)
        else:
            raise ValueError(
                f"S3Loader: provider must be 's3', 'gcs', or 'azure', "
                f"got '{provider}'."
            )
