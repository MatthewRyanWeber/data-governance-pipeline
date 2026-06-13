"""
Google BigQuery loader with native bulk load, MERGE upsert, and automatic
EU data-residency detection for GDPR compliance.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class BigQueryLoader).
1.1   2026-06-11   Config validated before cfg['dataset'] is read so missing
                   keys raise ConfigValidationError, not KeyError; upsert now
                   calls _ensure_table so the first upsert into a new table
                   works; all-key MERGE omits WHEN MATCHED instead of
                   referencing a non-existent __noop__ column.
1.2   2026-06-12   Dry-run path returns 0 instead of None (loader contract).
"""

import time
import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_BIGQUERY
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class BigQueryLoader(BaseLoader):
    """
    Google BigQuery loader with native bulk load, MERGE upsert, and
    automatic EU data-residency detection for GDPR compliance.

    # GDPR: Art. 44-49 -- cross-border transfer safeguards
    """

    _DTYPE_MAP: dict[str, str] = {
        "int64":               "INT64",
        "Int64":               "INT64",
        "int32":               "INT64",
        "float64":             "FLOAT64",
        "float32":             "FLOAT64",
        "bool":                "BOOL",
        "boolean":             "BOOL",
        "datetime64[ns]":      "DATETIME",
        "datetime64[ns, UTC]": "TIMESTAMP",
        "object":              "STRING",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_BIGQUERY:
            raise RuntimeError(
                "google-cloud-bigquery not installed.  "
                "Run: pip install google-cloud-bigquery "
                "google-cloud-bigquery-storage db-dtypes"
            )

    def _client(self, cfg: dict):
        from google.cloud import bigquery as _bigquery
        from google.oauth2 import service_account as _gcp_sa
        project = cfg["project"]
        location = cfg.get("location", "US")
        # Emulator/test endpoint (e.g. goccy/bigquery-emulator): anonymous
        # credentials, custom API endpoint.  Refuse to attach anonymous
        # credentials to a real Google endpoint — that path is only for a
        # local/emulator host, never production.
        if cfg.get("api_endpoint"):
            from urllib.parse import urlparse
            from google.api_core.client_options import ClientOptions
            from google.auth.credentials import AnonymousCredentials
            endpoint_host = urlparse(cfg["api_endpoint"]).hostname or ""
            if endpoint_host.endswith("googleapis.com"):
                raise ValueError(
                    "BigQueryLoader: api_endpoint must not point at the real "
                    "googleapis.com endpoint — it forces anonymous "
                    "credentials and is intended for emulators only. Omit "
                    "api_endpoint to use real authentication."
                )
            return _bigquery.Client(
                project=project,
                client_options=ClientOptions(api_endpoint=cfg["api_endpoint"]),
                credentials=AnonymousCredentials(),
            )
        creds_path = cfg.get("credentials_path")
        if creds_path:
            creds = _gcp_sa.Credentials.from_service_account_file(
                creds_path,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            return _bigquery.Client(
                project=project, credentials=creds, location=location
            )
        return _bigquery.Client(project=project, location=location)

    def _ensure_table(self, client, dataset_ref, table_id, df, if_exists):
        from google.cloud import bigquery as _bq_local
        table_ref = dataset_ref.table(table_id)
        schema = [
            _bq_local.SchemaField(
                c,
                self._DTYPE_MAP.get(str(df[c].dtype), "STRING"),
                mode="NULLABLE",
            )
            for c in df.columns
        ]
        if if_exists == "replace":
            try:
                client.delete_table(table_ref, not_found_ok=True)
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)
        table = _bq_local.Table(table_ref, schema=schema)
        client.create_table(table, exists_ok=True)

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str = "append",
        natural_keys: list[str] | None = None,
    ) -> int:
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return 0
        # Validate before reading cfg['dataset'] so a missing key surfaces
        # as ConfigValidationError instead of an opaque KeyError.
        self._validate_config(cfg, ["project", "dataset"])
        validate_sql_identifier(cfg["dataset"], "dataset")
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._bulk_load(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        location = cfg.get("location", "US")
        self.gov.destination_registered(
            "bigquery",
            f"{cfg['project']}/{cfg['dataset']}@{location}",
            table,
        )
        self._log_gdpr_transfer(location)
        return len(df)

    def _bulk_load(self, df, cfg, table, if_exists):
        from google.cloud import bigquery as _bigquery
        client = self._client(cfg)
        dataset = cfg["dataset"]
        table_id = f"{cfg['project']}.{dataset}.{table}"

        if cfg.get("load_method") == "streaming":
            self._streaming_insert(client, df, cfg, table_id, if_exists)
            return

        write_disposition = (
            _bigquery.WriteDisposition.WRITE_TRUNCATE
            if if_exists == "replace"
            else _bigquery.WriteDisposition.WRITE_APPEND
        )
        job_cfg = _bigquery.LoadJobConfig(write_disposition=write_disposition)
        for attempt in range(1, 4):
            try:
                job = client.load_table_from_dataframe(
                    df, table_id, job_config=job_cfg
                )
                job.result()
                logger.info(
                    "[BIGQUERY] Loaded %s rows -> %s (errors: %s)",
                    f"{len(df):,}", table_id, job.errors or "none",
                )
                return
            except Exception as exc:
                if attempt == 3:
                    raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                time.sleep(wait)

    def _streaming_insert(self, client, df, cfg, table_id, if_exists):
        """insert_rows_json path — no LOAD job, rows visible immediately.

        Streaming inserts trade the LOAD job's atomicity for latency;
        they're also the only write path BigQuery emulators support.
        """
        from google.cloud import bigquery as _bq_local

        dataset_ref = client.dataset(cfg["dataset"])
        table_name = table_id.rsplit(".", 1)[-1]
        if if_exists == "replace":
            client.delete_table(table_id, not_found_ok=True)
        schema = [
            _bq_local.SchemaField(
                str(col),
                "INTEGER" if df[col].dtype.kind == "i"
                else "FLOAT" if df[col].dtype.kind == "f"
                else "BOOLEAN" if df[col].dtype.kind == "b"
                else "STRING",
            )
            for col in df.columns
        ]
        table_ref = dataset_ref.table(table_name)
        try:
            client.get_table(table_ref)
        except Exception:
            client.create_table(_bq_local.Table(table_ref, schema=schema))

        records = df.where(df.notna(), None).to_dict(orient="records")
        errors = client.insert_rows_json(table_id, records)
        if errors:
            raise RuntimeError(
                f"BigQueryLoader: streaming insert reported errors: "
                f"{errors[:3]}"
            )
        logger.info("[BIGQUERY] Streamed %s rows -> %s",
                    f"{len(df):,}", table_id)

    def _upsert(self, df, cfg, table, natural_keys):
        from google.cloud import bigquery as _bigquery
        client = self._client(cfg)
        project = cfg["project"]
        dataset = cfg["dataset"]
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt = f"`{project}.{dataset}.{table}`"
        fqt_tmp = f"`{project}.{dataset}.{tmp_table}`"
        tmp_id = f"{project}.{dataset}.{tmp_table}"

        # First upsert into a fresh dataset must create the target,
        # otherwise the MERGE fails with "table not found".
        dataset_ref = _bigquery.DatasetReference(project, dataset)
        self._ensure_table(client, dataset_ref, table, df, "append")

        tmp_cfg = _bigquery.LoadJobConfig(
            write_disposition=_bigquery.WriteDisposition.WRITE_TRUNCATE
        )
        job = client.load_table_from_dataframe(df, tmp_id, job_config=tmp_cfg)
        job.result()

        non_key_cols = [c for c in df.columns if c not in natural_keys]
        on_clause = " AND ".join(
            f"t.`{k}` = s.`{k}`" for k in natural_keys
        )
        all_cols = ", ".join(f"`{c}`" for c in df.columns)
        stage_cols = ", ".join(f"s.`{c}`" for c in df.columns)

        # When every column is a key there is nothing to update: omit the
        # WHEN MATCHED clause instead of referencing a non-existent column.
        if non_key_cols:
            update_clause = ", ".join(
                f"t.`{c}` = s.`{c}`" for c in non_key_cols
            )
            matched_part = f"WHEN MATCHED THEN\n                UPDATE SET {update_clause}"
        else:
            matched_part = ""

        merge_sql = f"""
            MERGE {fqt} AS t
            USING {fqt_tmp} AS s ON ({on_clause})
            {matched_part}
            WHEN NOT MATCHED THEN
                INSERT ({all_cols}) VALUES ({stage_cols})
        """

        try:
            job = client.query(merge_sql)
            job.result()
            logger.info("[BIGQUERY] MERGE INTO %s -- %s rows", fqt, f"{len(df):,}")
            self.gov.transformation_applied(
                "BIGQUERY_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys,
                 "rows": len(df)},
            )
        finally:
            try:
                client.delete_table(tmp_id, not_found_ok=True)
            except Exception as exc:
                logger.debug("Cleanup failed: %s", exc)

    def _log_gdpr_transfer(self, location: str) -> None:
        loc_upper = location.upper()
        if "EU" in loc_upper or "EUROPE" in loc_upper:
            self.gov.transfer_logged(
                source_country="EU",
                dest_country="EU",
                transfer_type="INTRA_EU",
                safeguard="EU/EEA intra-zone -- no restrictions",
            )
        else:
            region_map = {
                "US": "US", "US-CENTRAL1": "US", "US-EAST1": "US",
                "US-WEST1": "US", "ASIA": "SG", "ASIA-EAST1": "TW",
                "ASIA-SOUTHEAST1": "SG", "AUSTRALIA-SOUTHEAST1": "AU",
            }
            dest_cc = region_map.get(loc_upper, "US")
            self.gov.transfer_logged(
                source_country="US",
                dest_country=dest_cc,
                transfer_type="BIGQUERY_REGION",
                safeguard="SCC",
            )
