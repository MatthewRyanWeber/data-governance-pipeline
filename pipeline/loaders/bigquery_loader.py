"""
Google BigQuery loader with native bulk load, MERGE upsert, and automatic
EU data-residency detection for GDPR compliance.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class BigQueryLoader).
"""

import time
import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_BIGQUERY

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class BigQueryLoader:
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

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
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
    ) -> None:
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

    def _bulk_load(self, df, cfg, table, if_exists):
        from google.cloud import bigquery as _bigquery
        client = self._client(cfg)
        dataset = cfg["dataset"]
        table_id = f"{cfg['project']}.{dataset}.{table}"
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
                    "[BQ] Loaded %s rows -> %s (errors: %s)",
                    f"{len(df):,}", table_id, job.errors or "none",
                )
                return
            except Exception as exc:
                if attempt == 3:
                    raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                time.sleep(wait)

    def _upsert(self, df, cfg, table, natural_keys):
        from google.cloud import bigquery as _bigquery
        client = self._client(cfg)
        project = cfg["project"]
        dataset = cfg["dataset"]
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt = f"`{project}.{dataset}.{table}`"
        fqt_tmp = f"`{project}.{dataset}.{tmp_table}`"
        tmp_id = f"{project}.{dataset}.{tmp_table}"

        tmp_cfg = _bigquery.LoadJobConfig(
            write_disposition=_bigquery.WriteDisposition.WRITE_TRUNCATE
        )
        job = client.load_table_from_dataframe(df, tmp_id, job_config=tmp_cfg)
        job.result()

        non_key_cols = [c for c in df.columns if c not in natural_keys]
        on_clause = " AND ".join(
            f"t.`{k}` = s.`{k}`" for k in natural_keys
        )
        update_clause = ", ".join(
            f"t.`{c}` = s.`{c}`" for c in non_key_cols
        )
        all_cols = ", ".join(f"`{c}`" for c in df.columns)
        stage_cols = ", ".join(f"s.`{c}`" for c in df.columns)

        merge_sql = f"""
            MERGE {fqt} AS t
            USING {fqt_tmp} AS s ON ({on_clause})
            WHEN MATCHED THEN
                UPDATE SET {update_clause or "t.__noop__ = 0"}
            WHEN NOT MATCHED THEN
                INSERT ({all_cols}) VALUES ({stage_cols})
        """

        try:
            job = client.query(merge_sql)
            job.result()
            logger.info("[BQ] MERGE INTO %s -- %s rows", fqt, f"{len(df):,}")
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
