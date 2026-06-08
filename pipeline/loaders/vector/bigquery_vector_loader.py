"""
BigQuery vector loader -- writes DataFrames to BigQuery with ARRAY<FLOAT64>
vector columns and provides VECTOR_SEARCH() nearest-neighbour queries.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class BigQueryVectorLoader).
"""

import re
import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_BIGQUERY
from pipeline.loaders.base import BaseLoader, validate_sql_identifier, validate_float_vector

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class BigQueryVectorLoader(BaseLoader):
    """
    BigQuery vector loader with ARRAY<FLOAT64> and VECTOR_SEARCH().

    Stores vectors as ARRAY<FLOAT64> columns and leverages BigQuery's
    built-in VECTOR_SEARCH() TVF for approximate nearest-neighbour
    retrieval with COSINE or EUCLIDEAN distance.

    Quick-start
    ───────────
        from pipeline.loaders.vector import BigQueryVectorLoader
        loader = BigQueryVectorLoader(gov)
        loader.load(df, cfg, "vectors_table")
    """

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_BIGQUERY:
            raise RuntimeError(
                "BigQueryVectorLoader requires google-cloud-bigquery.\n"
                "Install with:  pip install google-cloud-bigquery pyarrow"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to BigQuery with an ARRAY<FLOAT64> vector column."""
        from google.cloud import bigquery
        import numpy as _np

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"BigQueryVectorLoader: if_exists must be 'append' or "
                f"'replace', got '{if_exists}'."
            )
        if not table:
            raise ValueError(
                "BigQueryVectorLoader: table name is required."
            )
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._validate_config(cfg, ["project", "dataset"])

        if df.empty:
            return 0

        vector_col = cfg.get("vector_column", "embedding")
        embed_cols = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")

        if embed_cols and vector_col not in df.columns:
            df = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if vector_col not in df.columns:
            raise ValueError(
                f"BigQueryVectorLoader: vector column '{vector_col}' not "
                "in DataFrame."
            )

        out = df.copy()
        out[vector_col] = out[vector_col].apply(
            lambda v: v.tolist() if isinstance(v, _np.ndarray) else list(v)
        )

        client_kwargs = {}
        if cfg.get("credentials_path"):
            from google.oauth2 import service_account
            client_kwargs["credentials"] = (
                service_account.Credentials
                .from_service_account_file(cfg["credentials_path"])
            )

        client = bigquery.Client(project=cfg["project"], **client_kwargs)
        table_id = f"{cfg['project']}.{cfg['dataset']}.{table}"

        write_disp = (bigquery.WriteDisposition.WRITE_TRUNCATE
                      if if_exists == "replace"
                      else bigquery.WriteDisposition.WRITE_APPEND)

        job_config = bigquery.LoadJobConfig(write_disposition=write_disp)
        job = client.load_table_from_dataframe(out, table_id,
                                               job_config=job_config)
        timeout = int(cfg.get("job_timeout_seconds", 600))
        job.result(timeout=timeout)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered("bigquery_vector", cfg["project"], table)
        return len(df)

    def search(self, cfg, table, query_vector, vector_col="embedding",
               limit=10, distance="COSINE",
               options="fraction_lists_to_search=0.1"):
        """Search using BigQuery's VECTOR_SEARCH() TVF."""
        from google.cloud import bigquery

        if not query_vector:
            raise ValueError(
                "BigQueryVectorLoader.search(): query_vector must be "
                "a non-empty list of floats."
            )
        if not cfg.get("project"):
            raise ValueError(
                "BigQueryVectorLoader: cfg must contain 'project'."
            )
        if not cfg.get("dataset"):
            raise ValueError(
                "BigQueryVectorLoader: cfg must contain 'dataset'."
            )
        validate_sql_identifier(table, "table")

        if options and not re.fullmatch(r"[\w=.,\s]+", options):
            raise ValueError(
                f"BigQueryVectorLoader.search(): options string contains "
                f"disallowed characters: {options!r}. "
                "Only alphanumerics, =, ., and commas are allowed."
            )
        if distance not in ("COSINE", "EUCLIDEAN"):
            raise ValueError(
                f"BigQueryVectorLoader.search(): distance must be "
                f"'COSINE' or 'EUCLIDEAN', got '{distance}'."
            )
        query_vector = validate_float_vector(query_vector, "query_vector")

        client_kwargs = {}
        if cfg.get("credentials_path"):
            from google.oauth2 import service_account
            client_kwargs["credentials"] = (
                service_account.Credentials
                .from_service_account_file(cfg["credentials_path"])
            )

        client = bigquery.Client(project=cfg["project"], **client_kwargs)
        table_id = f"{cfg['project']}.{cfg['dataset']}.{table}"
        vec_literal = "[" + ",".join(str(v) for v in query_vector) + "]"

        sql = f"""
            SELECT base.*, distance AS _distance
            FROM VECTOR_SEARCH(
                TABLE `{table_id}`,
                '{vector_col}',
                (SELECT {vec_literal} AS query_vec),
                distance_type => '{distance}',
                top_k => {limit},
                options => '{options}'
            )
            ORDER BY _distance ASC
        """

        result = client.query(sql).to_dataframe()

        logger.info(
            "BigQuery VECTOR_SEARCH on %s returned %d results.",
            table_id, len(result),
        )
        return result

    @staticmethod
    def _embed(df, embed_cols, model_name):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "BigQueryVectorLoader: embed_columns requires "
                "sentence-transformers.\nInstall with: "
                "pip install sentence-transformers"
            ) from exc
        model = SentenceTransformer(model_name)
        texts = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
