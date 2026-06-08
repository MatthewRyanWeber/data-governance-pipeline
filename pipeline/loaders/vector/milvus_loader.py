"""
Milvus loader -- writes governed DataFrames to a Milvus vector database
collection with support for Milvus Lite, Standalone, and Zilliz Cloud.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class MilvusLoader).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_MILVUS
from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class MilvusLoader(BaseLoader):
    """
    Milvus vector database loader with insert, upsert, and overwrite.

    Connects via pymilvus MilvusClient to local files, standalone instances,
    or Zilliz Cloud. Creates collections with auto-schema and configurable
    metric type (COSINE, L2, IP). Batches inserts at 100 records by default.

    Quick-start
    ───────────
        from pipeline.loaders.vector import MilvusLoader
        loader = MilvusLoader(gov)
        loader.load(df, {"uri": "./milvus.db", "vector_column": "embedding"},
                    "my_collection")
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_MILVUS:
            raise RuntimeError(
                "MilvusLoader requires the pymilvus package.\n"
                "Install with:  pip install pymilvus\n"
                "For local file mode: pip install pymilvus[milvus_lite]"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a Milvus collection."""
        from pymilvus import MilvusClient

        if if_exists not in ("append", "upsert", "overwrite"):
            raise ValueError(
                f"MilvusLoader: if_exists must be 'append', 'upsert', or "
                f"'overwrite', got '{if_exists}'."
            )

        collection = table or cfg.get("collection")
        if not collection:
            raise ValueError(
                "MilvusLoader: supply collection name via cfg['collection'] "
                "or the table parameter."
            )
        if self._dry_run_guard(collection, len(df)):
            return 0
        self._validate_config(cfg, ["uri"])

        uri = cfg.get("uri")

        vector_col = cfg.get("vector_column")
        embed_cols = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")
        id_col = cfg.get("id_column", "id")
        batch_size = int(cfg.get("batch_size", self._BATCH))
        metric_type = cfg.get("metric_type", "COSINE")

        if embed_cols and not vector_col:
            df = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if not vector_col or vector_col not in df.columns:
            raise ValueError(
                f"MilvusLoader: vector column '{vector_col}' not in "
                "DataFrame. Set cfg['vector_column'] or cfg['embed_columns']."
            )

        import numpy as _np
        first_vec = df[vector_col].iloc[0]
        if isinstance(first_vec, _np.ndarray):
            first_vec = first_vec.tolist()
        vector_size = cfg.get("vector_size", len(first_vec))

        client_kwargs: dict = {"uri": uri}
        if cfg.get("token"):
            client_kwargs["token"] = cfg["token"]

        client = MilvusClient(**client_kwargs)

        try:
            if if_exists == "overwrite":
                if client.has_collection(collection):
                    client.drop_collection(collection)

            if not client.has_collection(collection):
                client.create_collection(
                    collection_name=collection,
                    dimension=vector_size,
                    metric_type=metric_type,
                    auto_id=(id_col not in df.columns),
                )

            all_records = df.to_dict(orient="records")
            total = 0
            for i in range(0, len(all_records), batch_size):
                records = []
                for rec in all_records[i: i + batch_size]:
                    vec = rec[vector_col]
                    if isinstance(vec, _np.ndarray):
                        vec = vec.tolist()
                    rec[vector_col] = vec
                    records.append(rec)

                if if_exists == "upsert":
                    res = client.upsert(
                        collection_name=collection, data=records
                    )
                else:
                    res = client.insert(
                        collection_name=collection, data=records
                    )

                total += (res.get("insert_count", 0)
                          or res.get("upsert_count", 0)
                          or len(records))

        finally:
            client.close()

        self.gov.load_complete(total, collection)
        self.gov.destination_registered("milvus", uri, collection)
        return total

    def search(self, cfg, query_vector, table="", limit=10,
               output_fields=None, filter_expr="") -> list:
        """Run a nearest-neighbour search against a Milvus collection."""
        from pymilvus import MilvusClient

        if not query_vector:
            raise ValueError(
                "MilvusLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )

        uri = cfg.get("uri")
        collection = table or cfg.get("collection")
        if not uri:
            raise ValueError("MilvusLoader: cfg must contain 'uri'.")
        if not collection:
            raise ValueError("MilvusLoader: supply collection name.")

        client_kwargs: dict = {"uri": uri}
        if cfg.get("token"):
            client_kwargs["token"] = cfg["token"]

        client = MilvusClient(**client_kwargs)
        try:
            kwargs: dict = {
                "collection_name": collection,
                "data": [query_vector],
                "limit": limit,
            }
            if output_fields:
                kwargs["output_fields"] = output_fields
            if filter_expr:
                kwargs["filter"] = filter_expr

            results = client.search(**kwargs)
        finally:
            client.close()

        logger.info(
            "Milvus search on %s returned %d results.",
            collection, len(results[0]) if results else 0,
        )
        return results[0] if results else []

    @staticmethod
    def _embed(df, embed_cols, model_name):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "MilvusLoader: embed_columns requires "
                "sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model = SentenceTransformer(model_name)
        texts = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
