"""
Pinecone loader -- writes governed DataFrames to a Pinecone managed vector
database with batched upserts and metadata from non-vector columns.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class PineconeLoader).
1.1   2026-06-07   Full rewrite: overwrite mode, search, describe_index,
                   validate_float_vector, gov.load_complete integration.
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_PINECONE
from pipeline.loaders.base import BaseLoader, validate_float_vector

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class PineconeLoader(BaseLoader):
    """
    Pinecone managed vector database loader with batched upserts.

    Connects via pinecone-client, upserts vectors with metadata extracted
    from non-vector DataFrame columns. Supports namespaces for logical
    partitioning. Batches at 100 vectors per request to stay within
    Pinecone's payload limits.

    Quick-start
    ───────────
        from pipeline.loaders.vector import PineconeLoader
        loader = PineconeLoader(gov)
        loader.load(df, cfg, "my_index")
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_PINECONE:
            raise RuntimeError(
                "PineconeLoader requires the pinecone-client package.\n"
                "Install with:  pip install pinecone-client"
            )

    def load(self, df, cfg, table="", if_exists="upsert",
             natural_keys=None) -> int:
        """Write df to a Pinecone index.

        Parameters
        ----------
        df : DataFrame with a vector column and optional metadata columns.
        cfg : dict with keys: api_key, index_name, vector_column,
              namespace, id_column, batch_size.
        table : Alias for index_name (overrides cfg['index_name']).
        if_exists : 'upsert' (default) or 'overwrite'. Overwrite deletes
                    all vectors in the namespace before upserting.
        """
        if if_exists not in ("upsert", "overwrite"):
            raise ValueError(
                f"PineconeLoader: if_exists must be 'upsert' or "
                f"'overwrite', got '{if_exists}'."
            )

        index_name = table or cfg.get("index_name")
        if not index_name:
            raise ValueError(
                "PineconeLoader: supply index name via cfg['index_name'] "
                "or the table parameter."
            )
        if self._dry_run_guard(index_name, len(df)):
            return 0
        self._validate_config(cfg, ["api_key", "index_name"])

        from pinecone import Pinecone

        api_key = cfg.get("api_key")

        vector_col = cfg.get("vector_column", "embedding")
        embed_cols = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")
        id_col = cfg.get("id_column", "id")
        namespace = cfg.get("namespace", "")
        batch_size = int(cfg.get("batch_size", self._BATCH))

        if embed_cols and vector_col not in df.columns:
            df = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if vector_col not in df.columns:
            raise ValueError(
                f"PineconeLoader: vector column '{vector_col}' not in "
                "DataFrame. Set cfg['vector_column'] or cfg['embed_columns']."
            )
        if id_col not in df.columns:
            raise ValueError(
                f"PineconeLoader: id_column '{id_col}' not in DataFrame."
            )

        if df.empty:
            return 0

        import numpy as _np

        pc = Pinecone(api_key=api_key)
        index = pc.Index(index_name)

        if if_exists == "overwrite":
            index.delete(delete_all=True, namespace=namespace)
            logger.info(
                "PineconeLoader: deleted all vectors in namespace '%s'.",
                namespace,
            )

        meta_cols = [c for c in df.columns
                     if c not in (id_col, vector_col)]

        all_records = df.to_dict(orient="records")
        total = 0
        for i in range(0, len(all_records), batch_size):
            vectors = []
            for rec in all_records[i: i + batch_size]:
                vec = rec[vector_col]
                if isinstance(vec, _np.ndarray):
                    vec = vec.tolist()
                elif not isinstance(vec, list):
                    vec = list(vec)

                metadata = {col: rec[col] for col in meta_cols
                            if pd.notna(rec[col])}

                vectors.append({
                    "id": str(rec[id_col]),
                    "values": vec,
                    "metadata": metadata,
                })

            index.upsert(vectors=vectors, namespace=namespace)
            total += len(vectors)

        self.gov.load_complete(total, index_name)
        self.gov.destination_registered(
            "pinecone", index_name, namespace or index_name,
        )
        logger.info(
            "PineconeLoader: upserted %d vectors to %s (namespace=%s).",
            total, index_name, namespace,
        )
        return total

    def search(self, cfg, query_vector, table="", limit=10,
               namespace="", filter_dict=None,
               include_metadata=True) -> dict:
        """Query a Pinecone index by vector similarity."""
        from pinecone import Pinecone

        if not query_vector:
            raise ValueError(
                "PineconeLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )
        query_vector = validate_float_vector(query_vector, "query_vector")

        api_key = cfg.get("api_key")
        if not api_key:
            raise ValueError("PineconeLoader: cfg must contain 'api_key'.")

        index_name = table or cfg.get("index_name")
        if not index_name:
            raise ValueError("PineconeLoader: supply index name.")

        pc = Pinecone(api_key=api_key)
        index = pc.Index(index_name)

        kwargs: dict = {
            "vector": query_vector,
            "top_k": limit,
            "namespace": namespace or cfg.get("namespace", ""),
            "include_metadata": include_metadata,
        }
        if filter_dict:
            kwargs["filter"] = filter_dict

        results = index.query(**kwargs)

        logger.info(
            "Pinecone search on %s returned %d matches.",
            index_name, len(results.get("matches", [])),
        )
        return dict(results)

    def describe_index(self, cfg, table="") -> dict:
        """Return index statistics (dimension, count, etc.)."""
        from pinecone import Pinecone

        api_key = cfg.get("api_key")
        if not api_key:
            raise ValueError("PineconeLoader: cfg must contain 'api_key'.")

        index_name = table or cfg.get("index_name")
        if not index_name:
            raise ValueError("PineconeLoader: supply index name.")

        pc = Pinecone(api_key=api_key)
        index = pc.Index(index_name)
        return dict(index.describe_index_stats())

    @staticmethod
    def _embed(df, embed_cols, model_name):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "PineconeLoader: embed_columns requires "
                "sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model = SentenceTransformer(model_name)
        texts = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
