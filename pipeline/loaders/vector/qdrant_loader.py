"""
Qdrant loader -- writes governed DataFrames to a Qdrant vector database
with collection creation and batched point upserts.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class QdrantLoader).
1.1   2026-06-07   Full rewrite: collection_info, validate_float_vector,
                   gov.load_complete integration, improved _build_client.
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_QDRANT
from pipeline.loaders.base import BaseLoader, validate_float_vector

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class QdrantLoader(BaseLoader):
    """
    Qdrant vector database loader with collection management and batch upserts.

    Connects via qdrant-client to local, in-memory, or cloud Qdrant instances.
    Creates collections with configurable distance metrics (Cosine, Euclid,
    Dot). Upserts points in batches of 100 to balance throughput and memory.

    Quick-start
    ───────────
        from pipeline.loaders.vector import QdrantLoader
        loader = QdrantLoader(gov)
        loader.load(df, {"url": "http://localhost:6333",
                         "collection_name": "docs",
                         "vector_column": "embedding",
                         "dimensions": 384}, "docs")
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_QDRANT:
            raise RuntimeError(
                "QdrantLoader requires the qdrant-client package.\n"
                "Install with:  pip install qdrant-client"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a Qdrant collection as points.

        Parameters
        ----------
        df : DataFrame with a vector column, an optional id column, and
             payload columns.
        cfg : dict with keys: url (or path/memory), api_key (optional),
              collection_name, vector_column, dimensions, id_column,
              distance (optional, default 'cosine').
        table : Alias for collection_name.
        if_exists : 'append' (default) or 'overwrite'. Overwrite recreates
                    the collection.
        """
        if if_exists not in ("append", "overwrite"):
            raise ValueError(
                f"QdrantLoader: if_exists must be 'append' or "
                f"'overwrite', got '{if_exists}'."
            )

        collection_name = table or cfg.get("collection_name")
        if not collection_name:
            raise ValueError(
                "QdrantLoader: supply collection name via "
                "cfg['collection_name'] or the table parameter."
            )
        if self._dry_run_guard(collection_name, len(df)):
            return 0
        self._validate_config(cfg, ["url|path|memory"])

        from qdrant_client.models import (
            VectorParams, Distance, PointStruct,
        )

        vector_col = cfg.get("vector_column", "embedding")
        embed_cols = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")
        id_col = cfg.get("id_column")
        batch_size = int(cfg.get("batch_size", self._BATCH))

        if embed_cols and vector_col not in df.columns:
            df = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if vector_col not in df.columns:
            raise ValueError(
                f"QdrantLoader: vector column '{vector_col}' not in "
                "DataFrame. Set cfg['vector_column'] or cfg['embed_columns']."
            )

        if df.empty:
            return 0

        import numpy as _np
        first_vec = df[vector_col].iloc[0]
        if isinstance(first_vec, _np.ndarray):
            first_vec = first_vec.tolist()
        dimensions = cfg.get("dimensions", len(first_vec))

        distance_map = {
            "cosine": Distance.COSINE,
            "euclid": Distance.EUCLID,
            "dot": Distance.DOT,
        }
        distance_str = cfg.get("distance", "cosine").lower()
        distance = distance_map.get(distance_str, Distance.COSINE)

        client = self._build_client(cfg)

        try:
            if if_exists == "overwrite":
                if client.collection_exists(collection_name):
                    client.delete_collection(collection_name)
                    logger.info(
                        "QdrantLoader: deleted collection %s for overwrite.",
                        collection_name,
                    )

            if not client.collection_exists(collection_name):
                client.create_collection(
                    collection_name=collection_name,
                    vectors_config=VectorParams(
                        size=dimensions,
                        distance=distance,
                    ),
                )
                logger.info(
                    "QdrantLoader: created collection %s "
                    "(dim=%d, distance=%s).",
                    collection_name, dimensions, distance_str,
                )

            payload_cols = [c for c in df.columns
                            if c not in (id_col, vector_col)]

            all_records = df.to_dict(orient="records")
            total = 0
            for i in range(0, len(all_records), batch_size):
                batch_recs = all_records[i: i + batch_size]
                points = []

                for row_idx, rec in enumerate(batch_recs):
                    vec = rec[vector_col]
                    if isinstance(vec, _np.ndarray):
                        vec = vec.tolist()
                    elif not isinstance(vec, list):
                        vec = list(vec)

                    if id_col and id_col in df.columns:
                        raw_id = rec[id_col]
                        try:
                            point_id = int(raw_id)
                        except (ValueError, TypeError):
                            import hashlib
                            import uuid as _uuid
                            point_id = str(_uuid.UUID(
                                hashlib.sha256(
                                    str(raw_id).encode()
                                ).hexdigest()[:32]
                            ))
                    else:
                        point_id = i + row_idx

                    payload = {}
                    for col in payload_cols:
                        val = rec[col]
                        if pd.notna(val):
                            payload[col] = val

                    points.append(PointStruct(
                        id=point_id,
                        vector=vec,
                        payload=payload,
                    ))

                client.upsert(
                    collection_name=collection_name,
                    points=points,
                    wait=True,
                )
                total += len(points)

        finally:
            client.close()

        self.gov.load_complete(total, collection_name)
        self.gov.destination_registered(
            "qdrant",
            cfg.get("url", cfg.get("path", ":memory:")),
            collection_name,
        )
        logger.info(
            "QdrantLoader: upserted %d points to %s.",
            total, collection_name,
        )
        return total

    def search(self, cfg, query_vector, table="", limit=10,
               query_filter=None, with_payload=True) -> list:
        """Run a nearest-neighbour search on a Qdrant collection."""
        if not query_vector:
            raise ValueError(
                "QdrantLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )
        query_vector = validate_float_vector(query_vector, "query_vector")

        collection_name = table or cfg.get("collection_name")
        if not collection_name:
            raise ValueError("QdrantLoader: supply collection name.")

        client = self._build_client(cfg)
        try:
            kwargs: dict = {
                "collection_name": collection_name,
                "query": query_vector,
                "limit": limit,
                "with_payload": with_payload,
            }
            if query_filter:
                kwargs["query_filter"] = query_filter

            response = client.query_points(**kwargs)
            results = response.points
        finally:
            client.close()

        logger.info(
            "Qdrant search on %s returned %d results.",
            collection_name, len(results),
        )
        return results

    def collection_info(self, cfg, table="") -> dict:
        """Return collection metadata (point count, config, etc.)."""
        collection_name = table or cfg.get("collection_name")
        if not collection_name:
            raise ValueError("QdrantLoader: supply collection name.")

        client = self._build_client(cfg)
        try:
            info = client.get_collection(collection_name)
        finally:
            client.close()

        return {
            "collection": collection_name,
            "points_count": info.points_count,
            "vectors_count": info.vectors_count,
            "status": info.status.value,
        }

    @staticmethod
    def _build_client(cfg):
        """Build a QdrantClient from cfg (url, path, or memory mode)."""
        from qdrant_client import QdrantClient

        if cfg.get("memory"):
            return QdrantClient(":memory:")
        if cfg.get("path"):
            return QdrantClient(path=cfg["path"])

        url = cfg.get("url")
        if not url:
            raise ValueError(
                "QdrantLoader: cfg must contain 'url', 'path', or "
                "memory=True."
            )
        kwargs: dict = {"url": url}
        if cfg.get("api_key"):
            kwargs["api_key"] = cfg["api_key"]
        return QdrantClient(**kwargs)

    @staticmethod
    def _embed(df, embed_cols, model_name):
        """Generate sentence-transformer embeddings from text columns."""
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "QdrantLoader: embed_columns requires "
                "sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model = SentenceTransformer(model_name)
        texts = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
