"""
Chroma loader -- writes governed DataFrames to a ChromaDB embedded vector
database with support for add, upsert, and overwrite modes.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class ChromaLoader).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_CHROMA

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class ChromaLoader:
    """
    ChromaDB vector database loader with batch add/upsert.

    Supports HTTP client (host/port), persistent local client (path),
    or ephemeral in-memory client. Documents and metadata are extracted
    from non-vector DataFrame columns automatically.

    Quick-start
    ───────────
        from pipeline.loaders.vector import ChromaLoader
        loader = ChromaLoader(gov)
        loader.load(df, {"path": "./chroma_db", "id_column": "doc_id"},
                    "my_collection")
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_CHROMA:
            raise RuntimeError(
                "ChromaLoader requires the chromadb package.\n"
                "Install with:  pip install chromadb"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a Chroma collection."""
        if if_exists not in ("append", "upsert", "overwrite"):
            raise ValueError(
                f"ChromaLoader: if_exists must be 'append', 'upsert', or "
                f"'overwrite', got '{if_exists}'."
            )

        collection = table or cfg.get("collection")
        if not collection:
            raise ValueError(
                "ChromaLoader: supply collection name via cfg['collection'] "
                "or the table parameter."
            )

        vector_col = cfg.get("vector_column")
        embed_cols = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")
        id_col = cfg.get("id_column", "id")
        doc_col = cfg.get("document_column")
        batch_size = int(cfg.get("batch_size", self._BATCH))

        if embed_cols and not vector_col:
            df = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if id_col not in df.columns:
            raise ValueError(
                f"ChromaLoader: id_column '{id_col}' not in DataFrame. "
                "Set cfg['id_column'] to a column of unique string IDs."
            )

        client = self._build_client(cfg)
        col = self._get_or_create_collection(client, collection, if_exists)

        total = 0
        for i in range(0, len(df), batch_size):
            chunk = df.iloc[i: i + batch_size]

            ids = chunk[id_col].astype(str).tolist()
            documents = (
                chunk[doc_col].astype(str).tolist()
                if doc_col and doc_col in chunk.columns
                else [str(idx) for idx in ids]
            )

            embeddings = None
            if vector_col and vector_col in chunk.columns:
                import numpy as _np
                embeddings = [
                    v.tolist() if isinstance(v, _np.ndarray) else list(v)
                    for v in chunk[vector_col]
                ]

            meta_cols = [c for c in chunk.columns
                         if c not in (id_col, doc_col, vector_col)]
            metadatas = (chunk[meta_cols].to_dict(orient="records")
                         if meta_cols else None)

            kwargs: dict = {"ids": ids, "documents": documents}
            if embeddings:
                kwargs["embeddings"] = embeddings
            if metadatas:
                kwargs["metadatas"] = metadatas

            if if_exists == "upsert":
                col.upsert(**kwargs)
            else:
                col.add(**kwargs)

            total += len(ids)

        self.gov.load_complete(total, collection)
        self.gov.destination_registered("chroma", collection, collection)
        return total

    def query(self, cfg, query_embeddings, table="", n_results=10,
              where=None) -> dict:
        """Query a Chroma collection by embedding similarity."""
        if not query_embeddings or not query_embeddings[0]:
            raise ValueError(
                "ChromaLoader.query(): query_embeddings must be a non-empty "
                "list of embedding vectors."
            )

        collection = table or cfg.get("collection")
        if not collection:
            raise ValueError("ChromaLoader: supply collection name.")

        client = self._build_client(cfg)
        col = client.get_collection(collection)
        kwargs = {"query_embeddings": query_embeddings,
                  "n_results": n_results}
        if where:
            kwargs["where"] = where

        results = col.query(**kwargs)
        logger.info(
            "Chroma query on %s returned results for %d queries.",
            collection, len(query_embeddings),
        )
        return results

    @staticmethod
    def _build_client(cfg):
        import chromadb
        if cfg.get("host"):
            return chromadb.HttpClient(
                host=cfg["host"],
                port=int(cfg.get("port", 8000)),
            )
        if cfg.get("path"):
            return chromadb.PersistentClient(path=cfg["path"])
        return chromadb.Client()

    @staticmethod
    def _get_or_create_collection(client, name, if_exists):
        if if_exists == "overwrite":
            try:
                client.delete_collection(name)
            except Exception:
                pass
            return client.create_collection(name)
        try:
            return client.get_collection(name)
        except Exception:
            return client.create_collection(name)

    @staticmethod
    def _embed(df, embed_cols, model_name):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "ChromaLoader: embed_columns requires "
                "sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model = SentenceTransformer(model_name)
        texts = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
