"""
Weaviate loader -- writes governed DataFrames to a Weaviate vector database
with automatic schema class creation and batch object imports.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class WeaviateLoader).
1.1   2026-06-07   Full rewrite: search, delete_class, v4 client API,
                   validate_float_vector, gov.load_complete integration.
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_WEAVIATE
from pipeline.loaders.base import validate_float_vector

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class WeaviateLoader:
    """
    Weaviate vector database loader with schema management and batch imports.

    Connects via weaviate-client v4 API, creates schema classes on demand,
    and batch-imports objects with properties and optional pre-computed
    vectors. Supports both local and Weaviate Cloud instances.

    Quick-start
    ───────────
        from pipeline.loaders.vector import WeaviateLoader
        loader = WeaviateLoader(gov)
        loader.load(df, {"url": "http://localhost:8080",
                         "class_name": "Document"}, "Document")
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_WEAVIATE:
            raise RuntimeError(
                "WeaviateLoader requires the weaviate-client package.\n"
                "Install with:  pip install weaviate-client"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a Weaviate class as objects.

        Parameters
        ----------
        df : DataFrame with properties and optional vector column.
        cfg : dict with keys: url, api_key (optional), class_name,
              vector_column (optional), embed_columns (optional).
        table : Alias for class_name (overrides cfg['class_name']).
        if_exists : 'append' (default) or 'overwrite'. Overwrite deletes
                    the class and recreates it.
        """
        if if_exists not in ("append", "overwrite"):
            raise ValueError(
                f"WeaviateLoader: if_exists must be 'append' or "
                f"'overwrite', got '{if_exists}'."
            )

        url = cfg.get("url")
        if not url:
            raise ValueError("WeaviateLoader: cfg must contain 'url'.")

        class_name = table or cfg.get("class_name")
        if not class_name:
            raise ValueError(
                "WeaviateLoader: supply class name via cfg['class_name'] "
                "or the table parameter."
            )
        if class_name[0].islower():
            raise ValueError(
                f"WeaviateLoader: class name '{class_name}' must start with "
                "an uppercase letter (Weaviate convention)."
            )

        vector_col = cfg.get("vector_column")
        embed_cols = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")
        batch_size = int(cfg.get("batch_size", self._BATCH))

        if embed_cols and not vector_col:
            df = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if df.empty:
            return 0

        client = self._build_client(cfg)

        try:
            if if_exists == "overwrite":
                self._delete_class_if_exists(client, class_name)

            self._ensure_class(client, class_name)

            import numpy as _np
            total = 0

            property_cols = [c for c in df.columns if c != vector_col]

            with client.batch.fixed_size(batch_size=batch_size) as batch:
                for _, row in df.iterrows():
                    properties = {}
                    for col in property_cols:
                        val = row[col]
                        if pd.notna(val):
                            properties[col] = val

                    vector = None
                    if vector_col and vector_col in df.columns:
                        vec = row[vector_col]
                        if isinstance(vec, _np.ndarray):
                            vector = vec.tolist()
                        elif isinstance(vec, list):
                            vector = vec
                        else:
                            vector = list(vec)

                    batch.add_object(
                        collection=class_name,
                        properties=properties,
                        vector=vector,
                    )
                    total += 1

        finally:
            client.close()

        self.gov.load_complete(total, class_name)
        self.gov.destination_registered("weaviate", url, class_name)
        logger.info(
            "WeaviateLoader: imported %d objects to class %s.",
            total, class_name,
        )
        return total

    def search(self, cfg, query_vector, table="", limit=10,
               return_properties=None, where_filter=None) -> list:
        """Run a nearVector search on a Weaviate class."""
        if not query_vector:
            raise ValueError(
                "WeaviateLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )
        query_vector = validate_float_vector(query_vector, "query_vector")

        url = cfg.get("url")
        if not url:
            raise ValueError("WeaviateLoader: cfg must contain 'url'.")

        class_name = table or cfg.get("class_name")
        if not class_name:
            raise ValueError("WeaviateLoader: supply class name.")

        client = self._build_client(cfg)

        try:
            collection = client.collections.get(class_name)
            response = collection.query.near_vector(
                near_vector=query_vector,
                limit=limit,
                return_properties=return_properties,
            )
            results = []
            for obj in response.objects:
                item = dict(obj.properties)
                if obj.metadata and obj.metadata.distance is not None:
                    item["_distance"] = obj.metadata.distance
                results.append(item)
        finally:
            client.close()

        logger.info(
            "Weaviate search on %s returned %d results.",
            class_name, len(results),
        )
        return results

    def delete_class(self, cfg, table="") -> None:
        """Delete a Weaviate class and all its objects."""
        url = cfg.get("url")
        if not url:
            raise ValueError("WeaviateLoader: cfg must contain 'url'.")

        class_name = table or cfg.get("class_name")
        if not class_name:
            raise ValueError("WeaviateLoader: supply class name.")

        client = self._build_client(cfg)
        try:
            self._delete_class_if_exists(client, class_name)
        finally:
            client.close()

        logger.info("WeaviateLoader: deleted class %s.", class_name)

    @staticmethod
    def _build_client(cfg):
        """Build a weaviate-client v4 connection."""
        import weaviate

        url = cfg["url"]
        api_key = cfg.get("api_key")

        # Parse host and port from URL
        _scheme = url.split("://")[0] if "://" in url else "http"
        _rest = url.split("://")[-1].split("/")[0]
        _is_https = _scheme == "https"

        if ":" in _rest:
            _host, _port_str = _rest.rsplit(":", 1)
            try:
                _port = int(_port_str)
            except ValueError:
                _port = 443 if _is_https else 8080
        else:
            _host = _rest
            _port = 443 if _is_https else 8080

        grpc_port = int(cfg.get("grpc_port", 50051))

        if api_key:
            return weaviate.connect_to_custom(
                http_host=_host,
                http_port=_port,
                http_secure=_is_https,
                grpc_host=cfg.get("grpc_host", _host),
                grpc_port=grpc_port,
                grpc_secure=_is_https,
                auth_credentials=weaviate.auth.AuthApiKey(api_key),
            )
        return weaviate.connect_to_local(
            host=_host,
            port=_port,
            grpc_port=grpc_port,
        )

    @staticmethod
    def _delete_class_if_exists(client, class_name):
        """Delete a class if it exists, logging any failure."""
        try:
            client.collections.delete(class_name)
        except Exception as exc:
            logger.warning(
                "WeaviateLoader: could not delete class %s: %s",
                class_name, exc,
            )

    @staticmethod
    def _ensure_class(client, class_name):
        """Create the class if it does not exist."""
        try:
            client.collections.get(class_name)
        except Exception:
            client.collections.create(name=class_name)

    @staticmethod
    def _embed(df, embed_cols, model_name):
        """Generate sentence-transformer embeddings from text columns."""
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "WeaviateLoader: embed_columns requires "
                "sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model = SentenceTransformer(model_name)
        texts = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
