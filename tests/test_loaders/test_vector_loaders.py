"""
Deep load-path tests for the vector-database loaders.

Each SDK client is mocked (via the loader's _build_client method or the inline
SDK import) so the load logic — collection create/overwrite, batched
add/upsert/insert, payload/metadata extraction — runs without a live vector DB.
Validation guards (if_exists, missing collection, missing vector column,
dry_run) need no mocking.

Drivers are installed in this environment, so construction is real.

Revision history
────────────────
1.0   2026-06-09   Initial release: chroma, milvus, pinecone, qdrant, weaviate.
1.1   2026-06-11   Regression tests: qdrant auto-ids offset by existing point
                   count (append no longer overwrites), non-integer float ids
                   rejected; milvus create_collection field names; weaviate
                   batch-failure accounting; lancedb upsert requires keys.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.constants import (
    HAS_CHROMA, HAS_MILVUS, HAS_PINECONE, HAS_QDRANT, HAS_WEAVIATE,
)
from pipeline.loaders.vector.chroma_loader import ChromaLoader
from pipeline.loaders.vector.milvus_loader import MilvusLoader
from pipeline.loaders.vector.pinecone_loader import PineconeLoader
from pipeline.loaders.vector.qdrant_loader import QdrantLoader
from pipeline.loaders.vector.weaviate_loader import WeaviateLoader
from pipeline.exceptions import ConfigValidationError


def _vec_df():
    return pd.DataFrame({
        "id": [1, 2],
        "embedding": [[0.1, 0.2], [0.3, 0.4]],
        "title": ["alpha", "beta"],
    })


# ── Chroma ────────────────────────────────────────────────────────────────

@unittest.skipUnless(HAS_CHROMA, "chromadb not installed")
class TestChromaLoader(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = ChromaLoader(self.gov)
        self.client = MagicMock()
        self.col = self.client.get_collection.return_value
        self.cfg = {"id_column": "id", "vector_column": "embedding"}

    def _load(self, **kw):
        with patch.object(self.loader, "_build_client", return_value=self.client):
            return self.loader.load(_vec_df(), self.cfg, "docs", **kw)

    def test_append_calls_add(self):
        n = self._load(if_exists="append")
        self.assertEqual(n, 2)
        self.col.add.assert_called_once()
        kwargs = self.col.add.call_args.kwargs
        self.assertEqual(kwargs["ids"], ["1", "2"])
        self.assertEqual(len(kwargs["embeddings"]), 2)

    def test_upsert_calls_upsert(self):
        self._load(if_exists="upsert")
        self.col.upsert.assert_called_once()

    def test_overwrite_deletes_and_creates(self):
        with patch.object(self.loader, "_build_client", return_value=self.client):
            self.loader.load(_vec_df(), self.cfg, "docs", if_exists="overwrite")
        self.client.delete_collection.assert_called_once_with("docs")
        self.client.create_collection.assert_called_once_with("docs")

    def test_metadata_extracted_from_other_columns(self):
        self._load()
        meta = self.col.add.call_args.kwargs["metadatas"]
        self.assertEqual(meta, [{"title": "alpha"}, {"title": "beta"}])

    def test_invalid_if_exists_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), self.cfg, "docs", if_exists="replace")

    def test_missing_collection_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), self.cfg, "")

    def test_missing_id_column_config_raises(self):
        with self.assertRaises(ConfigValidationError):
            self.loader.load(_vec_df(), {}, "docs")

    def test_id_column_absent_from_df_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), {"id_column": "missing"}, "docs")

    def test_dry_run_returns_zero(self):
        loader = ChromaLoader(self.gov, dry_run=True)
        with patch.object(loader, "_build_client") as bc:
            n = loader.load(_vec_df(), self.cfg, "docs")
        self.assertEqual(n, 0)
        bc.assert_not_called()


# ── Milvus ────────────────────────────────────────────────────────────────

@unittest.skipUnless(HAS_MILVUS, "pymilvus not installed")
class TestMilvusLoader(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = MilvusLoader(self.gov)
        self.client = MagicMock()
        self.client.has_collection.return_value = False
        self.client.insert.return_value = {"insert_count": 2}
        self.client.upsert.return_value = {"upsert_count": 2}
        self.cfg = {"uri": "http://localhost:19530", "vector_column": "embedding"}

    def _load(self, **kw):
        with patch("pymilvus.MilvusClient", return_value=self.client):
            return self.loader.load(_vec_df(), self.cfg, "coll", **kw)

    def test_append_inserts_and_creates_collection(self):
        n = self._load(if_exists="append")
        self.assertEqual(n, 2)
        self.client.create_collection.assert_called_once()
        self.client.insert.assert_called_once()
        self.assertEqual(self.client.insert.call_args.kwargs["collection_name"], "coll")

    def test_upsert_calls_upsert(self):
        self._load(if_exists="upsert")
        self.client.upsert.assert_called_once()

    def test_overwrite_drops_when_exists(self):
        self.client.has_collection.return_value = True
        self._load(if_exists="overwrite")
        self.client.drop_collection.assert_called_once_with("coll")

    def test_missing_vector_column_raises(self):
        with patch("pymilvus.MilvusClient", return_value=self.client):
            with self.assertRaises(ValueError):
                self.loader.load(pd.DataFrame({"id": [1]}), self.cfg, "coll")

    def test_missing_uri_config_raises(self):
        with self.assertRaises(ConfigValidationError):
            self.loader.load(_vec_df(), {"vector_column": "embedding"}, "coll")

    def test_dry_run_returns_zero(self):
        loader = MilvusLoader(self.gov, dry_run=True)
        with patch("pymilvus.MilvusClient") as mc:
            n = loader.load(_vec_df(), self.cfg, "coll")
        self.assertEqual(n, 0)
        mc.assert_not_called()

    def test_create_collection_uses_configured_field_names(self):
        """Regression: the schema hardcoded "vector"/"id" while inserts used
        cfg's vector_column/id_column, so inserts missed the schema fields."""
        cfg = {"uri": "http://localhost:19530", "vector_column": "embedding",
               "id_column": "id"}
        with patch("pymilvus.MilvusClient", return_value=self.client):
            self.loader.load(_vec_df(), cfg, "coll", if_exists="append")
        create_kwargs = self.client.create_collection.call_args.kwargs
        self.assertEqual(create_kwargs["vector_field_name"], "embedding")
        self.assertEqual(create_kwargs["primary_field_name"], "id")


# ── Pinecone ──────────────────────────────────────────────────────────────

@unittest.skipUnless(HAS_PINECONE, "pinecone not installed")
class TestPineconeLoader(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = PineconeLoader(self.gov)
        self.index = MagicMock()
        self.pc = MagicMock()
        self.pc.Index.return_value = self.index
        self.cfg = {"api_key": "k", "index_name": "idx", "vector_column": "embedding"}

    def _load(self, **kw):
        with patch("pinecone.Pinecone", return_value=self.pc):
            return self.loader.load(_vec_df(), self.cfg, "idx", **kw)

    def test_upsert_builds_vectors(self):
        n = self._load(if_exists="upsert")
        self.assertEqual(n, 2)
        self.index.upsert.assert_called_once()
        vectors = self.index.upsert.call_args.kwargs["vectors"]
        self.assertEqual(vectors[0]["id"], "1")
        self.assertEqual(vectors[0]["values"], [0.1, 0.2])
        self.assertEqual(vectors[0]["metadata"], {"title": "alpha"})

    def test_overwrite_deletes_all(self):
        self._load(if_exists="overwrite")
        self.index.delete.assert_called_once_with(delete_all=True, namespace="")

    def test_invalid_if_exists_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), self.cfg, "idx", if_exists="append")

    def test_missing_api_key_config_raises(self):
        with self.assertRaises(ConfigValidationError):
            self.loader.load(_vec_df(), {"index_name": "idx"}, "idx")

    def test_dry_run_returns_zero(self):
        loader = PineconeLoader(self.gov, dry_run=True)
        with patch("pinecone.Pinecone") as p:
            n = loader.load(_vec_df(), self.cfg, "idx")
        self.assertEqual(n, 0)
        p.assert_not_called()


# ── Qdrant ────────────────────────────────────────────────────────────────

@unittest.skipUnless(HAS_QDRANT, "qdrant-client not installed")
class TestQdrantLoader(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = QdrantLoader(self.gov)
        self.client = MagicMock()
        self.client.collection_exists.return_value = False
        self.cfg = {"url": "http://localhost:6333", "vector_column": "embedding",
                    "id_column": "id"}

    def _load(self, **kw):
        with patch.object(self.loader, "_build_client", return_value=self.client):
            return self.loader.load(_vec_df(), self.cfg, "coll", **kw)

    def test_append_creates_and_upserts_points(self):
        n = self._load(if_exists="append")
        self.assertEqual(n, 2)
        self.client.create_collection.assert_called_once()
        self.client.upsert.assert_called_once()
        self.assertEqual(self.client.upsert.call_args.kwargs["collection_name"], "coll")

    def test_overwrite_deletes_existing(self):
        self.client.collection_exists.return_value = True
        self._load(if_exists="overwrite")
        self.client.delete_collection.assert_called_once_with("coll")

    def test_invalid_if_exists_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), self.cfg, "coll", if_exists="upsert")

    def test_missing_location_config_raises(self):
        with self.assertRaises(ConfigValidationError):
            self.loader.load(_vec_df(), {"vector_column": "embedding"}, "coll")

    def test_dry_run_returns_zero(self):
        loader = QdrantLoader(self.gov, dry_run=True)
        with patch.object(loader, "_build_client") as bc:
            n = loader.load(_vec_df(), self.cfg, "coll")
        self.assertEqual(n, 0)
        bc.assert_not_called()

    def test_auto_ids_offset_by_existing_point_count(self):
        """Regression: without id_column, point ids restarted at 0 so a
        second append overwrote prior points."""
        cfg_no_id = {"url": "http://localhost:6333", "vector_column": "embedding"}
        self.client.collection_exists.return_value = True
        self.client.get_collection.return_value.points_count = 7
        with patch.object(self.loader, "_build_client", return_value=self.client):
            self.loader.load(_vec_df(), cfg_no_id, "coll", if_exists="append")
        points = self.client.upsert.call_args.kwargs["points"]
        self.assertEqual([p.id for p in points], [7, 8])

    def test_auto_ids_start_at_zero_for_new_collection(self):
        cfg_no_id = {"url": "http://localhost:6333", "vector_column": "embedding"}
        self.client.collection_exists.return_value = False
        self.client.get_collection.return_value.points_count = 0
        with patch.object(self.loader, "_build_client", return_value=self.client):
            self.loader.load(_vec_df(), cfg_no_id, "coll", if_exists="append")
        points = self.client.upsert.call_args.kwargs["points"]
        self.assertEqual([p.id for p in points], [0, 1])

    def test_non_integer_float_id_rejected(self):
        """Regression: int(raw_id) truncated 1.5 and 1.7 to the same id."""
        df = pd.DataFrame({
            "id": [1.5, 1.7],
            "embedding": [[0.1, 0.2], [0.3, 0.4]],
        })
        with patch.object(self.loader, "_build_client", return_value=self.client):
            with self.assertRaises(ValueError):
                self.loader.load(df, self.cfg, "coll")

    def test_integral_float_id_accepted(self):
        """Pandas upcasts int columns with NaNs to float — 2.0 is a valid id."""
        df = pd.DataFrame({
            "id": [1.0, 2.0],
            "embedding": [[0.1, 0.2], [0.3, 0.4]],
        })
        with patch.object(self.loader, "_build_client", return_value=self.client):
            self.loader.load(df, self.cfg, "coll")
        points = self.client.upsert.call_args.kwargs["points"]
        self.assertEqual([p.id for p in points], [1, 2])

    def test_string_id_maps_to_deterministic_uuid(self):
        df = pd.DataFrame({
            "id": ["doc-a", "doc-a"],
            "embedding": [[0.1, 0.2], [0.3, 0.4]],
        })
        with patch.object(self.loader, "_build_client", return_value=self.client):
            self.loader.load(df, self.cfg, "coll")
        points = self.client.upsert.call_args.kwargs["points"]
        self.assertEqual(points[0].id, points[1].id)
        self.assertIsInstance(points[0].id, str)


# ── Weaviate ──────────────────────────────────────────────────────────────

@unittest.skipUnless(HAS_WEAVIATE, "weaviate-client not installed")
class TestWeaviateLoader(unittest.TestCase):
    def setUp(self):
        # Undo logging.disable pollution so assertLogs works in combined runs
        import logging
        logging.disable(logging.NOTSET)
        self.gov = MagicMock()
        self.loader = WeaviateLoader(self.gov)
        self.client = MagicMock()
        self.batch = self.client.batch.fixed_size.return_value.__enter__.return_value
        self.cfg = {"url": "http://localhost:8080", "vector_column": "embedding"}

    def _load(self, class_name="Docs", **kw):
        with patch.object(self.loader, "_build_client", return_value=self.client), \
             patch.object(self.loader, "_ensure_class"), \
             patch.object(self.loader, "_delete_class_if_exists"):
            return self.loader.load(_vec_df(), self.cfg, class_name, **kw)

    def test_append_adds_objects(self):
        n = self._load()
        self.assertEqual(n, 2)
        self.assertEqual(self.batch.add_object.call_count, 2)
        self.client.close.assert_called_once()

    def test_overwrite_deletes_class(self):
        with patch.object(self.loader, "_build_client", return_value=self.client), \
             patch.object(self.loader, "_ensure_class"), \
             patch.object(self.loader, "_delete_class_if_exists") as del_class:
            self.loader.load(_vec_df(), self.cfg, "Docs", if_exists="overwrite")
            del_class.assert_called_once()

    def test_lowercase_class_name_rejected(self):
        with patch.object(self.loader, "_build_client", return_value=self.client):
            with self.assertRaises(ValueError):
                self.loader.load(_vec_df(), self.cfg, "docs")  # must be Uppercase

    def test_invalid_if_exists_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), self.cfg, "Docs", if_exists="upsert")

    def test_missing_url_config_raises(self):
        with self.assertRaises(ConfigValidationError):
            self.loader.load(_vec_df(), {"vector_column": "embedding"}, "Docs")

    def test_dry_run_returns_zero(self):
        loader = WeaviateLoader(self.gov, dry_run=True)
        with patch.object(loader, "_build_client") as bc:
            n = loader.load(_vec_df(), self.cfg, "Docs")
        self.assertEqual(n, 0)
        bc.assert_not_called()

    def test_batch_failures_reduce_reported_success(self):
        """Regression: batch failures were never checked, so a fully failed
        import was reported as complete."""
        failure = MagicMock()
        failure.message = "vector dimension mismatch"
        self.client.batch.failed_objects = [failure]
        import logging
        with self.assertLogs("pipeline.loaders.vector.weaviate_loader",
                             level=logging.ERROR):
            n = self._load()
        self.assertEqual(n, 1)
        self.gov.load_complete.assert_called_once_with(1, "Docs")

    def test_fully_failed_batch_reports_zero(self):
        failures = [MagicMock(message="boom"), MagicMock(message="boom")]
        self.client.batch.failed_objects = failures
        import logging
        with self.assertLogs("pipeline.loaders.vector.weaviate_loader",
                             level=logging.ERROR):
            n = self._load()
        self.assertEqual(n, 0)
        self.gov.load_complete.assert_called_once_with(0, "Docs")


if __name__ == "__main__":
    unittest.main()
