"""
Tests that dry_run=True prevents all loaders from writing data.

Verifies the BaseLoader._dry_run_guard() integration across loader subclasses.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.constants import (
    HAS_CHROMA, HAS_LANCEDB, HAS_MILVUS, HAS_PINECONE, HAS_QDRANT,
    HAS_WEAVIATE,
)


class TestBaseLoaderDryRun(unittest.TestCase):
    """BaseLoader._dry_run_guard() returns True and logs when dry_run=True."""

    def setUp(self):
        logging.disable(logging.NOTSET)

    def test_dry_run_false_returns_false(self):
        from pipeline.loaders.base import BaseLoader
        loader = BaseLoader(MagicMock(), dry_run=False)
        self.assertFalse(loader._dry_run_guard("test_table", 100))

    def test_dry_run_true_returns_true(self):
        from pipeline.loaders.base import BaseLoader
        loader = BaseLoader(MagicMock(), dry_run=True)
        self.assertTrue(loader._dry_run_guard("test_table", 100))

    def test_dry_run_logs_info(self):
        from pipeline.loaders.base import BaseLoader
        loader = BaseLoader(MagicMock(), dry_run=True)
        with self.assertLogs("pipeline.loaders.base", level="INFO") as cm:
            loader._dry_run_guard("orders", 500)
        self.assertTrue(any("DRY RUN" in m for m in cm.output))
        self.assertTrue(any("orders" in m for m in cm.output))
        self.assertTrue(any("500" in m for m in cm.output))


class TestKafkaLoaderDryRun(unittest.TestCase):
    """KafkaLoader.load() short-circuits on dry_run=True."""

    def _make_loader(self, dry_run):
        with patch("pipeline.loaders.kafka_loader.HAS_KAFKA_LOADER", True):
            from pipeline.loaders.kafka_loader import KafkaLoader
            return KafkaLoader(MagicMock(), dry_run=dry_run)

    def test_dry_run_returns_zero(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"a": [1, 2, 3]})
        cfg = {"bootstrap_servers": "localhost:9092", "topic": "test"}
        result = loader.load(df, cfg, table="test_topic")
        self.assertEqual(result, 0)


class TestDuckDBLoaderDryRun(unittest.TestCase):
    """DuckDBLoader.load() short-circuits on dry_run=True."""

    def _make_loader(self, dry_run):
        with patch("pipeline.loaders.duckdb_loader.HAS_DUCKDB", True):
            from pipeline.loaders.duckdb_loader import DuckDBLoader
            return DuckDBLoader(MagicMock(), dry_run=dry_run)

    def test_dry_run_skips_write(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"a": [1]})
        cfg = {"db_path": ":memory:"}
        loader.load(df, cfg, table="test_table")


@unittest.skipUnless(HAS_MILVUS, "pymilvus not installed")
class TestMilvusLoaderDryRun(unittest.TestCase):
    """MilvusLoader.load() short-circuits on dry_run=True."""

    def _make_loader(self, dry_run):
        with patch("pipeline.loaders.vector.milvus_loader.HAS_MILVUS", True):
            from pipeline.loaders.vector.milvus_loader import MilvusLoader
            return MilvusLoader(MagicMock(), dry_run=dry_run)

    def test_dry_run_returns_zero(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"embedding": [[0.1, 0.2]]})
        cfg = {"uri": "./test.db", "vector_column": "embedding"}
        result = loader.load(df, cfg, table="test_collection")
        self.assertEqual(result, 0)


@unittest.skipUnless(HAS_PINECONE, "pinecone not installed")
class TestPineconeLoaderDryRun(unittest.TestCase):
    """PineconeLoader.load() short-circuits on dry_run=True."""

    def _make_loader(self, dry_run):
        with patch("pipeline.loaders.vector.pinecone_loader.HAS_PINECONE", True):
            from pipeline.loaders.vector.pinecone_loader import PineconeLoader
            return PineconeLoader(MagicMock(), dry_run=dry_run)

    def test_dry_run_returns_zero(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"id": [1], "embedding": [[0.1, 0.2]]})
        cfg = {"api_key": "test", "index_name": "test_idx",
               "vector_column": "embedding"}
        result = loader.load(df, cfg, table="test_idx")
        self.assertEqual(result, 0)


@unittest.skipUnless(HAS_QDRANT, "qdrant-client not installed")
class TestQdrantLoaderDryRun(unittest.TestCase):
    """QdrantLoader.load() short-circuits on dry_run=True."""

    def _make_loader(self, dry_run):
        with patch("pipeline.loaders.vector.qdrant_loader.HAS_QDRANT", True):
            from pipeline.loaders.vector.qdrant_loader import QdrantLoader
            return QdrantLoader(MagicMock(), dry_run=dry_run)

    def test_dry_run_returns_zero(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"embedding": [[0.1, 0.2]]})
        cfg = {"url": "http://localhost:6333", "vector_column": "embedding",
               "dimensions": 2}
        result = loader.load(df, cfg, table="test_coll")
        self.assertEqual(result, 0)


@unittest.skipUnless(HAS_WEAVIATE, "weaviate-client not installed")
class TestWeaviateLoaderDryRun(unittest.TestCase):
    """WeaviateLoader.load() short-circuits on dry_run=True."""

    def _make_loader(self, dry_run):
        with patch("pipeline.loaders.vector.weaviate_loader.HAS_WEAVIATE", True):
            from pipeline.loaders.vector.weaviate_loader import WeaviateLoader
            return WeaviateLoader(MagicMock(), dry_run=dry_run)

    def test_dry_run_returns_zero(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"text": ["hello"]})
        cfg = {"url": "http://localhost:8080", "class_name": "Document"}
        result = loader.load(df, cfg, table="Document")
        self.assertEqual(result, 0)


@unittest.skipUnless(HAS_CHROMA, "chromadb not installed")
class TestChromaLoaderDryRun(unittest.TestCase):
    """ChromaLoader.load() short-circuits on dry_run=True."""

    def _make_loader(self, dry_run):
        with patch("pipeline.loaders.vector.chroma_loader.HAS_CHROMA", True):
            from pipeline.loaders.vector.chroma_loader import ChromaLoader
            return ChromaLoader(MagicMock(), dry_run=dry_run)

    def test_dry_run_returns_zero(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"id": ["1"], "embedding": [[0.1, 0.2]]})
        cfg = {"path": "./chroma_test", "id_column": "id",
               "vector_column": "embedding"}
        result = loader.load(df, cfg, table="test_coll")
        self.assertEqual(result, 0)


@unittest.skipUnless(HAS_LANCEDB, "lancedb not installed")
class TestLanceDBLoaderDryRun(unittest.TestCase):
    """LanceDBLoader.load() short-circuits on dry_run=True."""

    def _make_loader(self, dry_run):
        with patch("pipeline.loaders.vector.lancedb_loader.HAS_LANCEDB", True):
            from pipeline.loaders.vector.lancedb_loader import LanceDBLoader
            return LanceDBLoader(MagicMock(), dry_run=dry_run)

    def test_dry_run_returns_zero(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"vector": [[0.1, 0.2]], "text": ["hi"]})
        cfg = {"db_path": "./lance_test", "vector_column": "vector"}
        result = loader.load(df, cfg, table="test_tbl")
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
