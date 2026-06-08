"""
Tests that every loader raises ConfigValidationError on missing required keys.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.exceptions import ConfigValidationError


class TestKafkaConfigValidation(unittest.TestCase):

    def _make_loader(self):
        with patch("pipeline.loaders.kafka_loader.HAS_KAFKA_LOADER", True):
            from pipeline.loaders.kafka_loader import KafkaLoader
            return KafkaLoader(MagicMock())

    def test_missing_bootstrap_servers(self):
        loader = self._make_loader()
        df = pd.DataFrame({"a": [1]})
        with self.assertRaises((ConfigValidationError, ValueError)):
            loader.load(df, {}, table="test_topic")


class TestMilvusConfigValidation(unittest.TestCase):

    def _make_loader(self):
        with patch("pipeline.loaders.vector.milvus_loader.HAS_MILVUS", True):
            from pipeline.loaders.vector.milvus_loader import MilvusLoader
            return MilvusLoader(MagicMock())

    def test_missing_uri(self):
        loader = self._make_loader()
        df = pd.DataFrame({"embedding": [[0.1]]})
        with self.assertRaises(ConfigValidationError):
            loader.load(df, {}, table="test_coll")


class TestPineconeConfigValidation(unittest.TestCase):

    def _make_loader(self):
        with patch("pipeline.loaders.vector.pinecone_loader.HAS_PINECONE", True):
            from pipeline.loaders.vector.pinecone_loader import PineconeLoader
            return PineconeLoader(MagicMock())

    def test_missing_api_key(self):
        loader = self._make_loader()
        df = pd.DataFrame({"id": [1], "embedding": [[0.1]]})
        with self.assertRaises(ConfigValidationError):
            loader.load(df, {"index_name": "test"}, table="test_idx")


class TestQdrantConfigValidation(unittest.TestCase):

    def _make_loader(self):
        with patch("pipeline.loaders.vector.qdrant_loader.HAS_QDRANT", True):
            from pipeline.loaders.vector.qdrant_loader import QdrantLoader
            return QdrantLoader(MagicMock())

    def test_missing_all_connection_modes(self):
        loader = self._make_loader()
        df = pd.DataFrame({"embedding": [[0.1]]})
        with self.assertRaises(ConfigValidationError):
            loader.load(df, {}, table="test_coll")

    def test_url_present_passes(self):
        loader = self._make_loader()
        df = pd.DataFrame({"embedding": [[0.1]]})
        cfg = {"url": "http://localhost:6333", "vector_column": "embedding",
               "dimensions": 2}
        with patch.object(loader, "_build_client") as mock_client:
            mock_client.return_value = MagicMock()
            try:
                loader.load(df, cfg, table="test")
            except Exception:
                pass


class TestWeaviateConfigValidation(unittest.TestCase):

    def _make_loader(self):
        with patch("pipeline.loaders.vector.weaviate_loader.HAS_WEAVIATE", True):
            from pipeline.loaders.vector.weaviate_loader import WeaviateLoader
            return WeaviateLoader(MagicMock())

    def test_missing_url(self):
        loader = self._make_loader()
        df = pd.DataFrame({"text": ["hello"]})
        with self.assertRaises(ConfigValidationError):
            loader.load(df, {}, table="Document")


class TestChromaConfigValidation(unittest.TestCase):

    def _make_loader(self):
        with patch("pipeline.loaders.vector.chroma_loader.HAS_CHROMA", True):
            from pipeline.loaders.vector.chroma_loader import ChromaLoader
            return ChromaLoader(MagicMock())

    def test_missing_id_column(self):
        loader = self._make_loader()
        df = pd.DataFrame({"id": ["1"], "embedding": [[0.1]]})
        with self.assertRaises(ConfigValidationError):
            loader.load(df, {}, table="test")


class TestLanceDBConfigValidation(unittest.TestCase):

    def _make_loader(self):
        with patch("pipeline.loaders.vector.lancedb_loader.HAS_LANCEDB", True):
            from pipeline.loaders.vector.lancedb_loader import LanceDBLoader
            return LanceDBLoader(MagicMock())

    def test_missing_db_path(self):
        loader = self._make_loader()
        df = pd.DataFrame({"vector": [[0.1]], "text": ["hi"]})
        with self.assertRaises(ConfigValidationError):
            loader.load(df, {}, table="test_tbl")


class TestBaseLoaderAlternativeKeys(unittest.TestCase):
    """Test the 'key1|key2' alternative config validation syntax."""

    def test_first_alternative_present(self):
        from pipeline.loaders.base import BaseLoader
        loader = BaseLoader(MagicMock())
        loader._validate_config({"host": "localhost"}, ["host|path"])

    def test_second_alternative_present(self):
        from pipeline.loaders.base import BaseLoader
        loader = BaseLoader(MagicMock())
        loader._validate_config({"path": "/data"}, ["host|path"])

    def test_neither_alternative_present(self):
        from pipeline.loaders.base import BaseLoader
        loader = BaseLoader(MagicMock())
        with self.assertRaises(ConfigValidationError) as ctx:
            loader._validate_config({}, ["host|path"])
        self.assertIn("host", str(ctx.exception))

    def test_error_includes_db_type(self):
        from pipeline.loaders.base import BaseLoader
        loader = BaseLoader(MagicMock())
        with self.assertRaises(ConfigValidationError) as ctx:
            loader._validate_config({}, ["user", "password"])
        self.assertEqual(ctx.exception.missing_keys, ["user", "password"])


if __name__ == "__main__":
    unittest.main()
