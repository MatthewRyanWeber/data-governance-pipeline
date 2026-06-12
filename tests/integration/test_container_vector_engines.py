"""
Integration tests for container-backed vector databases:
Qdrant, Weaviate, Milvus — real servers, real vector reads.

Revision history
────────────────
1.0   2026-06-12   Initial release.
"""

import os
import unittest
from unittest.mock import MagicMock

import pandas as pd
import pytest

os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")


def _docker_available() -> bool:
    try:
        import docker
        docker.from_env().ping()
        return True
    except Exception:
        return False


DOCKER = _docker_available()

from pipeline.loaders import resolve_loader  # noqa: E402


def _loader(db_type: str):
    loader_class, _, _ = resolve_loader(db_type)
    return loader_class(MagicMock())


def _vec_df(ids=(1, 2, 3), names=None):
    names = names or [f"doc{i}" for i in ids]
    return pd.DataFrame({
        "id": list(ids),
        "name": names,
        "embedding": [[float(i), 0.5, 0.25] for i in ids],
    })


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestQdrantIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("qdrant/qdrant:v1.12.4")
            .with_exposed_ports(6333)
        )
        cls.container.start()
        wait_for_logs(cls.container, "Qdrant HTTP listening", timeout=60)
        cls.url = f"http://127.0.0.1:{cls.container.get_exposed_port(6333)}"

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _client(self):
        from qdrant_client import QdrantClient
        return QdrantClient(url=self.url)

    def test_load_then_count_and_search(self):
        loader = _loader("qdrant")
        cfg = {"url": self.url, "vector_column": "embedding",
               "id_column": "id"}
        rows = loader.load(_vec_df(), cfg, table="docs")
        self.assertEqual(rows, 3)

        client = self._client()
        self.assertEqual(client.count("docs").count, 3)
        hits = client.query_points(
            "docs", query=[1.0, 0.5, 0.25], limit=1).points
        self.assertEqual(hits[0].id, 1)

    def test_append_without_id_column_does_not_overwrite(self):
        loader = _loader("qdrant")
        cfg = {"url": self.url, "vector_column": "embedding"}
        loader.load(_vec_df(ids=(1, 2, 3)), cfg, table="docs_auto")
        loader.load(_vec_df(ids=(4, 5)), cfg, table="docs_auto")
        client = self._client()
        # Pre-fix, auto ids restarted at 0 each load and the second
        # append silently overwrote the first
        self.assertEqual(client.count("docs_auto").count, 5)


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestWeaviateIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("semitechnologies/weaviate:1.27.0")
            .with_env("AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED", "true")
            .with_env("PERSISTENCE_DATA_PATH", "/var/lib/weaviate")
            .with_env("DEFAULT_VECTORIZER_MODULE", "none")
            .with_exposed_ports(8080, 50051)
        )
        cls.container.start()
        wait_for_logs(cls.container, "Serving weaviate", timeout=90)
        cls.http_port = int(cls.container.get_exposed_port(8080))
        cls.grpc_port = int(cls.container.get_exposed_port(50051))
        cls.url = f"http://127.0.0.1:{cls.http_port}"

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def test_load_then_count(self):
        loader = _loader("weaviate")
        cfg = {
            "url": self.url,
            "grpc_port": self.grpc_port,
            "vector_column": "embedding",
        }
        rows = loader.load(_vec_df(), cfg, table="Docs")
        self.assertEqual(rows, 3)

        import weaviate
        client = weaviate.connect_to_local(
            host="127.0.0.1", port=self.http_port, grpc_port=self.grpc_port)
        try:
            collection = client.collections.get("Docs")
            total = collection.aggregate.over_all(total_count=True).total_count
        finally:
            client.close()
        self.assertEqual(total, 3)


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestMilvusIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from testcontainers.milvus import MilvusContainer
        cls.container = MilvusContainer("milvusdb/milvus:v2.4.15")
        cls.container.start()
        cls.uri = (f"http://127.0.0.1:"
                   f"{cls.container.get_exposed_port(19530)}")

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def test_load_with_custom_field_names_then_count(self):
        loader = _loader("milvus")
        # Pre-fix, create_collection hardcoded field names "vector"/"id"
        # while inserts used the configured names — every insert failed
        cfg = {
            "uri": self.uri,
            "vector_column": "embedding",
            "id_column": "id",
        }
        rows = loader.load(_vec_df(), cfg, table="docs")
        self.assertEqual(rows, 3)

        from pymilvus import MilvusClient
        client = MilvusClient(uri=self.uri)
        client.load_collection("docs")
        stats = client.get_collection_stats("docs")
        self.assertEqual(int(stats["row_count"]), 3)


if __name__ == "__main__":
    unittest.main()
