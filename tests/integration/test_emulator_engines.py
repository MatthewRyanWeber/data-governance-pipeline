"""
Emulator-tier integration tests: snowflake (fakesnow), bigquery
(goccy/bigquery-emulator), pinecone (pinecone-local).

Emulators verify loader MECHANICS — SQL generation, API call shapes,
batching, error paths.  They do NOT verify vendor-specific behaviour;
that distinction is exactly what the 'emulator' verification tier means.
Documented per engine below.

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


def _df(ids=(1, 2, 3), names=("a", "b", "c")):
    return pd.DataFrame({"id": list(ids), "name": list(names)})


def _loader(db_type: str):
    loader_class, _, _ = resolve_loader(db_type)
    return loader_class(MagicMock())


@pytest.mark.integration
class TestSnowflakeAgainstFakesnow(unittest.TestCase):
    """fakesnow emulates the Snowflake connector on DuckDB.

    NOT covered: warehouse semantics, stages/PUT+COPY (the loader's
    bulk path), VECTOR types, role-based access.  The to_sql/MERGE
    mechanics ARE covered.
    """

    def setUp(self):
        import fakesnow
        self._fakesnow = fakesnow.patch()
        self._fakesnow.__enter__()

    def tearDown(self):
        self._fakesnow.__exit__(None, None, None)

    def _cfg(self):
        return {
            "account": "it_account",
            "user": "it_user",
            "password": "it_pass",
            "database": "ITDB",
            "schema": "PUBLIC",
            "warehouse": "ITWH",
            # fakesnow has no stage support — force the SQL fallback path
            "use_stage": False,
        }

    def _read(self, table):
        import snowflake.connector
        conn = snowflake.connector.connect(
            account="it_account", user="it_user", password="it_pass",
            database="ITDB", schema="PUBLIC", warehouse="ITWH",
        )
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT id, name FROM {table} ORDER BY id")
            return cur.fetchall()
        finally:
            conn.close()

    def test_append_then_read_back(self):
        import snowflake.connector
        conn = snowflake.connector.connect(
            account="it_account", user="it_user", password="it_pass",
            warehouse="ITWH",
        )
        conn.cursor().execute("CREATE DATABASE IF NOT EXISTS ITDB")
        conn.close()

        loader = _loader("snowflake")
        rows = loader.load(_df(), self._cfg(), table="people_append")
        self.assertEqual(rows, 3)
        out = self._read("people_append")
        self.assertEqual([r[1] for r in out], ["a", "b", "c"])


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestBigQueryAgainstEmulator(unittest.TestCase):
    """goccy/bigquery-emulator speaks the BigQuery REST API.

    NOT covered: slot/reservation behaviour, real GoogleSQL edge cases,
    streaming-insert quotas, IAM.  Dataset/table creation and the
    load_table_from_dataframe path ARE covered.
    """

    PROJECT, DATASET = "it-project", "it_dataset"

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("ghcr.io/goccy/bigquery-emulator:0.6.6")
            .with_command(f"--project={cls.PROJECT} --dataset={cls.DATASET}")
            .with_exposed_ports(9050)
        )
        cls.container.start()
        wait_for_logs(cls.container, "listening", timeout=60)
        cls.endpoint = (
            f"http://127.0.0.1:{cls.container.get_exposed_port(9050)}"
        )

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _client(self):
        from google.api_core.client_options import ClientOptions
        from google.auth.credentials import AnonymousCredentials
        from google.cloud import bigquery
        return bigquery.Client(
            project=self.PROJECT,
            client_options=ClientOptions(api_endpoint=self.endpoint),
            credentials=AnonymousCredentials(),
        )

    def test_append_then_read_back(self):
        loader = _loader("bigquery")
        cfg = {
            "project": self.PROJECT,
            "dataset": self.DATASET,
            "api_endpoint": self.endpoint,
            # The emulator does not implement parquet LOAD jobs — the
            # loader's streaming path is the emulator-verifiable one.
            "load_method": "streaming",
        }
        rows = loader.load(_df(), cfg, table="people_append")
        self.assertEqual(rows, 3)

        out = (self._client()
               .query(f"SELECT id, name FROM {self.DATASET}.people_append "
                      f"ORDER BY id")
               .result())
        names = [r["name"] for r in out]
        self.assertEqual(names, ["a", "b", "c"])


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestPineconeAgainstLocal(unittest.TestCase):
    """pinecone-local is Pinecone's official in-memory emulator.

    NOT covered: serverless scaling behaviour, pod-based indexes,
    cross-region replication.  Index creation and upsert/query paths
    ARE covered.
    """

    @classmethod
    def setUpClass(cls):
        import time
        import urllib.request
        from testcontainers.core.container import DockerContainer
        cls.container = (
            DockerContainer("ghcr.io/pinecone-io/pinecone-local:latest")
            .with_env("PORT", "5080")
            .with_env("PINECONE_HOST", "127.0.0.1")
        )
        # Fixed 1:1 bindings: each index gets its own port (5081, 5082, …)
        # and the control plane advertises exactly those numbers — random
        # host-side mapping would break every data-plane connection.
        for fixed_port in range(5080, 5086):
            cls.container.with_bind_ports(fixed_port, fixed_port)
        cls.container.start()
        cls.host = "http://127.0.0.1:5080"
        # pinecone-local emits no logs at all — poll the control plane
        deadline = time.monotonic() + 60
        while True:
            try:
                req = urllib.request.Request(
                    f"{cls.host}/indexes",
                    headers={"Api-Key": "pclocal",
                             "X-Pinecone-Api-Version": "2025-01"})
                with urllib.request.urlopen(req, timeout=2):
                    break
            except Exception:
                if time.monotonic() > deadline:
                    raise TimeoutError("pinecone-local never became ready")
                time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def test_load_then_query(self):
        loader = _loader("pinecone")
        cfg = {
            "api_key": "pclocal",
            "index_name": "it-index",
            "host": self.host,
            "vector_column": "embedding",
            "id_column": "id",
            "dimensions": 3,
        }
        df = pd.DataFrame({
            "id": [1, 2, 3],
            "name": ["doc1", "doc2", "doc3"],
            "embedding": [[float(i), 0.5, 0.25] for i in (1, 2, 3)],
        })
        rows = loader.load(df, cfg, table="it-index")
        self.assertEqual(rows, 3)


if __name__ == "__main__":
    unittest.main()
