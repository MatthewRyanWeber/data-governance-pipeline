"""
Integration tests for streaming and object/file destinations.

Real services via containers: Kafka (Redpanda), SFTP (atmoz/sftp),
S3 (MinIO), Azure Blob (Azurite).  The Kafka test covers both the
loader (producer) and the extractor (consumer offset commit).

Revision history
────────────────
1.0   2026-06-12   Initial release.
1.1   2026-06-16   Added a dedicated Microsoft Fabric loader test driving the
                   real MicrosoftFabricLoader write path against Azurite (the
                   same ADLS engine that backs the core azure_blob tier), which
                   promotes fabric from experimental to core.
"""

import io
import json
import os
import unittest
from unittest.mock import MagicMock, patch

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
    loader_class, needs_db_type, _ = resolve_loader(db_type)
    if needs_db_type:
        return loader_class(MagicMock(), db_type)
    return loader_class(MagicMock())


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestKafkaIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from testcontainers.kafka import RedpandaContainer

        class _IPv4Redpanda(RedpandaContainer):
            # Redpanda advertises this host in broker metadata; 'localhost'
            # resolves to ::1 first on Windows while Docker only publishes
            # on IPv4, so every producer/consumer connection would time out.
            def get_container_host_ip(self) -> str:
                return "127.0.0.1"

        cls.container = _IPv4Redpanda("redpandadata/redpanda:v24.2.4")
        cls.container.start()
        cls.bootstrap = cls.container.get_bootstrap_server()

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def test_loader_publishes_and_messages_arrive(self):
        loader = _loader("kafka")
        cfg = {"bootstrap_servers": self.bootstrap, "topic": "it_topic"}
        rows = loader.load(_df(), cfg, table="it_topic")
        self.assertEqual(rows, 3)

        from kafka import KafkaConsumer
        consumer = KafkaConsumer(
            "it_topic",
            bootstrap_servers=self.bootstrap,
            auto_offset_reset="earliest",
            consumer_timeout_ms=15000,
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        )
        try:
            received = [m.value for m in consumer]
        finally:
            consumer.close()
        self.assertEqual(len(received), 3)
        self.assertEqual({r["name"] for r in received}, {"a", "b", "c"})

    def test_extractor_commits_offsets_between_runs(self):
        loader = _loader("kafka")
        cfg = {"bootstrap_servers": self.bootstrap, "topic": "it_offsets"}
        loader.load(_df(), cfg, table="it_offsets")

        from pipeline.streaming.kafka_extractor import KafkaStreamExtractor

        def _consume_all(extractor):
            batches = []
            for batch in extractor.consume():
                batches.append(batch)
            return batches

        first = KafkaStreamExtractor(
            MagicMock(), bootstrap_servers=self.bootstrap,
            group_id="it_group", topics=["it_offsets"],
            batch_size=10, timeout_ms=2000,
        )
        first_batches = _consume_all(first)
        total_first = sum(len(b) for b in first_batches)
        self.assertEqual(total_first, 3)

        # A second consumer in the same group must see nothing — the
        # offsets were committed after the caller consumed each batch.
        second = KafkaStreamExtractor(
            MagicMock(), bootstrap_servers=self.bootstrap,
            group_id="it_group", topics=["it_offsets"],
            batch_size=10, timeout_ms=2000,
        )
        second_batches = _consume_all(second)
        total_second = sum(len(b) for b in second_batches)
        self.assertEqual(total_second, 0)


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestSFTPIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("atmoz/sftp:alpine")
            .with_command("ituser:itpass:::upload")
            .with_exposed_ports(22)
        )
        cls.container.start()
        wait_for_logs(cls.container, "Server listening on", timeout=60)
        cls.cfg = {
            "host": "127.0.0.1",
            "port": int(cls.container.get_exposed_port(22)),
            "username": "ituser",
            "password": "itpass",
            "remote_path": "upload/people.csv",
            "format": "csv",
            "auto_add_host_key": True,
        }

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def test_upload_then_download_matches(self):
        loader = _loader("sftp")
        rows = loader.load(_df(), self.cfg, table="people")
        self.assertEqual(rows, 3)

        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect("127.0.0.1", port=self.cfg["port"],
                       username="ituser", password="itpass")
        try:
            sftp = client.open_sftp()
            with sftp.file("upload/people.csv", "r") as fh:
                out = pd.read_csv(io.BytesIO(fh.read()))
        finally:
            client.close()
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestMinIOS3Integration(unittest.TestCase):

    ACCESS, SECRET = "it_access", "it_secret_key"

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("minio/minio:latest")
            .with_env("MINIO_ROOT_USER", cls.ACCESS)
            .with_env("MINIO_ROOT_PASSWORD", cls.SECRET)
            .with_command("server /data")
            .with_exposed_ports(9000)
        )
        cls.container.start()
        wait_for_logs(cls.container, "API:", timeout=60)
        cls.endpoint = (
            f"http://127.0.0.1:{cls.container.get_exposed_port(9000)}"
        )
        import boto3
        cls.client = boto3.client(
            "s3", endpoint_url=cls.endpoint,
            aws_access_key_id=cls.ACCESS, aws_secret_access_key=cls.SECRET,
        )
        cls.client.create_bucket(Bucket="it-bucket")

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _cfg(self, key, fmt):
        return {
            "bucket": "it-bucket",
            "key": key,
            "format": fmt,
            "provider": "s3",
            "endpoint_url": self.endpoint,
            "aws_access_key": self.ACCESS,
            "aws_secret_key": self.SECRET,
        }

    def test_parquet_object_round_trip(self):
        loader = _loader("s3")
        rows = loader.load(_df(), self._cfg("data/people.parquet", "parquet"),
                           table="people")
        self.assertEqual(rows, 3)
        obj = self.client.get_object(Bucket="it-bucket",
                                     Key="data/people.parquet")
        out = pd.read_parquet(io.BytesIO(obj["Body"].read()))
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_csv_object_round_trip(self):
        loader = _loader("s3")
        rows = loader.load(_df(), self._cfg("data/people.csv", "csv"),
                           table="people")
        self.assertEqual(rows, 3)
        obj = self.client.get_object(Bucket="it-bucket", Key="data/people.csv")
        out = pd.read_csv(io.BytesIO(obj["Body"].read()))
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestGCSFakeServerIntegration(unittest.TestCase):
    """GCS via the S3Loader gcs provider, against fake-gcs-server.

    fake-gcs-server is the standard local Google Cloud Storage API server (the
    GCS analogue of MinIO for S3 / Azurite for Azure, both already core). The
    loader writes through gcsfs; read-back is via the server's raw JSON API — a
    different client than the write — so the round-trip is genuinely verified.
    """

    BUCKET = "it-gcs"

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("fsouza/fake-gcs-server:latest")
            .with_command("-scheme http -host 0.0.0.0 -port 4443 -backend memory")
            .with_exposed_ports(4443)
        )
        cls.container.start()
        wait_for_logs(cls.container, "server started", timeout=60)
        cls.endpoint = f"http://127.0.0.1:{cls.container.get_exposed_port(4443)}"
        import requests
        resp = requests.post(
            f"{cls.endpoint}/storage/v1/b",
            params={"project": "test"}, json={"name": cls.BUCKET}, timeout=30,
        )
        assert resp.status_code == 200, resp.text

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _cfg(self, key, fmt):
        return {
            "bucket": self.BUCKET,
            "key": key,
            "format": fmt,
            "provider": "gcs",
            "storage_options": {
                "project": "test",
                "token": "anon",
                "endpoint_url": self.endpoint,
            },
        }

    def _read_back(self, key):
        import requests
        from urllib.parse import quote
        url = f"{self.endpoint}/storage/v1/b/{self.BUCKET}/o/{quote(key, safe='')}"
        resp = requests.get(url, params={"alt": "media"}, timeout=30)
        resp.raise_for_status()
        return resp.content

    def test_parquet_object_round_trip(self):
        loader = _loader("gcs")
        rows = loader.load(_df(), self._cfg("data/people.parquet", "parquet"),
                           table="people")
        self.assertEqual(rows, 3)
        out = pd.read_parquet(io.BytesIO(self._read_back("data/people.parquet")))
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_csv_object_round_trip(self):
        loader = _loader("gcs")
        rows = loader.load(_df(), self._cfg("data/people.csv", "csv"),
                           table="people")
        self.assertEqual(rows, 3)
        out = pd.read_csv(io.BytesIO(self._read_back("data/people.csv")))
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestAzuriteAzureBlobIntegration(unittest.TestCase):
    """azure_blob via the S3Loader azure provider, against Azurite.

    Also verifies the Fabric loader's storage path uses the same adlfs
    stack — Fabric-specific semantics are NOT covered (emulator tier).
    """

    # Azurite's documented well-known development credentials
    ACCOUNT = "devstoreaccount1"
    KEY = ("Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz"
           "4I6tq/K1SZFPTOtr/KBHBeksoGMGw==")

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("mcr.microsoft.com/azure-storage/azurite:latest")
            .with_command("azurite-blob --blobHost 0.0.0.0 --skipApiVersionCheck")
            .with_exposed_ports(10000)
        )
        cls.container.start()
        wait_for_logs(cls.container, "successfully listens", timeout=60)
        cls.port = int(cls.container.get_exposed_port(10000))
        cls.conn_str = (
            "DefaultEndpointsProtocol=http;"
            f"AccountName={cls.ACCOUNT};AccountKey={cls.KEY};"
            f"BlobEndpoint=http://127.0.0.1:{cls.port}/{cls.ACCOUNT};"
        )
        from azure.storage.blob import BlobServiceClient
        service = BlobServiceClient.from_connection_string(cls.conn_str)
        service.create_container("it-container")

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def test_blob_round_trip(self):
        loader = _loader("azure_blob")
        cfg = {
            "bucket": "it-container",
            "key": "data/people.csv",
            "format": "csv",
            "provider": "azure",
            "storage_options": {"connection_string": self.conn_str},
        }
        rows = loader.load(_df(), cfg, table="people")
        self.assertEqual(rows, 3)

        from azure.storage.blob import BlobServiceClient
        service = BlobServiceClient.from_connection_string(self.conn_str)
        blob = service.get_blob_client("it-container", "data/people.csv")
        out = pd.read_csv(io.BytesIO(blob.download_blob().readall()))
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestFabricAzuriteIntegration(unittest.TestCase):
    """Microsoft Fabric loader against Azurite.

    Drives the real MicrosoftFabricLoader write path (OneLake path layout +
    adlfs + parquet read/concat/rewrite) against Azurite — Microsoft's official
    storage emulator, the same ADLS engine that backs the core azure_blob tier.
    OneLake *service* semantics (auth, workspace provisioning) are out of scope,
    exactly as real-Azure quirks are out of scope for azure_blob.
    """

    ACCOUNT = "devstoreaccount1"
    KEY = ("Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz"
           "4I6tq/K1SZFPTOtr/KBHBeksoGMGw==")
    # adlfs treats the first path segment as the container; the Fabric loader
    # builds "<workspace_id>/<lakehouse_id>.Lakehouse/...", so workspace_id is
    # the container name and must satisfy Azure's naming rules.
    WORKSPACE = "fabric-ws"
    LAKEHOUSE = "lh1"

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("mcr.microsoft.com/azure-storage/azurite:latest")
            .with_command("azurite-blob --blobHost 0.0.0.0 --skipApiVersionCheck")
            .with_exposed_ports(10000)
        )
        cls.container.start()
        wait_for_logs(cls.container, "successfully listens", timeout=60)
        cls.port = int(cls.container.get_exposed_port(10000))
        cls.conn_str = (
            "DefaultEndpointsProtocol=http;"
            f"AccountName={cls.ACCOUNT};AccountKey={cls.KEY};"
            f"BlobEndpoint=http://127.0.0.1:{cls.port}/{cls.ACCOUNT};"
        )
        from azure.storage.blob import BlobServiceClient
        cls.service = BlobServiceClient.from_connection_string(cls.conn_str)
        cls.service.create_container(cls.WORKSPACE)

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _cfg(self):
        return {
            "workspace_id": self.WORKSPACE,
            "lakehouse_id": self.LAKEHOUSE,
            "path": "Files",
            "format": "parquet",
            "connection_string": self.conn_str,
        }

    def _read_back(self, table):
        blob_path = f"{self.LAKEHOUSE}.Lakehouse/Files/{table}.parquet"
        blob = self.service.get_blob_client(self.WORKSPACE, blob_path)
        return pd.read_parquet(io.BytesIO(blob.download_blob().readall()))

    def test_parquet_write_lands_in_onelake_path(self):
        loader = _loader("fabric")
        rows = loader.load(_df(), self._cfg(), table="people")
        self.assertEqual(rows, 3)
        out = self._read_back("people")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_append_reads_concats_and_rewrites(self):
        loader = _loader("fabric")
        loader.load(_df(), self._cfg(), table="appended")
        # Append must not overwrite — the loader reads the existing file,
        # concatenates, and rewrites. Expect 3 + 3 = 6 rows.
        rows = loader.load(_df(ids=(4, 5, 6), names=("d", "e", "f")),
                           self._cfg(), table="appended", if_exists="append")
        self.assertEqual(rows, 3)
        out = self._read_back("appended")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c", "d", "e", "f"])

    def test_replace_overwrites_existing_file(self):
        loader = _loader("fabric")
        loader.load(_df(), self._cfg(), table="replaced")
        rows = loader.load(_df(ids=(9,), names=("z",)),
                           self._cfg(), table="replaced", if_exists="replace")
        self.assertEqual(rows, 1)
        out = self._read_back("replaced")
        self.assertEqual(out["name"].tolist(), ["z"])


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestAthenaS3StagingIntegration(unittest.TestCase):
    """Athena loader's S3 staging path against MinIO (a real S3 engine).

    Proves the data-plane half — the parquet staging write and the replace-mode
    prefix delete — lands correctly in a real object store. The Athena control
    plane (start_query_execution / MSCK REPAIR) has no free real engine, so it
    is mocked here; Athena therefore stays in the experimental tier — this test
    is stronger evidence, not a core promotion.
    """

    ACCESS, SECRET = "it_access", "it_secret_key"
    BUCKET = "it-athena"

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("minio/minio:latest")
            .with_env("MINIO_ROOT_USER", cls.ACCESS)
            .with_env("MINIO_ROOT_PASSWORD", cls.SECRET)
            .with_command("server /data")
            .with_exposed_ports(9000)
        )
        cls.container.start()
        wait_for_logs(cls.container, "API:", timeout=60)
        cls.endpoint = f"http://127.0.0.1:{cls.container.get_exposed_port(9000)}"
        import boto3
        cls.client = boto3.client(
            "s3", endpoint_url=cls.endpoint,
            aws_access_key_id=cls.ACCESS, aws_secret_access_key=cls.SECRET,
        )
        cls.client.create_bucket(Bucket=cls.BUCKET)

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _cfg(self, prefix):
        # Each test gets its own data prefix so the shared bucket can't leak
        # objects across tests (they run in the same class-scoped MinIO).
        return {
            "database": "it_db",
            "s3_data_dir": f"s3://{self.BUCKET}/{prefix}",
            "s3_staging_dir": f"s3://{self.BUCKET}/staging",
            "endpoint_url": self.endpoint,
            "aws_access_key": self.ACCESS,
            "aws_secret_key": self.SECRET,
            "region": "us-east-1",
        }

    def _patched_boto3(self):
        """Patch boto3.client so 's3' hits real MinIO and 'athena' is mocked."""
        import boto3
        real_client = boto3.client

        def _factory(service, **kw):
            if service == "athena":
                m = MagicMock()
                m.start_query_execution.return_value = {"QueryExecutionId": "q1"}
                m.get_query_execution.return_value = {
                    "QueryExecution": {"Status": {"State": "SUCCEEDED"}}
                }
                return m
            return real_client(service, **kw)

        return patch("boto3.client", side_effect=_factory)

    def _objects_under(self, prefix):
        resp = self.client.list_objects_v2(Bucket=self.BUCKET, Prefix=f"{prefix}/")
        return [o["Key"] for o in resp.get("Contents", [])]

    def test_staging_write_lands_in_s3(self):
        loader = _loader("athena")
        with self._patched_boto3():
            rows = loader.load(_df(), self._cfg("write"), table="people")
        self.assertEqual(rows, 3)
        keys = self._objects_under("write")
        self.assertEqual(len(keys), 1)
        obj = self.client.get_object(Bucket=self.BUCKET, Key=keys[0])
        out = pd.read_parquet(io.BytesIO(obj["Body"].read()))
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_replace_deletes_prior_objects(self):
        loader = _loader("athena")
        with self._patched_boto3():
            loader.load(_df(), self._cfg("replace"), table="people")
            # replace must delete the prior staged object before writing the
            # new one — otherwise replace silently behaves like append.
            loader.load(_df(ids=(9,), names=("z",)), self._cfg("replace"),
                        table="people", if_exists="replace")
        keys = self._objects_under("replace")
        self.assertEqual(len(keys), 1)
        obj = self.client.get_object(Bucket=self.BUCKET, Key=keys[0])
        out = pd.read_parquet(io.BytesIO(obj["Body"].read()))
        self.assertEqual(out["name"].tolist(), ["z"])


if __name__ == "__main__":
    unittest.main()
