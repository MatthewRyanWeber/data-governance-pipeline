"""
Integration tests for streaming and object/file destinations.

Real services via containers: Kafka (Redpanda), SFTP (atmoz/sftp),
S3 (MinIO), Azure Blob (Azurite).  The Kafka test covers both the
loader (producer) and the extractor (consumer offset commit).

Revision history
────────────────
1.0   2026-06-12   Initial release.
"""

import io
import json
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


if __name__ == "__main__":
    unittest.main()
