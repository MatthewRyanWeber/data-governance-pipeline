"""
Integration test: a partitioned Merkle ledger survives an object-store
round-trip.

Path A's realistic deployment writes per-partition segments to a (local or
shared) filesystem, then collects them to object storage; verification happens
wherever the segments are gathered. This proves the segment artifacts are
portable: govern partitions locally -> upload the whole ledger to MinIO (S3) ->
download to a fresh dir -> verify() still holds, and tamper in the object store
is still caught after the round-trip.

Revision history
────────────────
1.0   2026-06-15   Initial release.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

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


def _partition(k, n=10):
    base = k * n
    return pd.DataFrame({
        "id": range(base, base + n),
        "email": [f"user{base + i}@example.com" for i in range(n)],
    })


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestPartitionedLedgerObjectStore(unittest.TestCase):
    ACCESS, SECRET = "it_access", "it_secret_key"
    BUCKET = "ledger-bucket"

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

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build_local_ledger(self):
        from pipeline.partitioned_ledger import PartitionedLedger
        from pipeline.partitioned_governance import govern_partitions
        local = Path(self.tmp) / "ledger"
        led = PartitionedLedger(local)
        govern_partitions([(f"part-{k:04d}", _partition(k)) for k in range(3)], led)
        self.assertTrue(led.verify())
        return local

    def _upload(self, local: Path, prefix: str):
        for f in local.rglob("*"):
            if f.is_file():
                key = f"{prefix}/{f.relative_to(local).as_posix()}"
                self.client.upload_file(str(f), self.BUCKET, key)

    def _download(self, prefix: str) -> Path:
        dest_root = Path(self.tmp) / "downloaded"
        objs = self.client.list_objects_v2(Bucket=self.BUCKET, Prefix=f"{prefix}/")
        for obj in objs.get("Contents", []):
            key = obj["Key"]
            rel = key[len(prefix) + 1:]
            dest = dest_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            self.client.download_file(self.BUCKET, key, str(dest))
        return dest_root

    def test_round_trip_through_object_store_verifies(self):
        from pipeline.partitioned_ledger import PartitionedLedger
        local = self._build_local_ledger()
        self._upload(local, "run-ok")
        recovered = self._download("run-ok")
        self.assertTrue(PartitionedLedger(recovered).verify())

    def test_tamper_in_object_store_detected_after_round_trip(self):
        from pipeline.partitioned_ledger import PartitionedLedger
        local = self._build_local_ledger()
        self._upload(local, "run-tampered")
        # Overwrite one segment object in the bucket with altered content:
        # change a hashed field of the first event (leaving its stale self_hash).
        import json
        key = "run-tampered/segment-part-0001.jsonl"
        body = self.client.get_object(Bucket=self.BUCKET, Key=key)["Body"].read()
        lines = body.decode("utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["action"] = str(rec.get("action", "X")) + "_TAMPERED"
        lines[0] = json.dumps(rec, sort_keys=True)
        self.client.put_object(
            Bucket=self.BUCKET, Key=key,
            Body=("\n".join(lines) + "\n").encode("utf-8"),
        )
        recovered = self._download("run-tampered")
        self.assertFalse(PartitionedLedger(recovered).verify())


if __name__ == "__main__":
    unittest.main()
