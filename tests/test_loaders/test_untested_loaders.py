"""
Tests for loaders that lacked dedicated coverage: Athena, Delta Lake,
Iceberg, Fabric, Kafka, S3, SFTP, CockroachDB, PostGIS, Firebolt,
LanceDB, BigQuery Vector, Snowflake Vector.

Each test mocks the SDK so no real connections are needed. Covers:
config validation, dry_run guard, governance logging, and empty df.

Revision history
────────────────
1.0   2026-06-09   Initial release.
1.1   2026-06-10   Fix: stub optional SDK modules in sys.modules so lazy
                    imports inside load() don't raise ModuleNotFoundError.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.exceptions import ConfigValidationError


def _ensure_mock_module(*names):
    """Insert a MagicMock module into sys.modules for each name that
    isn't already importable.  Uses MagicMock so that attribute access
    (patch targets, from-imports) auto-creates sub-mocks.  Handles
    dotted names by creating parent packages as needed.
    Skips names that are already importable to avoid clobbering real
    libraries installed in the environment."""
    from importlib.util import find_spec
    for dotted in names:
        try:
            if find_spec(dotted) is not None:
                continue
        except (ModuleNotFoundError, ValueError):
            pass
        parts = dotted.split(".")
        for i in range(len(parts)):
            partial = ".".join(parts[: i + 1])
            if partial not in sys.modules:
                mock_mod = MagicMock()
                mock_mod.__path__ = []
                mock_mod.__name__ = partial
                sys.modules[partial] = mock_mod


_ensure_mock_module(
    "deltalake",
    "pyiceberg",
    "adlfs",
    "kafka",
    "lancedb",
    "google.cloud.bigquery",
    "snowflake.sqlalchemy",
    "snowflake.connector",
)

_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})
_EMPTY = pd.DataFrame()


def _gov():
    return MagicMock()


# ── Athena ──────────────────────────────────────────────────────────────────

class TestAthenaLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.constants.HAS_S3", True):
            from pipeline.loaders.athena_loader import AthenaLoader
            return AthenaLoader(_gov(), dry_run=dry_run)

    def test_missing_config_raises(self):
        loader = self._make()
        with self.assertRaises((ValueError, ConfigValidationError)):
            loader.load(_DF, {}, table="t")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"database": "db", "s3_data_dir": "s3://b/d", "s3_staging_dir": "s3://b/s"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)

    def test_empty_df_returns_zero(self):
        loader = self._make()
        cfg = {"database": "db", "s3_data_dir": "s3://b/d", "s3_staging_dir": "s3://b/s"}
        with patch("boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock()
            result = loader.load(_EMPTY, cfg, table="t")
        self.assertEqual(result, 0)

    def test_governance_event_emitted(self):
        gov = _gov()
        with patch("pipeline.constants.HAS_S3", True):
            from pipeline.loaders.athena_loader import AthenaLoader
            loader = AthenaLoader(gov, dry_run=False)
        cfg = {"database": "db", "s3_data_dir": "s3://bkt/data", "s3_staging_dir": "s3://bkt/stg"}
        mock_s3 = MagicMock()
        mock_athena = MagicMock()
        mock_athena.start_query_execution.return_value = {"QueryExecutionId": "x"}
        mock_athena.get_query_execution.return_value = {
            "QueryExecution": {"Status": {"State": "SUCCEEDED"}}
        }

        def _client(svc, **kw):
            return mock_s3 if svc == "s3" else mock_athena

        with patch("boto3.client", side_effect=_client):
            loader.load(_DF, cfg, table="t")
        gov._event.assert_called_once()


# ── Delta Lake ──────────────────────────────────────────────────────────────

class TestDeltaLakeLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.loaders.delta_lake_loader.HAS_DELTALAKE", True):
            from pipeline.loaders.delta_lake_loader import DeltaLakeLoader
            return DeltaLakeLoader(_gov(), dry_run=dry_run)

    def test_missing_path_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {}, table="t")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        result = loader.load(_DF, {"path": "/tmp/delta"}, table="t")
        self.assertEqual(result, 0)

    def test_empty_df_returns_zero(self):
        loader = self._make()
        with patch("deltalake.write_deltalake"):
            result = loader.load(_EMPTY, {"path": "/tmp/delta"}, table="t")
        self.assertEqual(result, 0)

    def test_governance_event_on_append(self):
        gov = _gov()
        with patch("pipeline.loaders.delta_lake_loader.HAS_DELTALAKE", True):
            from pipeline.loaders.delta_lake_loader import DeltaLakeLoader
            loader = DeltaLakeLoader(gov, dry_run=False)
        with patch("deltalake.write_deltalake"):
            loader.load(_DF, {"path": "/tmp/delta"}, table="t")
        gov._event.assert_called_once()

    def test_invalid_if_exists_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {"path": "/tmp/d"}, table="t", if_exists="invalid")


# ── Iceberg ─────────────────────────────────────────────────────────────────

class TestIcebergLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.loaders.iceberg_loader.HAS_ICEBERG", True):
            from pipeline.loaders.iceberg_loader import IcebergLoader
            return IcebergLoader(_gov(), dry_run=dry_run)

    def test_missing_namespace_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {}, table="t")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        result = loader.load(_DF, {"namespace": "ns"}, table="t")
        self.assertEqual(result, 0)

    def test_empty_df_returns_zero(self):
        loader = self._make()
        mock_catalog = MagicMock()
        with patch.object(loader, "_load_catalog", return_value=mock_catalog):
            result = loader.load(_EMPTY, {"namespace": "ns"}, table="t")
        self.assertEqual(result, 0)

    def test_governance_event_emitted(self):
        gov = _gov()
        with patch("pipeline.loaders.iceberg_loader.HAS_ICEBERG", True):
            from pipeline.loaders.iceberg_loader import IcebergLoader
            loader = IcebergLoader(gov, dry_run=False)
        mock_catalog = MagicMock()
        mock_catalog.table_exists.return_value = True
        mock_table = MagicMock()
        mock_catalog.load_table.return_value = mock_table
        with patch.object(loader, "_load_catalog", return_value=mock_catalog):
            loader.load(_DF, {"namespace": "ns"}, table="t")
        gov._event.assert_called_once()


# ── Microsoft Fabric ────────────────────────────────────────────────────────

class TestMicrosoftFabricLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.loaders.microsoft_fabric_loader.HAS_FABRIC", True):
            from pipeline.loaders.microsoft_fabric_loader import MicrosoftFabricLoader
            return MicrosoftFabricLoader(_gov(), dry_run=dry_run)

    def test_missing_workspace_raises(self):
        loader = self._make()
        with self.assertRaises((ValueError, ConfigValidationError)):
            loader.load(_DF, {}, table="t")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"workspace_id": "w", "lakehouse_id": "l"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)

    def test_empty_df_returns_zero(self):
        loader = self._make()
        cfg = {"workspace_id": "w", "lakehouse_id": "l"}
        with patch("adlfs.AzureBlobFileSystem"):
            result = loader.load(_EMPTY, cfg, table="t")
        self.assertEqual(result, 0)

    def test_governance_event_emitted(self):
        gov = _gov()
        with patch("pipeline.loaders.microsoft_fabric_loader.HAS_FABRIC", True):
            from pipeline.loaders.microsoft_fabric_loader import MicrosoftFabricLoader
            loader = MicrosoftFabricLoader(gov, dry_run=False)
        cfg = {"workspace_id": "w", "lakehouse_id": "l"}
        mock_fs = MagicMock()
        mock_fs.open.return_value.__enter__ = MagicMock()
        mock_fs.open.return_value.__exit__ = MagicMock()
        with patch("adlfs.AzureBlobFileSystem", return_value=mock_fs):
            loader.load(_DF, cfg, table="t")
        gov._event.assert_called_once()


# ── Kafka ───────────────────────────────────────────────────────────────────

class TestKafkaLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.loaders.kafka_loader.HAS_KAFKA_LOADER", True):
            from pipeline.loaders.kafka_loader import KafkaLoader
            return KafkaLoader(_gov(), dry_run=dry_run)

    def test_missing_bootstrap_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {"topic": "t"}, table="")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"bootstrap_servers": "localhost:9092", "topic": "t"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)

    def test_governance_events_emitted(self):
        gov = _gov()
        with patch("pipeline.loaders.kafka_loader.HAS_KAFKA_LOADER", True):
            from pipeline.loaders.kafka_loader import KafkaLoader
            loader = KafkaLoader(gov, dry_run=False)
        cfg = {"bootstrap_servers": "localhost:9092", "topic": "t"}
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_producer.send.return_value = mock_future
        with patch.object(loader, "_build_producer", return_value=mock_producer):
            loader.load(_DF, cfg, table="t")
        gov.load_complete.assert_called_once()

    def test_invalid_if_exists_raises(self):
        loader = self._make()
        cfg = {"bootstrap_servers": "localhost:9092", "topic": "t"}
        with self.assertRaises(ValueError):
            loader.load(_DF, cfg, table="t", if_exists="replace")


# ── S3 ──────────────────────────────────────────────────────────────────────

class TestS3Loader(unittest.TestCase):

    def _make(self, dry_run=False):
        from pipeline.loaders.s3_loader import S3Loader
        return S3Loader(_gov(), dry_run=dry_run)

    def test_missing_bucket_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {}, table="t")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"bucket": "bkt", "key": "data.parquet"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)

    def test_empty_df_returns_zero(self):
        loader = self._make()
        cfg = {"bucket": "bkt", "key": "data.parquet"}
        result = loader.load(_EMPTY, cfg, table="t")
        self.assertEqual(result, 0)

    def test_invalid_format_raises(self):
        loader = self._make()
        cfg = {"bucket": "bkt", "key": "data.xml", "format": "xml"}
        with self.assertRaises(ValueError):
            loader.load(_DF, cfg, table="t")

    def test_governance_event_emitted(self):
        gov = _gov()
        from pipeline.loaders.s3_loader import S3Loader
        loader = S3Loader(gov, dry_run=False)
        cfg = {"bucket": "bkt", "key": "data.csv", "format": "csv", "provider": "s3"}
        with patch("boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock()
            loader.load(_DF, cfg, table="t")
        gov._event.assert_called_once()


# ── SFTP ────────────────────────────────────────────────────────────────────

class TestSFTPLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.constants.HAS_SFTP", True):
            from pipeline.loaders.sftp_loader import SFTPLoader
            return SFTPLoader(_gov(), dry_run=dry_run)

    def test_missing_host_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {"username": "u"}, table="t")

    def test_missing_username_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {"host": "h"}, table="t")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"host": "h", "username": "u", "remote_path": "/data/f.csv"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)

    def test_empty_df_returns_zero(self):
        loader = self._make()
        cfg = {"host": "h", "username": "u", "remote_path": "/data/f.csv", "password": "p", "auto_add_host_key": True}
        mock_ssh = MagicMock()
        mock_sftp = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp
        mock_sftp.file.return_value.__enter__ = MagicMock()
        mock_sftp.file.return_value.__exit__ = MagicMock()
        with patch("paramiko.SSHClient", return_value=mock_ssh):
            result = loader.load(_EMPTY, cfg, table="t")
        self.assertEqual(result, 0)

    def test_governance_event_emitted(self):
        gov = _gov()
        with patch("pipeline.constants.HAS_SFTP", True):
            from pipeline.loaders.sftp_loader import SFTPLoader
            loader = SFTPLoader(gov, dry_run=False)
        cfg = {"host": "h", "username": "u", "remote_path": "/data/f.csv", "password": "p", "auto_add_host_key": True}
        mock_ssh = MagicMock()
        mock_sftp = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp
        mock_sftp.file.return_value.__enter__ = MagicMock()
        mock_sftp.file.return_value.__exit__ = MagicMock()
        with patch("paramiko.SSHClient", return_value=mock_ssh):
            loader.load(_DF, cfg, table="t")
        gov._event.assert_called_once()

    def test_invalid_format_raises(self):
        loader = self._make()
        cfg = {"host": "h", "username": "u", "remote_path": "/f.xml", "format": "xml"}
        with self.assertRaises(ValueError):
            loader.load(_DF, cfg, table="t")


# ── PostGIS ─────────────────────────────────────────────────────────────────

class TestPostGISLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        from pipeline.loaders.postgis_loader import PostGISLoader
        return PostGISLoader(_gov(), dry_run=dry_run)

    def test_missing_host_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {}, table="t")

    def test_missing_table_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {"host": "h"}, table="")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"host": "h", "user": "u", "password": "p", "db_name": "d"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)

    def test_empty_df_returns_zero(self):
        loader = self._make()
        cfg = {"host": "h", "user": "u", "password": "p", "db_name": "d"}
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock()
        with patch("sqlalchemy.create_engine", return_value=mock_engine):
            result = loader.load(_EMPTY, cfg, table="t")
        self.assertEqual(result, 0)

    def test_sql_injection_in_table_name_rejected(self):
        loader = self._make()
        cfg = {"host": "h", "user": "u", "password": "p", "db_name": "d"}
        with self.assertRaises(ValueError):
            loader.load(_DF, cfg, table="t; DROP TABLE users")


# ── CockroachDB ─────────────────────────────────────────────────────────────

class TestCockroachDBLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        from pipeline.loaders.cockroachdb_loader import CockroachDBLoader
        return CockroachDBLoader(_gov(), dry_run=dry_run)

    def test_missing_host_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {}, table="t")

    def test_missing_table_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {"host": "h", "db_name": "d"}, table="")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"host": "h", "user": "u", "db_name": "d"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)

    def test_empty_df_returns_zero(self):
        loader = self._make()
        cfg = {"host": "h", "user": "u", "db_name": "d", "password": "p"}
        mock_engine = MagicMock()
        with patch.object(loader, "_engine_scope") as mock_scope:
            mock_scope.return_value.__enter__ = MagicMock(return_value=mock_engine)
            mock_scope.return_value.__exit__ = MagicMock()
            result = loader.load(_EMPTY, cfg, table="t")
        self.assertEqual(result, 0)

    def test_sql_injection_in_table_rejected(self):
        loader = self._make()
        cfg = {"host": "h", "user": "u", "db_name": "d"}
        with self.assertRaises(ValueError):
            loader.load(_DF, cfg, table="t; DROP TABLE x")

    def test_governance_event_emitted(self):
        gov = _gov()
        from pipeline.loaders.cockroachdb_loader import CockroachDBLoader
        loader = CockroachDBLoader(gov, dry_run=False)
        cfg = {"host": "h", "user": "u", "db_name": "d", "password": "p"}
        mock_engine = MagicMock()
        with patch.object(loader, "_engine_scope") as mock_scope:
            mock_scope.return_value.__enter__ = MagicMock(return_value=mock_engine)
            mock_scope.return_value.__exit__ = MagicMock()
            loader.load(_DF, cfg, table="t")
        gov._event.assert_called_once()


# ── LanceDB ─────────────────────────────────────────────────────────────────

class TestLanceDBLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.loaders.vector.lancedb_loader.HAS_LANCEDB", True):
            from pipeline.loaders.vector.lancedb_loader import LanceDBLoader
            return LanceDBLoader(_gov(), dry_run=dry_run)

    def test_missing_uri_raises(self):
        loader = self._make()
        with self.assertRaises((ValueError, ConfigValidationError)):
            loader.load(_DF, {}, table="t")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        result = loader.load(_DF, {"uri": "/tmp/lance"}, table="t")
        self.assertEqual(result, 0)

    def test_governance_events_emitted(self):
        gov = _gov()
        with patch("pipeline.loaders.vector.lancedb_loader.HAS_LANCEDB", True):
            from pipeline.loaders.vector.lancedb_loader import LanceDBLoader
            loader = LanceDBLoader(gov, dry_run=False)
        mock_db = MagicMock()
        mock_db.table_names.return_value = []
        with patch("lancedb.connect", return_value=mock_db):
            loader.load(_DF, {"uri": "/tmp/lance"}, table="t")
        gov.load_complete.assert_called_once()

    def test_invalid_if_exists_raises(self):
        loader = self._make()
        with self.assertRaises(ValueError):
            loader.load(_DF, {"uri": "/tmp/lance"}, table="t", if_exists="invalid")


# ── BigQuery Vector ─────────────────────────────────────────────────────────

class TestBigQueryVectorLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.loaders.vector.bigquery_vector_loader.HAS_BIGQUERY", True):
            from pipeline.loaders.vector.bigquery_vector_loader import BigQueryVectorLoader
            return BigQueryVectorLoader(_gov(), dry_run=dry_run)

    def test_missing_table_raises(self):
        loader = self._make()
        cfg = {"host": "project.dataset"}
        with self.assertRaises(ValueError):
            loader.load(_DF, cfg, table="")

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"host": "project.dataset"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)


# ── Snowflake Vector ────────────────────────────────────────────────────────

class TestSnowflakeVectorLoader(unittest.TestCase):

    def _make(self, dry_run=False):
        with patch("pipeline.loaders.vector.snowflake_vector_loader.HAS_SNOWFLAKE", True):
            from pipeline.loaders.vector.snowflake_vector_loader import SnowflakeVectorLoader
            return SnowflakeVectorLoader(_gov(), dry_run=dry_run)

    def test_dry_run_returns_zero(self):
        loader = self._make(dry_run=True)
        cfg = {"host": "acct.snowflakecomputing.com", "user": "u", "password": "p",
               "database": "db", "schema": "s", "warehouse": "wh"}
        result = loader.load(_DF, cfg, table="t")
        self.assertEqual(result, 0)

    def test_missing_table_raises(self):
        loader = self._make()
        cfg = {"host": "h"}
        with self.assertRaises(ValueError):
            loader.load(_DF, cfg, table="")


if __name__ == "__main__":
    unittest.main()
