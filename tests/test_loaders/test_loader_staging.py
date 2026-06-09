"""
Cloud-staging COPY-path tests for Snowflake, Redshift, and Synapse.

These warehouses bulk-load via an object-store stage (Snowflake internal stage,
Redshift S3, Synapse Blob) then COPY INTO.  The stage clients (boto3 / azure
blob) and the warehouse connection are mocked so the staging + COPY SQL paths
run without real cloud — proprietary warehouses can't be containerised, so
mocking is the only way to cover these branches.

Revision history
────────────────
1.0   2026-06-09   Initial release: PUT/COPY (snowflake), S3 COPY (redshift),
                   Blob COPY (synapse).
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

import pipeline.loaders.redshift_loader as rs_mod
import pipeline.loaders.snowflake_loader as sf_mod
import pipeline.loaders.synapse_loader as syn_mod
from pipeline.loaders.snowflake_loader import SnowflakeLoader
from pipeline.loaders.redshift_loader import RedshiftLoader
from pipeline.loaders.synapse_loader import SynapseLoader

_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})


def _cursor_sql(cursor):
    calls = list(cursor.execute.call_args_list) + list(cursor.executemany.call_args_list)
    return [str(c[0][0]) for c in calls if c[0]]


class TestSnowflakeStaging(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(sf_mod, "HAS_SNOWFLAKE", True):
            self.loader = SnowflakeLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        # COPY INTO returns a result row whose [3] is the loaded row count.
        self.cursor.fetchone.return_value = (None, None, None, 2)
        self.cfg = {"account": "a", "user": "u", "password": "p",
                    "database": "DB", "warehouse": "WH"}

    def test_put_and_copy_into_executed(self):
        with patch.object(self.loader, "_connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, "events", if_exists="append")
        sql = _cursor_sql(self.cursor)
        self.assertTrue(any(s.startswith("PUT file://") for s in sql))
        self.assertTrue(any("COPY INTO" in s and '"DB"."PUBLIC"."EVENTS"' in s for s in sql))
        self.assertTrue(any(s.startswith("REMOVE") for s in sql))
        self.gov.load_complete.assert_called_once_with(2, "events")

    def test_copy_failure_falls_back_to_sql(self):
        # If COPY raises, the loader must fall back to to_sql rather than crash.
        self.cursor.execute.side_effect = [None, Exception("COPY boom")]
        with patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_sql_fallback") as fb:
            self.loader.load(_DF, self.cfg, "events")
        fb.assert_called_once()


class TestRedshiftS3Copy(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(rs_mod, "HAS_REDSHIFT", True):
            self.loader = RedshiftLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p",
                    "s3_bucket": "mybucket", "iam_role": "arn:aws:iam::1:role/r"}

    def test_s3_upload_and_copy_with_iam_role(self):
        s3 = MagicMock()
        with patch("boto3.client", return_value=s3), \
             patch.object(self.loader, "_connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, "events", if_exists="append")
        s3.upload_file.assert_called_once()
        copy = next(s for s in _cursor_sql(self.cursor) if s.startswith("COPY"))
        self.assertIn("FROM 's3://mybucket/", copy)
        self.assertIn("IAM_ROLE 'arn:aws:iam::1:role/r'", copy)
        self.assertIn("GZIP", copy)
        # Staged object is cleaned up afterwards.
        s3.delete_object.assert_called_once()

    def test_copy_without_credentials_falls_back(self):
        s3 = MagicMock()
        cfg = {"host": "h", "database": "d", "user": "u", "password": "p",
               "s3_bucket": "b"}  # no iam_role, no keys
        with patch("boto3.client", return_value=s3), \
             patch.dict("os.environ", {}, clear=True), \
             patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_sql_fallback") as fb:
            self.loader.load(_DF, cfg, "events")
        fb.assert_called_once()


class TestSynapseBlobCopy(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(syn_mod, "HAS_SYNAPSE", True):
            self.loader = SynapseLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p",
                    "storage_account": "acct", "storage_container": "cont",
                    "storage_sas_token": "sas123"}

    def test_blob_upload_and_copy_into(self):
        blob_service = MagicMock()
        blob_client = blob_service.get_blob_client.return_value
        with patch("azure.storage.blob.BlobServiceClient", return_value=blob_service), \
             patch("pyodbc.connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, "events", if_exists="append")
        blob_client.upload_blob.assert_called_once()
        copy = next(s for s in _cursor_sql(self.cursor) if "COPY INTO" in s)
        self.assertIn("acct.blob.core.windows.net/cont", copy)
        self.assertIn("COMPRESSION='GZIP'", copy)


if __name__ == "__main__":
    unittest.main()
