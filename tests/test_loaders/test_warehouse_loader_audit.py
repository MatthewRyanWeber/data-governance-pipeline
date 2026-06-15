"""
Audited-bug regression tests for the Redshift and Synapse warehouse loaders.

Connection/cloud-SDK layers are mocked (no live warehouse, boto3, or Azure):
  - R-2 / SY-2: the upsert stage DROP runs in finally even when MERGE raises,
    so a failed MERGE cannot leak the staging table permanently.
  - R-1 / SY-1: a transient COPY/blob error in append mode does not re-append
    (no to_sql fallback) and propagates; the 'replace' stage-copy path still
    falls back safely.
  - R-3 / SY-3: a 120-char table name yields a staging name / object key whose
    table portion is bounded under the warehouse identifier limit.
  - SY-4: blob_client=None guard — a BlobServiceClient setup failure surfaces
    the real error instead of a NameError in the cleanup finally.

Revision history
────────────────
1.0   2026-06-14   Initial release: R-1/R-2/R-3 and SY-1/SY-2/SY-3/SY-4 coverage.
"""

import re
import sys
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

import pipeline.loaders.redshift_loader as rs_mod
import pipeline.loaders.synapse_loader as syn_mod
from pipeline.loaders.redshift_loader import RedshiftLoader
from pipeline.loaders.synapse_loader import SynapseLoader

_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})


def _cursor_sql(cursor):
    """All SQL strings passed to a DB-API cursor."""
    calls = list(cursor.execute.call_args_list) + list(cursor.executemany.call_args_list)
    return [str(c[0][0]) for c in calls if c[0]]


class TestRedshiftUpsertStageDrop(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(rs_mod, "HAS_REDSHIFT", True):
            self.loader = RedshiftLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p"}

    def test_stage_dropped_even_when_merge_raises(self):
        """R-2: a MERGE failure must still drop the stage in finally."""
        def execute(sql, *args, **kwargs):
            if "MERGE INTO" in str(sql):
                raise RuntimeError("MERGE failed")
            return MagicMock()

        self.cursor.execute.side_effect = execute
        with patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            with self.assertRaises(RuntimeError):
                self.loader.load(_DF, self.cfg, "t", natural_keys=["id"])
        dropped = [s for s in _cursor_sql(self.cursor)
                   if "DROP TABLE IF EXISTS" in s and "__stage__" in s]
        self.assertTrue(dropped, "stage DROP must run in finally on MERGE failure")

    def test_long_table_name_yields_bounded_staging_name(self):
        """R-3: a 120-char table must produce a bounded staging identifier."""
        long_table = "t" * 120
        with patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            self.loader.load(_DF, self.cfg, long_table, natural_keys=["id"])
        merge = next(s for s in _cursor_sql(self.cursor) if "MERGE INTO" in s)
        stage_ident = re.search(r't+__stage__\d+', merge).group(0)
        self.assertLessEqual(len(stage_ident), 127)
        self.assertIn("t" * 100 + "__stage__", stage_ident)


class TestRedshiftS3CopyAppendSafety(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(rs_mod, "HAS_REDSHIFT", True):
            self.loader = RedshiftLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p",
                    "s3_bucket": "b", "iam_role": "arn:aws:iam::1:role/r"}

    def test_append_copy_failure_does_not_reappend_and_propagates(self):
        """R-1: a transient COPY failure in append mode must not fall back to
        to_sql(append) — re-appending would duplicate every landed row."""
        def execute(sql, *args, **kwargs):
            if "COPY" in str(sql):
                raise RuntimeError("transient COPY failure")
            return MagicMock()

        self.cursor.execute.side_effect = execute
        with patch.dict(sys.modules, {"boto3": MagicMock()}), \
             patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_sql_fallback") as fallback, \
             patch("pandas.DataFrame.to_csv"), \
             patch("os.unlink"):
            with self.assertRaises(RuntimeError):
                self.loader.load(_DF, self.cfg, "events", if_exists="append")
        fallback.assert_not_called()

    def test_replace_copy_failure_still_falls_back(self):
        """R-1: the 'replace' stage-copy path truncates on write, so a COPY
        failure there may safely fall back to to_sql."""
        def execute(sql, *args, **kwargs):
            if "COPY" in str(sql):
                raise RuntimeError("transient COPY failure")
            return MagicMock()

        self.cursor.execute.side_effect = execute
        with patch.dict(sys.modules, {"boto3": MagicMock()}), \
             patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_sql_fallback") as fallback, \
             patch("pandas.DataFrame.to_csv"), \
             patch("os.unlink"):
            self.loader._s3_copy(_DF, self.cfg, "events", "replace")
        fallback.assert_called_once()

    def test_long_table_name_yields_bounded_s3_key(self):
        """R-3: the S3 key's table portion must be bounded under the limit."""
        long_table = "t" * 120
        captured = {}
        boto3 = MagicMock()
        boto3.client.return_value.upload_file.side_effect = (
            lambda path, bucket, key: captured.__setitem__("key", key)
        )
        with patch.dict(sys.modules, {"boto3": boto3}), \
             patch.object(self.loader, "_connect", return_value=self.conn), \
             patch("pandas.DataFrame.to_csv"), \
             patch("os.unlink"):
            self.loader._s3_copy(_DF, self.cfg, long_table, "replace")
        table_part = re.search(r'/(t+)_\d+\.csv\.gz', captured["key"]).group(1)
        self.assertEqual(len(table_part), 100)


class TestSynapseUpsertStageDrop(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(syn_mod, "HAS_SYNAPSE", True):
            self.loader = SynapseLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p"}

    def test_stage_dropped_even_when_merge_raises(self):
        """SY-2: a MERGE failure must still drop the stage in finally."""
        def execute(sql, *args, **kwargs):
            if "MERGE" in str(sql) and "USING" in str(sql):
                raise RuntimeError("MERGE failed")
            return MagicMock()

        self.cursor.execute.side_effect = execute
        with patch.object(self.loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"), \
             patch("pyodbc.connect", return_value=self.conn):
            with self.assertRaises(RuntimeError):
                self.loader.load(_DF, self.cfg, "t", natural_keys=["id"])
        dropped = [s for s in _cursor_sql(self.cursor)
                   if "DROP TABLE IF EXISTS" in s and "__stage__" in s]
        self.assertTrue(dropped, "stage DROP must run in finally on MERGE failure")

    def test_long_table_name_yields_bounded_staging_name(self):
        """SY-3: a 120-char table must produce a bounded staging identifier."""
        long_table = "t" * 120
        with patch.object(self.loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"), \
             patch("pyodbc.connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, long_table, natural_keys=["id"])
        merge = next(s for s in _cursor_sql(self.cursor)
                     if "MERGE" in s and "USING" in s)
        stage_ident = re.search(r't+__stage__\d+', merge).group(0)
        self.assertLessEqual(len(stage_ident), 128)
        self.assertIn("t" * 100 + "__stage__", stage_ident)


class TestSynapseBlobCopyAppendSafety(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(syn_mod, "HAS_SYNAPSE", True):
            self.loader = SynapseLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p",
                    "storage_account": "acct", "storage_container": "c",
                    "storage_sas_token": "sas"}

    def _patch_blob_ok(self):
        """Patch azure.storage.blob so BlobServiceClient(...).get_blob_client
        returns a working blob client."""
        azure_blob = MagicMock()
        return patch.dict(
            sys.modules,
            {"azure": MagicMock(),
             "azure.storage": MagicMock(),
             "azure.storage.blob": azure_blob},
        ), azure_blob

    def test_append_copy_failure_does_not_reappend_and_propagates(self):
        """SY-1: a transient COPY INTO failure in append mode must not fall back
        to to_sql(append)."""
        def execute(sql, *args, **kwargs):
            if "COPY INTO" in str(sql):
                raise RuntimeError("transient blob COPY failure")
            return MagicMock()

        self.cursor.execute.side_effect = execute
        blob_patch, _ = self._patch_blob_ok()
        with blob_patch, \
             patch("pyodbc.connect", return_value=self.conn), \
             patch.object(self.loader, "_sql_fallback") as fallback, \
             patch("pandas.DataFrame.to_csv"), \
             patch("os.unlink"), \
             patch("builtins.open", MagicMock()):
            with self.assertRaises(RuntimeError):
                self.loader.load(_DF, self.cfg, "events", if_exists="append")
        fallback.assert_not_called()

    def test_replace_copy_failure_still_falls_back(self):
        """SY-1: the 'replace' blob-copy path may safely fall back to to_sql."""
        def execute(sql, *args, **kwargs):
            if "COPY INTO" in str(sql):
                raise RuntimeError("transient blob COPY failure")
            return MagicMock()

        self.cursor.execute.side_effect = execute
        blob_patch, _ = self._patch_blob_ok()
        with blob_patch, \
             patch("pyodbc.connect", return_value=self.conn), \
             patch.object(self.loader, "_sql_fallback") as fallback, \
             patch("pandas.DataFrame.to_csv"), \
             patch("os.unlink"), \
             patch("builtins.open", MagicMock()):
            self.loader._blob_copy(_DF, self.cfg, "events", "replace")
        fallback.assert_called_once()

    def test_blob_client_none_guard_surfaces_real_error(self):
        """SY-4: if BlobServiceClient setup throws, the cleanup finally must not
        raise NameError on blob_client — the real error must surface."""
        azure_blob = MagicMock()
        azure_blob.BlobServiceClient.side_effect = RuntimeError("bad SAS token")
        blob_patch = patch.dict(
            sys.modules,
            {"azure": MagicMock(),
             "azure.storage": MagicMock(),
             "azure.storage.blob": azure_blob},
        )
        with blob_patch, \
             patch("pyodbc.connect", return_value=self.conn), \
             patch("pandas.DataFrame.to_csv"), \
             patch("os.unlink"):
            with self.assertRaises(RuntimeError) as ctx:
                self.loader._blob_copy(_DF, self.cfg, "events", "append")
        # The original error must propagate, not a NameError from cleanup.
        self.assertIn("bad SAS token", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
