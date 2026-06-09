"""
Deep load-path tests for BigQueryLoader (client mocked, no live BigQuery).

Asserts the generated write disposition for append/replace and the MERGE SQL
built for upserts — the string-building paths most prone to silent bugs (the
kind a real DuckDB round-trip just caught in this codebase).

Revision history
────────────────
1.0   2026-06-09   Initial release: mocked bulk-load and MERGE upsert coverage.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.constants import HAS_BIGQUERY
from pipeline.loaders.bigquery_loader import BigQueryLoader

_CFG = {"project": "proj", "dataset": "ds", "location": "US"}
_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})


@unittest.skipUnless(HAS_BIGQUERY, "google-cloud-bigquery not installed")
class TestBigQueryBulkLoad(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = BigQueryLoader(self.gov)

    def test_append_uses_write_append(self):
        client = MagicMock()
        with patch.object(self.loader, "_client", return_value=client):
            self.loader.load(_DF, _CFG, "tbl", if_exists="append")
        job_cfg = client.load_table_from_dataframe.call_args.kwargs["job_config"]
        from google.cloud import bigquery as bq
        self.assertEqual(job_cfg.write_disposition, bq.WriteDisposition.WRITE_APPEND)
        self.gov.load_complete.assert_called_once_with(2, "tbl")

    def test_replace_uses_write_truncate(self):
        client = MagicMock()
        with patch.object(self.loader, "_client", return_value=client):
            self.loader.load(_DF, _CFG, "tbl", if_exists="replace")
        job_cfg = client.load_table_from_dataframe.call_args.kwargs["job_config"]
        from google.cloud import bigquery as bq
        self.assertEqual(job_cfg.write_disposition, bq.WriteDisposition.WRITE_TRUNCATE)

    def test_table_id_fully_qualified(self):
        client = MagicMock()
        with patch.object(self.loader, "_client", return_value=client):
            self.loader.load(_DF, _CFG, "tbl")
        table_id = client.load_table_from_dataframe.call_args[0][1]
        self.assertEqual(table_id, "proj.ds.tbl")


@unittest.skipUnless(HAS_BIGQUERY, "google-cloud-bigquery not installed")
class TestBigQueryUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = BigQueryLoader(self.gov)

    def test_merge_sql_structure(self):
        client = MagicMock()
        with patch.object(self.loader, "_client", return_value=client):
            self.loader.load(_DF, _CFG, "tbl", natural_keys=["id"])
        merge_sql = client.query.call_args[0][0]
        self.assertIn("MERGE `proj.ds.tbl` AS t", merge_sql)
        self.assertIn("ON (t.`id` = s.`id`)", merge_sql)
        self.assertIn("WHEN MATCHED THEN", merge_sql)
        self.assertIn("t.`name` = s.`name`", merge_sql)       # non-key updated
        self.assertIn("WHEN NOT MATCHED THEN", merge_sql)
        self.assertNotIn("t.`id` = s.`id`,", merge_sql)        # key not in UPDATE SET
        self.gov.transformation_applied.assert_called_once()

    def test_staging_table_cleaned_up(self):
        client = MagicMock()
        with patch.object(self.loader, "_client", return_value=client):
            self.loader.load(_DF, _CFG, "tbl", natural_keys=["id"])
        client.delete_table.assert_called_once()


if __name__ == "__main__":
    unittest.main()
