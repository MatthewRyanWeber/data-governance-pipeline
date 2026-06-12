"""
Deep upsert/MERGE SQL-generation tests for the warehouse loaders.

Each loader's connection layer (_connect / _client / _engine) is mocked so the
SQL-string-building paths run without a live warehouse.  These assert the
MERGE/upsert structure — ON clause keyed correctly, UPDATE SET excluding the
keys — the exact class of bug a real DuckDB round-trip caught earlier.

Missing-driver flags are patched True only to construct the loader; no real
driver is imported because the connection method is replaced.

Revision history
────────────────
1.0   2026-06-09   Initial release: MERGE coverage for clickhouse, hana,
                   firebolt, databricks, yellowbrick, redshift, cockroachdb.
1.1   2026-06-11   Databricks upsert now stages into a real Delta table (no
                   temp view); ClickHouse upsert checks the existing table
                   engine, so the mock returns an empty engine lookup; added
                   coverage for the non-ReplacingMergeTree error.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

import pipeline.loaders.clickhouse_loader as ch_mod
import pipeline.loaders.firebolt_loader as fb_mod
import pipeline.loaders.databricks_loader as db_mod
import pipeline.loaders.redshift_loader as rs_mod
import pipeline.loaders.db2_loader as db2_mod
import pipeline.loaders.hana_loader as hana_mod
import pipeline.loaders.snowflake_loader as sf_mod
import pipeline.loaders.synapse_loader as syn_mod
from pipeline.loaders.clickhouse_loader import ClickHouseLoader
from pipeline.loaders.hana_loader import HanaLoader
from pipeline.loaders.firebolt_loader import FireboltLoader
from pipeline.loaders.databricks_loader import DatabricksLoader
from pipeline.loaders.yellowbrick_loader import YellowbrickLoader
from pipeline.loaders.redshift_loader import RedshiftLoader
from pipeline.loaders.cockroachdb_loader import CockroachDBLoader
from pipeline.loaders.snowflake_loader import SnowflakeLoader
from pipeline.loaders.synapse_loader import SynapseLoader
from pipeline.loaders.db2_loader import Db2Loader

_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})


def _cursor_sql(cursor):
    """All SQL strings passed to a DB-API cursor."""
    calls = list(cursor.execute.call_args_list) + list(cursor.executemany.call_args_list)
    return [str(c[0][0]) for c in calls if c[0]]


class TestClickHouseUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(ch_mod, "HAS_CLICKHOUSE", True):
            self.loader = ClickHouseLoader(self.gov)
        self.client = MagicMock()

    def test_upsert_uses_replacingmergetree_and_optimize(self):
        # Empty engine lookup result: the target table does not exist yet.
        self.client.query.return_value.result_rows = []
        with patch.object(self.loader, "_client", return_value=self.client):
            self.loader.load(_DF, {"database": "db"}, "events", natural_keys=["id"])
        commands = [str(c[0][0]) for c in self.client.command.call_args_list]
        self.assertTrue(any("ReplacingMergeTree" in c for c in commands))
        self.assertTrue(any("ORDER BY (`id`)" in c for c in commands))
        self.assertTrue(any("OPTIMIZE TABLE" in c and "FINAL" in c for c in commands))
        self.client.insert_df.assert_called_once()

    def test_upsert_into_plain_mergetree_raises(self):
        """A pre-existing plain MergeTree would silently duplicate rows."""
        self.client.query.return_value.result_rows = [("MergeTree",)]
        with patch.object(self.loader, "_client", return_value=self.client):
            with self.assertRaises(ValueError) as ctx:
                self.loader.load(_DF, {"database": "db"}, "events",
                                 natural_keys=["id"])
        self.assertIn("ReplacingMergeTree", str(ctx.exception))
        self.client.insert_df.assert_not_called()

    def test_replace_drops_table(self):
        with patch.object(self.loader, "_client", return_value=self.client):
            self.loader.load(_DF, {"database": "db"}, "events", if_exists="replace")
        commands = [str(c[0][0]) for c in self.client.command.call_args_list]
        self.assertTrue(any("DROP TABLE IF EXISTS" in c for c in commands))


class TestHanaUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(hana_mod, "HAS_HANA", True):
            self.loader = HanaLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "user": "u", "password": "p"}

    def test_merge_sql(self):
        with patch.object(self.loader, "_connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, "accounts", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(self.cursor) if "MERGE INTO" in s)
        self.assertIn('ON (T."id" = S."id")', merge)
        self.assertIn('UPDATE SET T."name" = S."name"', merge)
        self.assertNotIn('SET T."id"', merge)
        self.assertIn("WHEN NOT MATCHED THEN INSERT", merge)


class TestFireboltUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(fb_mod, "HAS_FIREBOLT", True):
            self.loader = FireboltLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"username": "u", "password": "p", "database": "d",
                    "account_name": "acct", "engine_name": "eng"}

    def test_merge_uses_values_subquery(self):
        with patch.object(self.loader, "_connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(self.cursor) if "MERGE INTO" in s)
        self.assertIn('MERGE INTO "t" AS t', merge)
        self.assertIn("VALUES", merge)            # VALUES subquery source
        self.assertIn('ON (t."id" = s."id")', merge)
        self.assertIn('t."name" = s."name"', merge)


class TestDatabricksUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(db_mod, "HAS_DATABRICKS", True):
            self.loader = DatabricksLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"server_hostname": "h", "http_path": "/p"}

    def test_merge_uses_backtick_quoting_and_staging_table(self):
        with patch.object(self.loader, "_connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, "t", natural_keys=["id"])
        sql = _cursor_sql(self.cursor)
        # Upsert stages into a real Delta table, not a VALUES-literal view.
        self.assertTrue(any("CREATE OR REPLACE TABLE" in s
                            and "_pipeline_stage_" in s for s in sql))
        merge = next(s for s in sql if "MERGE INTO" in s)
        self.assertIn("t.`id` = s.`id`", merge)
        self.assertIn("t.`name` = s.`name`", merge)
        self.assertNotIn("TEMPORARY VIEW", " ".join(sql))
        self.assertTrue(any("DROP TABLE IF EXISTS" in s
                            and "_pipeline_stage_" in s for s in sql))

    def test_bulk_insert_batches_rows_per_statement(self):
        """Bulk insert must pack many rows per INSERT, not one per row."""
        with patch.object(self.loader, "_connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, "t", if_exists="append")
        inserts = [str(c[0][0]) for c in self.cursor.execute.call_args_list
                   if c[0] and "INSERT INTO" in str(c[0][0])]
        self.assertEqual(len(inserts), 1)          # 2 rows fit one statement
        self.assertEqual(inserts[0].count("(?, ?)"), 2)  # multi-row VALUES


class TestYellowbrickUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = YellowbrickLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p"}

    def test_merge_sql(self):
        with patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_copy_from_stdin"):
            self.loader.load(_DF, self.cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(self.cursor) if "MERGE INTO" in s)
        self.assertIn('ON (t."id" = s."id")', merge)
        self.assertIn('"name" = s."name"', merge)
        self.assertIn("WHEN NOT MATCHED THEN INSERT", merge)


class TestRedshiftUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(rs_mod, "HAS_REDSHIFT", True):
            self.loader = RedshiftLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p"}

    def test_merge_sql(self):
        with patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            self.loader.load(_DF, self.cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(self.cursor) if "MERGE INTO" in s)
        self.assertIn('ON (t."id" = s."id")', merge)
        self.assertIn('t."name" = s."name"', merge)
        self.assertNotIn('SET t."id"', merge)


class TestCockroachUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = CockroachDBLoader(self.gov)
        self.cfg = {"host": "h", "user": "u", "db_name": "d"}

    def test_upsert_on_conflict_sql(self):
        engine = MagicMock()
        conn = engine.begin.return_value.__enter__.return_value
        with patch.object(self.loader, "_engine", return_value=engine):
            self.loader.load(_DF, self.cfg, "t", if_exists="upsert", natural_keys=["id"])
        executed = [str(c[0][0]) for c in conn.execute.call_args_list]
        upsert = next(s for s in executed if "ON CONFLICT" in s)
        self.assertIn("INSERT INTO t", upsert)
        self.assertIn("ON CONFLICT (id) DO UPDATE SET", upsert)
        self.assertIn("name = EXCLUDED.name", upsert)
        self.assertNotIn("id = EXCLUDED.id", upsert)   # key excluded from update

    def test_append_uses_to_sql(self):
        engine = MagicMock()
        with patch.object(self.loader, "_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql") as to_sql:
            self.loader.load(_DF, self.cfg, "t", if_exists="append")
        to_sql.assert_called_once()


class TestSnowflakeUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(sf_mod, "HAS_SNOWFLAKE", True):
            self.loader = SnowflakeLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"account": "a", "user": "u", "password": "p",
                    "database": "DB", "warehouse": "WH"}

    def test_merge_sql(self):
        with patch.object(self.loader, "_connect", return_value=self.conn), \
             patch.object(self.loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            self.loader.load(_DF, self.cfg, "accounts", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(self.cursor) if "MERGE INTO" in s)
        self.assertIn('"DB"."PUBLIC"."ACCOUNTS"', merge)
        self.assertIn('t."id" = s."id"', merge)
        self.assertIn('t."name" = s."name"', merge)
        self.assertIn("WHEN NOT MATCHED THEN", merge)


class TestSynapseUpsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(syn_mod, "HAS_SYNAPSE", True):
            self.loader = SynapseLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value
        self.cfg = {"host": "h", "database": "d", "user": "u", "password": "p"}

    def test_merge_uses_bracket_quoting(self):
        with patch.object(self.loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"), \
             patch("pyodbc.connect", return_value=self.conn):
            self.loader.load(_DF, self.cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(self.cursor) if "MERGE" in s and "USING" in s)
        self.assertIn("t.[id] = s.[id]", merge)
        self.assertIn("t.[name] = s.[name]", merge)


class TestDb2Upsert(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        with patch.object(db2_mod, "HAS_DB2", True):
            self.loader = Db2Loader(self.gov)
        self.cfg = {"host": "h", "user": "u", "password": "p", "database": "d"}

    def test_merge_sql_via_exec_immediate(self):
        ibm = MagicMock()
        ibm.connect.return_value = MagicMock()
        with patch.dict(sys.modules, {"ibm_db": ibm}), \
             patch.object(self.loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            self.loader.load(_DF, self.cfg, "accounts", natural_keys=["id"])
        executed = [str(c[0][1]) for c in ibm.exec_immediate.call_args_list if len(c[0]) > 1]
        merge = next(s for s in executed if "MERGE INTO" in s)
        self.assertIn('t."ID" = s."ID"', merge)            # keys upper-cased
        self.assertIn('t."NAME" = s."NAME"', merge)
        self.assertIn("WHEN NOT MATCHED THEN INSERT", merge)


if __name__ == "__main__":
    unittest.main()
