"""
Real round-trip tests for serverless loaders (no Docker, no mocks).

DuckDB, Parquet, and SQLite (via SQLLoader) run against genuine embedded
engines, so these exercise the actual write/read/upsert paths end-to-end —
the highest-fidelity coverage available without a database server.

Revision history
────────────────
1.0   2026-06-09   Initial release: embedded round-trip coverage.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from pipeline.loaders.duckdb_loader import DuckDBLoader
from pipeline.loaders.parquet_loader import ParquetLoader
from pipeline.loaders.sql_loader import SQLLoader


def _df():
    return pd.DataFrame({"id": [1, 2, 3], "name": ["a", "b", "c"]})


class TestDuckDBLoaderRoundTrip(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = DuckDBLoader(self.gov)
        self.tmp = tempfile.mkdtemp()
        self.db = str(Path(self.tmp) / "test.duckdb")

    def _read(self, table):
        return self.loader.query({"db_path": self.db}, f"SELECT * FROM {table} ORDER BY id")

    def test_append_writes_rows(self):
        n = self.loader.load(_df(), {"db_path": self.db}, table="t", if_exists="append")
        self.assertEqual(n, 3)
        self.assertEqual(len(self._read("t")), 3)

    def test_replace_overwrites(self):
        self.loader.load(_df(), {"db_path": self.db}, table="t", if_exists="append")
        self.loader.load(pd.DataFrame({"id": [9], "name": ["z"]}),
                         {"db_path": self.db}, table="t", if_exists="replace")
        out = self._read("t")
        self.assertEqual(list(out["id"]), [9])

    def test_upsert_updates_and_inserts(self):
        self.loader.load(_df(), {"db_path": self.db}, table="t", if_exists="append")
        update = pd.DataFrame({"id": [2, 4], "name": ["B", "d"]})
        self.loader.load(update, {"db_path": self.db}, table="t",
                         if_exists="upsert", natural_keys=["id"])
        out = self._read("t")
        self.assertEqual(out.loc[out["id"] == 2, "name"].iloc[0], "B")  # updated
        self.assertIn(4, list(out["id"]))                                # inserted
        self.assertEqual(len(out), 4)

    def test_upsert_all_key_columns_does_nothing_on_conflict(self):
        # When every column is a natural key there is nothing to update, so a
        # duplicate must be ignored rather than producing invalid SQL.
        keys_only = pd.DataFrame({"id": [1, 2]})
        self.loader.load(keys_only, {"db_path": self.db}, table="k",
                         if_exists="upsert", natural_keys=["id"])
        self.loader.load(pd.DataFrame({"id": [2, 3]}), {"db_path": self.db},
                         table="k", if_exists="upsert", natural_keys=["id"])
        out = self._read("k")
        self.assertEqual(sorted(out["id"]), [1, 2, 3])

    def test_dry_run_writes_nothing(self):
        loader = DuckDBLoader(self.gov, dry_run=True)
        n = loader.load(_df(), {"db_path": self.db}, table="t")
        self.assertEqual(n, 0)
        self.assertFalse(Path(self.db).exists())

    def test_empty_df_is_noop(self):
        n = self.loader.load(pd.DataFrame(), {"db_path": self.db}, table="t")
        self.assertEqual(n, 0)

    def test_invalid_if_exists_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_df(), {"db_path": self.db}, table="t", if_exists="merge")

    def test_injection_table_name_rejected(self):
        with self.assertRaises(ValueError):
            self.loader.load(_df(), {"db_path": self.db}, table="t; DROP TABLE x")

    def test_missing_db_path_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_df(), {}, table="t")

    def test_query_rejects_mutating_sql(self):
        self.loader.load(_df(), {"db_path": self.db}, table="t")
        with self.assertRaises(ValueError):
            self.loader.query({"db_path": self.db}, "DROP TABLE t")
        with self.assertRaises(ValueError):
            self.loader.query({"db_path": self.db}, "DELETE FROM t")

    def test_query_rejects_non_select(self):
        self.loader.load(_df(), {"db_path": self.db}, table="t")
        with self.assertRaises(ValueError):
            self.loader.query({"db_path": self.db}, "PRAGMA table_info(t)")


class TestParquetLoaderRoundTrip(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = ParquetLoader(self.gov)
        self.tmp = tempfile.mkdtemp()

    def test_write_and_read_back(self):
        path = str(Path(self.tmp) / "out.parquet")
        n = self.loader.load(_df(), {"path": path}, if_exists="replace")
        self.assertEqual(n, 3)
        back = pd.read_parquet(path)
        self.assertEqual(len(back), 3)
        self.assertEqual(list(back.columns), ["id", "name"])

    def test_path_derived_from_table(self):
        path = Path(self.tmp) / "mytable.parquet"
        self.loader.load(_df(), {}, table=str(Path(self.tmp) / "mytable"))
        self.assertTrue(path.exists())

    def test_partitioned_write(self):
        root = str(Path(self.tmp) / "dataset")
        df = pd.DataFrame({"id": [1, 2], "region": ["us", "eu"]})
        self.loader.load(df, {"path": root, "partition_cols": ["region"]},
                         if_exists="replace")
        # Partitioned datasets create a subdirectory per partition value.
        self.assertTrue((Path(root) / "region=us").exists())
        self.assertTrue((Path(root) / "region=eu").exists())

    def test_dry_run_writes_nothing(self):
        loader = ParquetLoader(self.gov, dry_run=True)
        path = str(Path(self.tmp) / "out.parquet")
        n = loader.load(_df(), {"path": path})
        self.assertEqual(n, 0)
        self.assertFalse(Path(path).exists())

    def test_empty_df_is_noop(self):
        path = str(Path(self.tmp) / "out.parquet")
        n = self.loader.load(pd.DataFrame(), {"path": path})
        self.assertEqual(n, 0)

    def test_no_path_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_df(), {})

    def test_invalid_if_exists_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_df(), {"path": "x.parquet"}, if_exists="upsert")


class TestSQLLoaderSQLiteRoundTrip(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = SQLLoader(self.gov, db_type="sqlite")
        self.tmp = tempfile.mkdtemp()
        # SQLLoader appends ".db" to db_name for sqlite.
        self.db_name = str(Path(self.tmp) / "store")
        self.cfg = {"db_name": self.db_name}

    def _read(self, table):
        conn = sqlite3.connect(self.db_name + ".db")
        try:
            return pd.read_sql(f"SELECT * FROM {table} ORDER BY id", conn)
        finally:
            conn.close()

    def test_append_and_replace(self):
        self.loader.load(_df(), self.cfg, table="t", if_exists="replace")
        self.assertEqual(len(self._read("t")), 3)
        self.loader.load(pd.DataFrame({"id": [4], "name": ["d"]}),
                         self.cfg, table="t", if_exists="append")
        self.assertEqual(len(self._read("t")), 4)

    def test_upsert_into_existing_table(self):
        self.loader.load(_df(), self.cfg, table="t", if_exists="replace")
        update = pd.DataFrame({"id": [2, 5], "name": ["B", "e"]})
        self.loader.load(update, self.cfg, table="t", natural_keys=["id"])
        out = self._read("t")
        self.assertEqual(out.loc[out["id"] == 2, "name"].iloc[0], "B")
        self.assertIn(5, list(out["id"]))
        self.assertEqual(len(out), 4)

    def test_upsert_creates_table_when_absent(self):
        # Upsert against a non-existent table falls back to a replace-create.
        self.loader.load(_df(), self.cfg, table="fresh", natural_keys=["id"])
        self.assertEqual(len(self._read("fresh")), 3)

    def test_dry_run_writes_nothing(self):
        loader = SQLLoader(self.gov, db_type="sqlite", dry_run=True)
        loader.load(_df(), self.cfg, table="t", if_exists="replace")
        self.assertFalse(Path(self.db_name + ".db").exists())

    def test_injection_table_name_rejected(self):
        with self.assertRaises(ValueError):
            self.loader.load(_df(), self.cfg, table="t; DROP TABLE users")

    def test_unknown_db_type_raises_on_engine(self):
        loader = SQLLoader(self.gov, db_type="oraclexyz")
        with self.assertRaises(ValueError):
            loader.load(_df(), {"db_name": "x"}, table="t")

    def test_load_complete_reported(self):
        self.loader.load(_df(), self.cfg, table="t", if_exists="replace")
        self.gov.load_complete.assert_called_with(3, "t")


if __name__ == "__main__":
    unittest.main()
