"""
Deep load-path tests for OracleLoader (connection mocked, no live Oracle).

Asserts table-name upper-casing, array-insert binds, replace-path DROP, and
the MERGE upsert SQL (ON clause, UPDATE SET excludes keys, staging cleanup).

Revision history
────────────────
1.0   2026-06-09   Initial release: mocked array-insert and MERGE coverage.
1.1   2026-06-11   INSERT now expected to carry an explicit column list;
                   added rollback-before-retry and all-key MERGE coverage.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.constants import HAS_ORACLE
from pipeline.loaders.oracle_loader import OracleLoader
from pipeline.exceptions import ConfigValidationError

_CFG = {"user": "u", "password": "p", "dsn": "host/svc"}
_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})


def _executed_sql(cursor):
    """All SQL strings passed to cursor.execute / executemany."""
    calls = list(cursor.execute.call_args_list) + list(cursor.executemany.call_args_list)
    return [c[0][0] for c in calls if c[0]]


@unittest.skipUnless(HAS_ORACLE, "oracledb not installed")
class TestOracleLoader(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = OracleLoader(self.gov)
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value

    def _load(self, **kw):
        with patch.object(self.loader, "_connect", return_value=self.conn):
            self.loader.load(_DF, _CFG, "customers", **kw)

    def test_table_name_uppercased_and_reported(self):
        self._load()
        self.gov.load_complete.assert_called_once_with(2, "CUSTOMERS")

    def test_array_insert_binds_positional(self):
        self._load(if_exists="append")
        sql = _executed_sql(self.cursor)
        # Explicit column list guards against column-order drift on
        # pre-existing tables.
        self.assertTrue(any(
            'INSERT INTO "CUSTOMERS" ("ID", "NAME") VALUES (:1, :2)' in s
            for s in sql
        ))
        self.cursor.executemany.assert_called()

    def test_failed_batch_rolled_back_before_retry(self):
        """A partial executemany must be rolled back before the retry,
        otherwise already-inserted rows are duplicated."""
        self.cursor.executemany.side_effect = [Exception("ORA-boom"), None]
        with patch.object(self.loader, "_connect", return_value=self.conn), \
             patch("pipeline.loaders.oracle_loader.time.sleep"):
            self.loader.load(_DF, _CFG, "customers", if_exists="append")
        self.conn.rollback.assert_called()

    def test_all_key_upsert_omits_when_matched(self):
        """When every column is a natural key the MERGE must omit
        WHEN MATCHED entirely (ROWID is not updatable)."""
        keys_only = pd.DataFrame({"id": [1, 2]})
        with patch.object(self.loader, "_connect", return_value=self.conn):
            self.loader.load(keys_only, _CFG, "customers", natural_keys=["id"])
        merge = next(s for s in _executed_sql(self.cursor) if "MERGE INTO" in s)
        self.assertNotIn("WHEN MATCHED", merge)
        self.assertNotIn("ROWID", merge)
        self.assertIn("WHEN NOT MATCHED THEN INSERT", merge)

    def test_replace_drops_table(self):
        self._load(if_exists="replace")
        sql = _executed_sql(self.cursor)
        self.assertTrue(any("DROP TABLE" in s and "PURGE" in s for s in sql))

    def test_merge_upsert_sql(self):
        self._load(natural_keys=["id"])
        merge = next(s for s in _executed_sql(self.cursor) if "MERGE INTO" in s)
        self.assertIn('ON (t."ID" = s."ID")', merge)
        self.assertIn('UPDATE SET t."NAME" = s."NAME"', merge)   # non-key updated
        self.assertNotIn('SET t."ID"', merge)                    # key not updated
        self.assertIn("WHEN NOT MATCHED THEN INSERT", merge)
        self.gov.transformation_applied.assert_called_once()

    def test_upsert_drops_staging_table(self):
        self._load(natural_keys=["id"])
        sql = _executed_sql(self.cursor)
        self.assertTrue(any("_STG_" in s and "DROP TABLE" in s for s in sql))

    def test_dry_run_never_connects(self):
        loader = OracleLoader(self.gov, dry_run=True)
        with patch.object(loader, "_connect") as conn:
            loader.load(_DF, _CFG, "t")
        conn.assert_not_called()

    def test_injection_table_rejected(self):
        with self.assertRaises(ValueError):
            self.loader.load(_DF, _CFG, "t; DROP TABLE x")

    def test_missing_config_raises(self):
        with self.assertRaises(ConfigValidationError):
            with patch.object(self.loader, "_connect", return_value=self.conn):
                self.loader.load(_DF, {"user": "u"}, "t")


if __name__ == "__main__":
    unittest.main()
