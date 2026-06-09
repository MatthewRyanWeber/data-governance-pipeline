"""
Tests for LoadVerifier — post-load row/column reconciliation.

Row-count and column-count checks run against a real SQLite database
(via connection_string), so the SQL query paths are exercised for real.
Tolerance, discrepancy reporting, injection rejection, and the
unsupported-destination (None) paths are all covered.

Revision history
────────────────
1.0   2026-06-09   Initial release: branch coverage for LoadVerifier.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from pipeline.load_verifier import LoadVerifier


class TestLoadVerifier(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.verifier = LoadVerifier(self.gov)
        self.tmp = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmp) / "verify.db")
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE customers (id INTEGER, name TEXT)")
        conn.executemany("INSERT INTO customers VALUES (?, ?)",
                         [(1, "a"), (2, "b"), (3, "c")])
        conn.commit()
        conn.close()
        self.cfg = {"connection_string": f"sqlite:///{self.db_path}",
                    "db_type": "sqlite"}

    def test_row_count_match(self):
        df = pd.DataFrame({"id": [1, 2, 3], "name": ["a", "b", "c"]})
        result = self.verifier.verify_row_count(df, self.cfg, "customers")
        self.assertTrue(result["match"])
        self.assertEqual(result["source_rows"], 3)
        self.assertEqual(result["dest_rows"], 3)
        self.assertEqual(result["difference"], 0)

    def test_row_count_mismatch_detected(self):
        df = pd.DataFrame({"id": list(range(10))})  # source has 10, dest has 3
        result = self.verifier.verify_row_count(df, self.cfg, "customers")
        self.assertFalse(result["match"])
        self.assertEqual(result["difference"], 3 - 10)

    def test_tolerance_allows_small_discrepancy(self):
        df = pd.DataFrame({"id": list(range(4))})  # 4 source vs 3 dest = 25% off
        within = self.verifier.verify_row_count(df, self.cfg, "customers", tolerance=0.5)
        self.assertTrue(within["match"])
        outside = self.verifier.verify_row_count(df, self.cfg, "customers", tolerance=0.1)
        self.assertFalse(outside["match"])

    def test_unsupported_destination_returns_none_match(self):
        df = pd.DataFrame({"id": [1]})
        result = self.verifier.verify_row_count(df, {"db_type": "parquet"}, "t")
        self.assertIsNone(result["match"])
        self.assertIsNone(result["dest_rows"])

    def test_bad_connection_returns_none(self):
        df = pd.DataFrame({"id": [1]})
        cfg = {"connection_string": "sqlite:////nonexistent/x.db", "db_type": "sqlite"}
        result = self.verifier.verify_row_count(df, cfg, "missing_table")
        self.assertIsNone(result["match"])

    def test_validate_identifier_rejects_injection(self):
        with self.assertRaises(ValueError):
            self.verifier._validate_identifier("t; DROP TABLE x")
        with self.assertRaises(ValueError):
            self.verifier._validate_identifier("1bad")
        self.assertEqual(self.verifier._validate_identifier("good_name"), '"good_name"')

    def test_injection_table_in_verify_returns_none(self):
        # An injection attempt surfaces as a failed count (None), never executes.
        df = pd.DataFrame({"id": [1]})
        result = self.verifier.verify_row_count(df, self.cfg, "t; DROP TABLE customers")
        self.assertIsNone(result["match"])
        # The table must still exist — nothing was dropped.
        conn = sqlite3.connect(self.db_path)
        n = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        conn.close()
        self.assertEqual(n, 3)

    def test_column_count_match(self):
        df = pd.DataFrame({"id": [1], "name": ["a"]})
        result = self.verifier.verify_column_count(df, self.cfg, "customers")
        self.assertTrue(result["match"])

    def test_column_count_missing_column(self):
        df = pd.DataFrame({"id": [1], "name": ["a"], "extra": [9]})
        result = self.verifier.verify_column_count(df, self.cfg, "customers")
        self.assertFalse(result["match"])
        self.assertIn("extra", result["missing_in_dest"])

    def test_column_count_unsupported_returns_none(self):
        df = pd.DataFrame({"id": [1]})
        result = self.verifier.verify_column_count(df, {"db_type": "mongodb"}, "t")
        self.assertIsNone(result["match"])


if __name__ == "__main__":
    unittest.main()
