"""
Tests for the DataFrame statistical profiler.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from pipeline.profiler import DataProfiler


class TestDataProfiler(unittest.TestCase):

    def setUp(self):
        self.gov = MagicMock()
        self.profiler = DataProfiler(self.gov)

    def test_basic_profile(self):
        df = pd.DataFrame({"id": [1, 2, 3], "name": ["alice", "bob", "carol"]})
        profile = self.profiler.profile(df)
        self.assertEqual(profile["table"]["row_count"], 3)
        self.assertEqual(profile["table"]["column_count"], 2)
        self.assertIn("id", profile["columns"])
        self.assertIn("name", profile["columns"])

    def test_numeric_stats(self):
        df = pd.DataFrame({"val": [10, 20, 30, 40, 50]})
        profile = self.profiler.profile(df)
        col = profile["columns"]["val"]
        self.assertEqual(col["min"], 10.0)
        self.assertEqual(col["max"], 50.0)
        self.assertEqual(col["mean"], 30.0)

    def test_string_stats(self):
        df = pd.DataFrame({"city": ["NYC", "LA", "Chicago"]})
        profile = self.profiler.profile(df)
        col = profile["columns"]["city"]
        self.assertEqual(col["min_length"], 2)
        self.assertEqual(col["max_length"], 7)
        self.assertIn("sample_values", col)

    def test_null_detection(self):
        df = pd.DataFrame({"a": [1, None, 3], "b": ["x", None, None]})
        profile = self.profiler.profile(df)
        self.assertEqual(profile["columns"]["a"]["null_count"], 1)
        self.assertEqual(profile["columns"]["b"]["null_count"], 2)
        self.assertGreater(profile["table"]["total_null_count"], 0)

    def test_duplicate_detection(self):
        df = pd.DataFrame({"a": [1, 1, 2]})
        profile = self.profiler.profile(df)
        self.assertEqual(profile["table"]["duplicate_row_count"], 1)

    def test_unique_count(self):
        df = pd.DataFrame({"status": ["active", "active", "inactive", "active"]})
        profile = self.profiler.profile(df)
        self.assertEqual(profile["columns"]["status"]["unique_count"], 2)

    def test_save_json(self):
        tmpdir = tempfile.mkdtemp()
        try:
            out_path = Path(tmpdir) / "profile.json"
            profile = {"table": {"row_count": 5}, "columns": {}}
            result = self.profiler.save_json(profile, out_path)
            self.assertTrue(result.exists())
            loaded = json.loads(result.read_text(encoding="utf-8"))
            self.assertEqual(loaded["table"]["row_count"], 5)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_governance_events(self):
        df = pd.DataFrame({"x": [1, 2]})
        self.profiler.profile(df)
        self.gov.profile_recorded.assert_called_once()
        self.gov.write_profile_report.assert_called_once()

    def test_empty_dataframe(self):
        df = pd.DataFrame({"a": pd.Series([], dtype="float64")})
        profile = self.profiler.profile(df)
        self.assertEqual(profile["table"]["row_count"], 0)


if __name__ == "__main__":
    unittest.main()
