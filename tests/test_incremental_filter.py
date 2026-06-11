"""
Tests for IncrementalFilter — watermark-based incremental loading.

Covers first-run (no watermark), datetime and numeric/string filtering,
watermark read/write round-trips, and the empty/missing-column guards.
The watermark state file is redirected to a temp path per test so the
real project state is never touched.

Revision history
────────────────
1.0   2026-06-09   Initial release: branch coverage for IncrementalFilter.
1.1   2026-06-11   Numeric watermarks are now stored as native JSON numbers;
                   regression tests for numeric filtering and for NaT rows
                   being included instead of silently dropped.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from pipeline.incremental_filter import IncrementalFilter


class TestIncrementalFilter(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.inc = IncrementalFilter(self.gov)
        self.tmp = tempfile.mkdtemp()
        # Redirect watermark persistence away from the real project state file.
        self.inc.state_file = Path(self.tmp) / "watermark.json"

    def test_read_watermark_first_run_returns_none(self):
        self.assertIsNone(self.inc.read_watermark("data.csv", "updated_at"))

    def test_filter_with_no_watermark_returns_all(self):
        df = pd.DataFrame({"updated_at": ["2024-01-01", "2024-02-01"]})
        result = self.inc.filter(df, "updated_at", None, "data.csv")
        self.assertEqual(len(result), 2)

    def test_filter_datetime_keeps_only_newer(self):
        df = pd.DataFrame({"updated_at": ["2024-01-01", "2024-02-01", "2024-03-01"]})
        result = self.inc.filter(df, "updated_at", "2024-01-15", "data.csv")
        self.assertEqual(list(result["updated_at"]), ["2024-02-01", "2024-03-01"])

    def test_update_and_read_watermark_roundtrip(self):
        df = pd.DataFrame({"updated_at": pd.to_datetime(
            ["2024-01-01", "2024-03-01", "2024-02-01"])})
        self.inc.update_watermark(df, "updated_at", "data.csv")
        wm = self.inc.read_watermark("data.csv", "updated_at")
        # Watermark is the max timestamp, ISO formatted.
        self.assertTrue(wm.startswith("2024-03-01"))

    def test_update_watermark_numeric(self):
        df = pd.DataFrame({"version": [3, 7, 5]})
        self.inc.update_watermark(df, "version", "data.csv")
        wm = self.inc.read_watermark("data.csv", "version")
        # Numeric watermarks persist as native JSON numbers, not strings.
        self.assertEqual(wm, 7)

    def test_update_watermark_empty_df_is_noop(self):
        df = pd.DataFrame({"updated_at": []})
        self.inc.update_watermark(df, "updated_at", "data.csv")
        self.assertFalse(self.inc.state_file.exists())

    def test_update_watermark_missing_column_is_noop(self):
        df = pd.DataFrame({"other": [1, 2]})
        self.inc.update_watermark(df, "updated_at", "data.csv")
        self.assertFalse(self.inc.state_file.exists())

    def test_watermarks_are_keyed_per_source_and_column(self):
        df_a = pd.DataFrame({"v": [5]})
        df_b = pd.DataFrame({"v": [9]})
        self.inc.update_watermark(df_a, "v", "a.csv")
        self.inc.update_watermark(df_b, "v", "b.csv")
        state = json.loads(self.inc.state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["a.csv::v"], 5)
        self.assertEqual(state["b.csv::v"], 9)

    def test_filter_falls_back_to_raw_comparison(self):
        # Non-datetime, non-coercible values fall back to raw > comparison.
        df = pd.DataFrame({"v": [1, 5, 9]})
        result = self.inc.filter(df, "v", 4, "data.csv")
        self.assertEqual(list(result["v"]), [5, 9])

    def test_filter_numeric_column_compares_numerically(self):
        # Regression: numeric watermark columns were coerced through
        # to_datetime, which broke version/sequence watermarks.
        df = pd.DataFrame({"version": [3, 7, 5, 10]})
        result = self.inc.filter(df, "version", 5, "data.csv")
        self.assertEqual(list(result["version"]), [7, 10])

    def test_filter_numeric_roundtrip_through_watermark_store(self):
        first_batch = pd.DataFrame({"version": [3, 7, 5]})
        self.inc.update_watermark(first_batch, "version", "data.csv")
        stored_watermark = self.inc.read_watermark("data.csv", "version")
        second_batch = pd.DataFrame({"version": [6, 7, 8, 9]})
        result = self.inc.filter(second_batch, "version", stored_watermark, "data.csv")
        self.assertEqual(list(result["version"]), [8, 9])

    def test_filter_numeric_legacy_string_watermark_still_works(self):
        # Watermarks written by older versions were strings — they must
        # still compare numerically against a numeric column.
        df = pd.DataFrame({"version": [3, 7, 5]})
        result = self.inc.filter(df, "version", "5", "data.csv")
        self.assertEqual(list(result["version"]), [7])

    def test_filter_datetime_includes_unparseable_rows(self):
        # Regression: rows that coerce to NaT were silently dropped on every
        # run forever — they must be included (processed) with a warning.
        df = pd.DataFrame({
            "updated_at": ["2024-01-01", "not a date", "2024-03-01"],
        })
        with self.assertLogs("pipeline.incremental_filter", level="WARNING") as cm:
            result = self.inc.filter(df, "updated_at", "2024-02-01", "data.csv")
        self.assertEqual(list(result["updated_at"]), ["not a date", "2024-03-01"])
        self.assertTrue(any("could not be parsed" in m for m in cm.output))


if __name__ == "__main__":
    unittest.main()
