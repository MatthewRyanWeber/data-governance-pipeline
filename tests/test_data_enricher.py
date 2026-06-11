"""
Tests for DataEnricher — left-join lookup enrichment.

Covers CSV/JSON lookups, column subsetting, unmatched-row NaN behaviour,
missing join column, unsupported formats, and the no-row-drop guarantee.

Revision history
────────────────
1.0   2026-06-09   Initial release: branch coverage for DataEnricher.
1.1   2026-06-11   Regression tests: key collision keeps the main table's
                   column, duplicate lookup keys no longer multiply rows,
                   lookup files are parsed once per (path, mtime).
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.data_enricher import DataEnricher


class TestDataEnricher(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.enricher = DataEnricher(self.gov)
        self.tmp = tempfile.mkdtemp()

    def _write_csv(self, df: pd.DataFrame, name: str = "lookup.csv") -> str:
        path = Path(self.tmp) / name
        df.to_csv(path, index=False, encoding="utf-8")
        return str(path)

    def test_basic_csv_enrichment(self):
        df = pd.DataFrame({"dept_id": [1, 2, 1], "name": ["a", "b", "c"]})
        lookup = self._write_csv(
            pd.DataFrame({"department_id": [1, 2], "dept_name": ["Eng", "HR"]})
        )
        result = self.enricher.enrich(df, "dept_id", lookup, "department_id")
        self.assertIn("dept_name", result.columns)
        self.assertEqual(list(result["dept_name"]), ["Eng", "HR", "Eng"])
        # The duplicate join key column is dropped.
        self.assertNotIn("department_id", result.columns)

    def test_left_join_never_drops_rows(self):
        df = pd.DataFrame({"dept_id": [1, 99]})  # 99 has no match
        lookup = self._write_csv(
            pd.DataFrame({"department_id": [1], "dept_name": ["Eng"]})
        )
        result = self.enricher.enrich(df, "dept_id", lookup, "department_id")
        self.assertEqual(len(result), 2)
        self.assertEqual(result["dept_name"][0], "Eng")
        self.assertTrue(pd.isna(result["dept_name"][1]))

    def test_missing_join_column_returns_unchanged(self):
        df = pd.DataFrame({"x": [1]})
        lookup = self._write_csv(pd.DataFrame({"department_id": [1], "n": ["e"]}))
        result = self.enricher.enrich(df, "dept_id", lookup, "department_id")
        pd.testing.assert_frame_equal(result, df)
        self.gov.enrichment_applied.assert_not_called()

    def test_unsupported_format_returns_unchanged(self):
        df = pd.DataFrame({"dept_id": [1]})
        path = Path(self.tmp) / "lookup.parquet"
        path.write_text("not real", encoding="utf-8")
        result = self.enricher.enrich(df, "dept_id", str(path), "department_id")
        pd.testing.assert_frame_equal(result, df)

    def test_lookup_cols_subset(self):
        df = pd.DataFrame({"dept_id": [1]})
        lookup = self._write_csv(pd.DataFrame({
            "department_id": [1], "dept_name": ["Eng"], "secret": ["x"], "budget": [9],
        }))
        result = self.enricher.enrich(
            df, "dept_id", lookup, "department_id", lookup_cols=["dept_name"]
        )
        self.assertIn("dept_name", result.columns)
        self.assertNotIn("secret", result.columns)
        self.assertNotIn("budget", result.columns)

    def test_json_lookup(self):
        df = pd.DataFrame({"dept_id": [1, 2]})
        path = Path(self.tmp) / "lookup.json"
        path.write_text(
            json.dumps([{"department_id": 1, "dept_name": "Eng"},
                        {"department_id": 2, "dept_name": "HR"}]),
            encoding="utf-8",
        )
        result = self.enricher.enrich(df, "dept_id", str(path), "department_id")
        self.assertEqual(list(result["dept_name"]), ["Eng", "HR"])

    def test_same_key_name_is_not_dropped(self):
        # When join_col == lookup_key, the column must survive (it's the data).
        df = pd.DataFrame({"id": [1, 2]})
        lookup = self._write_csv(pd.DataFrame({"id": [1, 2], "label": ["a", "b"]}))
        result = self.enricher.enrich(df, "id", lookup, "id")
        self.assertIn("id", result.columns)
        self.assertEqual(list(result["label"]), ["a", "b"])

    def test_lookup_key_collision_keeps_main_column(self):
        # Regression: when lookup_key collides with an existing main-table
        # column, the drop removed the MAIN df's column and its data.
        df = pd.DataFrame({
            "dept_id": [1, 2],
            "department_id": ["keep-1", "keep-2"],
        })
        lookup = self._write_csv(
            pd.DataFrame({"department_id": [1, 2], "dept_name": ["Eng", "HR"]})
        )
        result = self.enricher.enrich(df, "dept_id", lookup, "department_id")
        self.assertIn("department_id", result.columns)
        self.assertEqual(list(result["department_id"]), ["keep-1", "keep-2"])
        self.assertEqual(list(result["dept_name"]), ["Eng", "HR"])
        # The lookup's suffixed copy of the key is the one that goes.
        self.assertNotIn("department_id_lookup", result.columns)

    def test_duplicate_lookup_keys_do_not_multiply_rows(self):
        # Regression: duplicate join keys in the lookup fanned out the left
        # join and silently multiplied main-table rows.
        df = pd.DataFrame({"dept_id": [1, 2, 3]})
        lookup = self._write_csv(
            pd.DataFrame({
                "department_id": [1, 1, 2],
                "dept_name": ["Eng-first", "Eng-second", "HR"],
            })
        )
        with self.assertLogs("pipeline.data_enricher", level="WARNING") as cm:
            result = self.enricher.enrich(df, "dept_id", lookup, "department_id")
        self.assertEqual(len(result), 3)
        self.assertEqual(result["dept_name"][0], "Eng-first")
        self.assertTrue(any("duplicate" in m for m in cm.output))

    def test_lookup_file_is_parsed_once_across_calls(self):
        # Chunked runs call enrich once per chunk — the lookup must be
        # parsed once per (path, mtime), not once per call.
        df = pd.DataFrame({"dept_id": [1]})
        lookup = self._write_csv(
            pd.DataFrame({"department_id": [1], "dept_name": ["Eng"]})
        )
        with patch("pandas.read_csv", wraps=pd.read_csv) as wrapped_read:
            self.enricher.enrich(df, "dept_id", lookup, "department_id")
            self.enricher.enrich(df, "dept_id", lookup, "department_id")
            self.enricher.enrich(df, "dept_id", lookup, "department_id")
        self.assertEqual(wrapped_read.call_count, 1)


if __name__ == "__main__":
    unittest.main()
