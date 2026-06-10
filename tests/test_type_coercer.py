"""
Tests for configuration-driven dtype casting.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import unittest
from unittest.mock import MagicMock

import pandas as pd

from pipeline.type_coercer import TypeCoercer


class TestTypeCoercer(unittest.TestCase):

    def setUp(self):
        self.gov = MagicMock()
        self.coercer = TypeCoercer(self.gov)

    def test_int_coercion(self):
        df = pd.DataFrame({"id": ["1", "2", "3"]})
        result = self.coercer.coerce(df, {"id": "int"})
        self.assertTrue(pd.api.types.is_integer_dtype(result["id"]))
        self.assertEqual(list(result["id"]), [1, 2, 3])

    def test_float_coercion(self):
        df = pd.DataFrame({"price": ["1.5", "2.99", "0.01"]})
        result = self.coercer.coerce(df, {"price": "float"})
        self.assertTrue(pd.api.types.is_float_dtype(result["price"]))

    def test_str_coercion(self):
        df = pd.DataFrame({"zip": [10001, 20002, 30003]})
        result = self.coercer.coerce(df, {"zip": "str"})
        self.assertEqual(result["zip"].iloc[0], "10001")

    def test_bool_coercion(self):
        df = pd.DataFrame({"active": ["true", "false", "yes", "no"]})
        result = self.coercer.coerce(df, {"active": "bool"})
        self.assertTrue(result["active"].iloc[0])
        self.assertFalse(result["active"].iloc[1])
        self.assertTrue(result["active"].iloc[2])
        self.assertFalse(result["active"].iloc[3])

    def test_datetime_coercion(self):
        df = pd.DataFrame({"ts": ["2026-01-01", "2026-06-15"]})
        result = self.coercer.coerce(df, {"ts": "datetime"})
        self.assertTrue(pd.api.types.is_datetime64_any_dtype(result["ts"]))

    def test_date_coercion(self):
        df = pd.DataFrame({"day": ["2026-01-01 12:00:00", "2026-06-15 08:30:00"]})
        result = self.coercer.coerce(df, {"day": "date"})
        self.assertEqual(result["day"].iloc[0], "2026-01-01")
        self.assertEqual(result["day"].iloc[1], "2026-06-15")

    def test_missing_column_skipped(self):
        df = pd.DataFrame({"name": ["alice"]})
        result = self.coercer.coerce(df, {"nonexistent": "int"})
        self.assertEqual(list(result.columns), ["name"])

    def test_empty_type_map_noop(self):
        df = pd.DataFrame({"a": [1]})
        result = self.coercer.coerce(df, {})
        pd.testing.assert_frame_equal(result, df)

    def test_invalid_int_becomes_na(self):
        df = pd.DataFrame({"id": ["1", "abc", "3"]})
        result = self.coercer.coerce(df, {"id": "int"})
        self.assertTrue(pd.isna(result["id"].iloc[1]))

    def test_governance_event_logged(self):
        df = pd.DataFrame({"x": ["1"]})
        self.coercer.coerce(df, {"x": "int"})
        self.gov.transformation_applied.assert_called_once()
        args = self.gov.transformation_applied.call_args
        self.assertEqual(args[0][0], "TYPE_COERCION")
        self.assertEqual(args[0][1]["column"], "x")

    def test_multiple_columns(self):
        df = pd.DataFrame({"id": ["1", "2"], "name": [100, 200], "active": ["true", "false"]})
        result = self.coercer.coerce(df, {"id": "int", "name": "str", "active": "bool"})
        self.assertTrue(pd.api.types.is_integer_dtype(result["id"]))
        self.assertEqual(result["name"].iloc[0], "100")
        self.assertTrue(result["active"].iloc[0])


if __name__ == "__main__":
    unittest.main()
