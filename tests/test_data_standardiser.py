"""
Tests for DataStandardiser — format normalisation rules.

Covers phone_e164, date_iso8601, country_iso2, bool_normalize, the string
case rules (upper/lower/strip/title), null handling, and missing-column skips.

Revision history
────────────────
1.0   2026-06-09   Initial release: branch coverage for DataStandardiser.
"""

import unittest
from unittest.mock import MagicMock

import pandas as pd

from pipeline.data_standardiser import DataStandardiser


class TestDataStandardiser(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.ds = DataStandardiser(self.gov)

    def test_missing_column_is_skipped(self):
        df = pd.DataFrame({"a": [1]})
        result = self.ds.standardise(df, {"ghost": "upper"})
        pd.testing.assert_frame_equal(result, df)
        self.gov.standardisation_applied.assert_not_called()

    def test_country_iso2(self):
        df = pd.DataFrame({"country": ["United States", "uk", "Germany", "Atlantis"]})
        result = self.ds.standardise(df, {"country": "country_iso2"})
        # Known names map to ISO2; unknown passes through unchanged.
        self.assertEqual(list(result["country"]), ["US", "GB", "DE", "Atlantis"])

    def test_country_iso2_preserves_nulls(self):
        df = pd.DataFrame({"country": ["usa", None, "france"]})
        result = self.ds.standardise(df, {"country": "country_iso2"})
        self.assertEqual(result["country"][0], "US")
        self.assertTrue(pd.isna(result["country"][1]))
        self.assertEqual(result["country"][2], "FR")

    def test_date_iso8601(self):
        df = pd.DataFrame({"d": ["01/15/2024", "2024-03-02", "not a date"]})
        result = self.ds.standardise(df, {"d": "date_iso8601"})
        self.assertEqual(result["d"][0], "2024-01-15")
        self.assertEqual(result["d"][1], "2024-03-02")
        # Unparseable values are left as-is rather than becoming NaT.
        self.assertEqual(result["d"][2], "not a date")

    def test_bool_normalize(self):
        df = pd.DataFrame({"flag": ["Yes", "no", "1", "0", "TRUE", "maybe", None]})
        result = self.ds.standardise(df, {"flag": "bool_normalize"})
        self.assertEqual(
            list(result["flag"][:5]), ["True", "False", "True", "False", "True"]
        )
        # Unmapped value passes through; null stays null.
        self.assertEqual(result["flag"][5], "maybe")
        self.assertTrue(pd.isna(result["flag"][6]))

    def test_upper_lower_strip_title(self):
        df = pd.DataFrame({
            "u": ["abc"], "l": ["ABC"], "s": ["  pad  "], "t": ["hello world"],
        })
        result = self.ds.standardise(
            df, {"u": "upper", "l": "lower", "s": "strip", "t": "title"}
        )
        self.assertEqual(result["u"][0], "ABC")
        self.assertEqual(result["l"][0], "abc")
        self.assertEqual(result["s"][0], "pad")
        self.assertEqual(result["t"][0], "Hello World")

    def test_string_rule_preserves_nulls(self):
        df = pd.DataFrame({"u": ["abc", None]})
        result = self.ds.standardise(df, {"u": "upper"})
        self.assertEqual(result["u"][0], "ABC")
        self.assertTrue(pd.isna(result["u"][1]))

    def test_phone_e164(self):
        df = pd.DataFrame({"phone": ["202-555-0142", "(202) 555-0143", None]})
        result = self.ds.standardise(df, {"phone": "phone_e164"})
        self.assertEqual(result["phone"][0], "+12025550142")
        self.assertEqual(result["phone"][1], "+12025550143")
        self.assertTrue(pd.isna(result["phone"][2]))

    def test_phone_unparseable_passes_through(self):
        df = pd.DataFrame({"phone": ["garbage"]})
        result = self.ds.standardise(df, {"phone": "phone_e164"})
        self.assertEqual(result["phone"][0], "garbage")

    def test_reports_change_count(self):
        df = pd.DataFrame({"u": ["abc", "DEF"]})
        self.ds.standardise(df, {"u": "upper"})
        # Only "abc" -> "ABC" changes; "DEF" already upper.
        self.gov.standardisation_applied.assert_called_once_with("u", "upper", 1)

    def test_unknown_rule_reports_zero_changes(self):
        df = pd.DataFrame({"u": ["abc"]})
        result = self.ds.standardise(df, {"u": "no_such_rule"})
        self.assertEqual(result["u"][0], "abc")
        self.gov.standardisation_applied.assert_called_once_with("u", "no_such_rule", 0)


if __name__ == "__main__":
    unittest.main()
