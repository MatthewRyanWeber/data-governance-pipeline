"""
Tests for the BusinessRuleEngine — operator-defined transformation rules.

Exercises every rule type (rename, fill_null, map_values, derive, filter_out,
flag), the missing-column and bad-operator branches, the security-validation
path on derive expressions, and the per-rule error isolation that keeps one
bad rule from aborting the batch.

Revision history
────────────────
1.0   2026-06-09   Initial release: full branch coverage for BusinessRuleEngine.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from pipeline.business_rules import BusinessRuleEngine


def _fresh_df() -> pd.DataFrame:
    """A small synthetic frame; salary is a string to exercise numeric coercion."""
    return pd.DataFrame({
        "id": [1, 2, 3, 4],
        "status": ["active", "inactive", "active", "pending"],
        "salary": ["50000", "60000", None, "70000"],
        "dept": ["Eng", "HR", "Eng", "Sales"],
    })


class TestRename(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.engine = BusinessRuleEngine(self.gov)

    def test_rename_existing_column(self):
        df = _fresh_df()
        rules = [{"type": "rename", "from": "dept", "to": "department"}]
        result = self.engine.apply(df, rules)
        self.assertIn("department", result.columns)
        self.assertNotIn("dept", result.columns)
        self.gov.rule_applied.assert_called_once()

    def test_rename_missing_column_is_noop(self):
        df = _fresh_df()
        rules = [{"type": "rename", "from": "nonexistent", "to": "x"}]
        result = self.engine.apply(df, rules)
        self.assertEqual(list(result.columns), list(df.columns))
        self.gov.rule_applied.assert_not_called()


class TestFillNull(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.engine = BusinessRuleEngine(self.gov)

    def test_fill_null_replaces_nans(self):
        df = _fresh_df()
        rules = [{"type": "fill_null", "column": "salary", "value": "0"}]
        result = self.engine.apply(df, rules)
        self.assertEqual(result["salary"].isnull().sum(), 0)
        self.assertEqual(result.loc[2, "salary"], "0")
        # rows_affected reported should be the null count (1)
        self.gov.rule_applied.assert_called_once_with("fill_null", "fill_null", 1)

    def test_fill_null_missing_column_is_noop(self):
        df = _fresh_df()
        rules = [{"type": "fill_null", "column": "ghost", "value": 0}]
        self.engine.apply(df, rules)
        self.gov.rule_applied.assert_not_called()


class TestMapValues(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.engine = BusinessRuleEngine(self.gov)

    def test_map_values_translates(self):
        df = _fresh_df()
        rules = [{"type": "map_values", "column": "status",
                  "mapping": {"active": "A", "inactive": "I"}}]
        result = self.engine.apply(df, rules)
        self.assertEqual(list(result["status"]), ["A", "I", "A", "pending"])
        # 3 rows matched a mapping key (two active, one inactive)
        self.gov.rule_applied.assert_called_once_with("map_values", "map_values", 3)


class TestDerive(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.engine = BusinessRuleEngine(self.gov)

    def test_derive_arithmetic(self):
        df = pd.DataFrame({"a": [1, 2, 3], "b": [10, 20, 30]})
        rules = [{"type": "derive", "new_column": "total",
                  "expression": "a + b", "source_columns": ["a", "b"]}]
        result = self.engine.apply(df, rules)
        self.assertEqual(list(result["total"]), [11, 22, 33])

    def test_derive_rejects_injection_without_adding_column(self):
        # A code-injection attempt must be caught by the AST validator; the
        # engine isolates the failure, so the new column is never created.
        df = pd.DataFrame({"a": [1, 2]})
        rules = [{"type": "derive", "new_column": "evil",
                  "expression": "__import__('os').system('echo hi')",
                  "source_columns": ["a"]}]
        result = self.engine.apply(df, rules)
        self.assertNotIn("evil", result.columns)
        self.gov.error.assert_called_once()


class TestFilterOut(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.engine = BusinessRuleEngine(self.gov)

    def test_filter_out_drops_matching_rows(self):
        df = _fresh_df()
        rules = [{"type": "filter_out", "column": "status", "value": "inactive"}]
        result = self.engine.apply(df, rules)
        self.assertNotIn("inactive", list(result["status"]))
        self.assertEqual(len(result), 3)

    def test_filter_out_is_case_insensitive(self):
        df = _fresh_df()
        rules = [{"type": "filter_out", "column": "status", "value": "INACTIVE"}]
        result = self.engine.apply(df, rules)
        self.assertEqual(len(result), 3)

    def test_filter_out_missing_column_logs_and_skips(self):
        df = _fresh_df()
        rules = [{"type": "filter_out", "column": "ghost", "value": "x"}]
        result = self.engine.apply(df, rules)
        self.assertEqual(len(result), len(df))
        self.gov.rule_applied.assert_not_called()


class TestFlag(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.engine = BusinessRuleEngine(self.gov)

    def test_flag_gt(self):
        df = _fresh_df()
        rules = [{"type": "flag", "condition_column": "salary",
                  "operator": "gt", "threshold": 55000, "new_column": "high_paid"}]
        result = self.engine.apply(df, rules)
        # "50000">55000 False; "60000" True; None->NaN False; "70000" True
        self.assertEqual(list(result["high_paid"]), [False, True, False, True])

    def test_flag_all_operators(self):
        for op, expected in {
            "gte": [True, True, False, True],   # >=50000
            "lt": [False, False, False, False],  # <50000
            "lte": [True, False, False, False],  # <=50000
            "eq": [True, False, False, False],   # ==50000
            # NaN != 50000 is True in pandas (NaN compares unequal to all),
            # unlike eq/gt/lt where NaN yields False — so index 2 is True here.
            "neq": [False, True, True, True],    # !=50000
        }.items():
            with self.subTest(op=op):
                df = _fresh_df()
                rules = [{"type": "flag", "condition_column": "salary",
                          "operator": op, "threshold": 50000, "new_column": "f"}]
                result = self.engine.apply(df, rules)
                self.assertEqual(list(result["f"]), expected)

    def test_flag_unknown_operator_isolated(self):
        df = _fresh_df()
        rules = [{"type": "flag", "condition_column": "salary",
                  "operator": "bogus", "threshold": 0, "new_column": "f"}]
        result = self.engine.apply(df, rules)
        self.assertNotIn("f", result.columns)
        self.gov.error.assert_called_once()

    def test_flag_missing_column_logs_and_skips(self):
        df = _fresh_df()
        rules = [{"type": "flag", "condition_column": "ghost",
                  "operator": "gt", "threshold": 0, "new_column": "f"}]
        result = self.engine.apply(df, rules)
        self.assertNotIn("f", result.columns)
        self.gov.rule_applied.assert_not_called()


class TestEngineRobustness(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.engine = BusinessRuleEngine(self.gov)

    def test_unknown_rule_type_is_skipped(self):
        df = _fresh_df()
        result = self.engine.apply(df, [{"type": "teleport"}])
        self.assertEqual(len(result), len(df))
        self.gov.rule_applied.assert_not_called()

    def test_one_bad_rule_does_not_abort_the_rest(self):
        df = _fresh_df()
        rules = [
            {"type": "fill_null", "column": "salary"},   # missing 'value' -> KeyError
            {"type": "rename", "from": "dept", "to": "department"},  # should still run
        ]
        result = self.engine.apply(df, rules)
        self.assertIn("department", result.columns)
        self.gov.error.assert_called_once()

    def test_rules_apply_in_order(self):
        df = _fresh_df()
        rules = [
            {"type": "rename", "from": "salary", "to": "pay"},
            {"type": "fill_null", "column": "pay", "value": "0"},
        ]
        result = self.engine.apply(df, rules)
        self.assertIn("pay", result.columns)
        self.assertEqual(result["pay"].isnull().sum(), 0)

    def test_empty_rule_list_returns_unchanged(self):
        df = _fresh_df()
        result = self.engine.apply(df, [])
        pd.testing.assert_frame_equal(result, df)


class TestLoadRules(unittest.TestCase):
    def test_load_rules_from_file(self):
        gov = MagicMock()
        engine = BusinessRuleEngine(gov)
        rules = [{"type": "rename", "from": "a", "to": "b"}]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "rules.json"
            path.write_text(json.dumps(rules), encoding="utf-8")
            loaded = engine.load_rules(str(path))
        self.assertEqual(loaded, rules)


if __name__ == "__main__":
    unittest.main()
