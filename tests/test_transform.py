"""
Tests for pipeline.transform — Transformer class.

Covers mask_pii, drop_duplicates, fill_nulls, standardise_names,
flatten_nested, coerce_types, apply_business_rules, enrich,
and the full transform() pipeline.
"""

import hashlib
import unittest

import numpy as np
import pandas as pd

from pipeline.constants import RunContext
from pipeline.transform import Transformer


class MockGov:
    """Records every governance call for assertion."""

    def __init__(self):
        self.events = []

    def __getattr__(self, name):
        def recorder(*args, **kwargs):
            self.events.append((name, args, kwargs))
        return recorder


class TestMaskPii(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov)

    def test_columns_are_hashed(self):
        df = pd.DataFrame({
            "email": ["alice@example.com", "bob@example.com"],
            "name": ["Alice Test", "Bob Test"],
        })
        result = self.t.mask_pii(df, ["email"])
        expected_hash = hashlib.sha256("alice@example.com".encode()).hexdigest()[:8]
        self.assertEqual(result["email"].iloc[0], expected_hash)
        # name column untouched
        self.assertEqual(result["name"].iloc[0], "Alice Test")

    def test_none_values_preserved(self):
        df = pd.DataFrame({"email": [None, "alice@example.com"]})
        result = self.t.mask_pii(df, ["email"])
        self.assertIsNone(result["email"].iloc[0])
        self.assertIsNotNone(result["email"].iloc[1])

    def test_missing_column_ignored(self):
        df = pd.DataFrame({"name": ["Alice Test"]})
        result = self.t.mask_pii(df, ["nonexistent_col"])
        pd.testing.assert_frame_equal(result, df)

    def test_does_not_modify_original(self):
        df = pd.DataFrame({"email": ["alice@example.com"]})
        original_val = df["email"].iloc[0]
        self.t.mask_pii(df, ["email"])
        self.assertEqual(df["email"].iloc[0], original_val)


class TestDropDuplicates(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov)

    def test_removes_full_duplicates(self):
        df = pd.DataFrame({"a": [1, 1, 2], "b": [10, 10, 20]})
        result = self.t.drop_duplicates(df)
        self.assertEqual(len(result), 2)

    def test_with_subset(self):
        df = pd.DataFrame({"a": [1, 1, 2], "b": [10, 20, 30]})
        result = self.t.drop_duplicates(df, subset=["a"])
        self.assertEqual(len(result), 2)

    def test_no_duplicates(self):
        df = pd.DataFrame({"a": [1, 2, 3]})
        result = self.t.drop_duplicates(df)
        self.assertEqual(len(result), 3)

    def test_index_reset(self):
        df = pd.DataFrame({"a": [1, 1, 2]})
        result = self.t.drop_duplicates(df)
        self.assertEqual(list(result.index), list(range(len(result))))


class TestFillNulls(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov)

    def test_custom_fill_dict(self):
        df = pd.DataFrame({"a": [1.0, np.nan], "b": ["x", None]})
        result = self.t.fill_nulls(df, fill={"a": 99, "b": "missing"})
        self.assertEqual(result["a"].iloc[1], 99)
        self.assertEqual(result["b"].iloc[1], "missing")

    def test_default_fill_string_columns(self):
        df = pd.DataFrame({"name": ["Alice", None]})
        result = self.t.fill_nulls(df)
        self.assertEqual(result["name"].iloc[1], "")

    def test_default_fill_numeric_columns(self):
        df = pd.DataFrame({"score": [100.0, np.nan]})
        result = self.t.fill_nulls(df)
        self.assertEqual(result["score"].iloc[1], 0)

    def test_does_not_modify_original(self):
        df = pd.DataFrame({"a": [1.0, np.nan]})
        self.t.fill_nulls(df, fill={"a": 99})
        self.assertTrue(pd.isna(df["a"].iloc[1]))


class TestStandardiseNames(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov)

    def test_lowercased(self):
        df = pd.DataFrame({"MyColumn": [1]})
        result = self.t.standardise_names(df)
        self.assertEqual(list(result.columns), ["mycolumn"])

    def test_spaces_to_underscores(self):
        df = pd.DataFrame({"First Name": [1]})
        result = self.t.standardise_names(df)
        self.assertEqual(list(result.columns), ["first_name"])

    def test_special_chars_removed(self):
        df = pd.DataFrame({"email@addr!": [1], "cost ($)": [2]})
        result = self.t.standardise_names(df)
        for col in result.columns:
            self.assertRegex(col, r"^[a-z0-9_]+$")

    def test_does_not_modify_original(self):
        df = pd.DataFrame({"MyCol": [1]})
        self.t.standardise_names(df)
        self.assertEqual(list(df.columns), ["MyCol"])


class TestFlattenNested(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov)

    def test_dict_cells_expanded(self):
        df = pd.DataFrame({
            "id": [1],
            "meta": [{"city": "NYC", "zip": "10001"}],
        })
        result = self.t.flatten_nested(df)
        # flattened columns should contain city and zip values
        flat_values = result.iloc[0].to_dict()
        has_city = any("city" in str(k) and flat_values[k] == "NYC" for k in flat_values)
        self.assertTrue(has_city, f"Expected city=NYC in flattened result: {flat_values}")

    def test_list_cells_expanded(self):
        df = pd.DataFrame({
            "id": [1],
            "scores": [[90, 80, 70]],
        })
        result = self.t.flatten_nested(df)
        # list elements should be expanded into separate columns
        self.assertGreater(len(result.columns), 1)

    def test_scalar_columns_unchanged(self):
        df = pd.DataFrame({"a": [1, 2], "b": ["x", "y"]})
        result = self.t.flatten_nested(df)
        self.assertEqual(list(result["a"]), [1, 2])
        self.assertEqual(list(result["b"]), ["x", "y"])


class TestCoerceTypes(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov)

    def test_successful_coercion(self):
        df = pd.DataFrame({"amount": ["100", "200", "300"]})
        result = self.t.coerce_types(df, {"amount": "int64"})
        self.assertEqual(result["amount"].dtype, np.dtype("int64"))

    def test_graceful_failure(self):
        df = pd.DataFrame({"amount": ["abc", "def"]})
        result = self.t.coerce_types(df, {"amount": "int64"})
        # should silently keep the original dtype
        self.assertEqual(result["amount"].dtype, object)

    def test_missing_column_skipped(self):
        df = pd.DataFrame({"a": [1]})
        result = self.t.coerce_types(df, {"nonexistent": "float"})
        pd.testing.assert_frame_equal(result, df)

    def test_does_not_modify_original(self):
        df = pd.DataFrame({"x": ["1", "2"]})
        self.t.coerce_types(df, {"x": "int64"})
        self.assertEqual(df["x"].dtype, object)


class TestApplyBusinessRules(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov)

    def test_gt_operator(self):
        df = pd.DataFrame({"age": [10, 20, 30]})
        rules = [{"column": "age", "op": "gt", "value": 15}]
        result = self.t.apply_business_rules(df, rules)
        self.assertEqual(list(result["age"]), [20, 30])

    def test_lt_operator(self):
        df = pd.DataFrame({"age": [10, 20, 30]})
        rules = [{"column": "age", "op": "lt", "value": 25}]
        result = self.t.apply_business_rules(df, rules)
        self.assertEqual(list(result["age"]), [10, 20])

    def test_eq_operator(self):
        df = pd.DataFrame({"status": ["active", "inactive", "active"]})
        rules = [{"column": "status", "op": "eq", "value": "active"}]
        result = self.t.apply_business_rules(df, rules)
        self.assertEqual(len(result), 2)
        self.assertTrue((result["status"] == "active").all())

    def test_drop_if_null(self):
        df = pd.DataFrame({"val": [1.0, np.nan, 3.0]})
        rules = [{"column": "val", "op": "drop_if_null"}]
        result = self.t.apply_business_rules(df, rules)
        self.assertEqual(len(result), 2)

    def test_missing_column_ignored(self):
        df = pd.DataFrame({"a": [1, 2]})
        rules = [{"column": "nonexistent", "op": "gt", "value": 0}]
        result = self.t.apply_business_rules(df, rules)
        self.assertEqual(len(result), 2)

    def test_index_reset(self):
        df = pd.DataFrame({"age": [10, 20, 30]})
        rules = [{"column": "age", "op": "gt", "value": 15}]
        result = self.t.apply_business_rules(df, rules)
        self.assertEqual(list(result.index), list(range(len(result))))

    def test_multiple_rules(self):
        df = pd.DataFrame({"age": [10, 20, 30, 40]})
        rules = [
            {"column": "age", "op": "gt", "value": 15},
            {"column": "age", "op": "lt", "value": 35},
        ]
        result = self.t.apply_business_rules(df, rules)
        self.assertEqual(list(result["age"]), [20, 30])


class TestEnrich(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov)

    def test_left_join(self):
        df = pd.DataFrame({"dept_id": [1, 2, 3], "name": ["Alice", "Bob", "Carol"]})
        lookup = pd.DataFrame({"dept_id": [1, 2], "dept_name": ["Engineering", "Sales"]})
        result = self.t.enrich(df, {"dept_id": lookup})
        self.assertIn("dept_name", result.columns)
        self.assertEqual(result["dept_name"].iloc[0], "Engineering")
        # dept_id=3 has no match, should be NaN
        self.assertTrue(pd.isna(result["dept_name"].iloc[2]))

    def test_missing_join_column_skipped(self):
        df = pd.DataFrame({"a": [1]})
        lookup = pd.DataFrame({"b": [1], "extra": ["x"]})
        result = self.t.enrich(df, {"nonexistent": lookup})
        self.assertNotIn("extra", result.columns)

    def test_does_not_modify_original(self):
        df = pd.DataFrame({"dept_id": [1]})
        original_cols = list(df.columns)
        lookup = pd.DataFrame({"dept_id": [1], "dept_name": ["Eng"]})
        self.t.enrich(df, {"dept_id": lookup})
        self.assertEqual(list(df.columns), original_cols)


class TestTransformPipeline(unittest.TestCase):
    """Tests the full transform() orchestration method."""

    def setUp(self):
        self.gov = MockGov()
        self.ctx = RunContext(pipeline_id="test-run-001")
        self.t = Transformer(self.gov, run_context=self.ctx)

    def test_mask_strategy(self):
        df = pd.DataFrame({
            "email": ["alice@example.com"],
            "name": ["Alice Test"],
        })
        pii = [{"field": "email"}]
        result = self.t.transform(df, pii, "mask", drop_cols=[])
        # email should be masked (starts with MASKED_)
        email_col = [c for c in result.columns if "email" in c.lower()]
        if email_col:
            self.assertTrue(
                str(result[email_col[0]].iloc[0]).startswith("MASKED_"),
                "PII field should be masked",
            )

    def test_drop_strategy(self):
        df = pd.DataFrame({
            "email": ["alice@example.com"],
            "name": ["Alice Test"],
        })
        pii = [{"field": "email"}]
        result = self.t.transform(df, pii, "drop", drop_cols=[])
        email_cols = [c for c in result.columns if "email" in c.lower()]
        self.assertEqual(len(email_cols), 0, "PII field should be dropped")

    def test_retain_strategy(self):
        df = pd.DataFrame({
            "email": ["alice@example.com"],
            "name": ["Alice Test"],
        })
        pii = [{"field": "email"}]
        result = self.t.transform(df, pii, "retain", drop_cols=[])
        email_cols = [c for c in result.columns if "email" in c.lower()]
        self.assertTrue(len(email_cols) > 0, "Retained field should still exist")

    def test_string_pii_findings_converted(self):
        """When pii_findings is a list of strings, transform auto-wraps them."""
        df = pd.DataFrame({"email": ["alice@example.com"], "id": [1]})
        result = self.t.transform(df, ["email"], "mask", drop_cols=[])
        email_col = [c for c in result.columns if "email" in c.lower()]
        if email_col:
            self.assertTrue(str(result[email_col[0]].iloc[0]).startswith("MASKED_"))

    def test_drop_cols(self):
        df = pd.DataFrame({"a": [1], "internal_id": [99]})
        result = self.t.transform(df, [], "mask", drop_cols=["internal_id"])
        id_cols = [c for c in result.columns if "internal_id" in c.lower()]
        self.assertEqual(len(id_cols), 0)

    def test_pipeline_metadata_columns(self):
        df = pd.DataFrame({"a": [1]})
        result = self.t.transform(df, [], "mask", drop_cols=[])
        self.assertIn("_pipeline_id", result.columns)
        self.assertIn("_loaded_at_utc", result.columns)
        self.assertEqual(result["_pipeline_id"].iloc[0], "test-run-001")

    def test_governance_events_recorded(self):
        df = pd.DataFrame({"a": [1]})
        self.t.transform(df, [], "mask", drop_cols=[])
        event_names = [e[0] for e in self.gov.events]
        self.assertIn("transformation_applied", event_names)

    def test_deduplication_in_pipeline(self):
        df = pd.DataFrame({"a": [1, 1, 2], "b": [10, 10, 20]})
        result = self.t.transform(df, [], "mask", drop_cols=[])
        # should have removed the duplicate row
        self.assertEqual(len(result), 2)

    def test_column_sanitization(self):
        df = pd.DataFrame({"col with spaces!": [1]})
        result = self.t.transform(df, [], "mask", drop_cols=[])
        for col in result.columns:
            if not col.startswith("_"):
                self.assertRegex(col, r"^[a-zA-Z0-9_]+$")

    def test_flatten_nested_in_pipeline(self):
        df = pd.DataFrame({
            "id": [1],
            "meta": [{"city": "NYC"}],
        })
        result = self.t.transform(df, [], "mask", drop_cols=[])
        # Should have been flattened
        self.assertGreater(len(result.columns), 3)  # id + flattened + _pipeline_id + _loaded_at


class TestEdgeCases(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.t = Transformer(self.gov, run_context=RunContext(pipeline_id="edge-test"))

    def test_empty_dataframe(self):
        df = pd.DataFrame()
        result = self.t.transform(df, [], "mask", drop_cols=[])
        self.assertIn("_pipeline_id", result.columns)
        self.assertEqual(len(result), 0)

    def test_no_pii_fields(self):
        df = pd.DataFrame({"product": ["Widget"], "qty": [5]})
        result = self.t.transform(df, [], "mask", drop_cols=[])
        self.assertIn("_pipeline_id", result.columns)

    def test_all_null_column(self):
        df = pd.DataFrame({"a": [1, 2], "b": [None, None]})
        result = self.t.fill_nulls(df)
        # default fill for object column is ""
        self.assertTrue((result["b"] == "").all())

    def test_mask_pii_empty_df(self):
        df = pd.DataFrame({"email": pd.Series([], dtype=object)})
        result = self.t.mask_pii(df, ["email"])
        self.assertEqual(len(result), 0)

    def test_drop_duplicates_empty_df(self):
        df = pd.DataFrame({"a": pd.Series([], dtype=int)})
        result = self.t.drop_duplicates(df)
        self.assertEqual(len(result), 0)

    def test_apply_business_rules_empty_df(self):
        df = pd.DataFrame({"age": pd.Series([], dtype=int)})
        rules = [{"column": "age", "op": "gt", "value": 10}]
        result = self.t.apply_business_rules(df, rules)
        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
