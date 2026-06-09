"""
Tests for pipeline.loaders.base — validation helpers and BaseLoader class.

Revision history
────────────────
1.0   2026-06-08   Initial test suite covering validate_sql_identifier,
                   validate_float_vector, validate_column_names, and BaseLoader.
1.1   2026-06-09   Added retry_with_backoff and circuit breaker integration tests.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.exceptions import CircuitOpenError, ConfigValidationError
from pipeline.loaders.base import (
    BaseLoader,
    validate_column_names,
    validate_float_vector,
    validate_sql_identifier,
)


# ── validate_sql_identifier ─────────────────────────────────────────────────

class TestValidateSqlIdentifier(unittest.TestCase):
    """Rejects SQL-injection characters; accepts safe identifiers."""

    def test_empty_string_raises(self):
        with self.assertRaises(ValueError):
            validate_sql_identifier("", "table")

    def test_semicolon_raises(self):
        with self.assertRaises(ValueError):
            validate_sql_identifier("users;", "table")

    def test_quotes_raises(self):
        with self.assertRaises(ValueError):
            validate_sql_identifier('col"name', "column")

    def test_spaces_raises(self):
        with self.assertRaises(ValueError):
            validate_sql_identifier("my table", "table")

    def test_dashes_raises(self):
        with self.assertRaises(ValueError):
            validate_sql_identifier("my-table", "table")

    def test_sql_injection_payload_raises(self):
        with self.assertRaises(ValueError):
            validate_sql_identifier("users; DROP TABLE x", "table")

    def test_double_dash_comment_raises(self):
        with self.assertRaises(ValueError):
            validate_sql_identifier("col--comment", "column")

    def test_asterisk_raises(self):
        with self.assertRaises(ValueError):
            validate_sql_identifier("*", "column")

    def test_valid_simple_name(self):
        self.assertEqual(validate_sql_identifier("my_table", "table"), "my_table")

    def test_valid_schema_dot_table(self):
        self.assertEqual(
            validate_sql_identifier("schema.table_1", "table"), "schema.table_1"
        )

    def test_valid_underscore_start(self):
        self.assertEqual(
            validate_sql_identifier("_underscore_start", "column"),
            "_underscore_start",
        )


# ── validate_float_vector ───────────────────────────────────────────────────

class TestValidateFloatVector(unittest.TestCase):
    """Converts elements to float, rejects non-numeric / non-finite values."""

    def test_empty_list(self):
        self.assertEqual(validate_float_vector([], "vec"), [])

    def test_floats_returned_unchanged(self):
        self.assertEqual(validate_float_vector([1.0, 2.0, 3.0], "vec"), [1.0, 2.0, 3.0])

    def test_ints_converted_to_floats(self):
        result = validate_float_vector([1, 2, 3], "vec")
        self.assertEqual(result, [1.0, 2.0, 3.0])
        for v in result:
            self.assertIsInstance(v, float)

    def test_non_numeric_raises_at_index_0(self):
        with self.assertRaises(ValueError) as ctx:
            validate_float_vector(["a", 2.0], "vec")
        self.assertIn("vec[0]", str(ctx.exception))

    def test_nan_raises_at_index_1(self):
        with self.assertRaises(ValueError) as ctx:
            validate_float_vector([1.0, float("nan")], "vec")
        self.assertIn("vec[1]", str(ctx.exception))

    def test_inf_raises_at_index_1(self):
        with self.assertRaises(ValueError) as ctx:
            validate_float_vector([1.0, float("inf")], "vec")
        self.assertIn("vec[1]", str(ctx.exception))


# ── validate_column_names ───────────────────────────────────────────────────

class TestValidateColumnNames(unittest.TestCase):
    """Rejects DataFrame columns with SQL-injection characters."""

    def test_normal_columns_pass(self):
        df = pd.DataFrame(columns=["id", "name", "value"])
        validate_column_names(df, "test_df")

    def test_semicolon_in_column_raises(self):
        df = pd.DataFrame(columns=["id; DROP TABLE"])
        with self.assertRaises(ValueError):
            validate_column_names(df, "test_df")

    def test_quote_in_column_raises(self):
        df = pd.DataFrame(columns=["name'"])
        with self.assertRaises(ValueError):
            validate_column_names(df, "test_df")


# ── BaseLoader ──────────────────────────────────────────────────────────────

class TestBaseLoader(unittest.TestCase):
    """Tests for BaseLoader init, dry-run guard, and config validation."""

    def setUp(self):
        logging.disable(logging.NOTSET)

    def _make_loader(self, dry_run: bool = False) -> BaseLoader:
        gov = MagicMock()
        return BaseLoader(gov=gov, dry_run=dry_run)

    # -- __init__ --

    def test_init_stores_gov_and_default_dry_run(self):
        gov = MagicMock()
        loader = BaseLoader(gov=gov)
        self.assertIs(loader.gov, gov)
        self.assertFalse(loader.dry_run)

    def test_init_stores_dry_run_true(self):
        gov = MagicMock()
        loader = BaseLoader(gov=gov, dry_run=True)
        self.assertTrue(loader.dry_run)

    # -- _dry_run_guard --

    def test_dry_run_guard_returns_false_when_off(self):
        loader = self._make_loader(dry_run=False)
        self.assertFalse(loader._dry_run_guard("my_table", 100))

    def test_dry_run_guard_returns_true_and_logs_when_on(self):
        loader = self._make_loader(dry_run=True)
        with self.assertLogs("pipeline.loaders.base", level="INFO") as cm:
            result = loader._dry_run_guard("my_table", 500)
        self.assertTrue(result)
        self.assertTrue(
            any("[DRY RUN]" in msg and "my_table" in msg for msg in cm.output)
        )

    # -- _validate_config --

    def test_validate_config_all_present(self):
        loader = self._make_loader()
        cfg = {"host": "localhost", "user": "admin"}
        loader._validate_config(cfg, ["host", "user"])

    def test_validate_config_missing_key_raises(self):
        loader = self._make_loader()
        cfg = {"host": "localhost"}
        with self.assertRaises(ConfigValidationError) as ctx:
            loader._validate_config(cfg, ["host", "user"])
        self.assertIn("user", ctx.exception.missing_keys)

    def test_validate_config_alternative_key_present(self):
        loader = self._make_loader()
        cfg = {"path": "/data/file.parquet"}
        loader._validate_config(cfg, ["host|path"])

    def test_validate_config_alternative_key_all_missing_raises(self):
        loader = self._make_loader()
        cfg = {"timeout": 30}
        with self.assertRaises(ConfigValidationError):
            loader._validate_config(cfg, ["host|path"])


# ── Retry with backoff ─────────────────────────────────────────────────────

class TestRetryWithBackoff(unittest.TestCase):
    """Tests for BaseLoader._retry_with_backoff."""

    def _make(self):
        gov = MagicMock()
        return BaseLoader(gov=gov), gov

    def test_succeeds_first_try(self):
        loader, gov = self._make()
        fn = MagicMock(return_value="ok")
        result = loader._retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        self.assertEqual(result, "ok")
        fn.assert_called_once()
        gov.retry_attempt.assert_not_called()

    def test_succeeds_on_retry(self):
        loader, gov = self._make()
        fn = MagicMock(side_effect=[RuntimeError("fail"), "ok"])
        result = loader._retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        self.assertEqual(result, "ok")
        self.assertEqual(fn.call_count, 2)
        gov.retry_attempt.assert_called_once()

    def test_exhausted_raises_last_exception(self):
        loader, gov = self._make()
        fn = MagicMock(side_effect=RuntimeError("boom"))
        with self.assertRaises(RuntimeError) as ctx:
            loader._retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        self.assertIn("boom", str(ctx.exception))
        self.assertEqual(fn.call_count, 3)
        self.assertEqual(gov.retry_attempt.call_count, 2)

    def test_circuit_success_recorded(self):
        loader, gov = self._make()
        loader._init_circuit_breaker("test_cb", failure_threshold=5)
        cb = loader._circuit_breaker
        fn = MagicMock(return_value="ok")
        with patch.object(cb, "record_success") as mock_success:
            loader._retry_with_backoff(fn, max_retries=3, base_delay=0.01)
            mock_success.assert_called_once()

    def test_circuit_failure_recorded_on_exhaust(self):
        loader, gov = self._make()
        loader._init_circuit_breaker("test_cb", failure_threshold=5)
        cb = loader._circuit_breaker
        fn = MagicMock(side_effect=RuntimeError("fail"))
        with patch.object(cb, "record_failure") as mock_fail:
            with self.assertRaises(RuntimeError):
                loader._retry_with_backoff(fn, max_retries=2, base_delay=0.01)
            mock_fail.assert_called_once()

    def test_circuit_open_blocks_retry(self):
        loader, gov = self._make()
        loader._init_circuit_breaker("test_cb2", failure_threshold=1)
        loader._circuit_breaker.record_failure()
        fn = MagicMock(return_value="ok")
        with self.assertRaises(CircuitOpenError):
            loader._retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        fn.assert_not_called()

    def test_governance_logging_per_retry(self):
        loader, gov = self._make()
        fn = MagicMock(side_effect=[RuntimeError("e1"), RuntimeError("e2"), "ok"])
        loader._retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        self.assertEqual(gov.retry_attempt.call_count, 2)
        first_call = gov.retry_attempt.call_args_list[0]
        self.assertEqual(first_call[0][0], 1)
        self.assertEqual(first_call[0][1], 3)


if __name__ == "__main__":
    unittest.main()
