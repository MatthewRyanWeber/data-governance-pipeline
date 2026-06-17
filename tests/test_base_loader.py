"""
Tests for pipeline.loaders.base — validation helpers and BaseLoader class.

Revision history
────────────────
1.0   2026-06-08   Initial test suite covering validate_sql_identifier,
                   validate_float_vector, validate_column_names, and BaseLoader.
1.1   2026-06-09   Added retry_with_backoff and circuit breaker integration tests.
1.2   2026-06-09   Added field-level encryption helpers tests.
1.3   2026-06-17   Added _adaptive_chunksize and _execute_outside_transaction tests.
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


# ── Field-level encryption helpers ─────────────────────────────────────────

class TestFieldLevelEncryption(unittest.TestCase):
    """Tests for BaseLoader._encrypt_columns, _decrypt_columns, _apply_load_encryption."""

    def _make(self):
        gov = MagicMock()
        return BaseLoader(gov=gov), gov

    def _key(self):
        from pipeline.privacy.column_encryptor import ColumnEncryptor
        return ColumnEncryptor.generate_key()

    def test_encrypt_adds_prefix(self):
        loader, _ = self._make()
        df = pd.DataFrame({"secret": ["alice", "bob"]})
        key = self._key()
        result = loader._encrypt_columns(df, ["secret"], key)
        for val in result["secret"]:
            self.assertTrue(str(val).startswith("ENCRYPTED:"))

    def test_round_trip_recovers_values(self):
        loader, _ = self._make()
        df = pd.DataFrame({"secret": ["alice", "bob"], "public": [1, 2]})
        key = self._key()
        encrypted = loader._encrypt_columns(df.copy(), ["secret"], key)
        decrypted = loader._decrypt_columns(encrypted, ["secret"], key)
        self.assertEqual(decrypted["secret"].tolist(), ["alice", "bob"])
        self.assertEqual(decrypted["public"].tolist(), [1, 2])

    def test_apply_load_encryption_no_op_without_config(self):
        loader, _ = self._make()
        df = pd.DataFrame({"a": [1, 2]})
        result = loader._apply_load_encryption(df, {})
        self.assertEqual(result["a"].tolist(), [1, 2])

    def test_apply_load_encryption_encrypts_with_config(self):
        loader, _ = self._make()
        key = self._key()
        df = pd.DataFrame({"secret": ["val1", "val2"]})
        cfg = {"encrypt_columns": ["secret"], "encryption_key": key}
        result = loader._apply_load_encryption(df, cfg)
        for val in result["secret"]:
            self.assertTrue(str(val).startswith("ENCRYPTED:"))

    def test_missing_columns_ignored(self):
        loader, _ = self._make()
        key = self._key()
        df = pd.DataFrame({"a": [1]})
        result = loader._encrypt_columns(df, ["nonexistent"], key)
        self.assertEqual(result["a"].tolist(), [1])


# ── Adaptive write batching ────────────────────────────────────────────────

class TestAdaptiveChunksize(unittest.TestCase):
    """Tests for BaseLoader._adaptive_chunksize — byte- and parameter-aware."""

    def _make(self) -> BaseLoader:
        return BaseLoader(gov=MagicMock())

    def test_empty_frame_returns_fallback(self):
        loader = self._make()
        df = pd.DataFrame({"a": []})
        self.assertEqual(loader._adaptive_chunksize(df, fallback_rows=500), 500)

    def test_thin_rows_get_a_large_chunk(self):
        loader = self._make()
        # A few small integer columns: thousands of rows fit in the byte budget.
        df = pd.DataFrame({"a": range(2000), "b": range(2000)})
        chunk = loader._adaptive_chunksize(df)
        # Never larger than the frame itself, and not the old fixed 500 floor.
        self.assertLessEqual(chunk, len(df))
        self.assertGreater(chunk, 500)

    def test_large_cell_rows_get_a_small_chunk(self):
        loader = self._make()
        # ~1 MiB per row: an 8 MiB budget should allow only a handful of rows.
        big = "x" * (1024 * 1024)
        df = pd.DataFrame({"blob": [big] * 64})
        chunk = loader._adaptive_chunksize(df, target_bytes=8 * 1024 * 1024)
        self.assertGreaterEqual(chunk, 1)
        self.assertLessEqual(chunk, 12)

    def test_huge_cell_never_returns_zero(self):
        loader = self._make()
        # A single row larger than the whole budget must still load — one row.
        huge = "x" * (20 * 1024 * 1024)
        df = pd.DataFrame({"blob": [huge]})
        self.assertEqual(loader._adaptive_chunksize(df, target_bytes=8 * 1024 * 1024), 1)

    def test_multi_method_applies_parameter_cap(self):
        loader = self._make()
        # 100 thin columns with method="multi": the 2,100-parameter cap
        # (2000 // 100 = 20) must dominate the byte budget.
        df = pd.DataFrame({f"c{i}": range(500) for i in range(100)})
        chunk = loader._adaptive_chunksize(df, method="multi", max_param_count=2000)
        self.assertEqual(chunk, 20)

    def test_no_method_ignores_parameter_cap(self):
        loader = self._make()
        # Same wide frame without method="multi": no per-statement param cap,
        # so the chunk is governed by bytes and exceeds the param-capped 20.
        df = pd.DataFrame({f"c{i}": range(500) for i in range(100)})
        chunk = loader._adaptive_chunksize(df)
        self.assertGreater(chunk, 20)

    def test_never_exceeds_row_count(self):
        loader = self._make()
        df = pd.DataFrame({"a": range(10)})
        self.assertLessEqual(loader._adaptive_chunksize(df), 10)


# ── Maintenance DDL outside a transaction ──────────────────────────────────

class TestExecuteOutsideTransaction(unittest.TestCase):
    """Tests for BaseLoader._execute_outside_transaction — autocommit DDL."""

    def _make(self) -> BaseLoader:
        return BaseLoader(gov=MagicMock())

    def _engine(self):
        from sqlalchemy import create_engine
        return create_engine("sqlite://")  # in-memory, autocommit-capable

    def test_runs_statements_and_counts_them(self):
        loader = self._make()
        engine = self._engine()
        executed = loader._execute_outside_transaction(
            engine,
            ["CREATE TABLE t (id INTEGER)", "INSERT INTO t VALUES (1)"],
        )
        self.assertEqual(executed, 2)
        from sqlalchemy import text
        with engine.connect() as conn:
            self.assertEqual(conn.execute(text("SELECT COUNT(*) FROM t")).scalar(), 1)

    def test_best_effort_skips_a_failing_statement(self):
        loader = self._make()
        engine = self._engine()
        # The bogus middle statement is logged and skipped; the others run.
        executed = loader._execute_outside_transaction(
            engine,
            ["CREATE TABLE t (id INTEGER)", "ALTER DATABASE nonsense", "INSERT INTO t VALUES (1)"],
            best_effort=True,
        )
        self.assertEqual(executed, 2)

    def test_strict_mode_raises_on_first_failure(self):
        loader = self._make()
        engine = self._engine()
        with self.assertRaises(Exception):
            loader._execute_outside_transaction(
                engine, ["THIS IS NOT SQL"], best_effort=False,
            )


if __name__ == "__main__":
    unittest.main()
