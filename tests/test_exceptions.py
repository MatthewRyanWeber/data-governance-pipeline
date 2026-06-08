"""
Tests for pipeline.exceptions — custom exception classes.
"""

import unittest

from pipeline.exceptions import (
    ConfigValidationError,
    ContractViolationError,
    ExtractionError,
    LoaderError,
    ValidationError,
)


class TestConfigValidationError(unittest.TestCase):

    def test_attributes_stored(self):
        exc = ConfigValidationError(
            db_type="postgresql", missing_keys=["host", "port"]
        )
        self.assertEqual(exc.db_type, "postgresql")
        self.assertEqual(exc.missing_keys, ["host", "port"])

    def test_default_values(self):
        exc = ConfigValidationError()
        self.assertEqual(exc.db_type, "")
        self.assertEqual(exc.missing_keys, [])

    def test_auto_message_includes_db_type_and_keys(self):
        exc = ConfigValidationError(
            db_type="snowflake", missing_keys=["account", "warehouse"]
        )
        msg = str(exc)
        self.assertIn("snowflake", msg)
        self.assertIn("account", msg)
        self.assertIn("warehouse", msg)

    def test_custom_message_overrides_default(self):
        exc = ConfigValidationError(
            db_type="mysql",
            missing_keys=["host"],
            message="custom error text",
        )
        self.assertEqual(str(exc), "custom error text")

    def test_is_value_error(self):
        exc = ConfigValidationError()
        self.assertIsInstance(exc, ValueError)

    def test_raise_and_catch(self):
        with self.assertRaises(ConfigValidationError):
            raise ConfigValidationError(
                db_type="sqlite", missing_keys=["path"]
            )

    def test_caught_as_value_error(self):
        with self.assertRaises(ValueError):
            raise ConfigValidationError(db_type="sqlite")


class TestLoaderError(unittest.TestCase):

    def test_attributes_stored(self):
        exc = LoaderError(db_type="bigquery", table="events")
        self.assertEqual(exc.db_type, "bigquery")
        self.assertEqual(exc.table, "events")

    def test_default_values(self):
        exc = LoaderError()
        self.assertEqual(exc.db_type, "")
        self.assertEqual(exc.table, "")

    def test_auto_message_includes_info(self):
        exc = LoaderError(db_type="redshift", table="users")
        msg = str(exc)
        self.assertIn("redshift", msg)
        self.assertIn("users", msg)

    def test_custom_message_overrides_default(self):
        exc = LoaderError(
            db_type="postgres", table="orders", message="timeout after 30s"
        )
        self.assertEqual(str(exc), "timeout after 30s")

    def test_is_exception(self):
        exc = LoaderError()
        self.assertIsInstance(exc, Exception)
        self.assertNotIsInstance(exc, ValueError)

    def test_raise_and_catch(self):
        with self.assertRaises(LoaderError):
            raise LoaderError(db_type="mongo", table="docs")


class TestExtractionError(unittest.TestCase):

    def test_attributes_stored(self):
        exc = ExtractionError(source="/data/file.csv", format="csv")
        self.assertEqual(exc.source, "/data/file.csv")
        self.assertEqual(exc.format, "csv")

    def test_default_values(self):
        exc = ExtractionError()
        self.assertEqual(exc.source, "")
        self.assertEqual(exc.format, "")

    def test_auto_message_includes_info(self):
        exc = ExtractionError(source="s3://bucket/data.parquet", format="parquet")
        msg = str(exc)
        self.assertIn("s3://bucket/data.parquet", msg)
        self.assertIn("parquet", msg)

    def test_custom_message_overrides_default(self):
        exc = ExtractionError(
            source="file.json", format="json", message="malformed JSON"
        )
        self.assertEqual(str(exc), "malformed JSON")

    def test_is_exception(self):
        exc = ExtractionError()
        self.assertIsInstance(exc, Exception)
        self.assertNotIsInstance(exc, ValueError)

    def test_raise_and_catch(self):
        with self.assertRaises(ExtractionError):
            raise ExtractionError(source="bad.xml", format="xml")


class TestValidationError(unittest.TestCase):

    def test_attributes_stored(self):
        details = [{"field": "email", "error": "invalid"}]
        exc = ValidationError(rule_name="email_check", details=details)
        self.assertEqual(exc.rule_name, "email_check")
        self.assertEqual(exc.details, details)

    def test_default_values(self):
        exc = ValidationError()
        self.assertEqual(exc.rule_name, "")
        self.assertEqual(exc.details, [])

    def test_auto_message_includes_rule_and_count(self):
        details = [{"f": "a"}, {"f": "b"}, {"f": "c"}]
        exc = ValidationError(rule_name="not_null", details=details)
        msg = str(exc)
        self.assertIn("not_null", msg)
        self.assertIn("3", msg)

    def test_auto_message_zero_issues(self):
        exc = ValidationError(rule_name="schema_check")
        msg = str(exc)
        self.assertIn("0", msg)

    def test_custom_message_overrides_default(self):
        exc = ValidationError(
            rule_name="range_check",
            details=[{"f": "x"}],
            message="value out of range",
        )
        self.assertEqual(str(exc), "value out of range")

    def test_is_exception(self):
        exc = ValidationError()
        self.assertIsInstance(exc, Exception)
        self.assertNotIsInstance(exc, ValueError)

    def test_raise_and_catch(self):
        with self.assertRaises(ValidationError):
            raise ValidationError(rule_name="unique_check")


class TestContractViolationError(unittest.TestCase):

    def _sample_violation(self, severity="CRITICAL", clause="schema", rule="not_null",
                          column="id", expected="non-null", actual="null"):
        return {
            "severity": severity,
            "clause": clause,
            "rule": rule,
            "column": column,
            "expected": expected,
            "actual": actual,
        }

    def test_attributes_stored(self):
        v = [self._sample_violation()]
        w = [self._sample_violation(severity="WARNING", rule="freshness")]
        exc = ContractViolationError(
            contract_name="orders_v2", violations=v, warnings=w
        )
        self.assertEqual(exc.contract_name, "orders_v2")
        self.assertEqual(exc.violations, v)
        self.assertEqual(exc.warnings, w)

    def test_default_values(self):
        exc = ContractViolationError()
        self.assertEqual(exc.contract_name, "")
        self.assertEqual(exc.violations, [])
        self.assertEqual(exc.warnings, [])

    def test_message_includes_violation_count(self):
        v = [self._sample_violation(), self._sample_violation(rule="type_check")]
        exc = ContractViolationError(contract_name="test", violations=v)
        msg = str(exc)
        self.assertIn("2 failure(s)", msg)

    def test_message_includes_warning_count(self):
        w = [self._sample_violation(severity="WARNING")]
        exc = ContractViolationError(contract_name="test", warnings=w)
        msg = str(exc)
        self.assertIn("1 warning(s)", msg)

    def test_message_includes_contract_name(self):
        exc = ContractViolationError(contract_name="users_v3", violations=[])
        msg = str(exc)
        self.assertIn("users_v3", msg)

    def test_message_includes_severity(self):
        v = [self._sample_violation(severity="ERROR")]
        exc = ContractViolationError(contract_name="c", violations=v)
        msg = str(exc)
        self.assertIn("[ERROR]", msg)

    def test_message_includes_clause_and_rule(self):
        v = [self._sample_violation(clause="quality", rule="completeness")]
        exc = ContractViolationError(contract_name="c", violations=v)
        msg = str(exc)
        self.assertIn("quality.completeness", msg)

    def test_message_includes_column_when_present(self):
        v = [self._sample_violation(column="email")]
        exc = ContractViolationError(contract_name="c", violations=v)
        msg = str(exc)
        self.assertIn("[email]", msg)

    def test_message_excludes_column_when_absent(self):
        v = [{"severity": "CRITICAL", "clause": "schema", "rule": "row_count",
              "expected": ">0", "actual": "0"}]
        exc = ContractViolationError(contract_name="c", violations=v)
        msg = str(exc)
        self.assertNotIn("[]", msg)

    def test_message_includes_expected_and_actual(self):
        v = [self._sample_violation(expected="non-null", actual="null")]
        exc = ContractViolationError(contract_name="c", violations=v)
        msg = str(exc)
        self.assertIn("expected: non-null", msg)
        self.assertIn("actual: null", msg)

    def test_is_exception(self):
        exc = ContractViolationError()
        self.assertIsInstance(exc, Exception)
        self.assertNotIsInstance(exc, ValueError)

    def test_raise_and_catch(self):
        with self.assertRaises(ContractViolationError):
            raise ContractViolationError(
                contract_name="test",
                violations=[self._sample_violation()],
            )

    def test_multiple_violations_all_in_message(self):
        v = [
            self._sample_violation(clause="schema", rule="not_null", column="id"),
            self._sample_violation(clause="quality", rule="uniqueness", column="email"),
        ]
        exc = ContractViolationError(contract_name="multi", violations=v)
        msg = str(exc)
        self.assertIn("schema.not_null", msg)
        self.assertIn("quality.uniqueness", msg)
        self.assertIn("[id]", msg)
        self.assertIn("[email]", msg)


if __name__ == "__main__":
    unittest.main()
