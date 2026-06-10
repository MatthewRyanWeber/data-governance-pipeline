"""
Tests for the Great Expectations schema validator.

Tests the non-interactive parts: suite building and validation.
When great_expectations is not installed, tests verify graceful fallback.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.schema_validator import SchemaValidator


class TestSchemaValidatorWithoutGX(unittest.TestCase):
    """Tests that run regardless of whether great_expectations is installed."""

    def setUp(self):
        self.gov = MagicMock()
        self.dlq = MagicMock()

    def test_init_creates_suite_name(self):
        sv = SchemaValidator(self.gov, self.dlq)
        self.assertTrue(sv.suite_name.startswith("pipeline_suite_"))

    def test_build_suite_without_gx_returns_empty(self):
        with patch("pipeline.schema_validator.HAS_GX", False):
            sv = SchemaValidator(self.gov, self.dlq)
            df = pd.DataFrame({"a": [1, 2]})
            result = sv.build_suite(df, interactive=False)
            self.assertEqual(result, [])

    def test_validate_without_gx_returns_unchanged(self):
        with patch("pipeline.schema_validator.HAS_GX", False):
            sv = SchemaValidator(self.gov, self.dlq)
            df = pd.DataFrame({"a": [1, 2]})
            result_df, failed = sv.validate(df, [])
            self.assertEqual(failed, 0)
            pd.testing.assert_frame_equal(result_df, df)


class TestSchemaValidatorWithGX(unittest.TestCase):
    """Tests that require great_expectations with compatible API."""

    def setUp(self):
        self.gov = MagicMock()
        self.dlq = MagicMock()
        try:
            from great_expectations import expectations as gxe
            gxe.ExpectColumnToExist
            self._gx_ok = True
        except (ImportError, AttributeError):
            self._gx_ok = False

    def test_build_suite_generates_expectations(self):
        if not self._gx_ok:
            self.skipTest("great_expectations API incompatible or not installed")
        sv = SchemaValidator(self.gov, self.dlq)
        df = pd.DataFrame({"id": [1, 2, 3], "name": ["a", "b", "c"]})
        expectations = sv.build_suite(df, interactive=False)
        self.assertGreater(len(expectations), 0)

    def test_validate_passing_suite(self):
        if not self._gx_ok:
            self.skipTest("great_expectations API incompatible or not installed")
        sv = SchemaValidator(self.gov, self.dlq)
        df = pd.DataFrame({"id": [1, 2, 3], "name": ["a", "b", "c"]})
        expectations = sv.build_suite(df, interactive=False)
        result_df, failed = sv.validate(df, expectations)
        self.assertEqual(failed, 0)


if __name__ == "__main__":
    unittest.main()
