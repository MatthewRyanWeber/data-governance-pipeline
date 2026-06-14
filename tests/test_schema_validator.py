"""
Tests for the Great Expectations schema validator.

Tests the non-interactive parts: suite building and validation.
When great_expectations is not installed, tests verify graceful fallback.

Why the two TestSchemaValidatorWithGX cases may report as SKIPPED
───────────────────────────────────────────────────────────────
`schema_validator.py` targets the Great Expectations **1.x** API
(`gxe.ExpectColumnToExist`, `ctx.suites.add(...)`). GX is an *optional*
dependency, so these two tests skip — by design — whenever a compatible
GX is not importable. That happens in two situations:

  1. GX is not installed at all (it is not in the CI deps, so these two
     tests skip in CI today — they exercise an optional capability).
  2. GX is installed but is a 0.x release, whose API differs. This is the
     case on Python 3.14: GX 1.x requires `<3.14`, so the newest version
     that installs there is 0.18.x — incompatible with the 1.x calls.

The skips are therefore an environment/optional-dependency signal, NOT a
failure or a masked bug. To make them RUN, install GX 1.x on a supported
interpreter (Python 3.10–3.13): `pip install "great_expectations>=1.0"`.

Revision history
────────────────
1.0   2026-06-09   Initial release.
1.1   2026-06-14   Document why the GX cases skip (optional dep; GX 1.x is
                   uninstallable on Python 3.14, leaving an incompatible 0.x).
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
            self.skipTest(
                "Optional dep: needs Great Expectations 1.x (absent in CI; "
                "uninstallable on Python 3.14 — see module docstring)"
            )
        sv = SchemaValidator(self.gov, self.dlq)
        df = pd.DataFrame({"id": [1, 2, 3], "name": ["a", "b", "c"]})
        expectations = sv.build_suite(df, interactive=False)
        self.assertGreater(len(expectations), 0)

    def test_validate_passing_suite(self):
        if not self._gx_ok:
            self.skipTest(
                "Optional dep: needs Great Expectations 1.x (absent in CI; "
                "uninstallable on Python 3.14 — see module docstring)"
            )
        sv = SchemaValidator(self.gov, self.dlq)
        df = pd.DataFrame({"id": [1, 2, 3], "name": ["a", "b", "c"]})
        expectations = sv.build_suite(df, interactive=False)
        result_df, failed = sv.validate(df, expectations)
        self.assertEqual(failed, 0)


if __name__ == "__main__":
    unittest.main()
