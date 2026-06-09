"""
Property-based tests using hypothesis.

Validates invariants that must hold for all inputs:
1. validate_sql_identifier — accepted names match the safe regex
2. validate_float_vector — NaN/inf always rejected, finite always accepted
3. _validate_archive_member — path traversal and absolute paths always rejected
4. ColumnEncryptor — encrypt-then-decrypt round-trip recovers originals
5. validate_column_names — accepted names never contain injection characters
6. DataFrame with random column names — no crash on validate_column_names

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import re
import unittest

from hypothesis import given, strategies as st, settings, assume

from pipeline.loaders.base import (
    validate_sql_identifier,
    validate_float_vector,
    validate_column_names,
    _BAD_CHARS_RE,
)
from pipeline.compression import _validate_archive_member

import pandas as pd


SAFE_SQL_RE = re.compile(r"^[A-Za-z_][\w.]*$")


class TestSqlIdentifierProperty(unittest.TestCase):

    @given(st.text(min_size=1, max_size=50))
    @settings(max_examples=200)
    def test_accepted_names_match_safe_regex(self, name):
        try:
            result = validate_sql_identifier(name)
        except ValueError:
            return
        self.assertTrue(
            SAFE_SQL_RE.fullmatch(result),
            f"validate_sql_identifier accepted '{result}' which doesn't match safe regex",
        )

    @given(st.from_regex(r"[A-Za-z_][\w.]{0,30}", fullmatch=True))
    @settings(max_examples=100)
    def test_safe_names_always_accepted(self, name):
        result = validate_sql_identifier(name)
        self.assertEqual(result, name)


class TestFloatVectorProperty(unittest.TestCase):

    @given(st.lists(st.floats(allow_nan=False, allow_infinity=False), min_size=1, max_size=20))
    @settings(max_examples=200)
    def test_finite_floats_always_accepted(self, vec):
        result = validate_float_vector(vec)
        self.assertEqual(len(result), len(vec))

    @given(st.lists(
        st.one_of(
            st.just(float("nan")),
            st.just(float("inf")),
            st.just(float("-inf")),
        ),
        min_size=1, max_size=5,
    ))
    @settings(max_examples=50)
    def test_nan_inf_always_rejected(self, vec):
        with self.assertRaises(ValueError):
            validate_float_vector(vec)

    @given(st.lists(st.one_of(st.text(), st.none()), min_size=1, max_size=5))
    @settings(max_examples=50)
    def test_non_numeric_rejected(self, vec):
        assume(any(v is None or not _is_finite_float_str(v) for v in vec))
        with self.assertRaises(ValueError):
            validate_float_vector(vec)


def _is_finite_float_str(s):
    try:
        import math
        return math.isfinite(float(s))
    except (ValueError, TypeError):
        return False


class TestArchiveTraversalProperty(unittest.TestCase):

    @given(st.one_of(
        st.from_regex(r"\.\.[/\\].*", fullmatch=True),
        st.from_regex(r"[/\\].*", fullmatch=True),
        st.from_regex(r"[A-Za-z]:[/\\].*", fullmatch=True),
    ))
    @settings(max_examples=200)
    def test_traversal_paths_always_rejected(self, name):
        assume(len(name) > 0)
        with self.assertRaises(ValueError):
            _validate_archive_member(name)

    @given(st.from_regex(r"[a-z][a-z0-9_]{0,10}(\.[a-z]{1,5})?", fullmatch=True))
    @settings(max_examples=100)
    def test_safe_filenames_accepted(self, name):
        _validate_archive_member(name)


class TestColumnEncryptorRoundTrip(unittest.TestCase):

    @given(st.lists(st.text(min_size=1, max_size=50), min_size=1, max_size=10))
    @settings(max_examples=50)
    def test_encrypt_decrypt_recovers_values(self, values):
        from unittest.mock import MagicMock
        from pipeline.privacy.column_encryptor import ColumnEncryptor

        gov = MagicMock()
        key = ColumnEncryptor.generate_key()
        enc = ColumnEncryptor(gov, key)

        df = pd.DataFrame({"secret": values})
        original = df["secret"].tolist()

        df = enc.encrypt(df, ["secret"])
        for v in df["secret"]:
            self.assertTrue(str(v).startswith("ENCRYPTED:"))

        df = enc.decrypt(df, ["secret"])
        recovered = df["secret"].tolist()
        self.assertEqual(recovered, original)


class TestColumnNamesProperty(unittest.TestCase):

    @given(st.lists(
        st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_ ]{0,20}", fullmatch=True),
        min_size=1, max_size=5, unique=True,
    ))
    @settings(max_examples=100)
    def test_safe_column_names_accepted(self, names):
        df = pd.DataFrame({n: [1] for n in names})
        validate_column_names(df)

    @given(st.lists(
        st.text(min_size=1, max_size=30),
        min_size=1, max_size=5, unique=True,
    ))
    @settings(max_examples=200)
    def test_accepted_names_never_contain_bad_chars(self, names):
        df = pd.DataFrame({n: [1] for n in names})
        try:
            validate_column_names(df)
        except ValueError:
            return
        for col in df.columns:
            self.assertIsNone(
                _BAD_CHARS_RE.search(str(col)),
                f"validate_column_names accepted column '{col}' with bad chars",
            )


if __name__ == "__main__":
    unittest.main()
