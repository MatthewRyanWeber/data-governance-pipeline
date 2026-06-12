"""
Tests for PgvectorLoader — PostgreSQL + pgvector embeddings.

Validation guards (injection, if_exists, missing vector column, dry_run) run
with no mocking; the happy path mocks sqlalchemy.create_engine and to_sql to
assert the pgvector DDL (CREATE EXTENSION, ALTER COLUMN ... TYPE vector(n)).

Revision history
────────────────
1.0   2026-06-09   Initial release: validation + mocked load coverage.
1.1   2026-06-11   Updated for the create-then-alter load order; regression
                   tests: to_sql runs before the ALTER, ALTER failures
                   propagate, user/password required, engine disposed.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.constants import HAS_PGVECTOR
from pipeline.loaders.vector.pgvector_loader import PgvectorLoader
from pipeline.exceptions import ConfigValidationError

_CFG = {"host": "h", "db_name": "d", "user": "u", "password": "p"}


def _vec_df():
    return pd.DataFrame({"id": [1, 2], "embedding": [[0.1, 0.2], [0.3, 0.4]]})


@unittest.skipUnless(HAS_PGVECTOR, "pgvector not installed")
class TestPgvectorValidation(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = PgvectorLoader(self.gov)

    def test_invalid_if_exists_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), _CFG, "t", if_exists="merge")

    def test_missing_table_raises(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), _CFG, "")

    def test_injection_table_rejected(self):
        with self.assertRaises(ValueError):
            self.loader.load(_vec_df(), _CFG, "t; DROP TABLE x")

    def test_missing_config_raises(self):
        with self.assertRaises(ConfigValidationError):
            self.loader.load(_vec_df(), {"host": "h"}, "t")

    def test_missing_user_password_raises(self):
        """Regression: user/password used to KeyError mid-load instead of
        failing config validation."""
        with self.assertRaises(ConfigValidationError):
            self.loader.load(_vec_df(), {"host": "h", "db_name": "d"}, "t")

    def test_missing_vector_column_raises(self):
        df = pd.DataFrame({"id": [1]})  # no embedding column, no embed_columns
        with self.assertRaises(ValueError):
            self.loader.load(df, _CFG, "t")

    def test_dry_run_returns_zero_without_engine(self):
        loader = PgvectorLoader(self.gov, dry_run=True)
        with patch("sqlalchemy.create_engine") as ce:
            n = loader.load(_vec_df(), _CFG, "t")
        self.assertEqual(n, 0)
        ce.assert_not_called()

    def test_empty_df_returns_zero(self):
        empty = pd.DataFrame({"id": [], "embedding": []})
        self.assertEqual(self.loader.load(empty, _CFG, "t"), 0)


@unittest.skipUnless(HAS_PGVECTOR, "pgvector not installed")
class TestPgvectorLoadPath(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = PgvectorLoader(self.gov)

    def test_creates_extension_and_vector_column(self):
        engine = MagicMock()
        conn = engine.connect.return_value.__enter__.return_value
        with patch("sqlalchemy.create_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql") as to_sql:
            n = self.loader.load(_vec_df(), {**_CFG, "vector_size": 2}, "docs")
        self.assertEqual(n, 2)
        executed = [str(c[0][0]) for c in conn.execute.call_args_list]
        self.assertTrue(any("CREATE EXTENSION IF NOT EXISTS vector" in s for s in executed))
        self.assertTrue(any(
            "ALTER COLUMN embedding TYPE vector(2) USING embedding::vector(2)" in s
            for s in executed))
        to_sql.assert_called_once()
        self.gov.load_complete.assert_called_once_with(2, "docs")

    def test_table_created_before_alter(self):
        """Regression: the old ALTER-before-create order meant the first
        load/replace never produced a vector column."""
        call_order: list[str] = []
        engine = MagicMock()
        conn = engine.connect.return_value.__enter__.return_value

        def record_execute(stmt, *args, **kwargs):
            call_order.append(str(stmt))
            return MagicMock()

        conn.execute.side_effect = record_execute

        def record_to_sql(*args, **kwargs):
            call_order.append("TO_SQL")

        with patch("sqlalchemy.create_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql", side_effect=record_to_sql):
            self.loader.load(_vec_df(), {**_CFG, "vector_size": 2}, "docs")

        to_sql_index = call_order.index("TO_SQL")
        alter_index = next(
            i for i, s in enumerate(call_order) if "ALTER COLUMN" in s
        )
        self.assertLess(to_sql_index, alter_index,
                        "to_sql must create the table before the ALTER")

    def test_alter_failure_propagates(self):
        """Regression: a failed ALTER used to be swallowed, reporting a
        broken (non-vector) table as a successful load."""
        engine = MagicMock()
        conn = engine.connect.return_value.__enter__.return_value

        def explode_on_alter(stmt, *args, **kwargs):
            if "ALTER COLUMN" in str(stmt):
                raise RuntimeError("type vector does not exist")
            return MagicMock()

        conn.execute.side_effect = explode_on_alter

        with patch("sqlalchemy.create_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql"):
            with self.assertRaises(RuntimeError):
                self.loader.load(_vec_df(), {**_CFG, "vector_size": 2}, "docs")
        self.gov.load_complete.assert_not_called()

    def test_skips_alter_when_column_already_vector(self):
        """Appending to a table whose column is already vector(n) must not
        rewrite the table with another ALTER."""
        engine = MagicMock()
        conn = engine.connect.return_value.__enter__.return_value
        conn.execute.return_value.scalar.return_value = "vector"
        with patch("sqlalchemy.create_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql"):
            self.loader.load(_vec_df(), {**_CFG, "vector_size": 2}, "docs")
        executed = [str(c[0][0]) for c in conn.execute.call_args_list]
        self.assertFalse(any("ALTER COLUMN" in s for s in executed))

    def test_engine_disposed_after_load(self):
        """Regression: engines were created and never disposed."""
        engine = MagicMock()
        with patch("sqlalchemy.create_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql"):
            self.loader.load(_vec_df(), {**_CFG, "vector_size": 2}, "docs")
        engine.dispose.assert_called_once()

    def test_engine_disposed_even_when_load_fails(self):
        engine = MagicMock()
        with patch("sqlalchemy.create_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.loader.load(_vec_df(), {**_CFG, "vector_size": 2}, "docs")
        engine.dispose.assert_called_once()


if __name__ == "__main__":
    unittest.main()
