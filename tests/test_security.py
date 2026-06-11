"""
Security regression tests for SQL injection and code injection guards.

Validates that malicious input is rejected by validators across loaders and
the business-rule engine.

Revision history
----------------
1.0   2026-06-08   Initial creation: covers pgvector WHERE/select_cols,
                   duckdb mutating SQL, business_rules derive expression,
                   snowflake identifier injection, sftp host key policy.
1.1   2026-06-11   Regression tests: AccessPolicy mutations hold the lock
                   across the full read-modify-write (concurrent role/
                   assignment updates must not be lost).
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. pgvector WHERE clause injection
# ---------------------------------------------------------------------------

class TestPgvectorWhereClauseInjection(unittest.TestCase):
    """_validate_where_clause() must reject dangerous SQL fragments."""

    def _validate(self, clause):
        from pipeline.loaders.vector.pgvector_loader import _validate_where_clause
        return _validate_where_clause(clause)

    def test_semicolon_drop_table(self):
        with self.assertRaises(ValueError):
            self._validate("1=1; DROP TABLE users --")

    def test_block_comment_bypass(self):
        with self.assertRaises(ValueError):
            self._validate("col > 1 /* bypass */")

    def test_semicolon_delete(self):
        with self.assertRaises(ValueError):
            self._validate("col = 1; DELETE FROM data")

    def test_truncate(self):
        with self.assertRaises(ValueError):
            self._validate("col = 1; TRUNCATE TABLE x")

    def test_safe_clause_accepted(self):
        result = self._validate("status = 'active'")
        self.assertEqual(result, "status = 'active'")


# ---------------------------------------------------------------------------
# 2. pgvector / base validate_sql_identifier — select_cols injection
# ---------------------------------------------------------------------------

class TestValidateSqlIdentifier(unittest.TestCase):
    """validate_sql_identifier() must reject anything that isn't a plain name."""

    def _validate(self, name, label="identifier"):
        from pipeline.loaders.base import validate_sql_identifier
        return validate_sql_identifier(name, label)

    def test_semicolon_drop(self):
        with self.assertRaises(ValueError):
            self._validate("col; DROP TABLE x")

    def test_comment_injection(self):
        with self.assertRaises(ValueError):
            self._validate("col--comment")

    def test_star_rejected(self):
        with self.assertRaises(ValueError):
            self._validate("*")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            self._validate("")

    def test_valid_identifier_accepted(self):
        result = self._validate("my_column_1")
        self.assertEqual(result, "my_column_1")

    def test_schema_dot_table_accepted(self):
        result = self._validate("public.users")
        self.assertEqual(result, "public.users")


# ---------------------------------------------------------------------------
# 3. DuckDB query() rejects mutating SQL
# ---------------------------------------------------------------------------

class TestDuckDBQueryRejectsMutation(unittest.TestCase):
    """DuckDBLoader.query() must reject DROP, DELETE, INSERT, UPDATE."""

    def _make_loader(self):
        mock_gov = MagicMock()
        with patch("pipeline.loaders.duckdb_loader.HAS_DUCKDB", True):
            from pipeline.loaders.duckdb_loader import DuckDBLoader
            return DuckDBLoader(mock_gov)

    def test_drop(self):
        loader = self._make_loader()
        with self.assertRaises(ValueError):
            loader.query({"db_path": ":memory:"}, "DROP TABLE users")

    def test_delete(self):
        loader = self._make_loader()
        with self.assertRaises(ValueError):
            loader.query({"db_path": ":memory:"}, "DELETE FROM data")

    def test_insert(self):
        loader = self._make_loader()
        with self.assertRaises(ValueError):
            loader.query({"db_path": ":memory:"}, "INSERT INTO data VALUES (1)")

    def test_update(self):
        loader = self._make_loader()
        with self.assertRaises(ValueError):
            loader.query({"db_path": ":memory:"}, "UPDATE data SET col = 1")

    def test_truncate(self):
        loader = self._make_loader()
        with self.assertRaises(ValueError):
            loader.query({"db_path": ":memory:"}, "TRUNCATE TABLE data")

    def test_leading_whitespace_drop(self):
        loader = self._make_loader()
        with self.assertRaises(ValueError):
            loader.query({"db_path": ":memory:"}, "   DROP TABLE users")

    def test_nonsense_rejected(self):
        loader = self._make_loader()
        with self.assertRaises(ValueError):
            loader.query({"db_path": ":memory:"}, "GRANT ALL ON data TO evil")


# ---------------------------------------------------------------------------
# 4. business_rules derive expression injection
# ---------------------------------------------------------------------------

class TestDeriveExpressionInjection(unittest.TestCase):
    """_validate_derive_expression() must reject code injection attempts."""

    def _validate(self, expr):
        from pipeline.business_rules import _validate_derive_expression
        return _validate_derive_expression(expr)

    def test_dunder_import(self):
        with self.assertRaises(ValueError):
            self._validate("__import__('os').system('rm -rf /')")

    def test_exec(self):
        with self.assertRaises(ValueError):
            self._validate("exec('print(1)')")

    def test_eval(self):
        with self.assertRaises(ValueError):
            self._validate("eval('1+1')")

    def test_open_file(self):
        with self.assertRaises(ValueError):
            self._validate("open('/etc/passwd').read()")

    def test_lambda(self):
        with self.assertRaises(ValueError):
            self._validate("lambda: 1")

    # Valid expressions that must be accepted
    def test_valid_multiplication(self):
        self._validate("price * quantity")

    def test_valid_arithmetic(self):
        self._validate("a + b - c")

    def test_valid_comparison(self):
        self._validate("x > 0")

    def test_valid_ternary(self):
        self._validate("a + b if a > 0 else b")


# ---------------------------------------------------------------------------
# 5. Snowflake vector loader — identifier injection
# ---------------------------------------------------------------------------

class TestSnowflakeIdentifierInjection(unittest.TestCase):
    """validate_sql_identifier() blocks malicious table/column names for Snowflake."""

    def _validate(self, name, label="identifier"):
        from pipeline.loaders.base import validate_sql_identifier
        return validate_sql_identifier(name, label)

    def test_table_with_semicolon(self):
        with self.assertRaises(ValueError):
            self._validate("users; DROP TABLE secrets", "table")

    def test_column_with_subquery(self):
        with self.assertRaises(ValueError):
            self._validate("col FROM (SELECT * FROM secrets)--", "column")

    def test_column_with_space(self):
        with self.assertRaises(ValueError):
            self._validate("col name", "column")

    def test_table_with_quotes(self):
        with self.assertRaises(ValueError):
            self._validate("users'--", "table")

    def test_valid_snowflake_name(self):
        result = self._validate("analytics.embeddings_v2", "table")
        self.assertEqual(result, "analytics.embeddings_v2")


# ---------------------------------------------------------------------------
# 6. SFTP host key policy defaults to RejectPolicy
# ---------------------------------------------------------------------------

class TestSFTPHostKeyPolicy(unittest.TestCase):
    """SFTPLoader must default to RejectPolicy, not AutoAddPolicy."""

    def _run_load(self, cfg):
        """Instantiate SFTPLoader, call load(), return the mock SSHClient."""
        import paramiko

        mock_gov = MagicMock()
        with patch("pipeline.loaders.sftp_loader.HAS_SFTP", True):
            from pipeline.loaders.sftp_loader import SFTPLoader
            loader = SFTPLoader(mock_gov)

        mock_ssh = MagicMock()
        mock_ssh.open_sftp.return_value = MagicMock()

        # paramiko is imported inside load(), so patch it in sys.modules
        mock_paramiko = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh
        mock_paramiko.RejectPolicy = paramiko.RejectPolicy
        mock_paramiko.AutoAddPolicy = paramiko.AutoAddPolicy

        import pandas as pd
        df = pd.DataFrame({"a": [1]})

        with patch.dict("sys.modules", {"paramiko": mock_paramiko}):
            try:
                loader.load(df, cfg, table="test")
            except Exception:
                pass

        return mock_ssh

    def test_default_policy_is_reject(self):
        import paramiko

        cfg = {
            "host": "example.com",
            "username": "testuser",
            "password": "testpass",
            "remote_path": "/tmp/test.csv",
            "format": "csv",
        }
        mock_ssh = self._run_load(cfg)

        mock_ssh.set_missing_host_key_policy.assert_called_once()
        policy_arg = mock_ssh.set_missing_host_key_policy.call_args[0][0]
        self.assertIsInstance(policy_arg, paramiko.RejectPolicy)

    def test_auto_add_requires_explicit_flag(self):
        import paramiko

        cfg = {
            "host": "example.com",
            "username": "testuser",
            "password": "testpass",
            "remote_path": "/tmp/test.csv",
            "format": "csv",
            "auto_add_host_key": True,
        }
        mock_ssh = self._run_load(cfg)

        mock_ssh.set_missing_host_key_policy.assert_called_once()
        policy_arg = mock_ssh.set_missing_host_key_policy.call_args[0][0]
        self.assertIsInstance(policy_arg, paramiko.AutoAddPolicy)


# ---------------------------------------------------------------------------
# 7. AccessPolicy concurrent mutation safety
# ---------------------------------------------------------------------------

class TestAccessPolicyConcurrentMutation(unittest.TestCase):
    """Regression: the lock only covered _save, so concurrent add_role /
    assign_role calls could interleave the read-modify-write and lose
    updates."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmpdir = tempfile.mkdtemp(prefix="access_policy_")
        self.policy_file = Path(self.tmpdir) / "policies.json"
        self.policy = self._make_policy()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_policy(self):
        from pipeline.security.access_policy import AccessPolicy
        return AccessPolicy(MagicMock(), policy_file=self.policy_file)

    def test_concurrent_add_role_loses_no_roles(self):
        import json
        import threading
        errors = []

        def add(index):
            try:
                self.policy.add_role(f"role_{index}",
                                     denied_columns=[f"col_{index}"])
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=add, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(self.policy.list_roles()), 10)
        persisted = json.loads(self.policy_file.read_text(encoding="utf-8"))
        self.assertEqual(len(persisted["roles"]), 10)

    def test_concurrent_assign_role_loses_no_assignments(self):
        import json
        import threading
        self.policy.add_role("shared_role", denied_columns=["ssn"])
        errors = []

        def assign(index):
            try:
                self.policy.assign_role(f"user_{index}", "shared_role")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=assign, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        persisted = json.loads(self.policy_file.read_text(encoding="utf-8"))
        self.assertEqual(len(persisted["user_roles"]), 10)
        for i in range(10):
            self.assertEqual(self.policy.user_roles(f"user_{i}"), ["shared_role"])


if __name__ == "__main__":
    unittest.main()
