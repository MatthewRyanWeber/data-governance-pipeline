"""
Tests for the secrets manager credential resolution.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from pipeline.secrets_manager import SecretsManager


class TestSecretsManager(unittest.TestCase):

    def test_explicit_value_takes_priority(self):
        sm = SecretsManager(env_file="/nonexistent/.env")
        result = sm.get("DB_PASSWORD", explicit="my_secret")
        self.assertEqual(result, "my_secret")

    def test_env_var_fallback(self):
        sm = SecretsManager(env_file="/nonexistent/.env")
        with patch.dict(os.environ, {"TEST_SECRET_KEY": "from_env"}):
            result = sm.get("TEST_SECRET_KEY")
            self.assertEqual(result, "from_env")

    def test_dotenv_file_loaded(self):
        tmpdir = tempfile.mkdtemp()
        env_file = os.path.join(tmpdir, ".env")
        with open(env_file, "w", encoding="utf-8") as f:
            f.write("MY_VAR=dotenv_value\n")

        try:
            sm = SecretsManager(env_file=env_file)
            result = sm.get("MY_VAR")
            self.assertEqual(result, "dotenv_value")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_explicit_overrides_env_var(self):
        sm = SecretsManager(env_file="/nonexistent/.env")
        with patch.dict(os.environ, {"DB_PASS": "env_val"}):
            result = sm.get("DB_PASS", explicit="explicit_val")
            self.assertEqual(result, "explicit_val")

    def test_get_password_explicit(self):
        sm = SecretsManager(env_file="/nonexistent/.env")
        result = sm.get_password("DB_PASS", explicit="s3cret")
        self.assertEqual(result, "s3cret")

    def test_get_password_from_env(self):
        sm = SecretsManager(env_file="/nonexistent/.env")
        with patch.dict(os.environ, {"DB_PASS": "env_password"}):
            result = sm.get_password("DB_PASS")
            self.assertEqual(result, "env_password")

    def test_nonexistent_env_file_no_error(self):
        sm = SecretsManager(env_file="/this/does/not/exist/.env")
        self.assertIsInstance(sm._env, dict)


if __name__ == "__main__":
    unittest.main()
