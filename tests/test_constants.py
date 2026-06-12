"""
Tests for pipeline/constants.py — version single-sourcing.

Revision history
────────────────
1.0   2026-06-12   Initial release: VERSION lockstep with pyproject.toml.
"""

import re
import unittest
from pathlib import Path

from pipeline.constants import VERSION


class TestVersionLockstep(unittest.TestCase):
    """pyproject.toml and constants.VERSION must never drift."""

    def test_pyproject_version_matches_constants(self):
        pyproject = (Path(__file__).resolve().parent.parent
                     / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), VERSION)

    def test_version_is_semver(self):
        self.assertRegex(VERSION, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
