"""
Tests for the AppendOnlyWriter: write round-trip, seek blocked,
truncate blocked, external truncation detected, context manager,
and integration with GovernanceLogger.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import tempfile
import unittest
from pathlib import Path

from pipeline.append_only_writer import AppendOnlyWriter


class TestAppendOnlyWriter(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._path = Path(self._tmpdir) / "audit.jsonl"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_write_round_trip(self):
        with AppendOnlyWriter(self._path) as w:
            w.write("line1\n")
            w.write("line2\n")
        content = self._path.read_text(encoding="utf-8")
        self.assertEqual(content, "line1\nline2\n")

    def test_seek_raises_permission_error(self):
        with AppendOnlyWriter(self._path) as w:
            w.write("data\n")
            with self.assertRaises(PermissionError):
                w.seek(0)

    def test_truncate_raises_permission_error(self):
        with AppendOnlyWriter(self._path) as w:
            w.write("data\n")
            with self.assertRaises(PermissionError):
                w.truncate()

    def test_external_truncation_detected(self):
        w = AppendOnlyWriter(self._path, verify_integrity=True)
        w.open()
        w.write("first line\n")
        with open(self._path, "w", encoding="utf-8") as f:
            f.write("")
        with self.assertRaises(IOError):
            w.write("second line\n")
        w.close()

    def test_context_manager(self):
        with AppendOnlyWriter(self._path) as w:
            self.assertIsNotNone(w._file)
        self.assertIsNone(w._file)

    def test_multiple_writes_append(self):
        with AppendOnlyWriter(self._path) as w:
            for i in range(5):
                w.write(f"line {i}\n")
        lines = self._path.read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], "line 0")
        self.assertEqual(lines[4], "line 4")

    def test_lazy_open_on_write(self):
        w = AppendOnlyWriter(self._path)
        self.assertIsNone(w._file)
        w.write("auto-opened\n")
        self.assertIsNotNone(w._file)
        w.close()
        self.assertEqual(self._path.read_text(encoding="utf-8"), "auto-opened\n")

    def test_parent_dir_created(self):
        deep = Path(self._tmpdir) / "a" / "b" / "c" / "audit.jsonl"
        with AppendOnlyWriter(deep) as w:
            w.write("deep\n")
        self.assertTrue(deep.exists())


class TestGovernanceLoggerAppendOnly(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_ledger_uses_append_only_writer(self):
        from pipeline.governance_logger import GovernanceLogger
        gov = GovernanceLogger("test_src", log_dir=self._tmpdir)
        gov._event("TEST", "WRITE_ONE", {"val": 1})
        gov._event("TEST", "WRITE_TWO", {"val": 2})
        self.assertIsNotNone(gov._writer)
        with self.assertRaises(PermissionError):
            gov._writer.seek(0)
        with self.assertRaises(PermissionError):
            gov._writer.truncate()
        content = gov.ledger_file.read_text(encoding="utf-8")
        lines = [l for l in content.strip().split("\n") if l]
        self.assertEqual(len(lines), 2)

    def test_verify_integrity_param(self):
        from pipeline.governance_logger import GovernanceLogger
        gov = GovernanceLogger(
            "test_src", log_dir=self._tmpdir, verify_integrity=True,
        )
        gov._event("TEST", "FIRST")
        self.assertTrue(gov._verify_integrity)
        self.assertTrue(gov._writer._verify)


if __name__ == "__main__":
    unittest.main()
