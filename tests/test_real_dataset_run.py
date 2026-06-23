"""
Tests for scripts/real_dataset_run.py helpers.

The network fetch and the subprocess pipeline run need a live feed, so they are
not exercised here; the curation and verification logic that decides whether the
committed evidence is correct IS tested: artifact collection (newest-of-each into
canonical names, anchor not mistaken for the bare ledger), independent ledger
chain verification, and header-excluding row counts.

Revision history
────────────────
1.0   2026-06-22   Initial release.
"""

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Load the script by path — scripts/ is not an importable package.
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "real_dataset_run.py"
_spec = importlib.util.spec_from_file_location("real_dataset_run", _SCRIPT)
real_dataset_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(real_dataset_run)


def _chain(*payloads):
    """Build a valid hash-chained ledger: each prev_hash == prior self_hash."""
    lines = []
    prev = None
    for index, payload in enumerate(payloads):
        entry = {"action": payload, "prev_hash": prev, "self_hash": f"h{index}"}
        lines.append(json.dumps(entry))
        prev = f"h{index}"
    return "\n".join(lines) + "\n"


class TestVerifyLedgerChain(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_intact_chain_verifies(self):
        path = self.tmp / "ledger.jsonl"
        path.write_text(_chain("A", "B", "C"), encoding="utf-8")
        self.assertTrue(real_dataset_run._verify_ledger_chain(path))

    def test_broken_chain_fails(self):
        path = self.tmp / "ledger.jsonl"
        rows = [
            {"action": "A", "prev_hash": None, "self_hash": "h0"},
            {"action": "B", "prev_hash": "WRONG", "self_hash": "h1"},
        ]
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        self.assertFalse(real_dataset_run._verify_ledger_chain(path))

    def test_missing_or_empty_fails(self):
        self.assertFalse(real_dataset_run._verify_ledger_chain(self.tmp / "nope.jsonl"))
        empty = self.tmp / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        self.assertFalse(real_dataset_run._verify_ledger_chain(empty))


class TestCountRows(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_excludes_header(self):
        path = self.tmp / "data.csv"
        path.write_text("col_a,col_b\n1,2\n3,4\n5,6\n", encoding="utf-8")
        self.assertEqual(real_dataset_run._count_rows(path), 3)

    def test_header_only_is_zero(self):
        path = self.tmp / "data.csv"
        path.write_text("col_a,col_b\n", encoding="utf-8")
        self.assertEqual(real_dataset_run._count_rows(path), 0)


class TestCollectArtifacts(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.logs = self.tmp / "src LOGS"
        self.logs.mkdir()
        self.artifacts = self.tmp / "artifacts"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_curates_canonical_names_without_confusing_anchor(self):
        (self.logs / "audit_ledger_20260101_000000.jsonl").write_text(
            "ledger", encoding="utf-8")
        (self.logs / "audit_ledger_20260101_000000.jsonl.anchor").write_text(
            "anchor", encoding="utf-8")
        (self.logs / "metrics_report_20260101_000000.json").write_text(
            "{}", encoding="utf-8")
        (self.logs / "observability_history.jsonl").write_text(
            "obs", encoding="utf-8")

        real_dataset_run._collect_artifacts(self.logs, self.artifacts)

        # The bare ledger must be the ledger, not the anchor's contents.
        self.assertEqual((self.artifacts / "audit_ledger.jsonl").read_text(
            encoding="utf-8"), "ledger")
        self.assertEqual((self.artifacts / "audit_ledger.jsonl.anchor").read_text(
            encoding="utf-8"), "anchor")
        self.assertTrue((self.artifacts / "metrics_report.json").exists())
        self.assertTrue((self.artifacts / "observability_history.jsonl").exists())

    def test_picks_newest_when_multiple(self):
        old = self.logs / "metrics_report_20260101_000000.json"
        new = self.logs / "metrics_report_20260102_000000.json"
        old.write_text('{"run": "old"}', encoding="utf-8")
        new.write_text('{"run": "new"}', encoding="utf-8")
        import os
        import time
        now = time.time()
        os.utime(old, (now - 100, now - 100))
        os.utime(new, (now, now))

        real_dataset_run._collect_artifacts(self.logs, self.artifacts)
        self.assertIn("new", (self.artifacts / "metrics_report.json").read_text(
            encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
