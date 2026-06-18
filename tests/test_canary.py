"""
Tests for pipeline.monitoring.canary.CanaryRunner.

A real governed canary run (PII detect → mask → sqlite load → ledger verify)
against a synthetic frame, plus the track-record append, independent chain
check, history summary, and soak loop.

Revision history
────────────────
1.0   2026-06-18   Initial release.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pipeline.monitoring.canary import CanaryRunner


class TestCanaryRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.track = Path(self.tmp) / "track_record.jsonl"
        self.runner = CanaryRunner(track_record_path=self.track, rows=25)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run_once_passes_and_verifies_ledger(self):
        record = self.runner.run_once(workdir=Path(self.tmp) / "run1")
        self.assertEqual(record["status"], "pass")
        self.assertTrue(record["ledger_verified"])
        self.assertEqual(record["rows"], 25)
        self.assertGreater(record["duration_sec"], 0)

    def test_run_once_appends_track_record(self):
        self.runner.run_once(workdir=Path(self.tmp) / "run2")
        self.assertTrue(self.track.exists())
        lines = [l for l in self.track.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["status"], "pass")

    def test_verify_ledger_chain_detects_break(self):
        good = Path(self.tmp) / "good.jsonl"
        good.write_text(
            '{"self_hash": "a"}\n{"prev_hash": "a", "self_hash": "b"}\n',
            encoding="utf-8")
        self.assertTrue(self.runner.verify_ledger_chain(good))

        broken = Path(self.tmp) / "broken.jsonl"
        broken.write_text(
            '{"self_hash": "a"}\n{"prev_hash": "WRONG", "self_hash": "b"}\n',
            encoding="utf-8")
        self.assertFalse(self.runner.verify_ledger_chain(broken))

    def test_verify_ledger_chain_missing_file(self):
        self.assertFalse(self.runner.verify_ledger_chain(Path(self.tmp) / "nope.jsonl"))

    def test_summarize_history(self):
        self.runner.run_once(workdir=Path(self.tmp) / "r1")
        self.runner.run_once(workdir=Path(self.tmp) / "r2")
        summary = self.runner.summarize_history()
        self.assertEqual(summary["runs"], 2)
        self.assertEqual(summary["passed"], 2)
        self.assertEqual(summary["pass_rate"], 1.0)
        self.assertEqual(summary["last_status"], "pass")

    def test_summary_empty_history(self):
        summary = self.runner.summarize_history()
        self.assertEqual(summary["runs"], 0)
        self.assertIsNone(summary["last_status"])

    def test_dry_run_does_not_write_track_record(self):
        runner = CanaryRunner(track_record_path=self.track, rows=10, dry_run=True)
        runner.run_once(workdir=Path(self.tmp) / "dry")
        self.assertFalse(self.track.exists())

    def test_soak_runs_multiple_times(self):
        summary = self.runner.soak(runs=3)
        self.assertEqual(summary["runs"], 3)
        self.assertEqual(summary["passed"], 3)


if __name__ == "__main__":
    unittest.main()
