"""
Tests for LedgerWriter in isolation — the durable, tamper-evident,
hash-chained append primitive, exercised without GovernanceLogger to
prove the extraction stands on its own.

Revision history
────────────────
1.0   2026-06-14   Initial release.
"""

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.ledger_writer import LedgerWriter
from pipeline.run_artifacts import RunArtifacts


def _writer(tmpdir, dry_run=False):
    artifacts = RunArtifacts(log_dir=Path(tmpdir), timestamp="20260614_000000")
    artifacts.ensure_directories()
    return LedgerWriter(artifacts, dry_run=dry_run)


def _entry(action):
    return {"category": "TEST", "action": action, "detail": {}}


class TestLedgerWriterChain(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_chain_is_contiguous(self):
        w = _writer(self.tmpdir)
        for i in range(5):
            w.event(_entry(f"E{i}"))
        lines = [json.loads(line) for line in
                 w.ledger_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0]["prev_hash"], "GENESIS")
        for prev, cur in zip(lines, lines[1:]):
            self.assertEqual(cur["prev_hash"], prev["self_hash"])

    def test_verify_passes_on_intact_ledger(self):
        w = _writer(self.tmpdir)
        for i in range(3):
            w.event(_entry(f"E{i}"))
        self.assertTrue(w.verify_ledger())

    def test_anchor_written_with_count_and_last_hash(self):
        w = _writer(self.tmpdir)
        for i in range(4):
            w.event(_entry(f"E{i}"))
        anchor = json.loads(w.ledger_anchor_file.read_text(encoding="utf-8"))
        self.assertEqual(anchor["entry_count"], 4)
        self.assertEqual(anchor["last_hash"], w._prev_hash)

    def test_field_tampering_detected(self):
        w = _writer(self.tmpdir)
        for i in range(3):
            w.event(_entry(f"E{i}"))
        lines = w.ledger_file.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[1])
        tampered["detail"] = {"hacked": True}
        lines[1] = json.dumps(tampered, sort_keys=True)
        w.ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(w.verify_ledger())

    def test_tail_truncation_detected_via_anchor(self):
        w = _writer(self.tmpdir)
        for i in range(5):
            w.event(_entry(f"E{i}"))
        lines = w.ledger_file.read_text(encoding="utf-8").splitlines()
        # Drop the last 2 events — the surviving chain is still internally
        # valid, so only the anchor catches the truncation.
        w.ledger_file.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
        self.assertFalse(w.verify_ledger())

    def test_deletion_detected_via_anchor(self):
        w = _writer(self.tmpdir)
        w.event(_entry("E0"))
        # Close the append-only handle first: on Windows an open file
        # cannot be unlinked (real deletion happens post-run anyway).
        if w._writer is not None:
            w._writer.close()
        w.ledger_file.unlink()
        self.assertFalse(w.verify_ledger())

    def test_dry_run_writes_nothing_but_chains_in_memory(self):
        w = _writer(self.tmpdir, dry_run=True)
        for i in range(3):
            w.event(_entry(f"E{i}"))
        self.assertFalse(w.ledger_file.exists())
        self.assertEqual(len(w.entries), 3)
        self.assertEqual(w.entries[1]["prev_hash"], w.entries[0]["self_hash"])


if __name__ == "__main__":
    unittest.main()
