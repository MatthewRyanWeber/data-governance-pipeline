"""
Tests for the partitionable Merkle ledger (Path A's distributed-governance
ledger). Proves: many workers write independent segment chains concurrently
with no shared state and compose into one verifiable Merkle root; and that a
tampered, dropped, added, or unsealed ledger is detected.

Revision history
────────────────
1.0   2026-06-15   Initial release.
"""

import json
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pipeline.partitioned_ledger import (
    PartitionedLedger, verify_inclusion, _merkle_root,
)


def _event(seg_id, i):
    return {"category": "LOAD", "action": "ROW_GROUP",
            "detail": {"n": i}, "pipeline_id": seg_id, "event_id": f"{seg_id}-{i}"}


class TestPartitionedLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp) / "ledger"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_segments(self, n_segments, events_each):
        led = PartitionedLedger(self.root)

        def worker(k):
            seg_id = f"part-{k:04d}"
            seg = led.segment(seg_id)
            for i in range(events_each):
                seg.event(_event(seg_id, i))

        # Concurrent fan-out: each worker writes its own segment with zero
        # coordination — the property the single-file ledger cannot offer.
        with ThreadPoolExecutor(max_workers=min(8, n_segments)) as pool:
            list(pool.map(worker, range(n_segments)))
        return led

    def test_concurrent_segments_compose_and_verify(self):
        led = self._write_segments(n_segments=12, events_each=25)
        record = led.seal()
        self.assertEqual(record["segment_count"], 12)
        self.assertEqual(record["total_events"], 12 * 25)
        self.assertTrue(led.verify())
        # Re-opening from disk verifies too (no reliance on in-memory state).
        self.assertTrue(PartitionedLedger(self.root).verify())

    def test_unsealed_ledger_does_not_verify(self):
        self._write_segments(3, 5)
        self.assertFalse(PartitionedLedger(self.root).verify())

    def test_tampered_segment_detected(self):
        led = self._write_segments(4, 10)
        led.seal()
        # Alter one event's content in one segment file.
        victim = next(self.root.glob("segment-part-0001.jsonl"))
        lines = victim.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[3]); rec["detail"]["n"] = 9999
        lines[3] = json.dumps(rec, sort_keys=True)
        victim.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(PartitionedLedger(self.root).verify())

    def test_dropped_segment_detected(self):
        led = self._write_segments(4, 10)
        led.seal()
        # Delete a whole segment (file + anchor) after sealing.
        for p in self.root.glob("segment-part-0002.jsonl*"):
            p.unlink()
        self.assertFalse(PartitionedLedger(self.root).verify())

    def test_added_segment_detected(self):
        led = self._write_segments(3, 5)
        led.seal()
        # Sneak in an extra segment after the root was sealed.
        extra = led.segment("part-9999")
        for i in range(3):
            extra.event(_event("part-9999", i))
        self.assertFalse(PartitionedLedger(self.root).verify())

    def test_inclusion_proof_roundtrip(self):
        led = self._write_segments(7, 4)
        led.seal()
        pf = led.inclusion_proof("part-0003")
        self.assertTrue(verify_inclusion(pf["leaf"], pf["proof"], pf["merkle_root"]))
        # A forged leaf must not verify against the same proof/root.
        self.assertFalse(verify_inclusion("deadbeef", pf["proof"], pf["merkle_root"]))

    def test_inclusion_proof_unknown_segment_raises(self):
        led = self._write_segments(2, 2)
        led.seal()
        with self.assertRaises(ValueError):
            led.inclusion_proof("part-nope")

    def test_invalid_segment_id_rejected(self):
        led = PartitionedLedger(self.root)
        with self.assertRaises(ValueError):
            led.segment("../escape")

    def test_merkle_root_deterministic_and_order_independent(self):
        a = ["aa", "bb", "cc"]
        self.assertEqual(_merkle_root(a), _merkle_root(["aa", "bb", "cc"]))
        self.assertNotEqual(_merkle_root(a), _merkle_root(["aa", "bb", "cz"]))


if __name__ == "__main__":
    unittest.main()
