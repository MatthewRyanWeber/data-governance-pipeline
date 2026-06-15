"""
Tests for the per-partition governance entrypoint (Path A).

Proves a dataset can be split into partitions, governed concurrently (each into
its own ledger segment), then composed into one verifiable Merkle root — with
governance (PII masking) actually applied per partition.

Revision history
────────────────
1.0   2026-06-15   Initial release.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from pipeline.partitioned_ledger import PartitionedLedger
from pipeline.partitioned_governance import govern_partition, govern_partitions


def _frame(start, n):
    return pd.DataFrame({
        "id": range(start, start + n),
        "email": [f"user{i}@example.com" for i in range(start, start + n)],
        "name": [f"User {i}" for i in range(start, start + n)],
        "amount": [(i % 100) + 0.5 for i in range(start, start + n)],
    })


class TestPartitionedGovernance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp) / "run_ledger"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_single_partition_is_governed_and_chained(self):
        led = PartitionedLedger(self.root)
        out, meta = govern_partition(_frame(0, 10), "part-0000", led)
        # PII masked on this partition.
        self.assertEqual(meta["pii_actions"].get("email"), "MASKED")
        self.assertTrue(out["email"].str.startswith("MASKED_").all())
        # The partition's segment chain has events and verifies on its own.
        seg = led.segment("part-0000")
        self.assertTrue(seg.verify_ledger())

    def test_many_partitions_compose_into_one_verified_root(self):
        led = PartitionedLedger(self.root)
        partitions = [(f"part-{k:04d}", _frame(k * 50, 50)) for k in range(10)]
        governed, record = govern_partitions(partitions, led)

        self.assertEqual(len(governed), 10)
        self.assertEqual(record["segment_count"], 10)
        self.assertGreater(record["total_events"], 0)
        # Every partition was masked, and the whole thing verifies as one root.
        for out in governed.values():
            self.assertTrue(out["email"].str.startswith("MASKED_").all())
        self.assertTrue(led.verify())
        # Re-open from disk and verify — no reliance on in-memory state.
        self.assertTrue(PartitionedLedger(self.root).verify())

    def test_tampering_one_partition_breaks_the_whole_root(self):
        led = PartitionedLedger(self.root)
        govern_partitions(
            [(f"part-{k:04d}", _frame(k * 20, 20)) for k in range(4)], led,
        )
        # Corrupt one partition's segment after sealing: alter a hashed field
        # of the first event (leaving its stale self_hash) so the chain breaks.
        import json
        victim = next(self.root.glob("segment-part-0002.jsonl"))
        lines = victim.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["action"] = str(rec.get("action", "X")) + "_TAMPERED"
        lines[0] = json.dumps(rec, sort_keys=True)
        victim.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(PartitionedLedger(self.root).verify())


if __name__ == "__main__":
    unittest.main()
