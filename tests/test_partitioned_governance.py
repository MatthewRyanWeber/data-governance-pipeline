"""
Tests for the per-partition governance entrypoint (Path A).

Proves a dataset can be split into partitions, governed concurrently (each into
its own ledger segment), then composed into one verifiable Merkle root — with
governance (PII masking) actually applied per partition.

Revision history
────────────────
1.0   2026-06-15   Initial release.
1.1   2026-06-16   Cover segment_id traversal rejection and gov.ledger_file
                   pointing at the injected segment.
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

    def test_observe_config_runs_detectors_per_partition(self):
        led = PartitionedLedger(self.root)
        # A partition with a duplicate business key (same order_id) — the
        # silent-failure detector must fire and chain into this segment.
        df = pd.DataFrame({
            "order_id": [1, 2, 2, 3],
            "email": [f"u{i}@example.com" for i in range(4)],
        })
        out, meta = govern_partition(
            df, "part-0000", led, observe_config={"business_keys": ["order_id"]},
        )
        self.assertGreaterEqual(meta["observe_alerts"], 1)
        # The DUPLICATE_KEYS governance event is in the partition's own segment.
        seg_file = self.root / "segment-part-0000.jsonl"
        self.assertIn("DUPLICATE_KEYS", seg_file.read_text(encoding="utf-8"))

    def test_traversal_segment_id_rejected(self):
        # A crafted segment_id must not place the partition's log_dir outside
        # the ledger root.
        led = PartitionedLedger(self.root)
        for bad in ("..", "."):
            with self.assertRaises(ValueError):
                govern_partition(_frame(0, 3), bad, led)

    def test_gov_ledger_file_points_at_the_segment(self):
        # With an injected segment, gov.ledger_file must report the segment file
        # that actually receives events — not this run's default artifacts path.
        led = PartitionedLedger(self.root)
        govern_partition(_frame(0, 5), "part-0000", led)
        from pipeline.governance_logger import GovernanceLogger
        seg = led.segment("part-0000")
        gov = GovernanceLogger(
            source_name="part-0000",
            log_dir=str(self.root / "part-0000"),
            ledger=seg,
        )
        self.assertEqual(Path(gov.ledger_file), Path(seg.ledger_file))
        self.assertEqual(Path(gov.ledger_anchor_file), Path(seg.ledger_anchor_file))

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
