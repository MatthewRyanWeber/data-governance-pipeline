"""
Distributed-isolation test for Path A: govern partitions across real OS
PROCESSES (not threads).

A ThreadPoolExecutor shares memory, so it can't prove the property a distributed
engine actually needs — that govern_partition survives serialization and runs
with no shared mutable state. ProcessPoolExecutor does: each partition is
governed in a separate process, its function and arguments are pickled across
the boundary, and each writes its own ledger segment independently. The main
process then seals and verifies the composed Merkle root. This is the real
distributed property, runnable anywhere (no JVM/Spark/Docker); a live Spark job
is the same engine-agnostic entrypoint with cluster orchestration on top.

Revision history
────────────────
1.0   2026-06-15   Initial release.
"""

import shutil
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


def _govern_worker(args):
    """Top-level (picklable) worker run in a separate process per partition.

    Reconstructs the ledger from the shared root dir — exactly how a distributed
    executor would — so nothing but plain data crosses the process boundary.
    """
    root_dir, segment_id, records = args
    import pandas as pd
    from pipeline.partitioned_ledger import PartitionedLedger
    from pipeline.partitioned_governance import govern_partition

    df = pd.DataFrame(records)
    ledger = PartitionedLedger(root_dir)
    out, meta = govern_partition(
        df, segment_id, ledger, observe_config={"business_keys": ["id"]},
    )
    return {
        "segment_id": segment_id,
        "rows": meta["rows_out"],
        "masked": bool(out["email"].str.startswith("MASKED_").all()),
    }


def _records(k, n=40):
    base = k * n
    return [
        {"id": base + i, "email": f"user{base + i}@example.com", "name": f"User {base + i}"}
        for i in range(n)
    ]


class TestPartitionedGovernanceMultiprocess(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = str(Path(self.tmp) / "ledger")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_processes_compose_into_one_verified_root(self):
        from pipeline.partitioned_ledger import PartitionedLedger

        n_parts = 4
        work = [(self.root, f"part-{k:04d}", _records(k)) for k in range(n_parts)]

        with ProcessPoolExecutor(max_workers=n_parts) as pool:
            results = list(pool.map(_govern_worker, work))

        # Every partition was governed (PII masked) in its own process.
        self.assertEqual(len(results), n_parts)
        self.assertTrue(all(r["masked"] for r in results))

        # The independently-written segments compose into one verifiable root.
        ledger = PartitionedLedger(self.root)
        record = ledger.seal()
        self.assertEqual(record["segment_count"], n_parts)
        self.assertGreater(record["total_events"], 0)
        self.assertTrue(ledger.verify())
        # Fresh handle from disk verifies too.
        self.assertTrue(PartitionedLedger(self.root).verify())


if __name__ == "__main__":
    unittest.main()
