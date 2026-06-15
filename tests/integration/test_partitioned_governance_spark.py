"""
Real Spark integration for Path A: govern partitions via PySpark mapPartitions
into a partitioned Merkle ledger, then seal + verify.

This is the literal scenario the 100TB question referenced. Spark serialises
the per-partition function to separate Python worker processes (cloudpickle),
runs it on each partition, and each worker writes its own ledger segment; the
driver then composes and verifies the Merkle root. Uses Spark local mode, so it
exercises Spark's real execution + serialization machinery without a cluster.
Skips cleanly where pyspark/Java are unavailable.

Revision history
────────────────
1.0   2026-06-15   Initial release.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import importlib.util

import pytest

_HAS_SPARK = importlib.util.find_spec("pyspark") is not None


def _partition_func(root_dir):
    """Build the per-partition closure Spark ships to each Python worker.

    Captures only the ledger root (a string); all imports happen on the worker.
    """
    def _govern(idx, rows):
        records = list(rows)
        if not records:
            return iter([])
        import pandas as pd
        from pipeline.partitioned_ledger import PartitionedLedger
        from pipeline.partitioned_governance import govern_partition

        df = pd.DataFrame(records)
        ledger = PartitionedLedger(root_dir)
        out, meta = govern_partition(
            df, f"part-{idx:05d}", ledger, observe_config={"business_keys": ["id"]},
        )
        masked = bool(out["email"].str.startswith("MASKED_").all())
        return iter([(f"part-{idx:05d}", meta["rows_out"], masked)])

    return _govern


@pytest.mark.integration
@unittest.skipUnless(_HAS_SPARK, "pyspark not installed")
class TestPartitionedGovernanceSpark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pyspark.sql import SparkSession
        cls.spark = (
            SparkSession.builder
            .master("local[4]")
            .appName("path-a-governance")
            .config("spark.ui.enabled", "false")
            .getOrCreate()
        )
        cls.spark.sparkContext.setLogLevel("ERROR")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = str(Path(self.tmp) / "ledger")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_spark_map_partitions_governs_into_verified_root(self):
        from pipeline.partitioned_ledger import PartitionedLedger

        n_parts = 4
        records = [
            {"id": i, "email": f"user{i}@example.com", "name": f"User {i}"}
            for i in range(200)
        ]
        rdd = self.spark.sparkContext.parallelize(records, n_parts)

        results = rdd.mapPartitionsWithIndex(_partition_func(self.root)).collect()

        # Every non-empty partition governed its rows (PII masked) in a worker.
        self.assertTrue(results)
        self.assertTrue(all(masked for _sid, _rows, masked in results))

        # The independently-written segments compose into one verifiable root.
        ledger = PartitionedLedger(self.root)
        record = ledger.seal()
        self.assertEqual(record["segment_count"], len(results))
        self.assertGreater(record["total_events"], 0)
        self.assertTrue(ledger.verify())


if __name__ == "__main__":
    unittest.main()
