#!/usr/bin/env python
"""
Scale benchmark for Path A: govern millions of rows across many partitions via
real Spark, measure throughput, and extrapolate honestly toward 100TB/day.

Each worker GENERATES its own partition (so the driver never holds all the
data — flat memory, like a real distributed run), runs the full governance
(PII detect/mask, dedup, ...) into its own ledger segment; the driver then
seals + verifies the Merkle root over every segment. Reports rows/sec on this
one box and what that implies per day and across a cluster.

Usage:  PYTHONPATH=. python scripts/bench_distributed_governance.py [total_rows] [n_partitions]
        PYTHONPATH=. python scripts/bench_distributed_governance.py 5000000 100
"""

import shutil
import sys
import tempfile
import time
from pathlib import Path

_BYTES_PER_ROW = 200  # rough on-wire size assumed for the TB/day extrapolation


def _worker(rows_per_partition, root):
    def _govern(idx, _rows):
        import pandas as pd
        from pipeline.partitioned_ledger import PartitionedLedger
        from pipeline.partitioned_governance import govern_partition

        base = idx * rows_per_partition
        df = pd.DataFrame({
            "id": range(base, base + rows_per_partition),
            "email": [f"user{base + i}@example.com" for i in range(rows_per_partition)],
            "name": [f"User {base + i}" for i in range(rows_per_partition)],
            "amount": [(i % 1000) + 0.5 for i in range(rows_per_partition)],
        })
        _out, meta = govern_partition(df, f"part-{idx:06d}", PartitionedLedger(root))
        return iter([(meta["rows_out"],)])

    return _govern


def main(argv):
    total_rows = int(argv[0]) if argv else 5_000_000
    n_partitions = int(argv[1]) if len(argv) > 1 else 100
    rows_per_partition = total_rows // n_partitions
    total_rows = rows_per_partition * n_partitions

    from pyspark.sql import SparkSession
    spark = (
        SparkSession.builder.master("local[*]").appName("path-a-scale")
        .config("spark.ui.enabled", "false").getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    cores = spark.sparkContext.defaultParallelism

    tmp = tempfile.mkdtemp()
    root = str(Path(tmp) / "ledger")
    from pipeline.partitioned_ledger import PartitionedLedger

    print(f"governing {total_rows:,} rows across {n_partitions} partitions "
          f"({rows_per_partition:,}/partition) on local[{cores}] ...", flush=True)
    try:
        rdd = spark.sparkContext.parallelize(range(n_partitions), n_partitions)
        start = time.perf_counter()
        loaded = rdd.mapPartitionsWithIndex(_worker(rows_per_partition, root)).collect()
        govern_secs = time.perf_counter() - start

        rows_governed = sum(r[0] for r in loaded)
        record = PartitionedLedger(root).seal()
        verified = PartitionedLedger(root).verify()
    finally:
        spark.stop()
        shutil.rmtree(tmp, ignore_errors=True)

    rate = rows_governed / govern_secs if govern_secs else 0.0
    rows_day = rate * 86_400
    tb_day = rows_day * _BYTES_PER_ROW / 1e12
    boxes_for_100tb = 100 / tb_day if tb_day else float("inf")

    print("\n--- result ---")
    print(f"rows governed     : {rows_governed:,}")
    print(f"segments / events : {record['segment_count']} / {record['total_events']:,}")
    print(f"ledger verified   : {verified}")
    print(f"wall time         : {govern_secs:,.1f}s")
    print(f"throughput        : {rate:,.0f} rows/s on {cores} cores")
    print(f"\n--- honest extrapolation (governance compute only, ~{_BYTES_PER_ROW}B/row) ---")
    print(f"this box / day    : {rows_day/1e9:,.1f}B rows  ~ {tb_day:,.2f} TB/day")
    print(f"for 100 TB/day    : ~{boxes_for_100tb:,.0f} boxes like this "
          f"(design has no shared-writer bottleneck, so it scales out)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
