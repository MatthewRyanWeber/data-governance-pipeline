# Distributed governance (Path A) — governing 100TB/day

This pipeline is a single-process tool sized for ~1GB–1TB/day (see
[SCOPE.md](SCOPE.md)). You do **not** scale that process to 100TB/day. The
answer at that volume is **Path A**: let a distributed engine (Spark, Ray,
Dask) own the fan-out, and run *this pipeline's governance* on each partition.

Two pieces make that possible without losing the tamper-evident audit trail:

## 1. A partitionable ledger — `pipeline.partitioned_ledger.PartitionedLedger`

The single-file audit ledger is a serial hash chain (one writer, one chain) —
the contention point that can't scale across workers. `PartitionedLedger` gives
each partition its **own segment**: an independent SHA-256 chain in its own
file, written with zero coordination between workers. After the run, the
segment heads compose into a single **Merkle root**.

- `seal()` — compose the segment heads into the Merkle root anchor (run once,
  on the driver, after all partitions finish).
- `verify()` — check every segment's chain **and** the root; a tampered,
  dropped, added, or renamed segment is detected.
- `inclusion_proof(segment_id)` — an O(log n) proof that one partition is part
  of the sealed root, so a single partition can be audited without reading the
  others.

The `merkle_root` is the external trust value — publish it to a WORM/notary
store to make the whole ledger tamper-evident against an attacker who can
rewrite the files (the same trust boundary the single-file anchor has).

## 2. A per-partition governance entrypoint — `pipeline.partitioned_governance.govern_partition`

`govern_partition(df, segment_id, ledger)` runs the governance stages (PII
detection + masking, quality, etc.) on **one** partition and writes its audit
chain into that partition's segment. It shares no mutable state with other
partitions, so it is safe to call from a distributed engine's per-partition
task.

### Spark

```python
from pipeline.partitioned_ledger import PartitionedLedger
from pipeline.partitioned_governance import govern_partition
import pandas as pd

ledger = PartitionedLedger("s3://bucket/run_ledger/")  # or a local path

def govern(idx, rows):
    df = pd.DataFrame(list(rows))
    out, _meta = govern_partition(df, segment_id=f"part-{idx:05d}", ledger=ledger)
    return out.itertuples(index=False)

governed = rdd.mapPartitionsWithIndex(govern)
# ... write `governed` to the destination ...

# Once, on the driver, after the job completes:
ledger.seal()
assert ledger.verify()
```

This exact flow is verified by `tests/integration/test_partitioned_governance_spark.py`
(a real PySpark local-mode job: cloudpickled per-partition function, separate
worker processes, segments composed into a verified Merkle root) and by a
`ProcessPoolExecutor` test that proves the same isolation/serialization without
a JVM.

### Local / non-distributed

`govern_partitions(partitions, ledger)` is the reference coordinator — it fans
`govern_partition` over `(segment_id, df)` pairs with a thread pool, then seals
and verifies. It's what the tests use to exercise the full flow in one process.

## Measured throughput (and the partition-size lever)

`scripts/bench_distributed_governance.py` runs real Spark, generating rows
inside each worker (flat driver memory) and governing them into the partitioned
ledger. On one 12-core box, governing 5,000,000 rows (full PII masking +
tamper-evident ledger), ledger verified each time:

| partitions | rows/partition | rows/s | ≈ per box | for 100 TB/day |
|-----------:|---------------:|-------:|----------:|---------------:|
| 100        | 50,000         | ~22k   | 0.38 TB/day | ~260 boxes |
| 20         | 250,000        | ~100k  | 1.73 TB/day | ~58 boxes  |

The 4.5x swing is the **per-partition governance fixed cost** (each partition
builds a GovernanceLogger, writes a ledger segment + reports). **Use fewer,
larger partitions** (toward the ~1GB–1TB single-node envelope) to amortize it —
that also keeps `seal()`/`verify()`, a driver-side O(num-segments) reduce, cheap.
At extreme partition counts, seal hierarchically (the Merkle structure already
composes sub-roots). 100 TB/day is a cluster of dozens of such boxes — reachable
because the per-partition write path has no shared bottleneck (verified), not a
single process scaled up.

These are **governance-compute** numbers on one box in Spark local mode — not a
real cluster moving 100TB to destinations. They show the design holds past toy
scale and scales out linearly; the actual 100TB run needs the cluster + data.

## What this is and isn't

- It **is** the design for applying governance at distributed scale: per-shard
  audit chains that compose into one verifiable root, with no shared-writer
  bottleneck.
- It is **not** a distributed compute engine. This pipeline doesn't move the
  100TB; Spark/Ray/Dask does. This provides the governance the fan-out calls.
- Object-store segment paths (`s3://…`) work wherever the ledger's atomic write
  has a move primitive; otherwise use a shared filesystem and collect segments
  to the driver before `seal()`.
