#!/usr/bin/env python
"""
Path A demo — govern partitions concurrently into a partitioned Merkle ledger.

Simulates what a distributed engine does across executors, in one process: a
dataset is split into partitions, each partition is governed independently into
its OWN ledger segment (concurrently), then the segments are sealed into a
single Merkle root and verified. Writes its artifacts to ./ledger/.

Run from the repo root:
    PYTHONPATH=. python examples/distributed_run/run.py
"""

import shutil
from pathlib import Path

import pandas as pd

from pipeline.partitioned_ledger import PartitionedLedger, verify_inclusion
from pipeline.partitioned_governance import govern_partitions

_HERE = Path(__file__).resolve().parent


def _partition(k: int, n: int = 50) -> pd.DataFrame:
    base = k * n
    return pd.DataFrame({
        "order_id": range(base, base + n),
        "email": [f"user{base + i}@example.com" for i in range(n)],
        "name": [f"User {base + i}" for i in range(n)],
        "amount": [(i % 100) + 0.5 for i in range(n)],
    })


def main() -> int:
    root = _HERE / "ledger"
    shutil.rmtree(root, ignore_errors=True)  # clean snapshot on every run

    ledger = PartitionedLedger(root)
    partitions = [(f"part-{k:04d}", _partition(k)) for k in range(4)]

    governed, record = govern_partitions(partitions, ledger)

    print(f"partitions governed : {record['segment_count']}")
    print(f"total ledger events  : {record['total_events']}")
    print(f"merkle root          : {record['merkle_root']}")
    print(f"verify()             : {ledger.verify()}")

    # PII was masked in every partition.
    masked = all(out['email'].str.startswith('MASKED_').all() for out in governed.values())
    print(f"all emails masked    : {masked}")

    # Audit a single partition without reading the others (Merkle inclusion).
    proof = ledger.inclusion_proof("part-0002")
    ok = verify_inclusion(proof["leaf"], proof["proof"], proof["merkle_root"])
    print(f"inclusion part-0002  : {ok}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
