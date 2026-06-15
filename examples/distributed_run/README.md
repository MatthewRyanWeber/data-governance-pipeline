# Distributed-governance run (Path A) — real artifacts

The actual output of `run.py`, committed as evidence that governance composes
across partitions into one tamper-evident root — the design for governing a
distributed (100TB/day-class) run. See [docs/DISTRIBUTED_GOVERNANCE.md](../../docs/DISTRIBUTED_GOVERNANCE.md).

## Reproduce

```bash
PYTHONPATH=. python examples/distributed_run/run.py
```

It splits a dataset into 4 partitions, governs each **concurrently** into its
own ledger segment, seals them into a Merkle root, and verifies — printing:

```
partitions governed : 4
total ledger events  : 20
merkle root          : <64-hex>
verify()             : True
all emails masked    : True
inclusion part-0002  : True
```

## What `ledger/` contains

| Artifact | What it shows |
|----------|---------------|
| `segment-part-000N.jsonl` (+`.anchor`) | One **independent** SHA-256 hash chain per partition — written with no shared writer. Each holds that partition's governance events (PII masking, dedup, etc.). |
| `ledger.root.json` | The sealed **Merkle root** over the segment heads, plus each segment's id/count/head. This is the single value to publish to a WORM/notary store; it makes the whole set tamper-evident. |

## Verify it yourself

```python
from pipeline.partitioned_ledger import PartitionedLedger
assert PartitionedLedger("examples/distributed_run/ledger").verify()   # chains + root
```

Altering, dropping, adding, or renaming any segment changes the Merkle root and
fails `verify()`. A single partition can be audited in isolation with
`inclusion_proof(segment_id)` — O(log n), no need to read the others.

Source data is synthetic (`@example.com`) and PII is masked in the ledger, so
these artifacts are safe to publish.
