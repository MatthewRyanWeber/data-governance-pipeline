# Sample run — real artifacts, not a worked example

This directory holds the **actual output of a real pipeline run**, committed as
operational evidence. Nothing here is hand-written; `artifacts/` is exactly
what the pipeline emitted.

## Reproduce it

```bash
cd examples/sample_run
python -m pipeline.cli run customers.csv sqlite --config config.json --table customers
```

`customers.csv` is 5 synthetic customer rows (one with a missing email);
`config.json` enables observability with `email` as a critical field.

## What the artifacts prove

| Artifact | What it demonstrates |
|----------|----------------------|
| `artifacts/audit_ledger.jsonl` | 16 events, **SHA-256 hash-chained** — every entry carries `prev_hash` + `self_hash`. Includes `PII_MASKED` events for `full_name`, `email`, `phone`; `LOAD_VERIFICATION` (source vs destination reconciled); lifecycle events. |
| `artifacts/audit_ledger.jsonl.anchor` | The tamper-evidence sidecar: entry count + last hash. `gov.verify_ledger()` cross-checks the chain against it. |
| `artifacts/metrics_report.json` | Per-stage timings and row counts for the run. |
| `artifacts/observability_history.jsonl` | The freshness / volume / drift / null-spike observation recorded for this load (the `email` critical field was watched). |

## Verify the chain yourself

```python
import json, hashlib
rows = [json.loads(l) for l in open("artifacts/audit_ledger.jsonl") if l.strip()]
assert all("prev_hash" in r and "self_hash" in r for r in rows)
# each entry's prev_hash equals the previous entry's self_hash
for a, b in zip(rows, rows[1:]):
    assert b["prev_hash"] == a["self_hash"], "chain broken"
print(f"{len(rows)} events, chain intact")
```

The PII values in the ledger are masked, and the source data is fully synthetic
(`@example.com`, `555-010x`), so these artifacts are safe to publish.
