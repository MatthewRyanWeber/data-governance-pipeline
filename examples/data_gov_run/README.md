# Real-dataset run — live government data, real artifacts

This directory holds the **actual output of governing a real, public-domain US
government dataset** — not a synthetic demo. It is the "real miles" companion to
[`../sample_run`](../sample_run) (which proves the mechanics on a tiny crafted
file) and [`../canary`](../canary) (which proves the core stays correct over
time on a fixed synthetic frame).

The input is the [USGS "all earthquakes, past day" CSV feed][usgs] — a US
Government work, public domain under 17 U.S.C. § 105, containing geophysical
measurements and **no personal data**.

[usgs]: https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.csv

## Reproduce / refresh it

```bash
python scripts/real_dataset_run.py
```

The script fetches the live feed, runs it through `pipeline.cli run`, curates the
emitted artifacts into `artifacts/`, and writes `provenance.json`. Because the
feed is live, every refresh processes a different day's earthquakes — that is the
point: dated, ledger-verified evidence that accumulates over time.

Exit codes: `0` success, `1` governance failure (run failed or ledger did not
verify), `2` the feed could not be fetched (a network problem is logged loudly
and is **not** treated as a governance regression).

## What `provenance.json` records

Honest provenance for exactly what was processed: the source URL, fetch time,
the input's byte count / SHA-256 / row count, the pipeline version, and whether
the emitted audit ledger independently verified. The artifacts and provenance
are committed together so the evidence is self-describing.

## What the artifacts prove

| Artifact | What it demonstrates |
|----------|----------------------|
| `artifacts/audit_ledger.jsonl` | SHA-256 hash-chained audit of the run — extract, PII masking, transform, load, and `LOAD_VERIFICATION` reconciling source vs destination row counts. |
| `artifacts/audit_ledger.jsonl.anchor` | Tamper-evidence sidecar (entry count + last hash). |
| `artifacts/metrics_report.json` | Per-stage timings and the real `rows_input` / `rows_output` for the run. |
| `artifacts/observability_history.jsonl` | Freshness / volume / drift / null-spike observation for the load (`mag` and `time` watched as critical fields). |

## A real-data finding

Run against real columns, the default PII detector flags **`latitude` and
`longitude`** as personal data (geolocation). On an impersonal seismic feed that
is a false positive — exactly the kind of thing only real data surfaces, and a
reminder that column-name PII heuristics need a `column_purpose` override (which
the [policy importer](../policy_import) exists to supply) when a location column
is not about people.

## Verify the chain yourself

```python
import json
rows = [json.loads(l) for l in open("artifacts/audit_ledger.jsonl") if l.strip()]
assert all("prev_hash" in r and "self_hash" in r for r in rows)
for a, b in zip(rows, rows[1:]):
    assert b["prev_hash"] == a["self_hash"], "chain broken"
print(f"{len(rows)} events, chain intact")
```
