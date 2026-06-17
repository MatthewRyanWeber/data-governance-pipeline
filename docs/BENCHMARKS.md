# Benchmarks

Measured numbers from real runs. Each figure includes its method so it is
reproducible and honestly bounded — where a result falls within measurement
noise, it says so rather than rounding it into a claim.

## Governance overhead (real-workload load)

Loaded a **26.75 GB** dataset (**331,655 records, 517,382 pages**, stored as
binary blobs) into SQL Server, comparing an ungoverned load to a fully governed
load (PII scan + tamper-evident SHA-256 hash-chained audit ledger — **1,831
events, verified**).

**Result: full governance added no measurable time overhead.**

| Load | Avg wall-clock | Trials |
|------|---------------:|--------|
| Ungoverned | 885 s | 860 s, 909 s |
| Governed (PII scan + verified audit ledger) | 840 s | 743 s, 936 s |

The ~5% gap between the averages is **smaller than the run-to-run variance** —
the governed runs alone span 743–936 s — so it is noise, not a governance
speedup. The honest conclusion is that full governance is effectively free at
this scale: the I/O of moving 27 GB dominates, and the PII scan plus the
hash-chained audit ledger disappear into it.

### Method (why the number is trustworthy)

- **Pre-grown SQL data file** so neither load pays autogrowth mid-run.
- **`RECOVERY SIMPLE`** so transaction-log behaviour is identical for both.
- **OS cache warmed** (the entire source read once) before any timing, so both
  paths start equally warm.
- **Alternating trials** (Regular, Governed, Regular, Governed) averaged, so any
  "the second run is warmer" drift cancels out.
- **Identical load path** — same batching, same inserts; the *only* difference
  is the governance work.

Hardware: single workstation, SQL Server 2025 Developer, local disk. Numbers are
wall-clock and will vary with hardware; the **relative** finding (governance ≈
free) is the portable result.

### Reproduction (2026-06-17, cold start)

A fresh end-to-end governed run — from a **cold start** (all tables dropped and
the audit ledger cleared, then the full governed import re-run) — reproduced the
figure:

| Phase | Volume | Wall-clock |
|-------|--------|-----------:|
| Metadata load (documents + pages) | 331,655 + 517,382 rows | ~32 s |
| Blob phase (binary blobs) | 26.75 GB, 331,655 blobs | **838 s** |
| Finalize + verify | — | ~7 s |
| **End-to-end** | 849,037 rows + 26.75 GB | **878.9 s** |

Blob-phase throughput: **~32.7 MB/s (~396 blobs/s)**. The 838 s blob phase lands
on the 840 s governed average above, and the audit ledger again verified —
**1,831 SHA-256 hash-chained events, `verified=True`** — with record and blob
counts independently re-checked (0 empty, 0 orphaned).

Because this was a cold start rather than the warmed / pre-grown protocol of the
controlled table above, it is reported as a **separate confirming data point, not
an additional controlled trial**. That it still lands on the governed average is
the useful result: full governance stays effectively free at this scale.
