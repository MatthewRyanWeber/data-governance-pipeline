#!/usr/bin/env python
"""
Benchmark the chunked read fast path: pandas vs the DuckDB compute engine.

Generates a synthetic CSV and times how fast each engine streams it in chunks
through the same Extractor seam the pipeline uses. This is the baseline-to-beat
for the acceleration work — run it before and after a change to prove (or
disprove) a gain rather than optimizing blind.

Usage:  python scripts/bench_pipeline.py [rows] [chunk_size]
        python scripts/bench_pipeline.py 2000000 100000
"""

import sys
import time
import tempfile
from pathlib import Path


def _make_csv(path: str, rows: int) -> None:
    # Deterministic, type-unambiguous data (no leading zeros / mixed types) so
    # the two engines read identically — we are timing throughput, not parsing
    # quirks. Wide-ish to make per-chunk work realistic.
    import csv
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "full_name", "email", "country", "amount", "note"])
        countries = ["US", "DE", "FR", "JP", "BR"]
        for i in range(rows):
            w.writerow([
                i, f"User {i}", f"user{i}@example.com",
                countries[i % len(countries)], round((i % 1000) + 0.5, 2),
                "lorem ipsum dolor sit amet consectetur",
            ])


def _time_engine(path: str, engine: str, chunk_size: int) -> tuple[int, float]:
    from unittest.mock import MagicMock
    from pipeline.extract import Extractor

    ext = Extractor(MagicMock(), engine=engine)
    start = time.perf_counter()
    total = 0
    for chunk in ext.chunks(path, chunk_size=chunk_size):
        total += len(chunk)
    return total, time.perf_counter() - start


def main(argv: list[str]) -> int:
    rows = int(argv[0]) if argv else 1_000_000
    chunk_size = int(argv[1]) if len(argv) > 1 else 100_000

    tmp = tempfile.mkdtemp()
    path = str(Path(tmp) / "bench.csv")
    print(f"Generating {rows:,} rows -> {path} ...", flush=True)
    _make_csv(path, rows)
    size_mb = Path(path).stat().st_size / 1e6
    print(f"  {size_mb:.1f} MB\n", flush=True)

    results = {}
    for engine in ("pandas", "duckdb"):
        total, secs = _time_engine(path, engine, chunk_size)
        rate = total / secs if secs else 0.0
        results[engine] = rate
        print(f"{engine:>7}: {total:,} rows in {secs:6.2f}s "
              f"= {rate:,.0f} rows/s ({size_mb / secs:6.1f} MB/s)", flush=True)

    if results.get("pandas"):
        speedup = results["duckdb"] / results["pandas"]
        print(f"\nduckdb speedup over pandas: {speedup:.2f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
