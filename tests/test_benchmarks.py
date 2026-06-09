"""
Pipeline throughput and memory benchmarks.

All tests are marked @pytest.mark.slow so they are skipped in the normal
unit test suite.  Run them explicitly with:
    pytest tests/test_benchmarks.py -v -m slow

Revision history
────────────────
1.0   2026-06-09   Initial release: throughput 10K/100K, memory, profiler.
"""

import os
import shutil
import tempfile
import time
import tracemalloc

import pandas as pd
import pytest

from pipeline.constants import RunContext
from pipeline.extract import Extractor
from pipeline.governance_logger import GovernanceLogger
from pipeline.loaders.sql_loader import SQLLoader
from pipeline.transform import Transformer


def _make_csv(tmpdir: str, rows: int) -> str:
    """Generate a synthetic CSV with the given number of rows."""
    path = os.path.join(tmpdir, f"bench_{rows}.csv")
    df = pd.DataFrame({
        "id": range(rows),
        "name": [f"user_{i}" for i in range(rows)],
        "email": [f"user_{i}@example.com" for i in range(rows)],
        "amount": [round(i * 1.5, 2) for i in range(rows)],
    })
    df.to_csv(path, index=False, encoding="utf-8")
    return path


def _run_full_pipeline(csv_path: str, tmpdir: str, table: str = "bench") -> float:
    """Run CSV -> extract -> transform -> SQLite and return elapsed seconds."""
    db_path = os.path.join(tmpdir, "bench_output")
    run_context = RunContext()
    gov = GovernanceLogger(
        source_name=os.path.basename(csv_path),
        log_dir=os.path.join(tmpdir, "gov"),
        run_context=run_context,
    )
    gov.pipeline_start({"source": csv_path})

    start = time.perf_counter()

    extractor = Extractor(gov)
    df = extractor.extract(csv_path)
    transformer = Transformer(gov, run_context=run_context)
    df_out = transformer.transform(df, [], "mask", drop_cols=[])
    loader = SQLLoader(gov, db_type="sqlite")
    loader.load(df_out, {"db_name": db_path}, table, if_exists="replace")

    elapsed = time.perf_counter() - start
    gov.pipeline_end({"rows": len(df_out)})
    return elapsed


@pytest.mark.slow
class TestThroughput:
    """Pipeline throughput benchmarks."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp(prefix="bench_")

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_throughput_10k_rows(self):
        csv_path = _make_csv(self.tmpdir, 10_000)
        elapsed = _run_full_pipeline(csv_path, self.tmpdir, "bench_10k")
        rows_per_sec = 10_000 / elapsed
        print(f"\n10K rows: {elapsed:.2f}s ({rows_per_sec:.0f} rows/sec)")
        assert elapsed < 10, f"10K rows took {elapsed:.1f}s (limit: 10s)"

    def test_throughput_100k_rows(self):
        csv_path = _make_csv(self.tmpdir, 100_000)
        elapsed = _run_full_pipeline(csv_path, self.tmpdir, "bench_100k")
        rows_per_sec = 100_000 / elapsed
        print(f"\n100K rows: {elapsed:.2f}s ({rows_per_sec:.0f} rows/sec)")
        assert elapsed < 60, f"100K rows took {elapsed:.1f}s (limit: 60s)"

    def test_memory_usage_100k_rows(self):
        csv_path = _make_csv(self.tmpdir, 100_000)
        tracemalloc.start()
        _run_full_pipeline(csv_path, self.tmpdir, "bench_mem")
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_mb = peak / 1024 / 1024
        print(f"\n100K rows peak memory: {peak_mb:.1f} MB")
        assert peak_mb < 500, f"Peak memory {peak_mb:.0f} MB exceeds 500 MB limit"


@pytest.mark.slow
class TestProfilerBenchmark:
    """DataProfiler performance on large datasets."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp(prefix="bench_prof_")

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_profiler_on_large_dataset(self):
        from pipeline.profiler import DataProfiler

        gov = GovernanceLogger(
            source_name="bench_profiler",
            log_dir=os.path.join(self.tmpdir, "gov"),
            run_context=RunContext(),
        )
        profiler = DataProfiler(gov)

        df = pd.DataFrame({
            "id": range(100_000),
            "name": [f"user_{i}" for i in range(100_000)],
            "amount": [round(i * 1.5, 2) for i in range(100_000)],
        })

        start = time.perf_counter()
        profiler.profile(df)
        elapsed = time.perf_counter() - start
        print(f"\nProfile 100K rows: {elapsed:.2f}s")
        assert elapsed < 30, f"Profiling took {elapsed:.1f}s (limit: 30s)"
