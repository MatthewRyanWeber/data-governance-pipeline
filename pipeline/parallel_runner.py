"""
Parallel file runner — process files through the pipeline concurrently.

Uses ThreadPoolExecutor with bounded concurrency to run a pipeline function
against each file in parallel. Returns structured result dicts with timing.

Layer 6 — imports from Layer 0 (constants).

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
"""

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


def run_parallel(
    files: list[str | Path],
    pipeline_fn: Callable,
    max_workers: int | None = None,
) -> list[dict]:
    """
    Run *pipeline_fn* on each file in parallel and return structured results.

    Parameters
    ----------
    files : list[str | Path]
        Files to process.
    pipeline_fn : Callable
        Function that accepts a single file path and returns any result.
        Exceptions are caught and recorded — they do not halt other files.
    max_workers : int | None
        Thread pool size.  Defaults to ``min(os.cpu_count(), 8)``.

    Returns
    -------
    list[dict]
        One dict per file: ``{file, success, error, duration_s}``.
    """
    if not files:
        logger.warning("run_parallel called with an empty file list.")
        return []

    workers = max_workers or min(os.cpu_count() or 4, 8)
    total = len(files)
    logger.info("Starting parallel run — %d files, %d workers.", total, workers)

    results: list[dict] = []
    completed = 0

    def _process(file_path: str | Path) -> dict:
        start = time.perf_counter()
        try:
            pipeline_fn(file_path)
            return {
                "file": str(file_path),
                "success": True,
                "error": None,
                "duration_s": round(time.perf_counter() - start, 3),
            }
        except Exception as exc:
            logger.error("Pipeline failed for %s: %s", file_path, exc)
            return {
                "file": str(file_path),
                "success": False,
                "error": str(exc),
                "duration_s": round(time.perf_counter() - start, 3),
            }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_process, f): f for f in files}

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            pct = int(completed / total * 100)
            status = "OK" if result["success"] else "FAIL"
            logger.info(
                "[%d/%d %3d%%] %s — %s (%.1fs)",
                completed, total, pct, result["file"], status, result["duration_s"],
            )

    succeeded = sum(1 for r in results if r["success"])
    failed = total - succeeded
    logger.info("Parallel run complete — %d succeeded, %d failed.", succeeded, failed)
    return results
