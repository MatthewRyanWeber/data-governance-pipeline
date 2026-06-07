"""
Parallel file processing for the Data Governance Pipeline.
Processes multiple source files simultaneously using ThreadPoolExecutor.

Usage:
    from parallel_runner import run_parallel
    results = run_parallel(
        files=["data1.csv", "data2.json", "data3.xlsx"],
        db_type="postgresql",
        db_config={"host": "localhost", "port": 5432, ...},
        table_prefix="import_",
        workers=8,
    )
"""

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from pipeline import Extractor, Transformer, SQLLoader, MongoLoader
    from pipeline import GovernanceLogger, _detect_pii
except ImportError:
    from pipeline_v3 import Extractor, Transformer, SQLLoader, MongoLoader
    from pipeline_v3 import GovernanceLogger, _detect_pii


def run_parallel(files, db_type, db_config, *, table_prefix="",
                 table=None, if_exists="append", pii_strategy="hash",
                 drop_cols=None, workers=None, on_progress=None):
    """Process multiple files in parallel through the ETL pipeline.

    Args:
        files: list of source file paths
        db_type: "sqlite", "postgresql", "mysql", "sqlserver", "mongodb"
        db_config: database connection config dict
        table_prefix: prefix for auto-generated table names
        table: fixed table name (overrides prefix)
        if_exists: "append", "replace", "fail"
        pii_strategy: "hash", "mask", "drop", "keep"
        drop_cols: columns to drop
        workers: number of parallel workers (default: min(cpu_count, 8))
        on_progress: callback(done, total, message)

    Returns:
        {"total": int, "ok": int, "errors": int, "results": list}
    """
    workers = workers or min(os.cpu_count() or 4, 8)
    total = len(files)
    results = []
    ok_count = 0
    error_count = 0

    logger.info("Parallel ETL: %d files, %d workers, db=%s", total, workers, db_type)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for f in files:
            fut = pool.submit(
                _process_one_file, f, db_type, db_config,
                table_prefix, table, if_exists,
                pii_strategy, drop_cols or [],
            )
            futures[fut] = f

        done_count = 0
        for fut in as_completed(futures):
            source = futures[fut]
            done_count += 1
            basename = os.path.basename(source)

            try:
                result = fut.result()
                results.append(result)
                if result["status"] == "ok":
                    ok_count += 1
                    logger.info("[%d/%d] OK: %s → %d rows",
                                done_count, total, basename, result["rows"])
                else:
                    error_count += 1
                    logger.warning("[%d/%d] FAIL: %s — %s",
                                   done_count, total, basename, result["error"])
            except Exception as exc:
                error_count += 1
                results.append({"source": source, "status": "error",
                                "error": str(exc), "rows": 0})
                logger.error("[%d/%d] ERROR: %s — %s",
                             done_count, total, basename, exc)

            if on_progress:
                on_progress(done_count, total, f"[{done_count}/{total}] {basename}")

    logger.info("Parallel ETL complete: %d ok, %d errors out of %d",
                ok_count, error_count, total)

    return {"total": total, "ok": ok_count, "errors": error_count, "results": results}


def _process_one_file(source, db_type, db_config, table_prefix,
                      table, if_exists, pii_strategy, drop_cols):
    """Process a single file through extract → transform → load."""
    started = time.time()
    basename = os.path.basename(source)

    gov = GovernanceLogger()
    gov.pipeline_start({"source": source, "parallel": True})

    # Extract
    extractor = Extractor(gov)
    df = extractor.extract(source)

    # PII scan
    pii_findings = _detect_pii(list(df.columns))
    if pii_findings:
        gov.pii_detected(pii_findings)

    # Transform
    transformer = Transformer(gov)
    df = transformer.transform(df, pii_findings, pii_strategy, drop_cols)

    # Table name
    if table:
        dest_table = table
    else:
        name = Path(source).stem.lower().replace(" ", "_").replace("-", "_")
        dest_table = f"{table_prefix}{name}"

    # Load
    if db_type == "mongodb":
        loader = MongoLoader(gov)
        loader.load(df, db_config, dest_table)
    else:
        loader = SQLLoader(gov, db_type)
        loader.load(df, db_config, dest_table, if_exists)

    elapsed = time.time() - started

    gov.pipeline_end({
        "rows_loaded": len(df),
        "destination_table": dest_table,
        "elapsed_seconds": round(elapsed, 1),
    })

    return {
        "source": source,
        "status": "ok",
        "rows": len(df),
        "table": dest_table,
        "elapsed": round(elapsed, 1),
    }


def find_files(directory, extensions=None):
    """Find all processable files in a directory."""
    extensions = extensions or {".csv", ".json", ".xlsx", ".xls", ".xml"}
    files = []
    for root, dirs, filenames in os.walk(directory):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in filenames:
            if Path(f).suffix.lower() in extensions:
                files.append(os.path.join(root, f))
    return sorted(files)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage: python parallel_runner.py <directory_or_files...>")
        print("  Processes all CSV/JSON/Excel/XML files in parallel")
        sys.exit(1)

    path = sys.argv[1]
    if os.path.isdir(path):
        files = find_files(path)
    else:
        files = sys.argv[1:]

    if not files:
        print("No files found")
        sys.exit(1)

    print(f"Found {len(files)} files")
    results = run_parallel(
        files, db_type="sqlite",
        db_config={"database": "parallel_output.db"},
        table_prefix="import_",
    )
    print(f"Done: {results['ok']} ok, {results['errors']} errors")
