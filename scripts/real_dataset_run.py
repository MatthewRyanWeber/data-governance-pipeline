#!/usr/bin/env python
"""
Run a REAL public-domain government dataset through the full pipeline.

The canary proves the governance core stays correct on a fixed synthetic frame;
this proves it on real-world data with the messiness real data carries (mixed
types, sentinel nulls, unexpected columns). It fetches a live public-domain US
government feed (USGS earthquakes by default — public domain under 17 U.S.C.
§ 105, and free of personal data), runs it through `pipeline.cli run`, and writes
a `provenance.json` recording exactly what was processed: source URL, fetch time,
input bytes / SHA-256 / row count, and whether the emitted audit ledger verifies.

Committed on a schedule, the refreshed artifacts + provenance are "real miles":
dated evidence the pipeline governs real government data, not just a demo frame.

Exit codes (so a scheduler can tell a real failure from an environment one):
    0  success — dataset processed and the ledger chain verified
    1  governance failure — the pipeline run failed or the ledger did not verify
    2  network skip — the source could not be fetched (logged loudly, NOT a
       governance regression, so a flaky feed never turns the schedule red)

Usage:
    python scripts/real_dataset_run.py
    python scripts/real_dataset_run.py --url <csv-url> --table quakes \
        --output-dir examples/data_gov_run --source-name usgs_all_day
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from pipeline.constants import VERSION

logger = logging.getLogger(__name__)

# USGS "all earthquakes, past day" CSV feed. US Government work → public domain;
# geophysical data with no personal information.
DEFAULT_URL = (
    "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.csv"
)

EXIT_OK = 0
EXIT_GOVERNANCE_FAIL = 1
EXIT_NETWORK_SKIP = 2


def _download(url: str, dest: Path, timeout: float) -> tuple[int, int]:
    """Fetch url into dest. Returns (http_status, bytes_written).

    Raises urllib.error.URLError / socket.timeout on any network problem — the
    caller downgrades that to a loud skip rather than a governance failure.
    """
    request = urllib.request.Request(url, headers={"User-Agent": "dgp-real-run"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
        status = getattr(response, "status", 200) or 200
    dest.write_bytes(payload)
    return status, len(payload)


def _verify_ledger_chain(ledger_path: Path) -> bool:
    """Independent hash-chain check: each entry's prev_hash == prior self_hash.

    Deliberately separate from the pipeline's own verify so a broken run cannot
    self-certify through the same code path that wrote the ledger.
    """
    if not ledger_path.exists():
        return False
    rows = [json.loads(line) for line in
            ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return False
    for earlier, later in zip(rows, rows[1:]):
        if later.get("prev_hash") != earlier.get("self_hash"):
            return False
    return True


def _collect_artifacts(logs_dir: Path, artifacts_dir: Path) -> None:
    """Curate the run's timestamped LOGS output into a stable artifacts/ set.

    The pipeline writes to `<source> LOGS/` with timestamped names; mirror the
    sample_run layout by copying the latest of each into committable canonical
    names so the example stays diff-friendly across refreshes.
    """
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    # (canonical name, glob, predicate) — anchor must be matched before the
    # bare ledger so "*.jsonl" does not also grab "*.jsonl.anchor".
    wanted = [
        ("audit_ledger.jsonl.anchor", "audit_ledger*.jsonl.anchor", None),
        ("audit_ledger.jsonl", "audit_ledger*.jsonl",
         lambda p: not p.name.endswith(".anchor")),
        ("metrics_report.json", "metrics_report*.json", None),
        ("observability_history.jsonl", "observability_history*.jsonl", None),
    ]
    for canonical, pattern, predicate in wanted:
        matches = [p for p in logs_dir.glob(pattern)
                   if predicate is None or predicate(p)]
        if not matches:
            continue
        latest = max(matches, key=lambda p: p.stat().st_mtime)
        shutil.copyfile(latest, artifacts_dir / canonical)


def _count_rows(csv_path: Path) -> int:
    """Data rows (excludes the header), counted without loading the file."""
    with open(csv_path, "r", encoding="utf-8", errors="replace") as handle:
        total = sum(1 for _ in handle)
    return max(total - 1, 0)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Run a real gov dataset through "
                                                 "the pipeline.")
    parser.add_argument("--url", default=DEFAULT_URL, help="Source CSV URL.")
    parser.add_argument("--output-dir", default="examples/data_gov_run",
                        help="Where the input + artifacts + provenance land.")
    parser.add_argument("--source-name", default="usgs_all_day",
                        help="Slug for the downloaded input file.")
    parser.add_argument("--table", default="earthquakes",
                        help="Destination table name.")
    parser.add_argument("--config", default=None,
                        help="Pipeline config JSON (default: <output-dir>/config.json).")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Download timeout in seconds.")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    config_path = Path(args.config) if args.config else output_dir / "config.json"
    csv_name = f"{args.source_name}.csv"
    csv_path = output_dir / csv_name

    started = datetime.now(timezone.utc)

    # ── Fetch (network problems are a loud skip, not a governance failure) ──
    try:
        http_status, byte_count = _download(args.url, csv_path, args.timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("[REAL-RUN] could not fetch %s: %s — SKIPPING this run "
                       "(environment problem, not a governance regression).",
                       args.url, exc)
        return EXIT_NETWORK_SKIP

    input_sha256 = hashlib.sha256(csv_path.read_bytes()).hexdigest()
    input_rows = _count_rows(csv_path)
    logger.info("[REAL-RUN] fetched %s (%d bytes, %d rows, HTTP %d).",
                args.url, byte_count, input_rows, http_status)

    # ── Govern the real data through the same CLI an operator would use ────
    run_command = [
        sys.executable, "-m", "pipeline.cli", "run", csv_name, "sqlite",
        "--config", str(config_path.resolve()), "--table", args.table,
    ]
    # The run executes from output_dir so artifacts land beside the input, but
    # `pipeline` must still resolve there. An installed package already does;
    # add the repo root by ABSOLUTE path so an uninstalled checkout works too
    # (a cwd-relative PYTHONPATH would point at output_dir once cwd changes).
    repo_root = Path(__file__).resolve().parent.parent
    child_env = dict(os.environ)
    existing_path = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = (
        f"{repo_root}{os.pathsep}{existing_path}" if existing_path else str(repo_root)
    )
    completed = subprocess.run(run_command, cwd=output_dir, env=child_env)

    # Curate the timestamped run output into a clean, committable artifacts/ set,
    # then drop the raw LOGS dir and the local sqlite db so the example holds
    # only evidence (input, artifacts, provenance) — not run scratch.
    artifacts_dir = output_dir / "artifacts"
    for logs_dir in output_dir.glob("*LOGS"):
        if logs_dir.is_dir():
            _collect_artifacts(logs_dir, artifacts_dir)
            shutil.rmtree(logs_dir, ignore_errors=True)
    for scratch_db in output_dir.glob("*.db"):
        scratch_db.unlink()

    ledger_path = artifacts_dir / "audit_ledger.jsonl"
    ledger_verified = _verify_ledger_chain(ledger_path)

    status = "pass" if (completed.returncode == 0 and ledger_verified) else "fail"

    provenance = {
        "utc": started.isoformat(),
        "status": status,
        "source_url": args.url,
        "source_note": "US Government work — public domain (17 U.S.C. § 105); "
                       "no personal data.",
        "http_status": http_status,
        "input_bytes": byte_count,
        "input_sha256": input_sha256,
        "input_rows": input_rows,
        "table": args.table,
        "ledger_verified": ledger_verified,
        "pipeline_returncode": completed.returncode,
        "version": VERSION,
    }
    (output_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    logger.info("[REAL-RUN] %s — %d rows governed, ledger_verified=%s.",
                status.upper(), input_rows, ledger_verified)

    return EXIT_OK if status == "pass" else EXIT_GOVERNANCE_FAIL


if __name__ == "__main__":
    sys.exit(main())
