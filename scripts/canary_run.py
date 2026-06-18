#!/usr/bin/env python
"""
Run the governance canary and append to its track record.

Each invocation runs a fixed synthetic dataset through the real governance core
(PII detect → mask → governed sqlite load → ledger verify) and records a
pass/fail entry with timing. Schedule it (cron / Task Scheduler) so the track
record accumulates dated, ledger-verified runs — the production-miles evidence
a single demo run can't provide.

Exit code is 0 only if every run this invocation passed (fail loud), so a
scheduler treats a broken governance core as a failed job.

Usage:
    python scripts/canary_run.py                       # one run
    python scripts/canary_run.py --runs 20             # soak: 20 runs
    python scripts/canary_run.py --rows 1000 --track-record path/to/record.jsonl
"""

import argparse
import sys

from pipeline.monitoring.canary import CanaryRunner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the governance canary.")
    parser.add_argument("--runs", type=int, default=1, help="Number of runs (soak).")
    parser.add_argument("--rows", type=int, default=200, help="Synthetic rows per run.")
    parser.add_argument("--interval", type=float, default=0.0,
                        help="Seconds to wait between runs.")
    parser.add_argument("--track-record", default=None,
                        help="Path to the track-record JSONL.")
    args = parser.parse_args(argv)

    runner = CanaryRunner(track_record_path=args.track_record, rows=args.rows)
    summary = runner.soak(args.runs, interval_sec=args.interval)

    print(f"Canary: {summary['passed']}/{summary['runs']} passed this history "
          f"(pass_rate={summary['pass_rate']}, last={summary['last_status']}).")

    # Fail loud if the most recent invocation produced any failure. Recompute
    # over just this invocation's runs so an old failure in history doesn't
    # mask a clean run (and vice versa).
    return 0 if summary["last_status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
