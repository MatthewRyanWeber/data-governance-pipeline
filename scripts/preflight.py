#!/usr/bin/env python
"""
Reproduce the CI gates locally before pushing — if this is green, the Tests
workflow should be too.

Three CI failures in one session all came from the local box not matching CI:
local has the optional deps installed and uses sqlite, while CI runs with those
deps absent and against real Postgres/MySQL. This script closes the gap it can
close on a dev machine:

  1. pyflakes            (same as CI lint step)
  2. unreachable-code    (scripts/lint_unreachable.py)
  3. mypy                (same flags as CI)
  4. unit tests          (same ignores / markers as CI)
  5. unit tests with optional deps BLOCKED (loader tests only) — exercises the
     deps-absent path CI runs, catching the "from optional.submodule import X"
     class of bug that passes locally only because the dep happens to be
     installed.

Usage:  python scripts/preflight.py
Exit 0 only when every stage passes.
"""

import subprocess
import sys

_CI_IGNORES = [
    "--ignore=tests/test_integration_db.py",
    "--ignore=tests/integration",
    "--ignore=tests/test_benchmarks.py",
    "--ignore=tests/test_api_load.py",
]


def _run(label: str, cmd: list[str]) -> bool:
    print(f"\n{'=' * 70}\n{label}\n{'=' * 70}", flush=True)
    completed = subprocess.run(cmd)
    ok = completed.returncode == 0
    print(f"  -> {'PASS' if ok else 'FAIL'} ({label})", flush=True)
    return ok


def main() -> int:
    py = sys.executable
    stages = [
        ("pyflakes", [py, "-m", "pyflakes", "pipeline", "tests"]),
        ("unreachable-code", [py, "scripts/lint_unreachable.py", "pipeline"]),
        ("mypy", [py, "-m", "mypy", "pipeline", "--ignore-missing-imports"]),
        ("unit tests", [py, "-m", "pytest", "tests/", "-q", *_CI_IGNORES,
                        "-m", "not slow"]),
        ("unit tests (optional deps blocked)",
         [py, "-m", "pytest", "tests/test_loaders", "-q",
          "-p", "scripts.block_optional_deps", "-m", "not slow"]),
    ]

    results = [(label, _run(label, cmd)) for label, cmd in stages]

    print(f"\n{'=' * 70}\nPREFLIGHT SUMMARY\n{'=' * 70}")
    for label, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    all_ok = all(ok for _, ok in results)
    print("\n" + ("PREFLIGHT PASSED — safe to push." if all_ok
                  else "PREFLIGHT FAILED — fix the stage(s) above before pushing."))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
