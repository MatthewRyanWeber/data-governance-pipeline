#!/usr/bin/env python
"""
pytest plugin: make optional third-party deps un-importable for the duration
of a test run, so the suite executes the SAME code path CI does when those
deps are absent (the loader tests stub them via `_ensure_mock_module`).

This catches the class of bug that only fails where the dependency is missing
— e.g. `from deltalake.exceptions import TableNotFoundError` running on a path
that the mock stub can't satisfy. Locally those deps are usually installed, so
the failure never surfaces until CI; loading this plugin reproduces CI's
"not installed" condition on the developer's box.

Enable with:  pytest -p scripts.block_optional_deps ...
Only the exact dotted prefixes below are blocked (not whole roots like
`google`/`snowflake`), so unrelated sub-packages keep importing.
"""

import sys
from importlib.abc import MetaPathFinder

# Mirrors the optional deps the loader tests stub via _ensure_mock_module.
_BLOCKED_PREFIXES = (
    "deltalake",
    "pyiceberg",
    "adlfs",
    "kafka",
    "lancedb",
    "google.cloud.bigquery",
    "snowflake.sqlalchemy",
    "snowflake.connector",
)


def _is_blocked(name: str) -> bool:
    return any(name == p or name.startswith(p + ".") for p in _BLOCKED_PREFIXES)


class _OptionalDepBlocker(MetaPathFinder):
    """Raise ModuleNotFoundError for blocked optional deps at import time."""

    def find_spec(self, name, path, target=None):
        if _is_blocked(name):
            raise ModuleNotFoundError(
                f"optional dependency '{name}' is blocked by preflight so the "
                f"deps-absent code path (mirroring CI) is exercised"
            )
        return None  # defer to the normal finders for everything else


def pytest_configure(config):
    # Drop anything already imported so the loader code re-imports through the
    # blocker, then install the finder at the front of the meta path.
    for mod in [m for m in sys.modules if _is_blocked(m)]:
        del sys.modules[mod]
    sys.meta_path.insert(0, _OptionalDepBlocker())
