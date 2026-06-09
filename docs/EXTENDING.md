# Writing a Custom Loader

Step-by-step guide for adding a new destination to the data-governance-pipeline.

---

## Overview

Every loader inherits from `BaseLoader` and implements a `load()` method.
The dispatch system resolves `db_type` strings to loader classes at runtime
via lazy imports — only the SDK for the requested destination is loaded.

```
User config (db_type="foodb")
        │
        ▼
┌──────────────────────────┐
│  _LAZY_DISPATCH table    │   pipeline/loaders/__init__.py
│  "foodb" → FooDBLoader   │
└──────────────────────────┘
        │
        ▼
┌──────────────────────────┐
│  resolve_loader("foodb") │   Lazy-imports the module, returns class
└──────────────────────────┘
        │
        ▼
┌──────────────────────────┐
│  FooDBLoader(gov, ...)   │   Inherits BaseLoader
│  .load(df, cfg, table)   │
└──────────────────────────┘
        │
        ▼
┌──────────────────────────┐
│  GovernanceLogger._event │   Audit ledger entry (chained SHA-256)
└──────────────────────────┘
```

---

## 1. Create the loader module

Create `pipeline/loaders/foodb_loader.py`:

```python
"""
FooDB loader -- writes governed DataFrames to FooDB.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-10   Initial release.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class FooDBLoader(BaseLoader):
    """Write DataFrames to FooDB tables."""

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        try:
            import foodb_sdk as _sdk
            _ = _sdk
        except ImportError as exc:
            raise RuntimeError(
                "FooDBLoader requires the foodb-sdk package.\n"
                "Install with:  pip install foodb-sdk"
            ) from exc

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a FooDB table. Returns row count written."""
        import foodb_sdk

        self._validate_config(cfg, ["host", "api_key"])

        if self._dry_run_guard(table, len(df)):
            return 0

        if df.empty:
            return 0

        client = foodb_sdk.connect(
            host=cfg["host"],
            api_key=cfg["api_key"],
        )
        client.write(table, df, mode=if_exists)

        self.gov._event(
            "LOAD", "FOODB_WRITE_COMPLETE",
            {"table": table, "rows": len(df), "if_exists": if_exists},
        )
        return len(df)
```

### Key patterns

| Pattern | Required? | Purpose |
|---------|-----------|---------|
| `super().__init__(gov, dry_run=dry_run)` | Yes | Registers governance logger and dry_run flag |
| SDK import check in `__init__` | Yes | Fail fast if the SDK is missing |
| `self._validate_config(cfg, [...])` | Yes | Raises `ConfigValidationError` with clear message |
| `self._dry_run_guard(table, len(df))` | Yes | Short-circuits when `dry_run=True` |
| `self.gov._event(...)` | Yes | Writes to the chained-hash audit ledger |
| Return row count | Yes | Used by `MetricsCollector` for throughput tracking |

### Config validation syntax

`_validate_config` supports pipe-separated alternatives for keys where
multiple options are acceptable:

```python
self._validate_config(cfg, ["connection_string|host", "db_name"])
```

This means: require at least one of `connection_string` or `host`, and
always require `db_name`.

---

## 2. Add the dependency flag

In `pipeline/constants.py`, add a `HAS_*` flag using the `_has()` helper:

```python
HAS_FOODB = _has("foodb_sdk")
```

`_has()` uses `importlib.util.find_spec` — it checks importability without
actually importing the module. Multi-module dependencies are supported:

```python
HAS_SYNAPSE = _has("pyodbc", "azure.identity", "azure.storage.blob")
```

All listed modules must be importable for the flag to return `True`.

---

## 3. Register in the dispatch table

In `pipeline/loaders/__init__.py`, add an entry to `_LAZY_DISPATCH`:

```python
_LAZY_DISPATCH: dict[str, tuple[str, str, bool, bool]] = {
    # ...
    "foodb": ("pipeline.loaders.foodb_loader", "FooDBLoader", False, False),
}
```

### Dispatch tuple fields

| Position | Field | Meaning |
|----------|-------|---------|
| 0 | `module_path` | Dotted import path to the loader module |
| 1 | `class_name` | Class name within that module |
| 2 | `needs_db_type` | `True` if `__init__` takes a `db_type` argument (only `SQLLoader`) |
| 3 | `uses_mongo` | `True` if using MongoDB's `(collection, cfg)` signature (only `MongoLoader`) |

For new loaders, both booleans are almost always `False`.

### Required keys (optional)

If your loader has mandatory config keys, add an entry to `_REQUIRED_KEYS`
so `validate_loader_config()` catches missing keys at parse-time:

```python
_REQUIRED_KEYS: list[tuple[frozenset[str], list[str]]] = [
    # ...
    (frozenset({"foodb"}), ["host", "api_key"]),
]
```

### SQL-type registration (if applicable)

If your loader targets a SQL database and accepts table names as SQL
identifiers, add the db_type to `_SQL_TYPES`:

```python
_SQL_TYPES: frozenset[str] = frozenset({
    # ...
    "foodb",
})
```

This enables automatic SQL-identifier validation on the table name.

---

## 4. Opt-in features

### Circuit breaker

Protect against cascading failures when the destination is down:

```python
def __init__(self, gov, dry_run=False):
    super().__init__(gov, dry_run=dry_run)
    self._init_circuit_breaker(
        "foodb",
        failure_threshold=5,      # open after 5 consecutive failures
        recovery_timeout=60.0,    # try half-open after 60s
        success_threshold=3,      # close after 3 successes in half-open
    )

def load(self, df, cfg, table="", ...):
    self._check_circuit()         # raises CircuitOpenError if open
    try:
        # ... write logic ...
        self._record_circuit_success()
        return len(df)
    except Exception:
        self._record_circuit_failure()
        raise
```

Circuit breaker state is visible at the `/health` API endpoint.

### Engine lifecycle (SQL loaders)

For SQLAlchemy-backed loaders, implement `_engine(cfg)` and use the
context manager:

```python
def _engine(self, cfg):
    return create_engine(f"foodb://{cfg['host']}/{cfg['db_name']}")

def load(self, df, cfg, table="", ...):
    with self._engine_scope(cfg) as engine:
        df.to_sql(table, engine, if_exists=if_exists, index=False)
```

`_engine_scope` guarantees `engine.dispose()` is called.

---

## 5. Write tests

Create `tests/test_loaders/test_foodb_loader.py`:

```python
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.exceptions import ConfigValidationError


class TestFooDBLoader(unittest.TestCase):

    def _make_loader(self, dry_run=False):
        gov = MagicMock()
        with patch.dict("sys.modules", {"foodb_sdk": MagicMock()}):
            from pipeline.loaders.foodb_loader import FooDBLoader
            return FooDBLoader(gov, dry_run=dry_run)

    def test_missing_config_raises(self):
        loader = self._make_loader()
        df = pd.DataFrame({"a": [1]})
        with self.assertRaises(ConfigValidationError):
            loader.load(df, {}, table="t")

    def test_dry_run_skips_write(self):
        loader = self._make_loader(dry_run=True)
        df = pd.DataFrame({"a": [1]})
        result = loader.load(df, {"host": "h", "api_key": "k"}, table="t")
        self.assertEqual(result, 0)

    def test_governance_event_emitted(self):
        loader = self._make_loader()
        df = pd.DataFrame({"a": [1]})
        with patch("foodb_sdk.connect") as mock_conn:
            mock_conn.return_value = MagicMock()
            loader.load(df, {"host": "h", "api_key": "k"}, table="t")
        loader.gov._event.assert_called_once()

    def test_empty_dataframe_returns_zero(self):
        loader = self._make_loader()
        df = pd.DataFrame()
        result = loader.load(df, {"host": "h", "api_key": "k"}, table="t")
        self.assertEqual(result, 0)
```

Minimum test coverage for every loader:

1. Missing config keys raise `ConfigValidationError`
2. `dry_run=True` returns 0 without writing
3. Governance event emitted on successful write
4. Empty DataFrame handled gracefully
5. SQL-backed loaders: table name validation rejects injection characters

---

## 6. Catalog and lineage integration

### Catalog registration

The catalog auto-registers datasets from governance events. No loader
changes needed — `GovernanceLogger._event()` writes to the audit ledger,
and `CatalogStore` ingests from there.

```
┌─────────────────────────────────────────────────────┐
│                   catalog.db                        │
├──────────────┬──────────────────────────────────────┤
│   datasets   │ dataset_id (PK, SHA-256[:16])       │
│              │ name, description, owner, domain     │
│              │ source_type, source_path             │
│              │ row_count, col_count, quality_score   │
│              │ tags (JSON), last_updated, created_at │
├──────────────┼──────────────────────────────────────┤
│   columns    │ column_id (PK), dataset_id (FK)      │
│              │ name, dtype, nullable, pii            │
│              │ description, glossary_term, tags      │
├──────────────┼──────────────────────────────────────┤
│ dataset_tags │ dataset_id (FK) + tag (compound PK)  │
├──────────────┼──────────────────────────────────────┤
│ catalog_fts  │ FTS5 full-text index over datasets   │
└──────────────┴──────────────────────────────────────┘
```

### OpenLineage events

The lineage emitter produces OpenLineage-compatible events automatically
when the pipeline runs. Events are persisted to a JSONL file and
optionally POSTed to an OpenLineage-compatible server.

```
┌─────────────────────────────────────────────────┐
│              OpenLineage Event                  │
├─────────────────────────────────────────────────┤
│ eventType: START | COMPLETE | FAIL              │
│ job:                                            │
│   namespace: "data-governance-pipeline"         │
│   name: "extract-transform-load"                │
│ run:                                            │
│   runId: UUID                                   │
│ inputs:                                         │
│   - namespace / name / facets                   │
│ outputs:                                        │
│   - namespace / name / facets                   │
│     ├── schema: field names + types             │
│     ├── dataQuality: row_count, quality_score   │
│     └── custom: pipeline-specific metadata      │
└─────────────────────────────────────────────────┘
```

No changes are required in your loader for lineage — the pipeline
orchestrator handles event emission at the extract/transform/load
boundaries.

---

## Checklist

Before submitting a new loader:

- [ ] Module at `pipeline/loaders/<name>_loader.py`
- [ ] Inherits `BaseLoader`, calls `super().__init__(gov, dry_run=dry_run)`
- [ ] SDK import check in `__init__` with clear error message
- [ ] `_validate_config()` called with required keys
- [ ] `_dry_run_guard()` called before any writes
- [ ] `gov._event()` called on successful write
- [ ] Returns integer row count
- [ ] `HAS_*` flag in `pipeline/constants.py`
- [ ] Entry in `_LAZY_DISPATCH` dict
- [ ] Entry in `_REQUIRED_KEYS` (if loader has mandatory config keys)
- [ ] Entry in `_SQL_TYPES` (if SQL-backed)
- [ ] Tests: config validation, dry_run, governance event, empty df
- [ ] Revision history block at top of file
- [ ] pyflakes clean
