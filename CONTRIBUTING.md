# Contributing to Data Governance Pipeline

Thank you for your interest in contributing. This document covers how to get
set up, the standards we follow, and how to submit a pull request.

---

## Ways to contribute

- **Bug reports** — open an issue describing what happened, what you expected,
  and how to reproduce it
- **Bug fixes** — pick an open issue, fix it, and open a pull request
- **New destination loaders** — add support for a new data destination
  following the existing loader pattern
- **New governance features** — improvements to GDPR, CCPA, HIPAA, or SOC 2
  coverage
- **Documentation** — fix typos, clarify examples, improve docstrings
- **Tests** — increase coverage, add edge case tests, fix flaky tests

---

## Getting set up

**1. Fork and clone**

```bash
git clone https://github.com/YOUR_USERNAME/data-governance-pipeline.git
cd data-governance-pipeline
```

**2. Install dependencies**

```bash
pip install -e ".[dev]"
```

**3. Install optional dependencies for the area you're working on**

```bash
pip install -e ".[cloud]"               # Snowflake, BigQuery, Databricks, etc.
pip install -e ".[streaming]"           # Kafka, Kinesis, Pub/Sub
pip install -e ".[healthcare]"          # Epic Clarity + OMOP
pip install -e ".[all]"                 # Everything
```

**4. Run the test suite to confirm everything passes**

```bash
python -m pytest tests/ -q
python -m pyflakes pipeline/ tests/
```

All 1,350 tests should pass before you make any changes.

**Live integration tests (optional, needs Docker)** spin up real PostgreSQL,
MySQL, and MongoDB containers via testcontainers. They skip automatically when
no Docker engine is running, so they never block the unit suite:

```bash
pip install "testcontainers[postgres,mysql,mongodb]"
python -m pytest tests/test_integration_db.py -v
```

---

## Code standards

This project follows the conventions in `CLAUDE.md`. The short version:

**Style**
- Full descriptive names — `destination_id` not `dst_id`
- Comments explain *why*, not *what*
- Natural language first — code should read like plain English

**Every file must be pyflakes clean**

```bash
python -m pyflakes your_file.py
```

Zero warnings is the standard. No exceptions.

**No bare `except: pass`**

Always log before falling back:

```python
# Wrong
except Exception:
    pass

# Right
except Exception as exc:
    logger.warning("Could not load %s: %s — using default.", path, exc)
```

**Dry run support**

Any class or function that writes, modifies, or deletes data must support
a `dry_run=False` parameter. When `dry_run=True`, log or print what *would*
happen but do not write, modify, or delete anything.

**Revision history**

Every file gets a revision history block updated with your change:

```
Revision history
────────────────
1.0   2024-01-01   Initial release.
1.1   2024-06-15   Added X feature.
```

---

## Adding a new destination loader

The project has 37 destination loaders. Adding a new one is the most common
contribution. Follow this pattern:

**1. Create a new loader module in `pipeline/loaders/`**

```python
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

class YourLoader(BaseLoader):
    """One-sentence summary."""

    def __init__(self, gov, dry_run=False):
        super().__init__(gov, dry_run=dry_run)
        try:
            import your_package
        except ImportError:
            raise RuntimeError(
                "YourLoader requires your-package.\n"
                "Install with: pip install your-package"
            )

    def load(self, df, cfg, table, if_exists="append", natural_keys=None):
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return
        # ... your load logic ...
        self.gov.load_complete(len(df), table)
```

**2. Register in `pipeline/loaders/__init__.py`**

Add the dispatch entry in `_LOADER_DISPATCH`:

```python
"yourdest": (YourLoader, False, False),
```

**3. Add tests to `tests/test_loaders/test_loader_dispatch.py`**

At minimum:
- `test_yourdest_in_dispatch` — verifies the dispatch entry
- `test_raises_without_package` — verifies graceful degradation
- `test_load_calls_write` — verifies the load path with a mock

**4. Add the package to `pyproject.toml` optional dependencies**

---

## Adding a new governance feature

New governance classes go in the most appropriate extension file:

| File | For |
|---|---|
| `governance_extensions.py` | GDPR / CCPA features |
| `epic_extensions.py` | HIPAA / Epic EHR / OMOP features |
| `compliance_extensions.py` | SOC 2 / continuous monitoring / vendor risk |
| `grafana_extensions.py` | Observability and metrics |

Follow the same class structure — constructor takes `gov` and `dry_run`,
every write operation is logged to `gov._event()`, and HTML/JSON reports
use `pathlib.Path` with `encoding="utf-8"`.

---

## Pull request checklist

Before opening a PR, confirm:

- [ ] All existing tests still pass (`python -m pytest tests/ -q`)
- [ ] New tests added for the new functionality
- [ ] `python -m pyflakes your_changed_files.py` returns zero warnings
- [ ] Revision history updated in any modified files
- [ ] `pyproject.toml` updated if a new package is introduced
- [ ] `CHANGELOG.md` updated with a brief description of the change

---

## Reporting a bug

Open an issue and include:

1. What you were trying to do
2. What happened (paste the full error if there is one)
3. What you expected to happen
4. Your Python version (`python --version`) and OS
5. Which packages are installed (`pip list`)

---

## Questions

Open an issue with the `question` label and we'll respond as quickly as
possible.
