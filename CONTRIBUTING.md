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

**2. Install core dependencies**

```bash
pip install -r requirements.txt
```

**3. Install optional dependencies for the area you're working on**

```bash
pip install -r requirements_v2.txt        # all cloud/enterprise drivers
pip install ".[dev]"                       # pyflakes, black, ruff, pytest
pip install kafka-python lancedb pyarrow  # if working on streaming/vector
pip install prometheus_client             # if working on Grafana integration
```

**4. Run the test suite to confirm everything passes**

```bash
python test_loader_dispatch.py
python test_governance_extensions.py
python test_epic_extensions.py
python test_compliance_extensions.py
python test_grafana_extensions.py
```

All 346 tests should pass before you make any changes.

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

The project has 20 destination loaders. Adding a new one is the most common
contribution. Follow this pattern:

**1. Add an optional import near the top of `pipeline_v3.py`**

```python
try:
    import your_package as _your_pkg  # noqa: F401
    HAS_YOUR_DEST = True
except ImportError:
    HAS_YOUR_DEST = False
```

**2. Add the loader class before `_LOADER_DISPATCH`**

```python
class YourLoader:
    """
    One-sentence summary.

    Required cfg keys
    -----------------
    host     : str
    ...

    Requirements
    ------------
        pip install your-package
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_YOUR_DEST:
            raise RuntimeError(
                "YourLoader requires your-package.\n"
                "Install with: pip install your-package"
            )

    def load(self, df, cfg, table, if_exists="append", natural_keys=None):
        ...
        self.gov._event("LOAD", "YOUR_DEST_WRITE_COMPLETE", {...})
        return rows_written
```

**3. Register in `_LOADER_DISPATCH`**

```python
"yourdest": (YourLoader, False, False),
```

**4. Add tests to `test_loader_dispatch.py`**

At minimum:
- `test_yourdest_in_dispatch` — verifies the dispatch entry
- `test_raises_without_package` — verifies graceful degradation
- `test_load_calls_write` — verifies the load path with a mock

**5. Update `requirements_v2.txt` with the new package**

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

- [ ] All 346 existing tests still pass
- [ ] New tests added for the new functionality
- [ ] `python -m pyflakes your_changed_files.py` returns zero warnings
- [ ] Revision history updated in any modified files
- [ ] `requirements_v2.txt` updated if a new package is introduced
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
