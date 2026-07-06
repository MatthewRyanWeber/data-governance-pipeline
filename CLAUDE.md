# CLAUDE.md — Project Standards and Conventions

Read this before writing or modifying any code.

## Project context
- Package: `data-governance-pipeline` (source in `pipeline/`), Python >= 3.10
- Governance/compliance ETL: extract → standardise → enrich → load, with ledger, lineage, catalog, DSAR/consent/breach handling, ML governance, monitoring
- Streaming per-record with checkpointing (`checkpoint.py`, `crash_recovery.py`) — never batch, never lose resume position
- Docker: `docker-compose.yml` (run), `docker-compose.test.yml` (tests)
- All CI must be green before a change is considered done

---

## Revision history

Every file gets a revision history block near the top, below the docstring, in this exact format:

```
Revision history
────────────────
1.0   YYYY-MM-DD   Initial release: brief description.
1.1   YYYY-MM-DD   What changed.
```

Version numbering: `.1`/`.2`/`.3` for bug fixes and minor changes; `2.0`, `3.0` for major or breaking changes.

---

## Code style — natural language first

Code should read like plain English. Prefer clarity over cleverness — a new reader should understand what a function does without reading its implementation.

- Full-word names, no abbreviations: `destination_id` not `dst_id`, `source_label` not `src_lbl`
- One concept per line — don't chain unrelated operations
- Short functions — doing two distinct things means split it
- Comments explain *why*, never *what*

---

## Logging

Every file: `logger = logging.getLogger(__name__)`

- **Never bare `except: pass`** — always log the exception before falling back:
  ```python
  except Exception as exc:
      logger.warning("Could not load %s: %s — using default.", path, exc)
  ```
- Silent failures are bugs — if you recover, log it
- `info` = normal milestones, `warning` = recoverable problems, `error` = failures affecting output
- Never `print()` for operational messages

---

## Dry run mode

Every class or function that writes, modifies, or deletes data takes `dry_run: bool = False`.

When `dry_run=True`: log what *would* happen, touch nothing, and return the same type as the real path (copy of input df, empty list, etc.).

---

## PII and sensitive data

- Never log raw PII — mask or truncate first
- No real names, emails, SSNs, or credentials in sample data, tests, or comments — fully synthetic only (alice@example.com, 555-0101)
- Credentials come from environment variables — never hardcoded

---

## Privacy flags

Data-processing functions that touch personal data note the relevant compliance flag in their docstring:

```python
# GDPR: Art. 5(1)(b) — purpose limitation
# CCPA: §1798.100 — consumer right to know
```

Documentation only — enforced in code only inside governance classes.

---

## Error handling

- Validate inputs at the top of functions; raise `ValueError` with a clear message
- Don't catch exceptions you can't handle — let them propagate
- Broad catches (`Exception`) always log before falling back
- Custom exceptions live at the bottom of the file they belong to

---

## File I/O

- `encoding="utf-8"` on every read and write
- `pathlib.Path` for all paths — no raw strings
- JSON: `json.dumps(..., indent=2)`
- `threading.Lock` when writing shared state files

---

## Imports

- Order: standard library, third-party, local
- Optional imports wrapped with a `HAS_X` flag:
  ```python
  try:
      import some_optional_lib
      HAS_SOME_LIB = True
  except ImportError:
      HAS_SOME_LIB = False
  ```
- pyflakes clean: no unused imports, no placeholder-free f-strings

---

## Tests

- One test file per module: `test_<module_name>.py`; one test class per feature area
- Method names describe the scenario: `test_dry_run_does_not_modify_df`
- Every public method gets at least one test
- Isolated tests — no shared state; `tempfile.mkdtemp()` for file-writing tests, clean up in `tearDown`
- No real credentials or network calls — mock them
- Never skip a test for a missing dependency — install it instead
- All tests must pass before any commit

---

## What never goes in code or comments

- The name of any specific employer, institution, or IT department
- Real credentials, tokens, or passwords
- Real personal data

---

## pyflakes

Every file must be pyflakes clean before it is done — zero warnings, no exceptions:

```bash
python3 -m pyflakes yourfile.py
```

---

## Structure for a new class

```python
class MyClass:
    """
    One-sentence summary.

    Longer explanation if needed. What problem does this solve?
    What are the key design decisions?

    Quick-start
    ───────────
        from mymodule import MyClass
        obj = MyClass(...)
        obj.do_thing(...)
    """

    def __init__(self, gov, dry_run: bool = False) -> None:
        self.gov     = gov
        self.dry_run = dry_run

    def do_thing(self, ...) -> ...:
        """What this does, what it returns, what it raises."""
        ...
```
