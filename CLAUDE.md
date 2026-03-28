# CLAUDE.md — Project Standards and Conventions

This file defines the coding standards, conventions, and rules for this project.
Read this before writing or modifying any code.

---

## Revision history

Every file must have a revision history block near the top, below the docstring.
Use this exact format:

```
Revision history
────────────────
1.0   YYYY-MM-DD   Initial release: brief description.
1.1   YYYY-MM-DD   What changed.
1.2   YYYY-MM-DD   What changed.
```

Version numbering:
- `.1` / `.2` / `.3` — bug fixes, small additions, minor changes
- `2.0`, `3.0` — major new features or breaking changes

---

## Code style — natural language first

Code should read like plain English wherever possible. Prefer clarity over
cleverness. A new reader should be able to understand what a function does
without reading its implementation.

- Function and variable names are full words, not abbreviations
  - `destination_id` not `dst_id`
  - `source_label` not `src_lbl`
  - `registry_path` not `reg_pth`
- One concept per line — do not chain unrelated operations
- Short functions — if a function is doing two distinct things, split it
- Comments explain *why*, not *what* — the code says what, comments say why

---

## Logging

Use the standard `logging` module. Every file gets its own logger:

```python
import logging
logger = logging.getLogger(__name__)
```

Rules:
- **Never use a bare `except: pass`** — always log the exception before falling back
- Silent failures are bugs. If something goes wrong and you recover, log it:
  ```python
  except Exception as exc:
      logger.warning("Could not load %s: %s — using default.", path, exc)
  ```
- Use `logger.info` for normal operation milestones
- Use `logger.warning` for recoverable problems
- Use `logger.error` for failures that affect output
- Never use `print()` for operational messages — use the logger

---

## Dry run mode

Every class or function that writes, modifies, or deletes data must support
a `dry_run` flag:

```python
def __init__(self, ..., dry_run: bool = False):
    self.dry_run = dry_run
```

When `dry_run=True`:
- Log or print what *would* happen
- Do not write, modify, or delete anything
- Return the same type as the non-dry-run path (copy of input df, empty list, etc.)

---

## PII and sensitive data

- Never log raw PII values — mask or truncate before logging
- Never include real names, emails, SSNs, or credentials in sample data,
  tests, or comments
- Sample data must be fully synthetic (e.g. alice@example.com, 555-0101)
- Environment variables for credentials — never hardcode secrets

---

## Privacy flags

Any data processing function that touches personal data should note
the relevant compliance flag in its docstring:

```python
# GDPR: Art. 5(1)(b) — purpose limitation
# CCPA: §1798.100 — consumer right to know
```

This is documentation only — it does not need to be enforced in code unless
the class is specifically a governance class.

---

## Error handling

- Validate inputs at the top of functions, raise `ValueError` with a clear message
- Do not catch exceptions you cannot handle — let them propagate
- When catching broad exceptions (`Exception`), always log before falling back:
  ```python
  except Exception as exc:
      logger.warning("...", exc)
  ```
- Custom exceptions live at the bottom of the file they belong to

---

## File I/O

- Always use `encoding="utf-8"` on all file reads and writes
- Use `pathlib.Path` for all file paths — not raw strings
- JSON files: `json.dumps(..., indent=2)`
- Use thread locks (`threading.Lock`) when writing shared state files

---

## Imports

- Standard library imports first, then third-party, then local
- Optional imports wrapped in try/except with a `HAS_X` flag:
  ```python
  try:
      import some_optional_lib
      HAS_SOME_LIB = True
  except ImportError:
      HAS_SOME_LIB = False
  ```
- No unused imports — code must be pyflakes clean
- No f-strings with no placeholders (pyflakes flags these)

---

## Tests

- One test file per module: `test_<module_name>.py`
- Test class per feature area: `class TestFeatureName(unittest.TestCase)`
- Test method names describe the scenario: `test_dry_run_does_not_modify_df`
- Every public method gets at least one test
- Tests must be isolated — no shared state between tests
- Use `tempfile.mkdtemp()` for any test that writes files, clean up in `tearDown`
- No real credentials, no real network calls in tests — mock them
- All tests must pass before any commit

---

## What never goes in code or comments

- The name of any specific employer or institution
- The name of any specific IT department
- Any real credentials, tokens, or passwords
- Any real personal data

---

## pyflakes

Every file must be pyflakes clean before it is considered done:

```bash
python3 -m pyflakes yourfile.py
```

Zero warnings is the standard. No exceptions.

---

## General structure for a new class

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
