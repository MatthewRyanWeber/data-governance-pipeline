"""
Shared helper functions for loader modules.

Provides SQL-injection-safe identifier validation and float-vector validation
used by multiple loaders across the package.

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
"""

import math
import re
import logging

logger = logging.getLogger(__name__)


def validate_sql_identifier(name: str, label: str = "identifier") -> str:
    """
    Validate a SQL identifier (table name, column name, index name) to prevent
    SQL injection.  Only allows alphanumeric characters, underscores, and dots
    (for schema.table notation).

    Raises ValueError if the name contains any disallowed characters.
    Returns the name unchanged if valid.
    """
    if not name:
        raise ValueError(f"SQL {label} must not be empty.")
    if not re.fullmatch(r"[A-Za-z_][\w.]*", name):
        raise ValueError(
            f"SQL {label} '{name}' contains disallowed characters. "
            "Only letters, digits, underscores, and dots are allowed."
        )
    return name


def validate_float_vector(vec: list, label: str = "query_vector") -> list:
    """
    Validate that every element of a vector is a finite float.
    Prevents SQL injection via NaN, inf, or non-numeric values in
    concatenated vector literals.

    Raises ValueError on the first invalid element.
    Returns a list of Python floats.
    """
    result = []
    for i, v in enumerate(vec):
        try:
            f = float(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{label}[{i}] is not a valid float: {v!r}"
            ) from exc
        if not math.isfinite(f):
            raise ValueError(
                f"{label}[{i}] is not finite: {f!r}. "
                "NaN and inf are not valid vector components."
            )
        result.append(f)
    return result
