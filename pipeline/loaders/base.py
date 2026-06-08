"""
Shared helper functions and base class for loader modules.

Provides SQL-injection-safe identifier validation, float-vector validation,
DataFrame column name validation, and a BaseLoader class with dry_run support
and config validation used by all loader subclasses.

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
1.1   2026-06-08   Added BaseLoader, validate_column_names.
"""

import math
import re
import logging
from typing import TYPE_CHECKING

from pipeline.exceptions import ConfigValidationError

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

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


def validate_column_names(df: "pd.DataFrame", label: str = "DataFrame") -> None:
    """
    Validate that DataFrame column names are safe for SQL DDL construction.

    Rejects columns containing SQL-injection characters (semicolons, quotes,
    comment markers, etc.).  Raises ValueError on the first invalid column.
    """
    _bad_chars = re.compile(r"[;'\"\-\-/\\*]")
    for col in df.columns:
        col_str = str(col)
        if _bad_chars.search(col_str):
            raise ValueError(
                f"{label} column name {col_str!r} contains disallowed "
                "characters for SQL DDL construction."
            )


class BaseLoader:
    """
    Abstract base class for all pipeline loaders.

    Provides dry_run support and config validation so subclasses only
    need to implement their specific load/connect logic.

    Subclasses call super().__init__(gov, dry_run) and use:
        self._validate_config(cfg, ["host", "user", "password"])
        if self._dry_run_guard(table, len(df)): return
    """

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        self.gov = gov
        self.dry_run = dry_run

    def _validate_config(self, cfg: dict, required_keys: list[str]) -> None:
        """
        Validate that all required keys are present and non-empty in cfg.

        Supports 'key1|key2' syntax: at least one alternative must be present.
        Raises ConfigValidationError on missing keys.
        """
        missing = []
        for req in required_keys:
            if "|" in req:
                alternatives = req.split("|")
                if not any(cfg.get(alt) for alt in alternatives):
                    missing.append(f"one of ({', '.join(alternatives)})")
            else:
                if not cfg.get(req):
                    missing.append(req)

        if missing:
            db_type = getattr(self, "_db_type", self.__class__.__name__)
            raise ConfigValidationError(
                db_type=str(db_type),
                missing_keys=missing,
            )

    def _dry_run_guard(self, table: str, row_count: int) -> bool:
        """
        Log what would happen and return True if dry_run is active.

        Callers should short-circuit: ``if self._dry_run_guard(...): return``
        """
        if not self.dry_run:
            return False
        logger.info(
            "[DRY RUN] Would write %s rows to '%s' via %s — skipping.",
            f"{row_count:,}", table, self.__class__.__name__,
        )
        return True
