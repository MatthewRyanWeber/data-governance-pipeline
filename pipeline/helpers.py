"""
Pure utility functions used across the pipeline.

Layer 0 — imports only from constants (same layer).
"""

import hashlib
import logging
from pathlib import Path
from typing import Any

from pipeline.constants import PII_FIELD_PATTERNS, SENSITIVE_CATEGORIES

logger = logging.getLogger(__name__)


def file_hash(path: str | Path) -> str:
    """SHA-256 hex digest of a file in 64 KB chunks (tamper-evident lineage)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_pii(columns: list[str]) -> list[dict]:
    """
    Scan column names for PII using pre-compiled regex patterns.
    Returns one finding dict per matching column.

    Uses compiled patterns from constants — no per-call recompilation.
    """
    findings = []
    for col in columns:
        col_lower = col.lower()
        for pattern in PII_FIELD_PATTERNS:
            if pattern.search(col_lower):
                special = any(sp.search(col_lower) for sp in SENSITIVE_CATEGORIES)
                findings.append({
                    "field": col,
                    "matched_pattern": pattern.pattern,
                    "special_category": special,
                    "gdpr_reference": "Article 9" if special else "Article 4(1)",
                    "ccpa_reference": "§1798.140(o)",
                })
                break
    return findings


def flatten_record(
    record: Any, parent_key: str = "", separator: str = "__"
) -> dict:
    """
    Recursively flatten nested dicts/lists.
    {"a": {"b": 1}} → {"a__b": 1}
    {"scores": [9, 8]} → {"scores__0": 9, "scores__1": 8}
    """
    items: list[tuple[str, Any]] = []
    if isinstance(record, dict):
        for key, value in record.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else str(key)
            if isinstance(value, (dict, list)):
                items.extend(flatten_record(value, new_key, separator).items())
            else:
                items.append((new_key, value))
    elif isinstance(record, list):
        for index, value in enumerate(record):
            new_key = f"{parent_key}{separator}{index}" if parent_key else str(index)
            if isinstance(value, (dict, list)):
                items.extend(flatten_record(value, new_key, separator).items())
            else:
                items.append((new_key, value))
    else:
        return {parent_key: record}
    return dict(items)


def mask_value(value: Any) -> str | None:
    """Pseudonymise a value with SHA-256 hash prefix (GDPR Art. 25)."""
    if value is None:
        return None
    return "MASKED_" + hashlib.sha256(str(value).encode()).hexdigest()[:12]


def prompt(message: str, default: str = "") -> str:
    """Interactive prompt with optional default shown in brackets."""
    display = f"{message} [{default}]: " if default else f"{message}: "
    response = input(display).strip()
    return response if response else default


def yes_no(message: str, default: bool = True) -> bool:
    """Yes/No prompt. Returns bool; accepts default on empty input."""
    suffix = "[Y/n]" if default else "[y/N]"
    response = input(f"{message} {suffix}: ").strip().lower()
    return default if not response else response in ("y", "yes")


def not_na(value: Any) -> bool:
    """Check if a value is not None/NaN/empty — safe for non-pandas contexts."""
    if value is None:
        return False
    try:
        import pandas as pd
        if pd.isna(value):
            return False
    except (ImportError, TypeError, ValueError):
        pass
    return bool(str(value).strip())
