"""
Pure utility functions used across the pipeline.

Layer 0 — imports only from constants (same layer).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-11   read_jsonl_tail: rejoin lines split across chunk boundaries;
                   flatten_record: optional max_depth; load_file_cached for
                   (path, mtime)-keyed lookup/rules caching.
1.2   2026-06-12   interactive_prompt/confirm_yes_no moved to
                   pipeline.prompts (re-exported here until v5.0).
"""

import hashlib
import json
import logging
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

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
    record: Any,
    parent_key: str = "",
    separator: str = "__",
    max_depth: int | None = None,
) -> dict:
    """
    Recursively flatten nested dicts/lists.
    {"a": {"b": 1}} → {"a__b": 1}
    {"scores": [9, 8]} → {"scores__0": 9, "scores__1": 8}

    When max_depth is given, nesting below that depth is kept as-is so
    callers can cap how far flattening expands the schema.
    """
    # A depth of 1 means "flatten this level, keep anything deeper intact".
    can_recurse = max_depth is None or max_depth > 1
    child_depth = None if max_depth is None else max_depth - 1

    items: list[tuple[str, Any]] = []
    if isinstance(record, dict):
        for key, value in record.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else str(key)
            if isinstance(value, (dict, list)) and can_recurse:
                items.extend(
                    flatten_record(value, new_key, separator, child_depth).items()
                )
            else:
                items.append((new_key, value))
    elif isinstance(record, list):
        for index, value in enumerate(record):
            new_key = f"{parent_key}{separator}{index}" if parent_key else str(index)
            if isinstance(value, (dict, list)) and can_recurse:
                items.extend(
                    flatten_record(value, new_key, separator, child_depth).items()
                )
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


# Prompting moved to pipeline.prompts so this module stays free of user
# I/O; re-exported here until v5.0 for backward compatibility.
from pipeline.prompts import confirm_yes_no, interactive_prompt

__all__ = [
    "file_hash", "detect_pii", "flatten_record", "mask_value",
    "atomic_json_write", "read_jsonl_tail", "load_file_cached",
    "is_present",
    # Re-exported from pipeline.prompts until v5.0
    "interactive_prompt", "confirm_yes_no",
]


def atomic_json_write(path: Path, data: str) -> None:
    """Write JSON string to *path* atomically via temp-file-then-rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with open(tmp_fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        Path(tmp_path).replace(path)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise


def read_jsonl_tail(
    path: Path,
    count: int = 30,
    filter_fn: Callable[[dict], bool] | None = None,
) -> list[dict]:
    """Read the last *count* records from a JSONL file, newest first."""
    if not path.exists():
        return []
    # Read from end of file to avoid loading entire file into memory.
    # Work in bytes and decode per line so a multi-byte character split
    # across a chunk boundary cannot be mangled by early decoding.
    raw_lines: list[bytes] = []
    buffer_size = 8192
    partial_first_line = b""
    with open(path, "rb") as f:
        f.seek(0, 2)
        remaining = f.tell()
        while remaining > 0 and len(raw_lines) < count * 3:
            read_size = min(buffer_size, remaining)
            remaining -= read_size
            f.seek(remaining)
            chunk = f.read(read_size) + partial_first_line
            chunk_lines = chunk.splitlines()
            if remaining > 0 and chunk_lines:
                # The first element may start mid-line; hold it back and
                # rejoin it once the preceding chunk has been read, so the
                # record straddling the boundary stays intact.
                partial_first_line = chunk_lines.pop(0)
            else:
                partial_first_line = b""
            raw_lines = chunk_lines + raw_lines
    if partial_first_line:
        # Loop ended on the record budget with bytes still unread — this
        # held-back line may be incomplete, so it is only safe to keep it
        # when the whole file was consumed (handled above); discard here.
        logger.debug(
            "Discarding possibly-partial boundary line while tailing %s",
            path.name,
        )
    records: list[dict] = []
    for raw_line in reversed(raw_lines):
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Corrupt JSONL line in %s: %s", path.name, line[:100])
            continue
        if filter_fn and not filter_fn(record):
            continue
        records.append(record)
        if len(records) >= count:
            break
    return records


_FILE_CACHE: dict[str, tuple[float, Any]] = {}
_FILE_CACHE_LOCK = threading.Lock()


def load_file_cached(path: str | Path, loader: Callable[[str], Any]) -> Any:
    """
    Return loader(path), reusing the previous result while the file is unchanged.

    Keyed by (absolute path, mtime) so chunked pipeline runs parse a shared
    lookup/reference/rules file once instead of once per chunk. Callers must
    treat the returned object as read-only — it is shared across calls.
    """
    resolved_path = Path(path).resolve()
    modified_time = resolved_path.stat().st_mtime
    cache_key = str(resolved_path)
    with _FILE_CACHE_LOCK:
        cached = _FILE_CACHE.get(cache_key)
        if cached is not None and cached[0] == modified_time:
            return cached[1]
    data = loader(str(path))
    with _FILE_CACHE_LOCK:
        _FILE_CACHE[cache_key] = (modified_time, data)
    return data


def is_present(value: Any) -> bool:
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
