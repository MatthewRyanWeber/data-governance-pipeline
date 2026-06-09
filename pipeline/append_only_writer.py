"""
Append-only file writer that blocks seek and truncate operations.

Wraps a file opened in append mode with a proxy that raises
PermissionError on any attempt to reposition or truncate. Optional
integrity verification detects external truncation between writes.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class AppendOnlyWriter:
    """
    Write-once file handle that prevents seek, truncate, and overwrite.

    Quick-start
    -----------
        with AppendOnlyWriter("/data/audit.jsonl") as w:
            w.write('{"event": "START"}\\n')
            w.write('{"event": "END"}\\n')
    """

    def __init__(
        self,
        path: str | Path,
        verify_integrity: bool = False,
    ) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._verify = verify_integrity
        self._file = None
        self._expected_size: int | None = None

    def open(self) -> "AppendOnlyWriter":
        self._file = open(self._path, "a", encoding="utf-8")
        if self._verify:
            self._expected_size = self._path.stat().st_size
        return self

    def write(self, data: str) -> int:
        if self._file is None:
            self.open()
        if self._verify:
            self._check_integrity()
        n = self._file.write(data)
        self._file.flush()
        os.fsync(self._file.fileno())
        if self._verify:
            self._expected_size = self._path.stat().st_size
        return n

    def seek(self, *args, **kwargs):
        raise PermissionError(
            "AppendOnlyWriter: seek is not permitted on audit log files."
        )

    def truncate(self, *args, **kwargs):
        raise PermissionError(
            "AppendOnlyWriter: truncate is not permitted on audit log files."
        )

    def close(self) -> None:
        if self._file is not None:
            self._file.flush()
            self._file.close()
            self._file = None

    def _check_integrity(self) -> None:
        if self._expected_size is None:
            return
        actual = self._path.stat().st_size
        if actual < self._expected_size:
            raise IOError(
                f"AppendOnlyWriter: file was externally truncated "
                f"(expected >= {self._expected_size} bytes, got {actual})."
            )

    def __enter__(self) -> "AppendOnlyWriter":
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
