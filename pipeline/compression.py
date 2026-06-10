"""
Transparently decompresses source files before extraction.

Supports .gz, .bz2, .zip, .zst, .lz4, .tgz — auto-detected by extension.
Files without a compression extension pass through unchanged.

Layer 2 — imports from Layer 0 (constants).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
1.1   2026-06-08   Added archive path traversal validation, zip bomb protection,
                   ZipFile resource leak fix, builtins_open ordering fix.
"""

import bz2
import gzip
import io
import logging
import os
import re
import zipfile
from pathlib import Path

from pipeline.constants import HAS_LZ4, HAS_ZSTD, MAX_DECOMPRESSED_SIZE

logger = logging.getLogger(__name__)

# Alias to avoid shadowing built-in open() in class methods
_builtin_open = open


_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


def _validate_archive_member(name: str) -> None:
    """Reject archive members with path traversal or absolute paths."""
    normalized = os.path.normpath(name)
    if (normalized.startswith("..")
            or os.path.isabs(normalized)
            or name.startswith("/")
            or name.startswith("\\")
            or _WIN_DRIVE_RE.match(name)):
        raise ValueError(
            f"Archive member '{name}' contains a path traversal or "
            "absolute path — refusing to extract."
        )


class SizeLimitedReader(io.RawIOBase):
    """
    Wraps a readable stream and raises ValueError when the cumulative
    bytes read exceed max_bytes (zip bomb protection).
    """

    def __init__(self, stream: io.IOBase, max_bytes: int, owner=None) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._bytes_read = 0
        self._owner = owner

    def readable(self):
        return True

    def readinto(self, b):
        data = self._stream.read(len(b))
        if not data:
            return 0
        n = len(data)
        self._bytes_read += n
        if self._bytes_read > self._max_bytes:
            raise ValueError(
                f"Decompression size limit exceeded: {self._max_bytes:,} bytes. "
                "Possible zip bomb detected."
            )
        b[:n] = data
        return n

    def read(self, size=-1):
        data = self._stream.read(size)
        if data:
            self._bytes_read += len(data)
            if self._bytes_read > self._max_bytes:
                raise ValueError(
                    f"Decompression size limit exceeded: {self._max_bytes:,} bytes. "
                    "Possible zip bomb detected."
                )
        return data

    def close(self):
        self._stream.close()
        if self._owner is not None:
            try:
                self._owner.close()
            except Exception as exc:
                logger.warning("Failed to close archive owner: %s", exc)
        super().close()


class CompressionHandler:
    """
    Open compressed files as transparent byte streams.

    Quick-start
    -----------
        from pipeline.compression import CompressionHandler
        handler = CompressionHandler()
        with handler.open("data.csv.gz") as f:
            df = pd.read_csv(f)
    """

    SUPPORTED = {".gz", ".bz2", ".zip", ".zst", ".lz4", ".tgz"}

    def is_compressed(self, path: str | Path) -> bool:
        return Path(path).suffix.lower() in self.SUPPORTED

    def open(self, path: str | Path) -> io.IOBase:
        """Open a potentially-compressed file and return a readable byte stream."""
        ext = Path(path).suffix.lower()
        limit = MAX_DECOMPRESSED_SIZE

        if ext == ".gz":
            stream: io.IOBase = gzip.open(path, "rb")
            return SizeLimitedReader(stream, limit)

        if ext == ".bz2":
            stream = bz2.open(path, "rb")
            return SizeLimitedReader(stream, limit)

        if ext == ".zip":
            zf = zipfile.ZipFile(path, "r")
            try:
                members = [m for m in zf.namelist() if not m.endswith("/")]
                if not members:
                    raise ValueError(f"ZIP archive is empty: {path}")
                _validate_archive_member(members[0])
                inner = zf.open(members[0])
                return SizeLimitedReader(inner, limit, owner=zf)  # type: ignore[arg-type]
            except Exception:
                zf.close()
                raise

        if ext == ".zst":
            if not HAS_ZSTD:
                raise RuntimeError("Zstandard decompression requires: pip install zstandard")
            import zstandard
            dctx = zstandard.ZstdDecompressor()
            fh = _builtin_open(str(path), "rb")
            try:
                stream = dctx.stream_reader(fh)  # type: ignore[assignment]
                return SizeLimitedReader(stream, limit, owner=fh)
            except Exception:
                fh.close()
                raise

        if ext == ".lz4":
            if not HAS_LZ4:
                raise RuntimeError("LZ4 decompression requires: pip install lz4")
            import lz4.frame
            stream = lz4.frame.open(path, "rb")
            return SizeLimitedReader(stream, limit)

        if ext == ".tgz":
            import tarfile
            tf = tarfile.open(path, "r:gz")
            try:
                tar_members = [m for m in tf.getmembers() if m.isfile()]
                if not tar_members:
                    raise ValueError(f"TGZ archive is empty: {path}")
                _validate_archive_member(tar_members[0].name)
                inner_stream = tf.extractfile(tar_members[0])
                if inner_stream is None:
                    raise ValueError(f"Could not extract member from TGZ: {path}")
                return SizeLimitedReader(inner_stream, limit, owner=tf)  # type: ignore[arg-type]
            except Exception:
                tf.close()
                raise

        return _builtin_open(str(path), "rb")

    def inner_extension(self, path: str | Path) -> str:
        """
        Return the extension of the actual data file inside a compressed archive.

        "data.csv.gz" -> ".csv", "data.json" -> ".json" (passthrough).
        """
        p = Path(path)
        suffix = p.suffix.lower()
        if suffix not in self.SUPPORTED:
            return suffix

        if suffix == ".tgz":
            import tarfile
            try:
                with tarfile.open(path, "r:gz") as tf:
                    tar_members = [m for m in tf.getmembers() if m.isfile()]
                    if tar_members:
                        _validate_archive_member(tar_members[0].name)
                        return Path(tar_members[0].name).suffix.lower()
            except Exception as exc:
                logger.warning("Could not inspect archive %s: %s — defaulting to .csv", path, exc)
            return ".csv"

        if suffix == ".zip":
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    members = [m for m in zf.namelist() if not m.endswith("/")]
                    if members:
                        _validate_archive_member(members[0])
                        return Path(members[0]).suffix.lower()
            except Exception as exc:
                logger.warning("Could not inspect archive %s: %s — defaulting to .csv", path, exc)
            return ".csv"

        inner = Path(p.stem).suffix.lower()
        return inner if inner else ".csv"
