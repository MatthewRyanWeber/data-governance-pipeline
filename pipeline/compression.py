"""
Transparently decompresses source files before extraction.

Supports .gz, .bz2, .zip, .zst, .lz4, .tgz — auto-detected by extension.
Files without a compression extension pass through unchanged.

Layer 2 — imports from Layer 0 (constants).
"""

import bz2
import gzip
import io
import logging
import zipfile
from pathlib import Path

from pipeline.constants import HAS_LZ4, HAS_ZSTD

logger = logging.getLogger(__name__)


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

        if ext == ".gz":
            return gzip.open(path, "rb")

        if ext == ".bz2":
            return bz2.open(path, "rb")

        if ext == ".zip":
            zf = zipfile.ZipFile(path, "r")
            members = [m for m in zf.namelist() if not m.endswith("/")]
            if not members:
                raise ValueError(f"ZIP archive is empty: {path}")
            return zf.open(members[0])

        if ext == ".zst":
            if not HAS_ZSTD:
                raise RuntimeError("Zstandard decompression requires: pip install zstandard")
            import zstandard
            dctx = zstandard.ZstdDecompressor()
            fh = builtins_open(str(path), "rb")
            return dctx.stream_reader(fh)

        if ext == ".lz4":
            if not HAS_LZ4:
                raise RuntimeError("LZ4 decompression requires: pip install lz4")
            import lz4.frame
            return lz4.frame.open(path, "rb")

        if ext == ".tgz":
            import tarfile
            tf = tarfile.open(path, "r:gz")
            members = [m for m in tf.getmembers() if m.isfile()]
            if not members:
                raise ValueError(f"TGZ archive is empty: {path}")
            return tf.extractfile(members[0])

        return builtins_open(str(path), "rb")

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
                    members = [m for m in tf.getmembers() if m.isfile()]
                    if members:
                        return Path(members[0].name).suffix.lower()
            except Exception as exc:
                logger.warning("Could not inspect archive %s: %s — defaulting to .csv", path, exc)
            return ".csv"

        if suffix == ".zip":
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    members = [m for m in zf.namelist() if not m.endswith("/")]
                    if members:
                        return Path(members[0]).suffix.lower()
            except Exception as exc:
                logger.warning("Could not inspect archive %s: %s — defaulting to .csv", path, exc)
            return ".csv"

        inner = Path(p.stem).suffix.lower()
        return inner if inner else ".csv"


# Alias to avoid shadowing built-in open()
builtins_open = open
