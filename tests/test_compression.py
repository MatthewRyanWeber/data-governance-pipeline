"""
Round-trip tests for CompressionHandler.open() across every supported format.

Real compressed files are created on disk (gzip, bz2, zip, zstd, lz4, tgz) and
read back through the handler, exercising each branch of open() plus
inner_extension() and is_compressed().  Security validators (path traversal,
zip bombs) live in test_compression_security.py and are not duplicated here.

Revision history
────────────────
1.0   2026-06-09   Initial release: per-format open() / inner_extension coverage.
"""

import bz2
import gzip
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from pipeline.compression import CompressionHandler
from pipeline.constants import HAS_LZ4, HAS_ZSTD

_PAYLOAD = b"id,name\n1,alice\n2,bob\n"


class TestCompressionHandler(unittest.TestCase):
    def setUp(self):
        self.h = CompressionHandler()
        self.tmp = Path(tempfile.mkdtemp())

    def _read(self, path):
        stream = self.h.open(path)
        try:
            return stream.read()
        finally:
            stream.close()

    def test_is_compressed(self):
        self.assertTrue(self.h.is_compressed("data.csv.gz"))
        self.assertTrue(self.h.is_compressed("a.ZIP"))   # case-insensitive
        self.assertFalse(self.h.is_compressed("data.csv"))

    def test_gzip_roundtrip(self):
        p = self.tmp / "data.csv.gz"
        with gzip.open(p, "wb") as f:
            f.write(_PAYLOAD)
        self.assertEqual(self._read(p), _PAYLOAD)

    def test_bz2_roundtrip(self):
        p = self.tmp / "data.csv.bz2"
        with bz2.open(p, "wb") as f:
            f.write(_PAYLOAD)
        self.assertEqual(self._read(p), _PAYLOAD)

    def test_zip_roundtrip(self):
        p = self.tmp / "data.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("data.csv", _PAYLOAD)
        self.assertEqual(self._read(p), _PAYLOAD)

    def test_tgz_roundtrip(self):
        inner = self.tmp / "data.csv"
        inner.write_bytes(_PAYLOAD)
        p = self.tmp / "data.tgz"
        with tarfile.open(p, "w:gz") as tf:
            tf.add(inner, arcname="data.csv")
        self.assertEqual(self._read(p), _PAYLOAD)

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_zstd_roundtrip(self):
        import zstandard
        p = self.tmp / "data.csv.zst"
        p.write_bytes(zstandard.ZstdCompressor().compress(_PAYLOAD))
        self.assertEqual(self._read(p), _PAYLOAD)

    @unittest.skipUnless(HAS_LZ4, "lz4 not installed")
    def test_lz4_roundtrip(self):
        import lz4.frame
        p = self.tmp / "data.csv.lz4"
        with lz4.frame.open(p, "wb") as f:
            f.write(_PAYLOAD)
        self.assertEqual(self._read(p), _PAYLOAD)

    def test_uncompressed_passthrough(self):
        p = self.tmp / "plain.csv"
        p.write_bytes(_PAYLOAD)
        self.assertEqual(self._read(p), _PAYLOAD)

    def test_empty_zip_raises(self):
        p = self.tmp / "empty.zip"
        with zipfile.ZipFile(p, "w"):
            pass
        with self.assertRaises(ValueError):
            self.h.open(p)

    def test_inner_extension_simple(self):
        self.assertEqual(self.h.inner_extension("data.csv.gz"), ".csv")
        self.assertEqual(self.h.inner_extension("data.json.bz2"), ".json")
        self.assertEqual(self.h.inner_extension("data.json"), ".json")  # passthrough

    def test_inner_extension_zip_inspects_member(self):
        p = self.tmp / "bundle.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("records.json", _PAYLOAD)
        self.assertEqual(self.h.inner_extension(p), ".json")

    def test_inner_extension_tgz_inspects_member(self):
        inner = self.tmp / "records.tsv"
        inner.write_bytes(_PAYLOAD)
        p = self.tmp / "bundle.tgz"
        with tarfile.open(p, "w:gz") as tf:
            tf.add(inner, arcname="records.tsv")
        self.assertEqual(self.h.inner_extension(p), ".tsv")

    def test_inner_extension_no_inner_suffix_defaults_csv(self):
        # "data.gz" has no inner extension once .gz is stripped -> default .csv
        self.assertEqual(self.h.inner_extension("data.gz"), ".csv")


if __name__ == "__main__":
    unittest.main()
