"""
Security tests for archive path traversal and zip bomb protections.

Validates that _validate_archive_member rejects dangerous member names
and that SizeLimitedReader enforces decompression size limits.

Revision history
----------------
1.0   2026-06-08   Initial creation: path traversal, absolute paths,
                   SizeLimitedReader limit enforcement, ZIP integration.
1.1   2026-06-11   read(-1) must raise without buffering the whole stream.
"""

import io
import unittest
import zipfile

from pipeline.compression import (
    CompressionHandler,
    SizeLimitedReader,
    _validate_archive_member,
)



# ---------------------------------------------------------------------------
# 1. _validate_archive_member — path traversal and absolute path rejection
# ---------------------------------------------------------------------------

class TestValidateArchiveMember(unittest.TestCase):
    """_validate_archive_member() must reject traversal and absolute paths."""

    def test_normal_name_accepted(self):
        _validate_archive_member("data/file.csv")

    def test_normal_nested_accepted(self):
        _validate_archive_member("subdir/data.json")

    def test_simple_filename_accepted(self):
        _validate_archive_member("report.csv")

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            _validate_archive_member("../../../etc/passwd")

    def test_absolute_unix_path_rejected(self):
        with self.assertRaises(ValueError):
            _validate_archive_member("/etc/passwd")

    def test_absolute_windows_path_rejected(self):
        with self.assertRaises(ValueError):
            _validate_archive_member("C:\\Users\\data")

    def test_double_dot_mid_path_rejected(self):
        with self.assertRaises(ValueError):
            _validate_archive_member("data/../../../secret")

    def test_double_dot_at_end_rejected(self):
        with self.assertRaises(ValueError):
            _validate_archive_member("data/subdir/../../..")


# ---------------------------------------------------------------------------
# 2. SizeLimitedReader — decompression size limit enforcement
# ---------------------------------------------------------------------------

class TestSizeLimitedReader(unittest.TestCase):
    """SizeLimitedReader must raise ValueError when the limit is exceeded."""

    def test_read_within_limit(self):
        stream = io.BytesIO(b"x" * 100)
        reader = SizeLimitedReader(stream, max_bytes=200)
        data = reader.read(100)
        self.assertEqual(len(data), 100)

    def test_read_exactly_at_limit(self):
        stream = io.BytesIO(b"x" * 50)
        reader = SizeLimitedReader(stream, max_bytes=50)
        data = reader.read(50)
        self.assertEqual(len(data), 50)

    def test_read_beyond_limit_raises(self):
        stream = io.BytesIO(b"x" * 100)
        reader = SizeLimitedReader(stream, max_bytes=50)
        reader.read(50)
        with self.assertRaises(ValueError):
            reader.read(10)

    def test_small_stream_large_limit(self):
        stream = io.BytesIO(b"x" * 10)
        reader = SizeLimitedReader(stream, max_bytes=1000)
        data = reader.read(10)
        self.assertEqual(len(data), 10)

    def test_cumulative_reads_trip_limit(self):
        stream = io.BytesIO(b"x" * 100)
        reader = SizeLimitedReader(stream, max_bytes=80)
        reader.read(40)
        reader.read(40)
        with self.assertRaises(ValueError):
            reader.read(10)

    def test_single_read_over_limit_raises(self):
        stream = io.BytesIO(b"x" * 200)
        reader = SizeLimitedReader(stream, max_bytes=50)
        with self.assertRaises(ValueError):
            reader.read(200)

    def test_readinto_within_limit(self):
        stream = io.BytesIO(b"abcdef")
        reader = SizeLimitedReader(stream, max_bytes=100)
        buf = bytearray(6)
        n = reader.readinto(buf)
        self.assertEqual(n, 6)
        self.assertEqual(buf, b"abcdef")

    def test_readinto_beyond_limit_raises(self):
        stream = io.BytesIO(b"x" * 100)
        reader = SizeLimitedReader(stream, max_bytes=50)
        buf = bytearray(80)
        with self.assertRaises(ValueError):
            reader.readinto(buf)

    def test_unbounded_read_over_limit_raises(self):
        # Regression: read(-1) fully decompressed the stream before the
        # limit check, defeating the zip-bomb cap.
        stream = io.BytesIO(b"x" * 1_000_000)
        reader = SizeLimitedReader(stream, max_bytes=100)
        with self.assertRaises(ValueError):
            reader.read()

    def test_unbounded_read_stops_before_consuming_whole_stream(self):
        class CountingStream(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.bytes_served = 0

            def read(self, size=-1):
                data = super().read(size)
                self.bytes_served += len(data)
                return data

        stream = CountingStream(b"x" * 1_000_000)
        reader = SizeLimitedReader(stream, max_bytes=100)
        with self.assertRaises(ValueError):
            reader.read()
        # The reader must bail on the first over-limit increment instead of
        # buffering the full megabyte.
        self.assertLess(stream.bytes_served, 1_000_000)

    def test_unbounded_read_within_limit_returns_everything(self):
        stream = io.BytesIO(b"abc" * 10)
        reader = SizeLimitedReader(stream, max_bytes=100)
        self.assertEqual(reader.read(), b"abc" * 10)

    def test_read_none_treated_as_unbounded(self):
        stream = io.BytesIO(b"x" * 200)
        reader = SizeLimitedReader(stream, max_bytes=50)
        with self.assertRaises(ValueError):
            reader.read(None)

    def test_readable_returns_true(self):
        stream = io.BytesIO(b"data")
        reader = SizeLimitedReader(stream, max_bytes=100)
        self.assertTrue(reader.readable())

    def test_close_closes_inner_stream(self):
        stream = io.BytesIO(b"data")
        reader = SizeLimitedReader(stream, max_bytes=100)
        reader.close()
        self.assertTrue(stream.closed)


# ---------------------------------------------------------------------------
# 3. ZIP path traversal — integration via CompressionHandler.open()
# ---------------------------------------------------------------------------

class TestZipPathTraversalIntegration(unittest.TestCase):
    """Opening a ZIP with a traversal member name must raise ValueError."""

    def _make_zip_bytes(self, member_name: str, content: bytes) -> bytes:
        """Build an in-memory ZIP with one member at the given name."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(member_name, content)
        return buf.getvalue()

    def test_traversal_member_rejected(self):
        import os
        import tempfile

        raw = self._make_zip_bytes("../evil.txt", b"malicious payload")
        tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        try:
            tmp.write(raw)
            tmp.close()
            handler = CompressionHandler()
            with self.assertRaises(ValueError):
                handler.open(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_safe_member_accepted(self):
        import os
        import tempfile

        raw = self._make_zip_bytes("data/report.csv", b"col1,col2\na,b\n")
        tmp_path = tempfile.mktemp(suffix=".zip")
        with open(tmp_path, "wb") as f:
            f.write(raw)
        try:
            handler = CompressionHandler()
            stream = handler.open(tmp_path)
            data = stream.read()
            stream.close()
            self.assertEqual(data, b"col1,col2\na,b\n")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# 4. ZIP bomb protection — SizeLimitedReader catches oversized decompression
# ---------------------------------------------------------------------------

class TestZipBombProtection(unittest.TestCase):
    """SizeLimitedReader inside CompressionHandler must stop zip bombs."""

    def test_oversized_decompressed_stream(self):
        """A zip whose decompressed content exceeds the limit must raise."""
        import os
        import tempfile
        from unittest.mock import patch

        payload = b"A" * 2048
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.csv", payload)
        raw = buf.getvalue()

        tmp_path = tempfile.mktemp(suffix=".zip")
        with open(tmp_path, "wb") as f:
            f.write(raw)
        stream = None
        try:
            handler = CompressionHandler()
            with patch("pipeline.compression.MAX_DECOMPRESSED_SIZE", 500):
                stream = handler.open(tmp_path)
                with self.assertRaises(ValueError):
                    stream.read()
        finally:
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def test_within_limit_no_error(self):
        """A zip whose content is under the limit decompresses normally."""
        import os
        import tempfile
        from unittest.mock import patch

        payload = b"small data"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("small.csv", payload)
        raw = buf.getvalue()

        tmp_path = tempfile.mktemp(suffix=".zip")
        with open(tmp_path, "wb") as f:
            f.write(raw)
        try:
            handler = CompressionHandler()
            with patch("pipeline.compression.MAX_DECOMPRESSED_SIZE", 10_000):
                stream = handler.open(tmp_path)
                data = stream.read()
                stream.close()
            self.assertEqual(data, payload)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
