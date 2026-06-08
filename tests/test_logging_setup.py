"""
Tests for pipeline/logging_setup.py.

Covers correlation ID lifecycle, log filters (CorrelationIdFilter,
SensitiveDataFilter), JsonFormatter, the timed_operation context manager,
and the configure_logging setup function.

Revision history
────────────────
1.0   2026-06-08   Initial release: full coverage of logging_setup module.
"""

import json
import logging
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from pipeline.logging_setup import (
    CorrelationIdFilter,
    JsonFormatter,
    SensitiveDataFilter,
    clear_correlation_id,
    configure_logging,
    get_correlation_id,
    set_correlation_id,
    timed_operation,
)


def _make_record(message="test message", level=logging.INFO, args=()):
    """Helper — build a LogRecord without going through a real logger."""
    return logging.LogRecord(
        name="test",
        level=level,
        pathname="test.py",
        lineno=1,
        msg=message,
        args=args,
        exc_info=None,
    )


class TestCorrelationId(unittest.TestCase):
    """Correlation ID get / set / clear lifecycle."""

    def setUp(self):
        clear_correlation_id()

    def tearDown(self):
        clear_correlation_id()

    def test_initial_state_is_none(self):
        self.assertIsNone(get_correlation_id())

    def test_set_then_get(self):
        set_correlation_id("abc-123")
        self.assertEqual(get_correlation_id(), "abc-123")

    def test_clear_resets_to_none(self):
        set_correlation_id("abc-123")
        clear_correlation_id()
        self.assertIsNone(get_correlation_id())


class TestCorrelationIdFilter(unittest.TestCase):
    """CorrelationIdFilter injects pipeline_id into LogRecords."""

    def setUp(self):
        clear_correlation_id()
        self.filt = CorrelationIdFilter()

    def tearDown(self):
        clear_correlation_id()

    def test_filter_returns_true(self):
        record = _make_record()
        self.assertTrue(self.filt.filter(record))

    def test_no_correlation_gives_dash(self):
        record = _make_record()
        self.filt.filter(record)
        self.assertEqual(record.pipeline_id, "-")

    def test_set_correlation_appears_on_record(self):
        set_correlation_id("run-42")
        record = _make_record()
        self.filt.filter(record)
        self.assertEqual(record.pipeline_id, "run-42")


class TestSensitiveDataFilter(unittest.TestCase):
    """SensitiveDataFilter scrubs passwords, URLs with creds, SSNs, emails."""

    def setUp(self):
        self.filt = SensitiveDataFilter()

    def test_password_redacted(self):
        record = _make_record("password=secret123")
        self.filt.filter(record)
        self.assertIn("***REDACTED***", record.msg)
        self.assertNotIn("secret123", record.msg)

    def test_url_credentials_redacted(self):
        record = _make_record("connecting to ://user:pass@host")
        self.filt.filter(record)
        self.assertIn("***REDACTED***", record.msg)
        self.assertNotIn("user:pass", record.msg)

    def test_ssn_redacted(self):
        record = _make_record("SSN is 123-45-6789")
        self.filt.filter(record)
        self.assertIn("***REDACTED***", record.msg)
        self.assertNotIn("123-45-6789", record.msg)

    def test_email_redacted(self):
        record = _make_record("contact test@example.com for info")
        self.filt.filter(record)
        self.assertIn("***REDACTED***", record.msg)
        self.assertNotIn("test@example.com", record.msg)

    def test_normal_message_unchanged(self):
        record = _make_record("Loading 100 rows")
        self.filt.filter(record)
        self.assertEqual(record.msg, "Loading 100 rows")


class TestJsonFormatter(unittest.TestCase):
    """JsonFormatter emits valid single-line JSON with required keys."""

    def setUp(self):
        self.fmt = JsonFormatter(datefmt="%Y-%m-%d %H:%M:%S")

    def test_output_is_valid_json(self):
        record = _make_record("hello world")
        result = self.fmt.format(record)
        parsed = json.loads(result)
        self.assertIsInstance(parsed, dict)

    def test_required_keys_present(self):
        record = _make_record("hello world")
        result = self.fmt.format(record)
        parsed = json.loads(result)
        for key in ("timestamp", "level", "logger", "message",
                     "pipeline_id", "module", "lineno"):
            self.assertIn(key, parsed, f"Missing key: {key}")

    def test_exception_info_included(self):
        try:
            raise ValueError("boom")
        except ValueError:
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=99,
            msg="Something failed",
            args=(),
            exc_info=exc_info,
        )
        result = self.fmt.format(record)
        parsed = json.loads(result)
        self.assertIn("exception", parsed)
        self.assertIn("ValueError", parsed["exception"])


class TestTimedOperation(unittest.TestCase):
    """timed_operation context manager logs [PERF] with timing."""

    def setUp(self):
        logging.disable(logging.NOTSET)

    def test_emits_perf_log_line(self):
        perf_logger = logging.getLogger("pipeline.perf")
        captured = []

        class _CaptureHandler(logging.Handler):
            def emit(self, record):
                captured.append(self.format(record))

        capture_handler = _CaptureHandler()
        capture_handler.setLevel(logging.DEBUG)
        perf_logger.addHandler(capture_handler)
        perf_logger.setLevel(logging.DEBUG)

        try:
            with timed_operation("test_op"):
                pass

            self.assertTrue(len(captured) > 0, "No log lines captured")
            line = captured[0]
            self.assertIn("[PERF]", line)
            self.assertIn("test_op", line)
            self.assertIn("completed in", line)
        finally:
            perf_logger.removeHandler(capture_handler)


class TestConfigureLogging(unittest.TestCase):
    """configure_logging sets up file handlers, formatters, and module levels."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.log_path = Path(self.tmpdir)
        # Start each test with a clean root logger
        root = logging.getLogger()
        root.handlers.clear()

    def tearDown(self):
        # Clean up handlers to avoid polluting other tests
        root = logging.getLogger()
        for handler in list(root.handlers):
            handler.close()
        root.handlers.clear()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_creates_log_files(self):
        configure_logging(self.log_path)
        # Emit a warning so the errors file also gets content
        logging.getLogger("test_creates").warning("trigger file creation")
        self.assertTrue((self.log_path / "pipeline.log").exists())
        self.assertTrue((self.log_path / "pipeline_errors.log").exists())

    def test_root_logger_gets_handlers(self):
        configure_logging(self.log_path)
        root = logging.getLogger()
        # 3 handlers: all-file, error-file, console
        self.assertEqual(len(root.handlers), 3)

    def test_json_format_uses_json_formatter(self):
        configure_logging(self.log_path, json_format=True)
        root = logging.getLogger()
        json_formatter_found = any(
            isinstance(h.formatter, JsonFormatter) for h in root.handlers
        )
        self.assertTrue(json_formatter_found, "No JsonFormatter on any handler")

    def test_module_levels_applied(self):
        configure_logging(
            self.log_path,
            module_levels={"pipeline.loaders": logging.WARNING},
        )
        loaders_logger = logging.getLogger("pipeline.loaders")
        self.assertEqual(loaders_logger.level, logging.WARNING)

    def test_early_return_on_existing_handlers(self):
        """Second call is a no-op when root already has handlers."""
        configure_logging(self.log_path)
        root = logging.getLogger()
        handler_count = len(root.handlers)
        # Second call should return early
        configure_logging(self.log_path)
        self.assertEqual(len(root.handlers), handler_count)


if __name__ == "__main__":
    unittest.main()
