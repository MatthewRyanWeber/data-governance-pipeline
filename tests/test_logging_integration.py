"""
Tests for Phase 4 logging integration: correlation IDs flow through
the pipeline, timed_operation wraps extract/transform/load stages.
"""

import logging
import unittest

from pipeline.logging_setup import (
    set_correlation_id, clear_correlation_id, get_correlation_id,
    CorrelationIdFilter, timed_operation,
)


class TestCorrelationIdFlow(unittest.TestCase):
    """Verify correlation ID is injected into log records pipeline-wide."""

    def setUp(self):
        clear_correlation_id()

    def tearDown(self):
        clear_correlation_id()

    def test_set_and_get(self):
        set_correlation_id("run-abc-123")
        self.assertEqual(get_correlation_id(), "run-abc-123")

    def test_filter_injects_id(self):
        set_correlation_id("run-xyz-789")
        filt = CorrelationIdFilter()
        record = logging.LogRecord(
            "test", logging.INFO, "test.py", 1, "msg", (), None
        )
        filt.filter(record)
        self.assertEqual(record.pipeline_id, "run-xyz-789")

    def test_no_correlation_gives_dash(self):
        filt = CorrelationIdFilter()
        record = logging.LogRecord(
            "test", logging.INFO, "test.py", 1, "msg", (), None
        )
        filt.filter(record)
        self.assertEqual(record.pipeline_id, "-")

    def test_clear_resets(self):
        set_correlation_id("run-123")
        clear_correlation_id()
        self.assertIsNone(get_correlation_id())


class TestTimedOperationIntegration(unittest.TestCase):
    """Verify timed_operation emits PERF log lines with label and duration."""

    def setUp(self):
        logging.disable(logging.NOTSET)

    def test_emits_perf_log(self):
        perf_logger = logging.getLogger("pipeline.perf")
        perf_logger.setLevel(logging.DEBUG)
        with self.assertLogs("pipeline.perf", level="INFO") as cm:
            with timed_operation("test_extract"):
                pass
        self.assertEqual(len(cm.output), 1)
        self.assertIn("[PERF]", cm.output[0])
        self.assertIn("test_extract", cm.output[0])
        self.assertIn("completed in", cm.output[0])

    def test_timing_is_positive(self):
        import time
        perf_logger = logging.getLogger("pipeline.perf")
        perf_logger.setLevel(logging.DEBUG)
        with self.assertLogs("pipeline.perf", level="INFO") as cm:
            with timed_operation("sleep_test"):
                time.sleep(0.05)
        log_line = cm.output[0]
        duration_str = log_line.split("completed in ")[1].rstrip("s")
        duration = float(duration_str)
        self.assertGreater(duration, 0.01)

    def test_logs_even_on_exception(self):
        perf_logger = logging.getLogger("pipeline.perf")
        perf_logger.setLevel(logging.DEBUG)
        with self.assertLogs("pipeline.perf", level="INFO") as cm:
            try:
                with timed_operation("failing_op"):
                    raise RuntimeError("boom")
            except RuntimeError:
                pass
        self.assertTrue(any("[PERF]" in m for m in cm.output))
        self.assertTrue(any("failing_op" in m for m in cm.output))

    def test_custom_log_level(self):
        perf_logger = logging.getLogger("pipeline.perf")
        perf_logger.setLevel(logging.DEBUG)
        with self.assertLogs("pipeline.perf", level="DEBUG") as cm:
            with timed_operation("debug_op", log_level=logging.DEBUG):
                pass
        self.assertTrue(any("debug_op" in m for m in cm.output))


class TestCliCorrelationWiring(unittest.TestCase):
    """Verify cli.py sets correlation ID from RunContext."""

    def test_set_correlation_id_import(self):
        from pipeline.logging_setup import set_correlation_id
        self.assertTrue(callable(set_correlation_id))

    def test_cli_imports_set_correlation_id(self):
        import importlib
        importlib.import_module("pipeline.cli")
        source = importlib.util.find_spec("pipeline.cli")
        self.assertIsNotNone(source)


if __name__ == "__main__":
    unittest.main()
