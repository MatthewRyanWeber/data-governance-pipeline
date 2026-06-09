"""
Tests for pipeline/tracing.py — OpenTelemetry integration.

Covers no-op fallback when OTEL is not installed, traced_operation timing,
and get_current_trace_ids.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import logging
import unittest

from pipeline.tracing import (
    get_current_trace_ids,
    get_tracer,
    traced_operation,
)


class TestTracingNoopFallback(unittest.TestCase):
    """Tracing works gracefully when OTEL is not installed."""

    def test_get_tracer_returns_noop(self):
        tracer = get_tracer("test")
        self.assertIsNotNone(tracer)

    def test_traced_operation_yields(self):
        with traced_operation("test_op") as span:
            x = 1 + 1
        self.assertEqual(x, 2)

    def test_traced_operation_records_duration(self):
        captured = []

        class _CaptureHandler(logging.Handler):
            def emit(self, record):
                captured.append(self.format(record))

        perf_logger = logging.getLogger("pipeline.perf")
        handler = _CaptureHandler()
        handler.setLevel(logging.DEBUG)
        perf_logger.addHandler(handler)
        perf_logger.setLevel(logging.DEBUG)

        try:
            with traced_operation("timing_test"):
                pass
            self.assertTrue(len(captured) > 0)
            self.assertIn("[PERF]", captured[0])
            self.assertIn("timing_test", captured[0])
            self.assertIn("completed in", captured[0])
        finally:
            perf_logger.removeHandler(handler)

    def test_get_current_trace_ids_empty_without_otel(self):
        result = get_current_trace_ids()
        self.assertIsInstance(result, dict)

    def test_noop_tracer_span_interface(self):
        tracer = get_tracer("test")
        with tracer.start_as_current_span("test_span") as span:
            span.set_attribute("key", "value")
            span.add_event("test_event")

    def test_traced_operation_with_attributes(self):
        with traced_operation("test_op", attributes={"source": "test.csv"}):
            pass


if __name__ == "__main__":
    unittest.main()
