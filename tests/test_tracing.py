"""
Tests for pipeline/tracing.py — OpenTelemetry integration.

Covers no-op fallback when OTEL is not installed, traced_operation timing,
and get_current_trace_ids.

Revision history
────────────────
1.0   2026-06-09   Initial release.
1.1   2026-06-09   Added metrics no-op fallback tests.
"""

import logging
import unittest

from pipeline.tracing import (
    get_current_trace_ids,
    get_instruments,
    get_meter,
    get_tracer,
    traced_operation,
)


class TestTracingNoopFallback(unittest.TestCase):
    """Tracing works gracefully when OTEL is not installed."""

    def test_get_tracer_returns_noop(self):
        tracer = get_tracer("test")
        self.assertIsNotNone(tracer)

    def test_traced_operation_yields(self):
        with traced_operation("test_op"):
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


class TestMetricsNoopFallback(unittest.TestCase):
    """Metrics instruments work gracefully when OTEL metrics SDK is not installed."""

    def test_get_meter_returns_usable_object(self):
        meter = get_meter("test")
        self.assertIsNotNone(meter)

    def test_noop_counter_add_does_not_raise(self):
        meter = get_meter("test")
        counter = meter.create_counter("test.counter")
        counter.add(42)

    def test_noop_histogram_record_does_not_raise(self):
        meter = get_meter("test")
        histogram = meter.create_histogram("test.histogram")
        histogram.record(1.5)

    def test_get_instruments_returns_expected_keys(self):
        instruments = get_instruments()
        expected = {"extract_rows", "transform_duration", "load_rows",
                    "load_errors", "load_duration"}
        self.assertEqual(set(instruments.keys()), expected)

    def test_instruments_are_callable_without_error(self):
        instruments = get_instruments()
        instruments["extract_rows"].add(100)
        instruments["transform_duration"].record(0.5)
        instruments["load_rows"].add(200)
        instruments["load_errors"].add(1)
        instruments["load_duration"].record(1.2)


if __name__ == "__main__":
    unittest.main()
