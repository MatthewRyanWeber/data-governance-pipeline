"""
Optional OpenTelemetry tracing integration.

When opentelemetry-api and opentelemetry-sdk are installed, provides W3C
standard distributed tracing with OTLP export. Falls back to a no-op
implementation when OTEL is not available — callers never need to check.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-09   Initial release: init_tracing, get_tracer, traced_operation.
1.1   2026-06-09   Added native OTEL metrics: init_metrics, get_meter,
                   get_instruments.
"""

import contextlib
import logging
import os
import time

logger = logging.getLogger(__name__)

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False

try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    HAS_OTEL_METRICS = True
except ImportError:
    HAS_OTEL_METRICS = False

_initialized = False
_metrics_initialized = False
_instruments: dict | None = None


def init_tracing(
    service_name: str = "data-governance-pipeline",
    endpoint: str | None = None,
) -> None:
    """Configure the OpenTelemetry TracerProvider with an OTLP exporter.

    Reads ``OTEL_EXPORTER_OTLP_ENDPOINT`` from the environment if *endpoint*
    is not provided. Does nothing when opentelemetry is not installed.
    """
    global _initialized
    if not HAS_OTEL or _initialized:
        return

    endpoint = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        logger.debug("[TRACING] No OTLP endpoint configured — tracing disabled.")
        return

    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _initialized = True
        logger.info("[TRACING] OpenTelemetry initialized — exporting to %s", endpoint)
    except Exception as exc:
        logger.warning("[TRACING] Failed to initialize OTLP exporter: %s", exc)


def get_tracer(name: str = __name__):
    """Return an OpenTelemetry tracer, or a no-op tracer if OTEL is unavailable."""
    if HAS_OTEL:
        return trace.get_tracer(name)
    return _NoopTracer()


@contextlib.contextmanager
def traced_operation(name: str, attributes: dict | None = None):
    """Context manager that creates an OTEL span and records wall-clock duration.

    Falls back to simple timing when OTEL is not installed. Always logs
    duration to the ``pipeline.perf`` logger.
    """
    perf_logger = logging.getLogger("pipeline.perf")
    start = time.monotonic()

    if HAS_OTEL:
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(name, attributes=attributes or {}) as span:
            try:
                yield span
            finally:
                elapsed = time.monotonic() - start
                span.set_attribute("duration_s", round(elapsed, 3))
                perf_logger.info("[PERF] %s completed in %.3fs", name, elapsed)
    else:
        try:
            yield None
        finally:
            elapsed = time.monotonic() - start
            perf_logger.info("[PERF] %s completed in %.3fs", name, elapsed)


def get_current_trace_ids() -> dict[str, str]:
    """Return current trace_id and span_id as hex strings, or empty dict."""
    if not HAS_OTEL:
        return {}
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx and ctx.trace_id:
        return {
            "trace_id": format(ctx.trace_id, "032x"),
            "span_id": format(ctx.span_id, "016x"),
        }
    return {}


class _NoopSpan:
    """Minimal stand-in when OTEL is not installed."""

    def set_attribute(self, key, value):
        pass

    def add_event(self, name, attributes=None):
        pass


class _NoopTracer:
    """Minimal tracer stand-in when OTEL is not installed."""

    @contextlib.contextmanager
    def start_as_current_span(self, name, **kwargs):
        yield _NoopSpan()


# ── Metrics ────────────────────────────────────────────────────────────


class _NoopCounter:
    def add(self, amount, attributes=None):
        pass


class _NoopHistogram:
    def record(self, amount, attributes=None):
        pass


class _NoopMeter:
    def create_counter(self, name, **kwargs):
        return _NoopCounter()

    def create_histogram(self, name, **kwargs):
        return _NoopHistogram()


def init_metrics(
    service_name: str = "data-governance-pipeline",
    endpoint: str | None = None,
) -> None:
    """Configure the OpenTelemetry MeterProvider with an OTLP exporter.

    Reads ``OTEL_EXPORTER_OTLP_ENDPOINT`` from the environment if *endpoint*
    is not provided. Does nothing when opentelemetry metrics SDK is absent.
    """
    global _metrics_initialized
    if not HAS_OTEL_METRICS or _metrics_initialized:
        return

    endpoint = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        logger.debug("[METRICS] No OTLP endpoint configured — metrics export disabled.")
        return

    try:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

        resource = Resource.create({"service.name": service_name})
        exporter = OTLPMetricExporter(endpoint=endpoint)
        reader = PeriodicExportingMetricReader(exporter)
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        otel_metrics.set_meter_provider(provider)
        _metrics_initialized = True
        logger.info("[METRICS] OpenTelemetry metrics initialized — exporting to %s", endpoint)
    except Exception as exc:
        logger.warning("[METRICS] Failed to initialize OTLP metrics exporter: %s", exc)


def get_meter(name: str = __name__):
    """Return an OpenTelemetry meter, or a no-op meter if OTEL is unavailable."""
    if HAS_OTEL_METRICS:
        return otel_metrics.get_meter(name)
    return _NoopMeter()


def get_instruments() -> dict:
    """Return shared pipeline metric instruments, creating them on first call.

    Keys: extract_rows, transform_duration, load_rows, load_errors,
    load_duration. All are safe to call without OTEL installed.
    """
    global _instruments
    if _instruments is not None:
        return _instruments

    meter = get_meter("pipeline")
    _instruments = {
        "extract_rows": meter.create_counter(
            "pipeline.extract.rows",
            description="Total rows extracted",
        ),
        "transform_duration": meter.create_histogram(
            "pipeline.transform.duration_seconds",
            description="Transform stage duration in seconds",
        ),
        "load_rows": meter.create_counter(
            "pipeline.load.rows",
            description="Total rows loaded",
        ),
        "load_errors": meter.create_counter(
            "pipeline.load.errors",
            description="Total load errors",
        ),
        "load_duration": meter.create_histogram(
            "pipeline.load.duration_seconds",
            description="Load stage duration in seconds",
        ),
    }
    return _instruments
