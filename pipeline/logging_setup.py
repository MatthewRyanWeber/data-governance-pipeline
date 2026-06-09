"""
Centralized logging configuration.

Configures rotating file handlers (50 MB, 5 backups), an errors-only file,
and console output. Provides structured JSON logging, correlation ID injection,
sensitive data scrubbing, and per-module level overrides.

Every other module just does:

    import logging
    logger = logging.getLogger(__name__)

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-07   Initial release: rotating file + console handlers.
1.1   2026-06-08   Added JsonFormatter, CorrelationIdFilter, SensitiveDataFilter,
                   timed_operation, per-module level overrides.
1.2   2026-06-09   Added container-aware logging (configure_container_logging,
                   auto_configure_logging).
"""

import contextlib
import json
import logging
import os
import re
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path


# ── Correlation ID storage ──────────────────────────────────────────────────

_correlation = threading.local()


def set_correlation_id(pipeline_id: str) -> None:
    """Set the correlation ID for the current thread's log messages."""
    _correlation.pipeline_id = pipeline_id


def clear_correlation_id() -> None:
    """Clear the correlation ID for the current thread."""
    _correlation.pipeline_id = None


def get_correlation_id() -> str | None:
    """Return the current thread's correlation ID, or None."""
    return getattr(_correlation, "pipeline_id", None)


# ── Filters ─────────────────────────────────────────────────────────────────

class CorrelationIdFilter(logging.Filter):
    """Injects pipeline_id into every LogRecord for tracing a single run."""

    def filter(self, record):
        record.pipeline_id = get_correlation_id() or "-"
        return True


_SENSITIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?i)(password|passwd|pwd|secret|token|api_key|access_key|auth)\s*[=:]\s*\S+'),
    re.compile(r'(?i)(password|passwd|pwd|secret|token|api_key|access_key|auth)["\']\s*:\s*["\'][^"\']*["\']'),
    re.compile(r'://[^@/\s]+:[^@/\s]+@'),
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
]


class SensitiveDataFilter(logging.Filter):
    """Scrubs passwords, tokens, and PII patterns from log messages."""

    def filter(self, record):
        msg = record.getMessage()
        matched = False
        for pattern in _SENSITIVE_PATTERNS:
            if pattern.search(msg):
                msg = pattern.sub("***REDACTED***", msg)
                matched = True
        if matched:
            record.msg = msg
            record.args = None
        return True


# ── Formatters ──────────────────────────────────────────────────────────────

class JsonFormatter(logging.Formatter):
    """Emits each log record as a single JSON line for log aggregation."""

    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "pipeline_id": getattr(record, "pipeline_id", "-"),
            "module": record.module,
            "funcName": record.funcName,
            "lineno": record.lineno,
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


# ── timed_operation context manager ─────────────────────────────────────────

@contextlib.contextmanager
def timed_operation(label: str, log_level: int = logging.INFO):
    """Context manager that logs wall-clock duration of the wrapped block."""
    perf_logger = logging.getLogger("pipeline.perf")
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        perf_logger.log(log_level, "[PERF] %s completed in %.3fs", label, elapsed)


# ── Main configuration ──────────────────────────────────────────────────────

def configure_logging(
    log_directory: Path,
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
    error_level: int = logging.WARNING,
    json_format: bool = False,
    module_levels: dict[str, int] | None = None,
) -> None:
    """Set up the root logger with rotating file + errors-only + console."""
    log_directory.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on repeated calls
    if root.handlers:
        return

    if json_format:
        formatter = JsonFormatter(datefmt="%Y-%m-%d %H:%M:%S")
    else:
        formatter = logging.Formatter(  # type: ignore[assignment]
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Attach global filters
    correlation_filter = CorrelationIdFilter()
    sensitive_filter = SensitiveDataFilter()

    # All-levels rotating file
    all_handler = RotatingFileHandler(
        log_directory / "pipeline.log",
        maxBytes=50 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    all_handler.setLevel(file_level)
    all_handler.setFormatter(formatter)
    all_handler.addFilter(correlation_filter)
    all_handler.addFilter(sensitive_filter)
    root.addHandler(all_handler)

    # Errors-only rotating file
    error_handler = RotatingFileHandler(
        log_directory / "pipeline_errors.log",
        maxBytes=50 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    error_handler.setLevel(error_level)
    error_handler.setFormatter(formatter)
    error_handler.addFilter(correlation_filter)
    error_handler.addFilter(sensitive_filter)
    root.addHandler(error_handler)

    # Console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(correlation_filter)
    console_handler.addFilter(sensitive_filter)
    root.addHandler(console_handler)

    # Per-module log level overrides
    if module_levels:
        for module_name, level in module_levels.items():
            logging.getLogger(module_name).setLevel(level)


def setup_logging(log_directory: Path | None = None, **kwargs) -> None:
    """Convenience wrapper used by cli.py and the entry point."""
    if log_directory is None:
        log_directory = Path("logs")
    configure_logging(log_directory, **kwargs)


def _is_container_environment() -> bool:
    """Detect whether the process is running inside a container."""
    if os.environ.get("PIPELINE_CONTAINER"):
        return True
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return True
    if os.path.isfile("/.dockerenv"):
        return True
    return False


def configure_container_logging(
    console_level: int = logging.INFO,
    module_levels: dict[str, int] | None = None,
) -> None:
    """Set up JSON logging to stdout only — no file handlers.

    Designed for container environments where log aggregators (Datadog,
    CloudWatch, Loki, ELK) parse structured JSON from stdout.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    if root.handlers:
        return

    formatter = JsonFormatter(datefmt="%Y-%m-%d %H:%M:%S")
    correlation_filter = CorrelationIdFilter()
    sensitive_filter = SensitiveDataFilter()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(console_level)
    handler.setFormatter(formatter)
    handler.addFilter(correlation_filter)
    handler.addFilter(sensitive_filter)
    root.addHandler(handler)

    if module_levels:
        for module_name, level in module_levels.items():
            logging.getLogger(module_name).setLevel(level)


def auto_configure_logging(**kwargs) -> None:
    """Pick container or file-based logging based on environment detection."""
    if _is_container_environment():
        configure_container_logging(**kwargs)
    else:
        setup_logging(**kwargs)
