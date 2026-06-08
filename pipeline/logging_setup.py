"""
Centralized logging configuration.

Configures rotating file handlers (50 MB, 5 backups), an errors-only file,
and console output. Every other module just does:

    import logging
    logger = logging.getLogger(__name__)

Layer 0 — no internal package imports.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(
    log_directory: Path,
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
    error_level: int = logging.WARNING,
) -> None:
    """Set up the root logger with rotating file + errors-only + console."""
    log_directory.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on repeated calls
    if root.handlers:
        return

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # All-levels rotating file
    all_handler = RotatingFileHandler(
        log_directory / "pipeline.log",
        maxBytes=50 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    all_handler.setLevel(file_level)
    all_handler.setFormatter(formatter)
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
    root.addHandler(error_handler)

    # Console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)


def setup_logging(log_directory: Path | None = None, **kwargs) -> None:
    """Convenience wrapper used by cli.py and the entry point."""
    if log_directory is None:
        log_directory = Path("logs")
    configure_logging(log_directory, **kwargs)
