"""Backward-compatibility shim — moved to pipeline.extensions.grafana_extensions.

This root-level module will be removed in v5.0.
"""

import warnings

warnings.warn(
    "grafana_extensions at the repository root is deprecated and will be removed in "
    "v5.0. Import from pipeline.extensions.grafana_extensions instead.",
    DeprecationWarning,
    stacklevel=2,
)

from pipeline.extensions.grafana_extensions import *  # noqa: F401,F403
