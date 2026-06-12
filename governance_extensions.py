"""Backward-compatibility shim — moved to pipeline.extensions.governance_extensions.

This root-level module will be removed in v5.0.
"""

import warnings

warnings.warn(
    "governance_extensions at the repository root is deprecated and will be removed in "
    "v5.0. Import from pipeline.extensions.governance_extensions instead.",
    DeprecationWarning,
    stacklevel=2,
)

from pipeline.extensions.governance_extensions import *  # noqa: F401,F403
