"""
Shared pytest fixtures for data-governance-pipeline tests.

Revision history
----------------
1.0   2026-06-07   Initial creation.
1.1   2026-06-12   Derandomize hypothesis so property tests cannot flake
                   differently between runs.
"""

import pathlib
import sys
from unittest.mock import MagicMock

import pandas as pd
import pytest

from hypothesis import settings as _hypothesis_settings

# Property tests must fail the same way every run — a randomized example
# stream makes CI red/green nondeterministic.
_hypothesis_settings.register_profile("deterministic", derandomize=True)
_hypothesis_settings.load_profile("deterministic")

# Ensure project root is on sys.path so both `pipeline` and backward-compat
# shims (`pipeline_v3`, `governance_extensions`, etc.) are importable.
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


@pytest.fixture
def tmp_dir(tmp_path):
    """Return a fresh temporary directory (cleaned up by pytest)."""
    return tmp_path


@pytest.fixture
def mock_gov(tmp_dir):
    """Return a MagicMock GovernanceLogger whose log_dir points at tmp_dir."""
    gov = MagicMock()
    gov.log_dir = str(tmp_dir)
    gov._event = MagicMock()
    return gov


@pytest.fixture
def sample_df():
    """Small synthetic DataFrame for quick tests."""
    return pd.DataFrame({
        "id": [1, 2, 3],
        "email": ["alice@example.com", "bob@example.com", "carol@example.com"],
        "salary": [50000, 60000, 70000],
        "dept": ["Eng", "HR", "Sales"],
    })
