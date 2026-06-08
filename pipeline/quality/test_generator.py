"""
Automated test generation — creates Great Expectations from column profiles.

Analyzes profiling results and generates appropriate expectation suites
so users don't have to author them manually.

Layer 3 — imports from Layer 0 (constants).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Taste fixes: dry_run support, guard clause for None
                   profile, clearer variable names, warn on empty suite.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class TestGenerator:
    """
    Generates data quality expectations from column profiling results.

    Quick-start
    -----------
        from pipeline.quality.test_generator import TestGenerator
        gen = TestGenerator(gov)
        suite = gen.generate(profile)
        # suite is a list of expectation dicts ready for Great Expectations
    """

    NULL_RATE_TOLERANCE = 0.05
    CARDINALITY_LOW_THRESHOLD = 20
    LENGTH_TOLERANCE = 1.5

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        self.gov = gov
        self.dry_run = dry_run

    def generate(self, profile: dict) -> list[dict]:
        """
        Generate expectations from a column profile.

        Parameters
        ----------
        profile : dict  Output from ColumnProfiler.profile().

        Returns
        -------
        list[dict]  List of expectation configs.
        """
        if not profile:
            raise ValueError("Profile must not be None")

        expectations: list[dict] = []

        for column_profile in profile.get("columns", []):
            expectations.extend(self._generate_for_column(column_profile))

        row_count = profile.get("row_count", 0)
        if row_count > 0:
            expectations.append({
                "expectation_type": "expect_table_row_count_to_be_between",
                "kwargs": {
                    "min_value": max(1, int(row_count * 0.5)),
                    "max_value": int(row_count * 2.0),
                },
                "meta": {"source": "auto_generated", "based_on_count": row_count},
            })

        self.gov.transformation_applied("TESTS_AUTO_GENERATED", {
            "dataset": profile.get("dataset_name", ""),
            "expectations_count": len(expectations),
            "columns_profiled": len(profile.get("columns", [])),
        })

        logger.info("[TESTGEN] Generated %d expectations from profile of '%s'",
                     len(expectations), profile.get("dataset_name", ""))
        return expectations

    def _generate_for_column(self, column_profile: dict) -> list[dict]:
        """Generate expectations for a single column based on its profile."""
        expectations: list[dict] = []
        name = column_profile["name"]
        meta = {"source": "auto_generated", "column": name}

        if column_profile.get("null_rate", 0) == 0:
            expectations.append({
                "expectation_type": "expect_column_values_to_not_be_null",
                "kwargs": {"column": name},
                "meta": meta,
            })
        elif column_profile.get("null_rate", 1) < self.NULL_RATE_TOLERANCE:
            expectations.append({
                "expectation_type": "expect_column_values_to_not_be_null",
                "kwargs": {"column": name, "mostly": 1 - column_profile["null_rate"] - 0.02},
                "meta": meta,
            })

        dtype = column_profile.get("dtype", "")

        if "int" in dtype or "float" in dtype:
            expectations.extend(self._numeric_expectations(name, column_profile, meta))
        elif "datetime" in dtype:
            expectations.extend(self._datetime_expectations(name, column_profile, meta))
        elif dtype == "object" or "str" in dtype:
            expectations.extend(self._string_expectations(name, column_profile, meta))

        if (column_profile.get("unique_count", 0) > 0
                and column_profile.get("cardinality_rate", 1) == 1.0
                and column_profile.get("null_rate", 1) == 0):
            expectations.append({
                "expectation_type": "expect_column_values_to_be_unique",
                "kwargs": {"column": name},
                "meta": meta,
            })

        if column_profile.get("top_values") and column_profile["unique_count"] <= self.CARDINALITY_LOW_THRESHOLD:
            expectations.append({
                "expectation_type": "expect_column_values_to_be_in_set",
                "kwargs": {
                    "column": name,
                    "value_set": list(column_profile["top_values"].keys()),
                },
                "meta": meta,
            })

        return expectations

    def _numeric_expectations(self, name: str, column_profile: dict, meta: dict) -> list[dict]:
        expectations = []
        if column_profile.get("min") is not None and column_profile.get("max") is not None:
            margin = max(abs(column_profile["max"] - column_profile["min"]) * 0.1, 1)
            expectations.append({
                "expectation_type": "expect_column_values_to_be_between",
                "kwargs": {
                    "column": name,
                    "min_value": column_profile["min"] - margin,
                    "max_value": column_profile["max"] + margin,
                    "mostly": 0.99,
                },
                "meta": meta,
            })

        if column_profile.get("negative_count", 0) == 0 and column_profile.get("min", -1) >= 0:
            expectations.append({
                "expectation_type": "expect_column_values_to_be_between",
                "kwargs": {"column": name, "min_value": 0},
                "meta": {**meta, "reason": "no_negatives_observed"},
            })

        return expectations

    def _datetime_expectations(self, name: str, column_profile: dict, meta: dict) -> list[dict]:
        expectations = []
        if column_profile.get("min") and column_profile.get("max"):
            expectations.append({
                "expectation_type": "expect_column_values_to_be_between",
                "kwargs": {
                    "column": name,
                    "min_value": column_profile["min"],
                    "max_value": column_profile["max"],
                    "parse_strings_as_datetimes": True,
                },
                "meta": meta,
            })
        return expectations

    def _string_expectations(self, name: str, column_profile: dict, meta: dict) -> list[dict]:
        expectations = []
        if column_profile.get("max_length") is not None:
            expectations.append({
                "expectation_type": "expect_column_value_lengths_to_be_between",
                "kwargs": {
                    "column": name,
                    "min_value": 0,
                    "max_value": int(column_profile["max_length"] * self.LENGTH_TOLERANCE),
                },
                "meta": meta,
            })

        if column_profile.get("empty_count", 0) == 0:
            expectations.append({
                "expectation_type": "expect_column_value_lengths_to_be_between",
                "kwargs": {"column": name, "min_value": 1},
                "meta": {**meta, "reason": "no_empty_strings_observed"},
            })

        return expectations

    def to_ge_suite(
        self, expectations: list[dict], suite_name: str = "auto_generated",
    ) -> dict:
        """Convert expectations list to a Great Expectations suite JSON."""
        return {
            "expectation_suite_name": suite_name,
            "ge_cloud_id": None,
            "expectations": expectations,
            "meta": {
                "generator": "data-governance-pipeline/TestGenerator",
                "generated_utc": datetime.now(timezone.utc).isoformat(),
            },
        }

    def save_suite(
        self, expectations: list[dict], path: str | Path,
        suite_name: str = "auto_generated",
    ) -> Path:
        """Save expectations as a Great Expectations suite JSON file."""
        if not expectations:
            logger.warning("[TESTGEN] Saving suite '%s' with zero expectations", suite_name)

        suite = self.to_ge_suite(expectations, suite_name)
        out_path = Path(path)

        if not self.dry_run:
            out_path.write_text(json.dumps(suite, indent=2), encoding="utf-8")
            logger.info("[TESTGEN] Saved suite '%s' with %d expectations to %s",
                         suite_name, len(expectations), out_path)
        else:
            logger.info("[TESTGEN] dry_run — skipping write of suite '%s' to %s",
                         suite_name, out_path)

        return out_path
