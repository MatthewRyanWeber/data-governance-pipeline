"""
Automated test generation — creates Great Expectations from column profiles.

Analyzes profiling results and generates appropriate expectation suites
so users don't have to author them manually.

Layer 3 — imports from Layer 0 (constants).

Revision history
────────────────
1.0   2026-06-08   Initial release.
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

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

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
        expectations: list[dict] = []

        for col in profile.get("columns", []):
            expectations.extend(self._generate_for_column(col))

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

    def _generate_for_column(self, col: dict) -> list[dict]:
        """Generate expectations for a single column based on its profile."""
        exps: list[dict] = []
        name = col["name"]
        meta = {"source": "auto_generated", "column": name}

        if col.get("null_rate", 0) == 0:
            exps.append({
                "expectation_type": "expect_column_values_to_not_be_null",
                "kwargs": {"column": name},
                "meta": meta,
            })
        elif col.get("null_rate", 1) < self.NULL_RATE_TOLERANCE:
            exps.append({
                "expectation_type": "expect_column_values_to_not_be_null",
                "kwargs": {"column": name, "mostly": 1 - col["null_rate"] - 0.02},
                "meta": meta,
            })

        if col.get("unique_count") == col.get("null_count", -1) + len(
            col.get("top_values", {})
        ):
            pass

        dtype = col.get("dtype", "")

        if "int" in dtype or "float" in dtype:
            exps.extend(self._numeric_expectations(name, col, meta))
        elif "datetime" in dtype:
            exps.extend(self._datetime_expectations(name, col, meta))
        elif dtype == "object" or "str" in dtype:
            exps.extend(self._string_expectations(name, col, meta))

        if (col.get("unique_count", 0) > 0
                and col.get("cardinality_rate", 1) == 1.0
                and col.get("null_rate", 1) == 0):
            exps.append({
                "expectation_type": "expect_column_values_to_be_unique",
                "kwargs": {"column": name},
                "meta": meta,
            })

        if col.get("top_values") and col["unique_count"] <= self.CARDINALITY_LOW_THRESHOLD:
            exps.append({
                "expectation_type": "expect_column_values_to_be_in_set",
                "kwargs": {
                    "column": name,
                    "value_set": list(col["top_values"].keys()),
                },
                "meta": meta,
            })

        return exps

    def _numeric_expectations(self, name: str, col: dict, meta: dict) -> list[dict]:
        exps = []
        if col.get("min") is not None and col.get("max") is not None:
            margin = max(abs(col["max"] - col["min"]) * 0.1, 1)
            exps.append({
                "expectation_type": "expect_column_values_to_be_between",
                "kwargs": {
                    "column": name,
                    "min_value": col["min"] - margin,
                    "max_value": col["max"] + margin,
                    "mostly": 0.99,
                },
                "meta": meta,
            })

        if col.get("negative_count", 0) == 0 and col.get("min", -1) >= 0:
            exps.append({
                "expectation_type": "expect_column_values_to_be_between",
                "kwargs": {"column": name, "min_value": 0},
                "meta": {**meta, "reason": "no_negatives_observed"},
            })

        return exps

    def _datetime_expectations(self, name: str, col: dict, meta: dict) -> list[dict]:
        exps = []
        if col.get("min") and col.get("max"):
            exps.append({
                "expectation_type": "expect_column_values_to_be_between",
                "kwargs": {
                    "column": name,
                    "min_value": col["min"],
                    "max_value": col["max"],
                    "parse_strings_as_datetimes": True,
                },
                "meta": meta,
            })
        return exps

    def _string_expectations(self, name: str, col: dict, meta: dict) -> list[dict]:
        exps = []
        if col.get("max_length") is not None:
            exps.append({
                "expectation_type": "expect_column_value_lengths_to_be_between",
                "kwargs": {
                    "column": name,
                    "min_value": 0,
                    "max_value": int(col["max_length"] * self.LENGTH_TOLERANCE),
                },
                "meta": meta,
            })

        if col.get("empty_count", 0) == 0:
            exps.append({
                "expectation_type": "expect_column_value_lengths_to_be_between",
                "kwargs": {"column": name, "min_value": 1},
                "meta": {**meta, "reason": "no_empty_strings_observed"},
            })

        return exps

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
        suite = self.to_ge_suite(expectations, suite_name)
        out_path = Path(path)
        out_path.write_text(json.dumps(suite, indent=2), encoding="utf-8")
        logger.info("[TESTGEN] Saved suite '%s' with %d expectations to %s",
                     suite_name, len(expectations), out_path)
        return out_path
