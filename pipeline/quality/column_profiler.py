"""
Automated column profiling — generates statistics for every column.

Computes null rates, cardinality, min/max, mean/std, distributions,
and value frequency. Stores historical profiles as JSONL.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

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
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class ColumnProfiler:
    """
    Generates column-level statistics for a DataFrame.

    Quick-start
    -----------
        from pipeline.quality.column_profiler import ColumnProfiler
        profiler = ColumnProfiler(gov)
        profile = profiler.profile(df, dataset_name="customers")
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        history_file: str | Path | None = None,
    ) -> None:
        self.gov = gov
        self.history_file = (
            Path(history_file) if history_file
            else gov.log_dir / "column_profiles.jsonl"
        )

    def profile(
        self,
        df: "pd.DataFrame",
        dataset_name: str = "",
        top_n: int = 10,
    ) -> dict:
        """
        Profile all columns and return structured statistics.

        Returns dict with keys: dataset_name, row_count, column_count,
        generated_utc, columns (list of per-column profiles).
        """
        import pandas as pd

        columns = []
        for col in df.columns:
            series = df[col]
            prof: dict = {
                "name": col,
                "dtype": str(series.dtype),
                "null_count": int(series.isna().sum()),
                "null_rate": round(series.isna().mean(), 4),
                "unique_count": int(series.nunique()),
                "cardinality_rate": round(
                    series.nunique() / len(df), 4
                ) if len(df) > 0 else 0.0,
            }

            non_null = series.dropna()

            if pd.api.types.is_numeric_dtype(series):
                desc = non_null.describe()
                prof.update({
                    "min": float(desc["min"]) if len(non_null) > 0 else None,
                    "max": float(desc["max"]) if len(non_null) > 0 else None,
                    "mean": round(float(desc["mean"]), 4) if len(non_null) > 0 else None,
                    "std": round(float(desc["std"]), 4) if len(non_null) > 0 else None,
                    "median": round(float(non_null.median()), 4) if len(non_null) > 0 else None,
                    "p25": float(desc["25%"]) if len(non_null) > 0 else None,
                    "p75": float(desc["75%"]) if len(non_null) > 0 else None,
                    "zero_count": int((non_null == 0).sum()),
                    "negative_count": int((non_null < 0).sum()),
                })

            elif pd.api.types.is_datetime64_any_dtype(series):
                if len(non_null) > 0:
                    prof.update({
                        "min": str(non_null.min()),
                        "max": str(non_null.max()),
                        "range_days": (non_null.max() - non_null.min()).days,
                    })

            elif pd.api.types.is_string_dtype(series) or series.dtype == object:
                str_vals = non_null.astype(str)
                if len(str_vals) > 0:
                    lengths = str_vals.str.len()
                    prof.update({
                        "min_length": int(lengths.min()),
                        "max_length": int(lengths.max()),
                        "mean_length": round(float(lengths.mean()), 1),
                        "empty_count": int((str_vals == "").sum()),
                    })

            if prof["unique_count"] > 0:
                vc = non_null.value_counts().head(top_n)
                prof["top_values"] = {str(k): int(v) for k, v in vc.items()}
                if prof["unique_count"] > top_n * 2:
                    prof["top_values_truncated"] = True

            columns.append(prof)

        report = {
            "dataset_name": dataset_name,
            "row_count": len(df),
            "column_count": len(df.columns),
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "columns": columns,
        }

        with open(self.history_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(report, default=str) + "\n")

        self.gov.transformation_applied("COLUMN_PROFILE_GENERATED", {
            "dataset": dataset_name,
            "rows": len(df), "columns": len(df.columns),
        })
        logger.info("[PROFILE] Profiled '%s': %d rows, %d columns",
                     dataset_name, len(df), len(df.columns))
        return report

    def history(self, dataset_name: str = "", n: int = 30) -> list[dict]:
        """Return last n profiling records, optionally filtered by dataset."""
        if not self.history_file.exists():
            return []
        lines = self.history_file.read_text(encoding="utf-8").strip().splitlines()
        records = []
        for line in reversed(lines):
            try:
                rec = json.loads(line)
                if dataset_name and rec.get("dataset_name") != dataset_name:
                    continue
                records.append(rec)
                if len(records) >= n:
                    break
            except json.JSONDecodeError:
                pass
        return records
