"""
Statistical profiling for DataFrames.

Generates column-level statistics (nulls, uniques, numeric ranges,
string lengths) and writes a JSON profile report.

Layer 2 — imports from Layer 1 (governance_logger).
"""

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DataProfiler:
    """
    Generates a statistical profile of a DataFrame.

    Quick-start
    -----------
        from pipeline.profiler import DataProfiler
        profiler = DataProfiler(gov)
        profile = profiler.profile(df)
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def save_json(self, profile: dict, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(profile, indent=2, default=str), encoding="utf-8")
        return out

    def profile(self, df: "pd.DataFrame") -> dict:
        import pandas as pd

        row_count = len(df)
        dup_count = int(df.duplicated().sum())
        total_cells = row_count * len(df.columns)
        total_nulls = int(df.isnull().sum().sum())
        null_rate = round(total_nulls / total_cells, 4) if total_cells else 0

        columns_profile = {}
        for col in df.columns:
            s = df[col]
            null_count = int(s.isnull().sum())
            cp: dict = {
                "dtype": str(s.dtype),
                "null_count": null_count,
                "null_pct": round(null_count / row_count, 4) if row_count else 0,
                "unique_count": int(s.nunique(dropna=True)),
            }
            if pd.api.types.is_numeric_dtype(s):
                desc = s.describe()
                cp.update({
                    k: float(desc.get(dk, float("nan")))
                    for k, dk in [
                        ("min", "min"), ("max", "max"), ("mean", "mean"),
                        ("std", "std"), ("p25", "25%"), ("p50", "50%"), ("p75", "75%"),
                    ]
                })
            elif s.dtype == object:
                ls = s.dropna().astype(str).str.len()
                cp.update({
                    "min_length": int(ls.min()) if len(ls) else 0,
                    "max_length": int(ls.max()) if len(ls) else 0,
                    "sample_values": s.value_counts().head(5).index.tolist(),
                })
            columns_profile[col] = cp

        profile = {
            "table": {
                "row_count": row_count,
                "column_count": len(df.columns),
                "duplicate_row_count": dup_count,
                "total_null_count": total_nulls,
                "overall_null_rate": null_rate,
            },
            "columns": columns_profile,
        }
        self.gov.profile_recorded({
            "row_count": row_count, "column_count": len(df.columns),
            "duplicate_count": dup_count, "overall_null_rate": null_rate,
        })
        self.gov.write_profile_report(profile)
        return profile
