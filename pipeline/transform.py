"""
All transformation steps: flatten, minimise, PII strategy, dedup, sanitise.

Operates on DataFrames using vectorised operations instead of iterrows()
for ~10-20x performance improvement on wide DataFrames.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).
"""

import re
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pipeline.constants import default_run_context
from pipeline.helpers import flatten_record as _flatten_record, mask_value

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_COL_SANITISE = re.compile(r"[^a-z0-9_]")


class Transformer:
    """
    Applies all transformation steps to a DataFrame.

    Quick-start
    -----------
        from pipeline.transform import Transformer
        t = Transformer(gov)
        df = t.transform(df, pii_findings, "mask", drop_cols=["internal_id"])
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        array_strategy: str = "index",
        join_sep: str = ",",
        max_depth: int = 20,
        sep: str = "__",
        run_context=None,
    ) -> None:
        self.gov = gov
        self.pii_actions: dict[str, str] = {}
        self._array_strategy = array_strategy
        self._join_sep = join_sep
        self._max_depth = max_depth
        self._sep = sep
        self.run_context = run_context or default_run_context()

    def _flatten_kw(self) -> dict:
        return {"separator": self._sep}

    @staticmethod
    def _flatten_df(df, obj_cols: list, flatten_kw: dict):
        """Flatten remaining dict/list cells without iterrows() — vectorised."""
        import pandas as pd

        scalar_cols = [c for c in df.columns if c not in obj_cols]
        parts = [df[scalar_cols].reset_index(drop=True)]

        for col in obj_cols:
            series = df[col].reset_index(drop=True)
            expanded = series.apply(
                lambda v, _col=col, _fkw=flatten_kw:
                    _flatten_record(v, parent_key=_col, separator=_fkw.get("separator", "__"))
                    if isinstance(v, (dict, list)) else {_col: v}
            )
            parts.append(pd.DataFrame(list(expanded)))

        result = pd.concat(parts, axis=1)
        result = result.loc[:, ~result.columns.duplicated()]
        return result

    def mask_pii(self, df, columns: list[str]):
        """Hash-mask the listed columns in place (SHA-256, 8 hex chars)."""
        import hashlib
        import pandas as pd
        df = df.copy()
        for col in columns:
            if col in df.columns:
                df[col] = df[col].apply(
                    lambda v: hashlib.sha256(str(v).encode()).hexdigest()[:8]
                    if not pd.isna(v) else None
                )
        return df

    def drop_duplicates(self, df, subset: list[str] | None = None):
        return df.drop_duplicates(subset=subset).reset_index(drop=True)

    def fill_nulls(self, df, fill: dict | None = None):
        import pandas as pd
        df = df.copy()
        if fill:
            df = df.fillna(fill)
        else:
            for col in df.columns:
                if df[col].dtype == object or pd.api.types.is_string_dtype(df[col]):
                    df[col] = df[col].fillna("")
                else:
                    df[col] = df[col].fillna(0)
        return df

    def standardise_names(self, df):
        df = df.copy()
        df.columns = [_COL_SANITISE.sub("", c.lower().replace(" ", "_")) for c in df.columns]
        return df

    def flatten_nested(self, df, sep: str = "_", max_level: int = 3):
        return self._flatten_df(
            df,
            [c for c in df.columns if df[c].dtype == object],
            self._flatten_kw(),
        )

    def coerce_types(self, df, mapping: dict[str, str]):
        df = df.copy()
        for col, dtype in mapping.items():
            if col in df.columns:
                try:
                    df[col] = df[col].astype(dtype)
                except (ValueError, TypeError) as exc:
                    logger.debug("Could not coerce %s to %s: %s", col, dtype, exc)
        return df

    def apply_business_rules(self, df, rules: list):
        df = df.copy()
        for rule in rules:
            col = rule.get("column")
            op = rule.get("op")
            val = rule.get("value")
            if col not in df.columns:
                continue
            if op == "gt":
                df = df[df[col] > val]
            elif op == "lt":
                df = df[df[col] < val]
            elif op == "eq":
                df = df[df[col] == val]
            elif op == "drop_if_null":
                df = df[df[col].notna()]
        return df.reset_index(drop=True)

    def enrich(self, df, lookups: dict):
        df = df.copy()
        for join_col, lookup_df in lookups.items():
            if join_col in df.columns and join_col in lookup_df.columns:
                df = df.merge(lookup_df, on=join_col, how="left", suffixes=("", "_lookup"))
        return df

    def transform(self, df, pii_findings, pii_strategy, drop_cols) -> "pd.DataFrame":
        """Full transformation pipeline: flatten, minimise, PII, dedup, sanitise."""
        if pii_findings and isinstance(pii_findings[0], str):
            pii_findings = [{"field": col} for col in pii_findings]

        original_cols = list(df.columns)

        obj_cols = [
            c for c in df.columns
            if df[c].dtype == object
            and df[c].dropna().apply(lambda x: isinstance(x, (dict, list))).any()
        ]
        if obj_cols:
            df = self._flatten_df(df, obj_cols, self._flatten_kw())
            self.gov.transformation_applied("FLATTEN_NESTED", {"flattened_columns": obj_cols})

        if drop_cols:
            df = df.drop(columns=[c for c in drop_cols if c in df.columns],
                         errors="ignore")
            self.gov.data_minimization(original_cols, list(df.columns), drop_cols)

        for field in {f["field"]: f for f in pii_findings if f["field"] in df.columns}:
            if pii_strategy == "mask":
                df[field] = df[field].apply(mask_value)
                self.gov.pii_action(field, "MASKED")
                self.pii_actions[field] = "MASKED"
            elif pii_strategy == "drop":
                df = df.drop(columns=[field], errors="ignore")
                self.gov.pii_action(field, "DROPPED")
                self.pii_actions[field] = "DROPPED"
            else:
                self.gov.pii_action(field, "RETAINED_WITH_CONSENT")
                self.pii_actions[field] = "RETAINED_WITH_CONSENT"

        null_before = int(df.isnull().sum().sum())
        df = df.dropna(how="all")
        self.gov.transformation_applied("NULL_HANDLING", {
            "null_cells_before": null_before,
            "null_cells_after": int(df.isnull().sum().sum()),
        })

        rows_before = len(df)
        df = df.drop_duplicates()
        self.gov.transformation_applied("DEDUPLICATION", {
            "rows_before": rows_before, "rows_after": len(df),
            "duplicates_removed": rows_before - len(df),
        })

        def _sanitise_col(c: str) -> str:
            sanitised = re.sub(r"[^a-zA-Z0-9_]", "_", c)
            if c.startswith("_"):
                return sanitised.rstrip("_")
            return sanitised.strip("_")

        df.columns = [_sanitise_col(c) for c in df.columns]
        self.gov.transformation_applied("COLUMN_SANITIZATION", {
            "final_columns": list(df.columns),
        })

        df["_pipeline_id"] = self.run_context.pipeline_id
        df["_loaded_at_utc"] = datetime.now(timezone.utc).isoformat()
        self.gov.transformation_applied("TRANSFORM_COMPLETE", {
            "final_row_count": len(df), "final_col_count": len(df.columns),
        })
        return df
