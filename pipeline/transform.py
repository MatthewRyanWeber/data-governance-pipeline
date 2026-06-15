"""
All transformation steps: flatten, minimise, PII strategy, dedup, sanitise.

Operates on DataFrames using vectorised operations instead of iterrows()
for ~10-20x performance improvement on wide DataFrames.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-11   PII detection re-runs on columns created by flattening so
                   nested PII (user → user__email) is masked; flatten_nested
                   honours its sep/max_level parameters and only processes
                   columns that actually contain dicts/lists.
1.2   2026-06-15   Masking skips null cells — a missing PII value is no longer
                   turned into a MASKED_ token (it inflated the non-null count
                   and diverged by reader null representation). Masked output is
                   now identical across compute engines.
"""

import re
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pipeline.constants import default_run_context
from pipeline.helpers import detect_pii, flatten_record as _flatten_record, mask_value

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_COL_SANITISE = re.compile(r"[^a-z0-9_]")


def sanitise_column_name(name: str) -> str:
    """Normalise a column name: lowercase, replace non-alphanumeric with underscore, strip edges."""
    result = _COL_SANITISE.sub("_", name.lower())
    return result.strip("_")


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
        return {"separator": self._sep, "max_depth": self._max_depth}

    @staticmethod
    def _columns_containing_nested_values(df) -> list:
        """Object columns that actually hold dicts/lists — plain strings are skipped."""
        return [
            c for c in df.columns
            if df[c].dtype == object
            and df[c].dropna().apply(lambda x: isinstance(x, (dict, list))).any()
        ]

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
                    _flatten_record(
                        v,
                        parent_key=_col,
                        separator=_fkw.get("separator", "__"),
                        max_depth=_fkw.get("max_depth"),
                    )
                    if isinstance(v, (dict, list)) else {_col: v}
            )
            parts.append(pd.DataFrame(list(expanded)))

        result = pd.concat(parts, axis=1)
        result = result.loc[:, ~result.columns.duplicated()]
        return result

    def _detect_pii_in_flattened_columns(
        self, columns, original_columns: list[str], separator: str,
    ) -> list[dict]:
        """Detect PII in columns created by flattening.

        Flattening happens after the caller's PII scan, so nested PII
        (user → user__email) would otherwise escape masking. Each separator
        segment is scanned individually because the PII patterns anchor on
        word boundaries that the separator suppresses.
        """
        findings: list[dict] = []
        for column_name in columns:
            if column_name in original_columns:
                continue
            segment_findings = detect_pii(str(column_name).split(separator))
            if segment_findings:
                finding = dict(segment_findings[0])
                finding["field"] = column_name
                findings.append(finding)
        return findings

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
        df.columns = [sanitise_column_name(c) for c in df.columns]
        return df

    def flatten_nested(self, df, sep: str = "_", max_level: int = 3):
        nested_columns = self._columns_containing_nested_values(df)
        if not nested_columns:
            return df.copy()
        return self._flatten_df(
            df,
            nested_columns,
            {"separator": sep, "max_depth": max_level},
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
        """Full transformation pipeline: flatten, minimise, PII, dedup, sanitise.

        Pass pii_findings=None to disable the PII stage entirely (--skip-pii);
        an empty list still allows supplemental detection on columns created
        by flattening, which the caller's pre-flatten scan cannot see.
        """
        pii_detection_enabled = pii_findings is not None
        pii_findings = list(pii_findings or [])
        if pii_findings and isinstance(pii_findings[0], str):
            pii_findings = [{"field": col} for col in pii_findings]

        original_cols = list(df.columns)

        obj_cols = self._columns_containing_nested_values(df)
        if obj_cols:
            df = self._flatten_df(df, obj_cols, self._flatten_kw())
            self.gov.transformation_applied("FLATTEN_NESTED", {"flattened_columns": obj_cols})
            if pii_detection_enabled:
                pii_findings.extend(
                    self._detect_pii_in_flattened_columns(
                        df.columns, original_cols, self._sep,
                    )
                )

        if drop_cols:
            df = df.drop(columns=[c for c in drop_cols if c in df.columns],
                         errors="ignore")
            self.gov.data_minimization(original_cols, list(df.columns), drop_cols)

        for field in {f["field"]: f for f in pii_findings if f["field"] in df.columns}:
            if pii_strategy == "mask":
                # Mask only present values: masking a null/absent cell would
                # fabricate a token for data that isn't there (and inflate the
                # non-null count) — and it makes the masked output identical
                # regardless of how the reader represents null (pandas NaN vs
                # DuckDB None), so the compute engine can never change it.
                present = df[field].notna()
                df.loc[present, field] = df.loc[present, field].apply(mask_value)
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

        df.columns = [sanitise_column_name(c) for c in df.columns]
        self.gov.transformation_applied("COLUMN_SANITIZATION", {
            "final_columns": list(df.columns),
        })

        df["_pipeline_id"] = self.run_context.pipeline_id
        df["_loaded_at_utc"] = datetime.now(timezone.utc).isoformat()
        self.gov.transformation_applied("TRANSFORM_COMPLETE", {
            "final_row_count": len(df), "final_col_count": len(df.columns),
        })
        return df
