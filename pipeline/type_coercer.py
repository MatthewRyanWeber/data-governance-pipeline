"""
Configuration-driven dtype casting for DataFrame columns.

Prevents silent type mis-inference (numeric IDs as floats, ZIP codes losing
leading zeros, dates staying as strings).

Layer 2 — imports from Layer 1 (governance_logger).
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class TypeCoercer:
    """
    Applies explicit dtype casting from a column->type mapping.

    Supported type strings: int, float, str, bool, datetime, date.

    Quick-start
    -----------
        from pipeline.type_coercer import TypeCoercer
        tc = TypeCoercer(gov)
        df = tc.coerce(df, {"id": "int", "hired_date": "datetime", "zip": "str"})
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def coerce(self, df: "pd.DataFrame", type_map: dict[str, str]) -> "pd.DataFrame":
        """Apply type_map to the DataFrame. Missing columns are skipped with a warning."""
        import pandas as pd

        if not type_map:
            return df

        for col, target_type in type_map.items():
            if col not in df.columns:
                logger.warning("[TYPE_COERCE] Column '%s' not found — skipping.", col)
                continue

            original_dtype = str(df[col].dtype)
            try:
                t = target_type.lower()

                if t in ("int", "integer"):
                    before_nulls = int(pd.isnull(df[col]).sum())
                    df[col] = pd.to_numeric(df[col], errors="coerce").astype(pd.Int64Dtype())
                    coerce_failures = int(pd.isnull(df[col]).sum()) - before_nulls
                    if coerce_failures > 0:
                        logger.warning(
                            "[TYPE_COERCE] Column '%s': %d value(s) could not be "
                            "converted to int — set to <NA>.", col, coerce_failures,
                        )

                elif t in ("float", "double", "numeric", "decimal"):
                    before_nulls = int(pd.isnull(df[col]).sum())
                    df[col] = pd.to_numeric(df[col], errors="coerce")
                    coerce_failures = int(pd.isnull(df[col]).sum()) - before_nulls
                    if coerce_failures > 0:
                        logger.warning(
                            "[TYPE_COERCE] Column '%s': %d value(s) could not be "
                            "converted to float — set to NaN.", col, coerce_failures,
                        )

                elif t in ("str", "string", "text", "object"):
                    mask = pd.isna(df[col])
                    df[col] = df[col].astype(str)
                    df[col] = df[col].where(~mask, "")

                elif t in ("bool", "boolean"):
                    bool_map = {
                        "true": True, "1": True, "yes": True, "y": True,
                        "false": False, "0": False, "no": False, "n": False,
                    }
                    df[col] = df[col].apply(
                        lambda x, _m=bool_map: _m.get(str(x).lower(), None)
                        if pd.notna(x) else None
                    ).astype(pd.BooleanDtype())

                elif t in ("datetime", "timestamp"):
                    df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)

                elif t == "date":
                    parsed = pd.to_datetime(df[col], errors="coerce")
                    df[col] = parsed.dt.strftime("%Y-%m-%d").where(parsed.notna(), other=None)

                self.gov.transformation_applied("TYPE_COERCION", {
                    "column": col,
                    "from_dtype": original_dtype,
                    "to_type": target_type,
                })

            except Exception as exc:
                self.gov.error(f"TYPE_COERCION_FAILED:{col}", exc)

        return df
