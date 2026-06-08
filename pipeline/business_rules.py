"""
Operator-defined transformation rules from JSON config.

Supports: rename, fill_null, map_values, derive, filter_out, flag.
Non-developers can define transformation logic without writing Python.

Layer 2 — imports from Layer 1 (governance_logger).
"""

import json
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class BusinessRuleEngine:
    """
    Applies business rules loaded from a JSON config file.

    Quick-start
    -----------
        from pipeline.business_rules import BusinessRuleEngine
        bre = BusinessRuleEngine(gov)
        rules = bre.load_rules("business_rules.json")
        df = bre.apply(df, rules)
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def load_rules(self, rules_file: str) -> list[dict]:
        with open(rules_file, encoding="utf-8") as f:
            rules = json.load(f)
        logger.info("[RULES] Loaded %d rule(s) from %s", len(rules), rules_file)
        return rules

    def apply(self, df: "pd.DataFrame", rules: list[dict]) -> "pd.DataFrame":
        """Apply a list of rules to the DataFrame in order."""
        import pandas as pd

        for rule in rules:
            rule_name = rule.get("name", rule.get("type", "unnamed"))
            rule_type = rule.get("type", "").lower()
            rows_before = len(df)

            try:
                if rule_type == "rename":
                    if rule["from"] in df.columns:
                        df = df.rename(columns={rule["from"]: rule["to"]})
                        self.gov.rule_applied(rule_name, "rename", len(df))

                elif rule_type == "fill_null":
                    col = rule["column"]
                    if col in df.columns:
                        null_count = int(df[col].isnull().sum())
                        df[col] = df[col].fillna(rule["value"])
                        self.gov.rule_applied(rule_name, "fill_null", null_count)

                elif rule_type == "map_values":
                    col = rule["column"]
                    if col in df.columns:
                        mapping = rule["mapping"]
                        changed = int(df[col].isin(mapping.keys()).sum())
                        df[col] = df[col].replace(mapping)
                        self.gov.rule_applied(rule_name, "map_values", changed)

                elif rule_type == "derive":
                    expr = rule["expression"]
                    src_cols = rule.get("source_columns", [])
                    local_ns = {col: df[col] for col in src_cols if col in df.columns}
                    safe = re.sub(r"[^a-zA-Z0-9_\s\+\-\*/\(\)\.]", "", expr)
                    if safe != expr:
                        raise ValueError(f"Unsafe expression: {expr!r}")
                    _blocked = [
                        "__", "import", "exec", "eval", "compile",
                        "getattr", "setattr", "delattr",
                        "globals", "locals", "open", "system",
                    ]
                    _expr_lower = expr.lower()
                    for _kw in _blocked:
                        if _kw in _expr_lower:
                            raise ValueError(
                                f"Blocked keyword {_kw!r} in expression: {expr!r}"
                            )
                    try:
                        df[rule["new_column"]] = pd.eval(
                            expr, local_dict=local_ns,
                        )
                    except Exception as eval_exc:
                        raise ValueError(
                            f"derive rule expression failed: {expr!r} → {eval_exc}"
                        ) from eval_exc
                    self.gov.rule_applied(rule_name, "derive", len(df))

                elif rule_type == "filter_out":
                    col = rule["column"]
                    if col in df.columns:
                        mask = df[col].astype(str).str.lower() != str(rule["value"]).lower()
                        filtered = rows_before - int(mask.sum())
                        df = df[mask].reset_index(drop=True)
                        self.gov.rule_applied(rule_name, "filter_out", filtered)

                elif rule_type == "flag":
                    col = rule["condition_column"]
                    if col in df.columns:
                        op = rule.get("operator", "gt").lower()
                        thr = rule.get("threshold", 0)
                        ops = {
                            "gt": lambda s, v: s > v,
                            "gte": lambda s, v: s >= v,
                            "lt": lambda s, v: s < v,
                            "lte": lambda s, v: s <= v,
                            "eq": lambda s, v: s == v,
                            "neq": lambda s, v: s != v,
                        }
                        numeric_col = pd.to_numeric(df[col], errors="coerce")
                        flagged = int(ops[op](numeric_col, thr).sum())
                        df[rule["new_column"]] = ops[op](numeric_col, thr)
                        self.gov.rule_applied(rule_name, "flag", flagged)

                else:
                    logger.warning("[RULES] Unknown rule type: %r", rule_type)

            except Exception as exc:
                self.gov.error(f"RULE_FAILED:{rule_name}", exc)

        return df
