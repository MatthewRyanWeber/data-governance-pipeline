"""
Config-driven transformation orchestrator.

Chains all existing transformers (Transformer, BusinessRuleEngine,
DataStandardiser, TypeCoercer, DataEnricher, ReferentialIntegrityChecker)
into a single declarative pipeline defined by a YAML/JSON config.

Layer 4 — imports from Layer 2 (transform, standardiser, type_coercer,
          enricher, business_rules, referential_integrity).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-11   Rules and reference files are cached by (path, mtime) via
                   helpers.load_file_cached so chunked runs parse each file
                   once; referential-integrity validation runs against the
                   cached reference frame.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.helpers import load_file_cached

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger
    from pipeline.dead_letter_queue import DeadLetterQueue

logger = logging.getLogger(__name__)


class TransformPipeline:
    """
    Orchestrates multiple transformation steps from a declarative config.

    Quick-start
    -----------
        from pipeline.transform_pipeline import TransformPipeline
        tp = TransformPipeline(gov, dlq)
        df = tp.run(df, {
            "steps": [
                {"type": "standardise", "rules": {"phone": "phone_e164"}},
                {"type": "coerce_types", "mapping": {"id": "int", "hired": "datetime"}},
                {"type": "business_rules", "rules_file": "rules.json"},
                {"type": "deduplicate", "subset": ["email"]},
                {"type": "aggregate", "group_by": ["department"], "aggs": {"salary": "mean"}},
                {"type": "enrich", "join_col": "dept_id", "lookup": "depts.csv", "lookup_key": "id"},
                {"type": "filter", "column": "status", "op": "eq", "value": "active"},
                {"type": "fill_nulls", "fill": {"city": "Unknown"}},
                {"type": "referential_integrity", "fk_col": "dept_id", "ref": "depts.csv", "ref_col": "id"},
            ]
        })
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        dlq: "DeadLetterQueue | None" = None,
    ) -> None:
        self.gov = gov
        self.dlq = dlq
        self._step_handlers = {
            "standardise": self._step_standardise,
            "standardize": self._step_standardise,
            "coerce_types": self._step_coerce_types,
            "business_rules": self._step_business_rules,
            "deduplicate": self._step_deduplicate,
            "aggregate": self._step_aggregate,
            "enrich": self._step_enrich,
            "fill_nulls": self._step_fill_nulls,
            "drop_columns": self._step_drop_columns,
            "rename_columns": self._step_rename_columns,
            "filter": self._step_filter,
            "sort": self._step_sort,
            "referential_integrity": self._step_referential_integrity,
            "mask_pii": self._step_mask_pii,
            "flatten": self._step_flatten,
        }

    def run(
        self,
        df: "pd.DataFrame",
        config: dict,
    ) -> "pd.DataFrame":
        """Execute all steps in order, returning the transformed DataFrame."""
        steps = config.get("steps", [])
        if not steps:
            logger.warning("[TRANSFORM_PIPELINE] No steps defined — returning data unchanged.")
            return df

        logger.info("[TRANSFORM_PIPELINE] Running %d step(s)…", len(steps))

        for i, step in enumerate(steps):
            step_type = step.get("type", "").lower()
            step_name = step.get("name", f"step_{i}_{step_type}")

            handler = self._step_handlers.get(step_type)
            if handler is None:
                logger.warning(
                    "[TRANSFORM_PIPELINE] Unknown step type %r at index %d — skipping.",
                    step_type, i,
                )
                continue

            rows_before = len(df)
            cols_before = len(df.columns)

            try:
                df = handler(df, step)
            except Exception as exc:
                on_error = step.get("on_error", "warn")
                if on_error == "halt":
                    raise RuntimeError(
                        f"Transform step '{step_name}' failed: {exc}"
                    ) from exc
                logger.warning(
                    "[TRANSFORM_PIPELINE] Step '%s' failed: %s — continuing.",
                    step_name, exc,
                )
                self.gov.error(f"TRANSFORM_STEP_FAILED:{step_name}", exc)
                continue

            logger.info(
                "[TRANSFORM_PIPELINE] [%d/%d] %s: %d→%d rows, %d→%d cols",
                i + 1, len(steps), step_type,
                rows_before, len(df), cols_before, len(df.columns),
            )
            self.gov.transformation_applied(f"PIPELINE_STEP:{step_type}", {
                "step_index": i,
                "step_name": step_name,
                "rows_before": rows_before,
                "rows_after": len(df),
            })

        logger.info(
            "[TRANSFORM_PIPELINE] Complete — %d rows, %d columns.",
            len(df), len(df.columns),
        )
        return df

    # ── Step implementations ──────────────────────────────────────────────

    def _step_standardise(self, df, step):
        from pipeline.data_standardiser import DataStandardiser
        ds = DataStandardiser(self.gov)
        rules = step.get("rules", {})
        return ds.standardise(df, rules)

    def _step_coerce_types(self, df, step):
        from pipeline.type_coercer import TypeCoercer
        tc = TypeCoercer(self.gov)
        return tc.coerce(df, step.get("mapping", {}))

    def _step_business_rules(self, df, step):
        from pipeline.business_rules import BusinessRuleEngine
        bre = BusinessRuleEngine(self.gov)
        if "rules_file" in step:
            # Cached by (path, mtime) — chunked runs would otherwise re-parse
            # the same rules file once per chunk.
            rules = load_file_cached(step["rules_file"], bre.load_rules)
        else:
            rules = step.get("rules", [])
        return bre.apply(df, rules)

    def _step_deduplicate(self, df, step):
        subset = step.get("subset")
        keep = step.get("keep", "first")
        rows_before = len(df)
        df = df.drop_duplicates(subset=subset, keep=keep).reset_index(drop=True)
        self.gov.transformation_applied("DEDUPLICATION", {
            "rows_before": rows_before,
            "rows_after": len(df),
            "duplicates_removed": rows_before - len(df),
        })
        return df

    def _step_aggregate(self, df, step):
        """Group-by aggregation with common functions."""
        import pandas as pd

        group_by = step.get("group_by", [])
        aggs = step.get("aggs", {})

        if not group_by or not aggs:
            logger.warning("[TRANSFORM_PIPELINE] aggregate step needs 'group_by' and 'aggs'.")
            return df

        missing_cols = [c for c in group_by if c not in df.columns]
        if missing_cols:
            logger.warning("[TRANSFORM_PIPELINE] aggregate: missing group_by columns: %s", missing_cols)
            return df

        valid_aggs = {}
        for col, func in aggs.items():
            if col not in df.columns:
                logger.warning("[TRANSFORM_PIPELINE] aggregate: column '%s' not found — skipping.", col)
                continue
            if isinstance(func, str):
                valid_aggs[col] = func
            elif isinstance(func, list):
                valid_aggs[col] = func

        if not valid_aggs:
            return df

        result = df.groupby(group_by, as_index=False).agg(valid_aggs)

        if isinstance(result.columns, pd.MultiIndex):
            result.columns = [
                f"{col}_{func}" if func else col
                for col, func in result.columns
            ]

        self.gov.transformation_applied("AGGREGATION", {
            "group_by": group_by,
            "aggs": {k: str(v) for k, v in aggs.items()},
            "rows_before": len(df),
            "rows_after": len(result),
        })
        return result

    def _step_enrich(self, df, step):
        from pipeline.data_enricher import DataEnricher
        enricher = DataEnricher(self.gov)
        return enricher.enrich(
            df,
            join_col=step["join_col"],
            lookup_path=step["lookup"],
            lookup_key=step.get("lookup_key", step["join_col"]),
            lookup_cols=step.get("lookup_cols"),
        )

    def _step_fill_nulls(self, df, step):
        fill = step.get("fill", {})
        strategy = step.get("strategy", "value")

        if strategy == "value" and fill:
            df = df.fillna(fill)
        elif strategy == "forward":
            df = df.ffill()
        elif strategy == "backward":
            df = df.bfill()
        elif strategy == "mean":
            numeric = df.select_dtypes(include="number").columns
            df[numeric] = df[numeric].fillna(df[numeric].mean())
        elif strategy == "median":
            numeric = df.select_dtypes(include="number").columns
            df[numeric] = df[numeric].fillna(df[numeric].median())

        return df

    def _step_drop_columns(self, df, step):
        columns = step.get("columns", [])
        existing = [c for c in columns if c in df.columns]
        if existing:
            df = df.drop(columns=existing)
            self.gov.data_minimization(
                list(df.columns) + existing,
                list(df.columns),
                existing,
            )
        return df

    def _step_rename_columns(self, df, step):
        mapping = step.get("mapping", {})
        valid = {k: v for k, v in mapping.items() if k in df.columns}
        if valid:
            df = df.rename(columns=valid)
        return df

    def _step_filter(self, df, step):
        column = step.get("column")
        op = step.get("op", "eq")
        value = step.get("value")

        if column not in df.columns:
            logger.warning("[TRANSFORM_PIPELINE] filter: column '%s' not found.", column)
            return df

        ops = {
            "eq": lambda s, v: s == v,
            "neq": lambda s, v: s != v,
            "gt": lambda s, v: s > v,
            "gte": lambda s, v: s >= v,
            "lt": lambda s, v: s < v,
            "lte": lambda s, v: s <= v,
            "in": lambda s, v: s.isin(v),
            "not_in": lambda s, v: ~s.isin(v),
            "contains": lambda s, v: s.astype(str).str.contains(str(v), na=False),
            "not_null": lambda s, v: s.notna(),
            "is_null": lambda s, v: s.isna(),
        }

        if op not in ops:
            raise ValueError(f"Unknown filter operator: {op!r}. Must be one of: {sorted(ops)}")

        mask = ops[op](df[column], value)
        return df[mask].reset_index(drop=True)

    def _step_sort(self, df, step):
        by = step.get("by", [])
        ascending = step.get("ascending", True)
        if by:
            valid = [c for c in by if c in df.columns]
            if valid:
                df = df.sort_values(valid, ascending=ascending).reset_index(drop=True)
        return df

    @staticmethod
    def _read_reference_file(reference_path: str):
        """Read a CSV/Excel/JSON reference file — mirrors the checker's formats."""
        import pandas as pd

        ext = Path(reference_path).suffix.lower()
        if ext == ".csv":
            return pd.read_csv(reference_path, encoding="utf-8")
        if ext in (".xlsx", ".xls"):
            return pd.read_excel(reference_path)
        if ext == ".json":
            return pd.read_json(reference_path)
        logger.warning("[REFERENTIAL_INTEGRITY] Unsupported reference format: %s", ext)
        return None

    def _step_referential_integrity(self, df, step):
        if self.dlq is None:
            logger.warning("[TRANSFORM_PIPELINE] referential_integrity requires a DLQ — skipping.")
            return df

        fk_col = step["fk_col"]
        reference_path = step["ref"]
        reference_col = step.get("ref_col", step["fk_col"])
        on_violation = step.get("on_violation", "dlq")

        if fk_col not in df.columns:
            logger.warning(
                "[REFERENTIAL_INTEGRITY] Foreign key column '%s' not found — skipping.",
                fk_col,
            )
            return df

        # The validation mirrors ReferentialIntegrityChecker.check but runs
        # against a (path, mtime)-cached reference frame: the checker re-reads
        # the reference file from disk on every call, which re-parsed the same
        # file once per chunk in chunked runs.
        reference_df = load_file_cached(reference_path, self._read_reference_file)
        if reference_df is None:
            return df

        valid_keys = set(reference_df[reference_col].dropna().astype(str))
        foreign_keys_as_str = df[fk_col].astype(str)
        valid_mask = foreign_keys_as_str.isin(valid_keys)
        invalid_count = int((~valid_mask).sum())
        valid_count = int(valid_mask.sum())

        self.gov.referential_integrity_checked(
            fk_col, reference_path, valid_count, invalid_count,
        )

        if invalid_count > 0:
            invalid_values = df.loc[~valid_mask, fk_col].unique().tolist()
            logger.warning(
                "[RI CHECK] '%s': %d invalid FK value(s): %s%s",
                fk_col, invalid_count,
                invalid_values[:5], "…" if len(invalid_values) > 5 else "",
            )
            if on_violation == "dlq":
                bad_indices = df.index[~valid_mask].tolist()
                reason = (
                    f"REFERENTIAL_INTEGRITY: '{fk_col}' value not found "
                    f"in '{reference_path}':'{reference_col}'"
                )
                df = self.dlq.write(df, bad_indices, reason)
        else:
            logger.info("[RI CHECK] '%s': all %d values valid.", fk_col, valid_count)

        return df

    def _step_mask_pii(self, df, step):
        from pipeline.transform import Transformer
        t = Transformer(self.gov)
        columns = step.get("columns", [])
        return t.mask_pii(df, columns)

    def _step_flatten(self, df, step):
        from pipeline.transform import Transformer
        t = Transformer(self.gov, sep=step.get("sep", "__"))
        return t.flatten_nested(
            df,
            sep=step.get("sep", "__"),
            max_level=step.get("max_level", 3),
        )
