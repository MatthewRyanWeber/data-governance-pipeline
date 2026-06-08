"""
Great Expectations 1.x schema validation with interactive suite builder.

Auto-generates baseline expectations from DataFrame dtypes, then
optionally lets the operator add custom rules interactively.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_GX, DEFAULT_RUN_CONTEXT
from pipeline.helpers import prompt

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.dead_letter_queue import DeadLetterQueue
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SchemaValidator:
    """
    Validates DataFrames against Great Expectations suites.

    Quick-start
    -----------
        from pipeline.schema_validator import SchemaValidator
        sv = SchemaValidator(gov, dlq)
        expectations = sv.build_suite(df)
        df, failed = sv.validate(df, expectations)
    """

    def __init__(self, gov: "GovernanceLogger", dlq: "DeadLetterQueue | None" = None,
                 run_context=None) -> None:
        self.gov = gov
        self.dlq = dlq
        rc = run_context or DEFAULT_RUN_CONTEXT
        self.suite_name = f"pipeline_suite_{rc.pipeline_id[:8]}"
        self.expectation_configs: list[dict] = []

    def build_suite(self, df: "pd.DataFrame", interactive: bool = True) -> list:
        if not HAS_GX:
            logger.warning("[GREAT_EXPECTATIONS] great-expectations not installed — skipping validation.")
            return []

        from great_expectations import expectations as gxe
        import pandas as pd

        expectations = []
        logger.info("[GREAT_EXPECTATIONS] Auto-generating baseline expectations…")

        for col in df.columns:
            expectations.append(gxe.ExpectColumnToExist(column=col))
            self.expectation_configs.append({"type": "ExpectColumnToExist", "column": col})
            if pd.api.types.is_numeric_dtype(df[col]):
                if df[col].isnull().sum() == 0:
                    expectations.append(gxe.ExpectColumnValuesToNotBeNull(column=col))
                non_null = df[col].dropna()
                if len(non_null):
                    hd = max(abs(float(non_null.max()) - float(non_null.min())) * 0.5, 1)
                    expectations.append(gxe.ExpectColumnValuesToBeBetween(
                        column=col,
                        min_value=float(non_null.min()) - hd,
                        max_value=float(non_null.max()) + hd,
                    ))

        logger.info("[GREAT_EXPECTATIONS] %d baseline expectation(s) generated.", len(expectations))
        if interactive:
            expectations = self._interactive_builder(df, expectations)
        return expectations

    def _interactive_builder(self, df, expectations):
        from great_expectations import expectations as gxe

        cols = list(df.columns)
        logger.info("[GREAT_EXPECTATIONS] Add custom expectations (0 to finish):")
        while True:
            print("  1.Not-null  2.Unique  3.Range  4.Allowed-values  5.Regex  6.Min-rows  0.Done")
            c = prompt("Add", "0")
            if c == "0":
                break
            if c in ("1", "2", "3", "4", "5"):
                col = prompt(f"Column ({', '.join(cols[:8])}…)")
                if col not in cols:
                    print(f"  '{col}' not found.")
                    continue
            if c == "1":
                expectations.append(gxe.ExpectColumnValuesToNotBeNull(column=col))
            elif c == "2":
                expectations.append(gxe.ExpectColumnValuesToBeUnique(column=col))
            elif c == "3":
                try:
                    mn = float(prompt(f"Min {col}"))
                    mx = float(prompt(f"Max {col}"))
                    expectations.append(gxe.ExpectColumnValuesToBeBetween(
                        column=col, min_value=mn, max_value=mx,
                    ))
                except ValueError:
                    print("  Invalid number.")
            elif c == "4":
                vals = [v.strip() for v in input("  Allowed values (comma-sep): ").split(",") if v.strip()]
                if vals:
                    expectations.append(gxe.ExpectColumnValuesToBeInSet(column=col, value_set=vals))
            elif c == "5":
                pat = input(f"  Regex for {col}: ").strip()
                if pat:
                    expectations.append(gxe.ExpectColumnValuesToMatchRegex(column=col, regex=pat))
            elif c == "6":
                try:
                    n = int(prompt("Min rows"))
                    expectations.append(gxe.ExpectTableRowCountToBeBetween(min_value=n))
                except ValueError:
                    print("  Invalid number.")
        return expectations

    def validate(self, df, expectations, on_failure="dlq"):
        if not HAS_GX:
            return df, 0

        import great_expectations as gx

        rc = DEFAULT_RUN_CONTEXT
        logger.info("[GREAT_EXPECTATIONS] Running schema validation…")
        ctx = gx.get_context(mode="ephemeral")
        ds = ctx.data_sources.add_pandas("pipeline_ds")
        asset = ds.add_dataframe_asset("pipeline_asset")
        bdef = asset.add_batch_definition_whole_dataframe("batch_de")
        suite = ctx.suites.add(gx.ExpectationSuite(name=self.suite_name))
        for exp in expectations:
            suite.add_expectation(exp)
        vd = ctx.validation_definitions.add(gx.ValidationDefinition(
            name=f"vd_{rc.pipeline_id[:8]}", data=bdef, suite=suite,
        ))
        result = vd.run(batch_parameters={"dataframe": df})

        bad_idx: set[int] = set()
        failed = 0
        for r in result.results:
            exp_type = type(r.expectation_config).__name__
            col = (
                getattr(r.expectation_config, "column", None)
                or (r.expectation_config.kwargs.get("column")
                    if hasattr(r.expectation_config, "kwargs") else None)
            )
            ok = r.success
            unexpected = r.result.get("unexpected_count", 0) or 0
            failed += 0 if ok else 1
            self.gov.validation_expectation(exp_type, col, ok, int(unexpected))
            if not ok and col and on_failure == "dlq":
                idx_list = r.result.get("unexpected_index_list") or []
                ltp = {lbl: pos for pos, lbl in enumerate(df.index)}
                for lbl in idx_list:
                    if lbl in ltp:
                        bad_idx.add(ltp[lbl])

        total = len(result.results)
        passed = total - failed
        self.gov.validation_result(self.suite_name, result.success, passed, failed, total)

        logger.info(
            "[GREAT_EXPECTATIONS] %s %d/%d passed | %d row(s) flagged.",
            "✓" if result.success else "⚠", passed, total, len(bad_idx),
        )

        if failed > 0:
            if on_failure == "halt":
                raise RuntimeError(f"Validation failed: {failed} expectation(s)")
            if on_failure == "dlq" and bad_idx and self.dlq:
                df = self.dlq.write(df, list(bad_idx),
                                    f"FAILED_VALIDATION: {failed} expectation(s)")

        self.gov.write_validation_report()
        return df, failed
