"""
Data contract enforcer — enforces YAML-defined data contracts against DataFrames.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_YAML
from pipeline.exceptions import ContractViolationError

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DataContractEnforcer:
    """
    Enforces a data contract defined in a YAML file against a DataFrame,
    failing the pipeline immediately if any contract clause is violated.

    Unlike dbt contracts (which only work on SQL transformations), this
    works on any DataFrame regardless of source — files, streams, APIs,
    or databases.

    Contract YAML sections
    ----------------------
    contract    Metadata: name, version, owner, description.

    sla         Service-level agreement:
                  max_pipeline_duration_seconds — wall-clock time limit
                  min_rows / max_rows           — row count bounds
                  freshness_column              — column used for age check
                  max_age_days                  — maximum age of newest record

    quality     Quality score floors (uses DataQualityScorer output):
                  min_score         — composite score minimum (0-100)
                  min_completeness  — per-dimension minimums
                  min_uniqueness
                  min_validity
                  min_consistency
                  min_timeliness

    schema      Column-level constraints:
                  require_columns   — list of columns that MUST exist
                  forbid_columns    — list of columns that must NOT exist
                  allow_extra_columns — whether unlisted columns are OK
                  columns:
                    <col_name>:
                      dtype / nullable / unique / min / max /
                      min_length / max_length / pattern / allowed_values

    rules       Custom per-column or global rules.

    Quick-start
    -----------
        from pipeline.quality import DataContractEnforcer
        enforcer = DataContractEnforcer(gov, "contracts/employees.yaml")
        enforcer.enforce(df, quality_report=quality)

    Parameters
    ----------
    gov             : GovernanceLogger
    contract_path   : str | Path    Path to the contract YAML file.
    violation_log   : str | Path    Where to append JSON violation records.
    warn_only       : bool          If True, log violations but never raise.
    """

    def __init__(
        self,
        gov:            "GovernanceLogger",
        contract_path:  str | Path,
        violation_log:  str | Path = "contract_violations.jsonl",
        warn_only:      bool       = False,
    ) -> None:
        self.gov           = gov
        self.contract_path = Path(contract_path)
        self.violation_log = Path(violation_log)
        self.warn_only     = warn_only
        self._contract     = self._load_contract()

    # ── Contract loader ───────────────────────────────────────────────────

    def _load_contract(self) -> dict:
        """Load and minimally validate the YAML contract file."""
        if not HAS_YAML:
            raise RuntimeError(
                "DataContractEnforcer requires PyYAML: pip install pyyaml"
            )
        if not self.contract_path.exists():
            raise FileNotFoundError(
                f"Contract file not found: {self.contract_path}"
            )
        import yaml  # pylint: disable=import-outside-toplevel
        with open(self.contract_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError(
                f"Contract YAML must be a mapping at the top level: {self.contract_path}"
            )
        return data

    # ── Violation builder ─────────────────────────────────────────────────

    @staticmethod
    def _violation(
        clause:   str,
        rule:     str,
        expected: str,
        actual:   str,
        column:   str | None = None,
        severity: str        = "ERROR",
    ) -> dict:
        return {
            "clause":   clause,
            "column":   column,
            "rule":     rule,
            "expected": expected,
            "actual":   actual,
            "severity": severity,
        }

    # ── SLA checks ────────────────────────────────────────────────────────

    def _check_sla(
        self,
        df:              "pd.DataFrame",
        elapsed_seconds: float | None = None,
    ) -> list[dict]:
        sla  = self._contract.get("sla", {})
        viols: list[dict] = []

        if not sla:
            return viols

        # Row count bounds
        n = len(df)
        min_rows = sla.get("min_rows")
        max_rows = sla.get("max_rows")
        if min_rows is not None and n < min_rows:
            viols.append(self._violation(
                "sla", "min_rows",
                f">= {min_rows} rows", f"{n} rows", severity="CRITICAL"
            ))
        if max_rows is not None and n > max_rows:
            viols.append(self._violation(
                "sla", "max_rows",
                f"<= {max_rows} rows", f"{n} rows", severity="ERROR"
            ))

        # Pipeline duration
        max_dur = sla.get("max_pipeline_duration_seconds")
        if max_dur is not None and elapsed_seconds is not None:
            if elapsed_seconds > max_dur:
                viols.append(self._violation(
                    "sla", "max_pipeline_duration_seconds",
                    f"<= {max_dur}s", f"{elapsed_seconds:.1f}s",
                    severity="ERROR"
                ))

        # Freshness check
        fresh_col  = sla.get("freshness_column")
        max_age    = sla.get("max_age_days")
        if fresh_col and max_age and fresh_col in df.columns:
            try:
                series = pd.to_datetime(df[fresh_col], errors="coerce").dropna()
                if len(series) > 0:
                    newest   = series.max()
                    now      = pd.Timestamp.now(tz=newest.tzinfo)
                    age_days = (now - newest).days
                    if age_days > max_age:
                        viols.append(self._violation(
                            "sla", "max_age_days",
                            f"newest record <= {max_age} days old",
                            f"newest record is {age_days} days old",
                            column=fresh_col, severity="ERROR"
                        ))
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("Freshness check failed for column %s: %s", fresh_col, exc)

        return viols

    # ── Quality checks ────────────────────────────────────────────────────

    def _check_quality(self, quality_report: dict | None) -> list[dict]:
        qcfg  = self._contract.get("quality", {})
        viols: list[dict] = []

        if not qcfg or not quality_report:
            return viols

        score = quality_report.get("score", 100.0)
        dims  = quality_report.get("dimensions", {})

        min_score = qcfg.get("min_score")
        if min_score is not None and score < min_score:
            viols.append(self._violation(
                "quality", "min_score",
                f">= {min_score}", f"{score:.1f}", severity="CRITICAL"
            ))

        dim_map = {
            "min_completeness": "completeness",
            "min_uniqueness":   "uniqueness",
            "min_validity":     "validity",
            "min_consistency":  "consistency",
            "min_timeliness":   "timeliness",
        }
        for cfg_key, dim_name in dim_map.items():
            floor = qcfg.get(cfg_key)
            if floor is None:
                continue
            actual = dims.get(dim_name, 100.0)
            if actual < floor:
                viols.append(self._violation(
                    "quality", cfg_key,
                    f"{dim_name} >= {floor}", f"{dim_name} = {actual:.1f}",
                    severity="ERROR"
                ))

        return viols

    # ── Schema checks ─────────────────────────────────────────────────────

    def _check_schema(self, df: "pd.DataFrame") -> list[dict]:
        schema = self._contract.get("schema", {})
        viols:  list[dict] = []

        if not schema:
            return viols

        actual_cols = set(df.columns)

        # Required columns
        for col in schema.get("require_columns", []):
            if col not in actual_cols:
                viols.append(self._violation(
                    "schema", "require_columns",
                    f"column '{col}' present", "column missing",
                    column=col, severity="CRITICAL"
                ))

        # Forbidden columns
        for col in schema.get("forbid_columns", []):
            if col in actual_cols:
                viols.append(self._violation(
                    "schema", "forbid_columns",
                    f"column '{col}' absent", "column present — data may be unsafe",
                    column=col, severity="CRITICAL"
                ))

        # Extra columns
        declared    = set(schema.get("columns", {}).keys())
        allow_extra = schema.get("allow_extra_columns", True)
        if not allow_extra and declared:
            extras = actual_cols - declared - set(schema.get("require_columns", []))
            for col in sorted(extras):
                viols.append(self._violation(
                    "schema", "allow_extra_columns",
                    "no undeclared columns", f"unexpected column '{col}'",
                    column=col, severity="WARNING"
                ))

        # Per-column constraints
        for col, rules in schema.get("columns", {}).items():
            if col not in actual_cols:
                continue
            series = df[col]

            # dtype
            expected_dtype = rules.get("dtype")
            if expected_dtype and str(series.dtype) != expected_dtype:
                viols.append(self._violation(
                    "schema", "dtype",
                    f"dtype={expected_dtype}", f"dtype={series.dtype}",
                    column=col, severity="ERROR"
                ))

            # nullable
            nullable   = rules.get("nullable", True)
            null_count = series.isna().sum()
            if not nullable and null_count > 0:
                viols.append(self._violation(
                    "schema", "nullable",
                    "no NULL values", f"{null_count} NULLs found",
                    column=col, severity="CRITICAL"
                ))

            # unique
            if rules.get("unique"):
                dupe_count = series.dropna().duplicated().sum()
                if dupe_count > 0:
                    viols.append(self._violation(
                        "schema", "unique",
                        "all values unique", f"{dupe_count} duplicates found",
                        column=col, severity="ERROR"
                    ))

            # numeric min / max
            non_null = series.dropna()
            if len(non_null) == 0:
                continue

            if rules.get("min") is not None:
                try:
                    below = (pd.to_numeric(non_null, errors="coerce") < rules["min"]).sum()
                    if below > 0:
                        viols.append(self._violation(
                            "schema", "min",
                            f">= {rules['min']}",
                            f"{below} value(s) below minimum",
                            column=col, severity="ERROR"
                        ))
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Contract check failed for rule: %s", exc)

            if rules.get("max") is not None:
                try:
                    above = (pd.to_numeric(non_null, errors="coerce") > rules["max"]).sum()
                    if above > 0:
                        viols.append(self._violation(
                            "schema", "max",
                            f"<= {rules['max']}",
                            f"{above} value(s) above maximum",
                            column=col, severity="ERROR"
                        ))
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Contract check failed for rule: %s", exc)

            # string length
            if rules.get("min_length") is not None:
                try:
                    too_short = (non_null.astype(str).str.len() < rules["min_length"]).sum()
                    if too_short > 0:
                        viols.append(self._violation(
                            "schema", "min_length",
                            f"length >= {rules['min_length']}",
                            f"{too_short} value(s) too short",
                            column=col, severity="ERROR"
                        ))
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Contract check failed for rule: %s", exc)

            if rules.get("max_length") is not None:
                try:
                    too_long = (non_null.astype(str).str.len() > rules["max_length"]).sum()
                    if too_long > 0:
                        viols.append(self._violation(
                            "schema", "max_length",
                            f"length <= {rules['max_length']}",
                            f"{too_long} value(s) too long",
                            column=col, severity="ERROR"
                        ))
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Contract check failed for rule: %s", exc)

            # regex pattern
            if rules.get("pattern"):
                try:
                    bad = (~non_null.astype(str).str.match(rules["pattern"])).sum()
                    if bad > 0:
                        viols.append(self._violation(
                            "schema", "pattern",
                            f"matches /{rules['pattern']}/",
                            f"{bad} value(s) do not match pattern",
                            column=col, severity="ERROR"
                        ))
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Contract check failed for rule: %s", exc)

            # allowed values
            if rules.get("allowed_values") is not None:
                allowed = set(str(v) for v in rules["allowed_values"])
                bad = (~non_null.astype(str).isin(allowed)).sum()
                if bad > 0:
                    viols.append(self._violation(
                        "schema", "allowed_values",
                        f"one of {sorted(allowed)}",
                        f"{bad} value(s) not in allowed set",
                        column=col, severity="ERROR"
                    ))

        return viols

    # ── Custom rule checks ────────────────────────────────────────────────

    def _check_rules(self, df: "pd.DataFrame") -> list[dict]:
        rules = self._contract.get("rules", [])
        viols: list[dict] = []

        for rule in (rules or []):
            name    = rule.get("name", "unnamed_rule")
            desc    = rule.get("description", "")
            rtype   = rule.get("type", "column_condition")
            col     = rule.get("column")
            cond    = rule.get("condition", "")

            # Global null ratio rule
            if rtype == "global_null_ratio":
                max_pct = rule.get("max_null_pct", 20)
                for c in df.columns:
                    null_pct = df[c].isna().mean() * 100
                    if null_pct > max_pct:
                        viols.append(self._violation(
                            "rules", name,
                            f"{c} null% <= {max_pct}%",
                            f"{c} null% = {null_pct:.1f}%",
                            column=c, severity="WARNING"
                        ))
                continue

            # Column condition rule
            if col and cond and col in df.columns:
                non_null = df[col].dropna()
                if len(non_null) == 0:
                    continue
                try:
                    numeric = pd.to_numeric(non_null, errors="coerce").dropna()
                    if len(numeric) == 0:
                        continue
                    m = re.match(r"^\s*(>=|<=|!=|>|<|==)\s*(-?\d+\.?\d*)\s*$", cond)
                    if not m:
                        continue
                    op, val = m.group(1), float(m.group(2))
                    op_map = {
                        ">":  lambda s, v: s > v,
                        "<":  lambda s, v: s < v,
                        ">=": lambda s, v: s >= v,
                        "<=": lambda s, v: s <= v,
                        "==": lambda s, v: s == v,
                        "!=": lambda s, v: s != v,
                    }
                    bad = (~op_map[op](numeric, val)).sum()
                    if bad > 0:
                        viols.append(self._violation(
                            "rules", name,
                            f"{col} {cond}  [{desc}]",
                            f"{bad} value(s) failed condition",
                            column=col, severity="ERROR"
                        ))
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Contract check failed for rule: %s", exc)

        return viols

    # ── Public API ────────────────────────────────────────────────────────

    def check(
        self,
        df:               "pd.DataFrame",
        quality_report:   dict | None  = None,
        elapsed_seconds:  float | None = None,
    ) -> list[dict]:
        """
        Run all contract checks and return the list of violations.

        Does NOT raise — use enforce() if you want hard failures.

        Parameters
        ----------
        df               : pd.DataFrame
        quality_report   : dict | None   From DataQualityScorer.score()
        elapsed_seconds  : float | None  Pipeline wall-clock time so far

        Returns
        -------
        list[dict]  All violations found (empty = contract satisfied).
        """
        viols: list[dict] = []
        viols.extend(self._check_sla(df, elapsed_seconds))
        viols.extend(self._check_quality(quality_report))
        viols.extend(self._check_schema(df))
        viols.extend(self._check_rules(df))
        return viols

    def enforce(
        self,
        df:               "pd.DataFrame",
        quality_report:   dict | None  = None,
        elapsed_seconds:  float | None = None,
        table:            str | None   = None,
    ) -> list[dict]:
        """
        Run all contract checks.  Raises ContractViolationError if any
        CRITICAL or ERROR violations are found (WARNINGs are logged only).

        Parameters
        ----------
        df               : pd.DataFrame
        quality_report   : dict | None   From DataQualityScorer.score()
        elapsed_seconds  : float | None  Pipeline wall-clock time so far
        table            : str | None    Table name for contract selection.

        Returns
        -------
        list[dict]  Warnings that did not cause a failure (if any).

        Raises
        ------
        ContractViolationError  If any CRITICAL or ERROR violations exist
                                and warn_only=False.
        """
        viols    = self.check(df, quality_report, elapsed_seconds)
        warnings = [v for v in viols if v["severity"] == "WARNING"]
        failures = [v for v in viols if v["severity"] in ("CRITICAL", "ERROR")]
        contract_name = self._contract.get("contract", {}).get("name", str(self.contract_path))
        ts = datetime.now(timezone.utc).isoformat()

        # Log every violation to the governance ledger
        for v in viols:
            self.gov.transformation_applied("CONTRACT_VIOLATION", {
                "contract":  contract_name,
                "clause":    v["clause"],
                "column":    v["column"],
                "rule":      v["rule"],
                "severity":  v["severity"],
                "expected":  v["expected"],
                "actual":    v["actual"],
            })

        # Append to violation log file
        if viols:
            record = {
                "timestamp":     ts,
                "contract":      contract_name,
                "source":        str(self.contract_path),
                "rows":          len(df),
                "violations":    viols,
                "failure_count": len(failures),
                "warning_count": len(warnings),
            }
            try:
                with open(self.violation_log, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, default=str) + "\n")
            except OSError as exc:
                logger.warning("Could not write violation log: %s", exc)

        # Log summary
        if viols:
            border = "=" * 64
            lines = [
                f"\n  {border}",
                f"  CONTRACT ENFORCEMENT  —  {contract_name}",
                f"  {border}",
            ]
            for v in viols:
                sev_label = v["severity"]
                col_str = f"[{v['column']}] " if v["column"] else ""
                lines.append(
                    f"  [{sev_label}]  {v['clause'].upper():8s}  {col_str}{v['rule']}"
                )
                lines.append(f"           expected: {v['expected']}")
                lines.append(f"           actual:   {v['actual']}")
            lines.append(f"  {border}")
            lines.append(f"  {len(failures)} failure(s)  |  {len(warnings)} warning(s)")
            lines.append(f"  {border}")
            logger.warning("\n".join(lines))

        if failures and not self.warn_only:
            self.gov.transformation_applied("CONTRACT_ENFORCEMENT_FAILED", {
                "contract":      contract_name,
                "failure_count": len(failures),
                "warning_count": len(warnings),
            })
            raise ContractViolationError(
                contract_name=contract_name,
                violations=failures,
                warnings=warnings,
            )

        self.gov.transformation_applied("CONTRACT_SATISFIED", {
            "contract":      contract_name,
            "failure_count": len(failures),
            "warning_count": len(warnings),
            "warn_only":     self.warn_only,
        })
        return warnings

    # ── Reporting ─────────────────────────────────────────────────────────

    def violation_history(self, n: int = 50) -> list[dict]:
        """Return the last n violation records from the log file."""
        if not self.violation_log.exists():
            return []
        records = []
        for line in self.violation_log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return list(reversed(records[-n:]))

    def contract_info(self) -> dict:
        """Return the parsed contract metadata."""
        meta = self._contract.get("contract", {})
        sla  = self._contract.get("sla",      {})
        qual = self._contract.get("quality",   {})
        sch  = self._contract.get("schema",    {})
        return {
            "name":              meta.get("name"),
            "version":           meta.get("version"),
            "owner":             meta.get("owner"),
            "description":       (meta.get("description") or "").strip(),
            "sla_checks":        list(sla.keys()),
            "quality_floors":    {k: v for k, v in qual.items()},
            "required_columns":  sch.get("require_columns", []),
            "forbidden_columns": sch.get("forbid_columns",  []),
            "column_rules":      list(sch.get("columns", {}).keys()),
            "custom_rules":      [r.get("name") for r in self._contract.get("rules", [])],
        }


