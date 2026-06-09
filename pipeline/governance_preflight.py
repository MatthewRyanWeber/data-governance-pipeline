"""
Interactive governance pre-flight gate.

Discovers existing governance state for a source file and presents
confirmation prompts before enforcement.  Each check only runs when
its state file exists and contains relevant data — no state file
means no check, keeping first-run clean.

Layer 6 — imports from Layer 0 (constants, helpers), Layer 1 (governance_logger),
          Layer 3 (data_contract_enforcer).

Revision history
────────────────
1.0   2026-06-07   Initial release: 7-check preflight gate with interactive prompts.
1.1   2026-06-09   Close consent.db handle via contextlib.closing (was leaked,
                   risking a Windows file lock).
"""

import json
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import BASE_DIR, HAS_YAML
from pipeline.helpers import confirm_yes_no

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

CONFIG_DIR = BASE_DIR / "config"


def run_governance_preflight(
    gov: "GovernanceLogger",
    df: pd.DataFrame,
    src_path: str,
    src_label: str,
    pii_findings: list,
) -> tuple[pd.DataFrame, dict]:
    """
    Interactive governance pre-flight gate.

    Discovers existing governance state files and, for each one that
    contains data relevant to this source, shows what was found and
    asks the operator to confirm enforcement.

    Checks
    ------
    1. Schema drift         — schema_registry.json baseline
    2. Quality anomalies    — anomaly_baseline.json
    3. Column purposes      — column_purpose.json (informational)
    4. Purpose limitation   — purpose_registry.json (can drop columns)
    5. Data contracts       — *.yaml files (DataContractEnforcer)
    6. Consent database     — consent.db (can block rows)
    7. Prior violations     — contract_violations.jsonl (informational)

    Parameters
    ----------
    gov          : GovernanceLogger
    df           : pd.DataFrame    The DataFrame to be processed.
    src_path     : str             Path to the source file.
    src_label    : str             Human-readable label for the source.
    pii_findings : list            PII findings from pii_discovery.

    Returns
    -------
    tuple[pd.DataFrame, dict]
        The (possibly modified) DataFrame and a summary dict.
    """
    summary: dict = {
        "checks_discovered": 0,
        "checks_applied": 0,
        "checks_skipped": 0,
        "checks_aborted": 0,
        "columns_dropped": [],
        "schema_drift": [],
        "anomalies": [],
        "contract_violations": [],
        "consent_blocked_rows": 0,
    }

    print("\n" + "=" * 64)
    print("  GOVERNANCE PRE-FLIGHT GATE")
    print("=" * 64)
    print(f"  Source : {src_label}")
    print(f"  Rows   : {len(df):,}")
    print(f"  Columns: {len(df.columns)}")
    print("=" * 64)

    # ── 1. Schema drift ─────────────────────────────────────────────────

    schema_registry_path = CONFIG_DIR / "schema_registry.json"
    if schema_registry_path.exists():
        summary["checks_discovered"] += 1
        try:
            registry = json.loads(schema_registry_path.read_text(encoding="utf-8"))
            baseline = registry.get(src_label)
            if baseline:
                baseline_cols = set(baseline.get("columns", []))
                current_cols = set(df.columns.tolist())
                added = sorted(current_cols - baseline_cols)
                removed = sorted(baseline_cols - current_cols)

                if added or removed:
                    print("\n  [1/7] SCHEMA DRIFT DETECTED")
                    print("  " + "-" * 40)
                    if added:
                        print(f"    New columns     : {', '.join(added)}")
                    if removed:
                        print(f"    Removed columns : {', '.join(removed)}")

                    summary["schema_drift"] = {
                        "added": added,
                        "removed": removed,
                    }

                    if confirm_yes_no("  Accept schema changes and continue?", True):
                        summary["checks_applied"] += 1
                        # Update registry with new schema
                        registry[src_label] = {
                            "columns": df.columns.tolist(),
                            "dtypes": {c: str(df[c].dtype) for c in df.columns},
                            "updated_utc": datetime.now(timezone.utc).isoformat(),
                        }
                        schema_registry_path.write_text(
                            json.dumps(registry, indent=2), encoding="utf-8",
                        )
                        print("    Schema registry updated.")
                    else:
                        summary["checks_skipped"] += 1
                        print("    Skipped — proceeding with current schema.")
                else:
                    print("\n  [1/7] Schema drift : none detected")
                    summary["checks_applied"] += 1
            else:
                print(f"\n  [1/7] Schema drift : no baseline for '{src_label}'")
        except Exception as exc:
            logger.error("Schema drift check failed: %s", exc)
            print(f"\n  [1/7] Schema drift check error: {exc}")
            summary["checks_aborted"] += 1
    else:
        print("\n  [1/7] Schema drift : no registry file")

    # ── 2. Quality anomalies ─────────────────────────────────────────────

    anomaly_baseline_path = CONFIG_DIR / "anomaly_baseline.json"
    if anomaly_baseline_path.exists():
        summary["checks_discovered"] += 1
        try:
            baselines = json.loads(anomaly_baseline_path.read_text(encoding="utf-8"))
            source_baseline = baselines.get(src_label)
            if source_baseline:
                anomalies: list[str] = []

                # Row count check
                expected_rows = source_baseline.get("expected_row_count")
                if expected_rows is not None:
                    tolerance = source_baseline.get("row_count_tolerance", 0.2)
                    actual_rows = len(df)
                    lower = expected_rows * (1 - tolerance)
                    upper = expected_rows * (1 + tolerance)
                    if actual_rows < lower or actual_rows > upper:
                        anomalies.append(
                            f"Row count {actual_rows:,} outside expected range "
                            f"[{int(lower):,} - {int(upper):,}]"
                        )

                # Null rate check per column
                null_baselines = source_baseline.get("null_rates", {})
                for col, expected_rate in null_baselines.items():
                    if col in df.columns:
                        actual_rate = df[col].isna().mean()
                        threshold = source_baseline.get("null_rate_tolerance", 0.05)
                        if abs(actual_rate - expected_rate) > threshold:
                            anomalies.append(
                                f"Column '{col}' null rate {actual_rate:.1%} "
                                f"vs baseline {expected_rate:.1%}"
                            )

                if anomalies:
                    print("\n  [2/7] QUALITY ANOMALIES DETECTED")
                    print("  " + "-" * 40)
                    for anomaly in anomalies:
                        print(f"    - {anomaly}")
                    summary["anomalies"] = anomalies

                    if confirm_yes_no("  Continue despite anomalies?", True):
                        summary["checks_applied"] += 1
                    else:
                        summary["checks_aborted"] += 1
                        print("    Aborted by operator.")
                        return df, summary
                else:
                    print("\n  [2/7] Quality anomalies : none detected")
                    summary["checks_applied"] += 1
            else:
                print(f"\n  [2/7] Quality anomalies : no baseline for '{src_label}'")
        except Exception as exc:
            logger.error("Quality anomaly check failed: %s", exc)
            print(f"\n  [2/7] Quality anomaly check error: {exc}")
            summary["checks_aborted"] += 1
    else:
        print("\n  [2/7] Quality anomalies : no baseline file")

    # ── 3. Column purposes (informational) ───────────────────────────────

    column_purpose_path = CONFIG_DIR / "column_purpose.json"
    if column_purpose_path.exists():
        summary["checks_discovered"] += 1
        try:
            purposes = json.loads(column_purpose_path.read_text(encoding="utf-8"))
            source_purposes = purposes.get(src_label, {})
            if source_purposes:
                print("\n  [3/7] COLUMN PURPOSES (informational)")
                print("  " + "-" * 40)
                categorized = {}
                for col, purpose in source_purposes.items():
                    categorized.setdefault(purpose, []).append(col)
                for purpose, cols in sorted(categorized.items()):
                    print(f"    {purpose}: {', '.join(cols)}")
                summary["checks_applied"] += 1
            else:
                print(f"\n  [3/7] Column purposes : none defined for '{src_label}'")
        except Exception as exc:
            logger.error("Column purpose check failed: %s", exc)
            print(f"\n  [3/7] Column purpose check error: {exc}")
            summary["checks_aborted"] += 1
    else:
        print("\n  [3/7] Column purposes : no purpose file")

    # ── 4. Purpose limitation ────────────────────────────────────────────

    purpose_registry_path = CONFIG_DIR / "purpose_registry.json"
    if purpose_registry_path.exists():
        summary["checks_discovered"] += 1
        try:
            purpose_reg = json.loads(purpose_registry_path.read_text(encoding="utf-8"))
            source_rules = purpose_reg.get(src_label)
            if source_rules:
                allowed_columns = set(source_rules.get("allowed_columns", []))
                required_purpose = source_rules.get("purpose", "")

                if allowed_columns:
                    excess = sorted(set(df.columns.tolist()) - allowed_columns)
                    if excess:
                        print("\n  [4/7] PURPOSE LIMITATION — columns outside allowed set")
                        print("  " + "-" * 40)
                        print(f"    Purpose    : {required_purpose}")
                        print(f"    Excess cols: {', '.join(excess)}")

                        if confirm_yes_no("  Drop columns not in the allowed set?", False):
                            df = df.drop(columns=[c for c in excess if c in df.columns])
                            summary["columns_dropped"].extend(excess)
                            summary["checks_applied"] += 1
                            print(f"    Dropped {len(excess)} column(s).")
                            gov.transformation_applied("PURPOSE_LIMITATION_APPLIED", {
                                "dropped_columns": excess,
                                "purpose": required_purpose,
                            })
                        else:
                            summary["checks_skipped"] += 1
                            print("    Skipped — all columns retained.")
                    else:
                        print("\n  [4/7] Purpose limitation : all columns within allowed set")
                        summary["checks_applied"] += 1
                else:
                    print(f"\n  [4/7] Purpose limitation : no column restrictions for '{src_label}'")
            else:
                print(f"\n  [4/7] Purpose limitation : no rules for '{src_label}'")
        except Exception as exc:
            logger.error("Purpose limitation check failed: %s", exc)
            print(f"\n  [4/7] Purpose limitation check error: {exc}")
            summary["checks_aborted"] += 1
    else:
        print("\n  [4/7] Purpose limitation : no registry file")

    # ── 5. Data contracts ────────────────────────────────────────────────

    contracts_dir = BASE_DIR / "contracts"
    if contracts_dir.exists() and HAS_YAML:
        summary["checks_discovered"] += 1
        yaml_files = sorted(contracts_dir.glob("*.yaml")) + sorted(contracts_dir.glob("*.yml"))
        if yaml_files:
            print(f"\n  [5/7] DATA CONTRACTS — {len(yaml_files)} contract file(s) found")
            print("  " + "-" * 40)
            for yf in yaml_files:
                print(f"    - {yf.name}")

            if confirm_yes_no("  Enforce data contracts?", True):
                from pipeline.quality.data_contract_enforcer import DataContractEnforcer

                all_violations: list[dict] = []
                for contract_file in yaml_files:
                    try:
                        enforcer = DataContractEnforcer(
                            gov, contract_file, warn_only=True,
                        )
                        warnings = enforcer.enforce(df)
                        if warnings:
                            all_violations.extend(warnings)
                            for warning in warnings:
                                print(
                                    f"    [WARN] {contract_file.name}: "
                                    f"{warning.get('rule', '?')} — {warning.get('actual', '?')}"
                                )
                    except Exception as exc:
                        logger.error("Contract enforcement failed for %s: %s", contract_file.name, exc)
                        print(f"    [ERROR] {contract_file.name}: {exc}")
                        all_violations.append({
                            "contract": contract_file.name,
                            "error": str(exc),
                        })

                summary["contract_violations"] = all_violations
                summary["checks_applied"] += 1
                if all_violations:
                    print(f"    {len(all_violations)} warning(s) / violation(s) logged.")
                else:
                    print("    All contracts satisfied.")
            else:
                summary["checks_skipped"] += 1
                print("    Skipped — contracts not enforced.")
        else:
            print("\n  [5/7] Data contracts : no YAML files in contracts/")
    elif not HAS_YAML:
        print("\n  [5/7] Data contracts : PyYAML not installed")
    else:
        print("\n  [5/7] Data contracts : no contracts/ directory")

    # ── 6. Consent database ──────────────────────────────────────────────

    consent_db_path = BASE_DIR / "consent.db"
    if consent_db_path.exists():
        summary["checks_discovered"] += 1
        try:
            # contextlib.closing guarantees the handle is released — a bare
            # `with sqlite3.connect(...)` commits but never closes, which can
            # leave consent.db locked on Windows.
            with closing(sqlite3.connect(str(consent_db_path))) as conn:
                cursor = conn.cursor()

                # Check if the consent table exists
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='consent'",
                )
                if cursor.fetchone():
                    cursor.execute("SELECT COUNT(*) FROM consent")
                    total_consents = cursor.fetchone()[0]

                    # Look for a subject_id column in the DataFrame to match against consent records
                    subject_columns = [
                        c for c in df.columns
                        if any(k in c.lower() for k in ("subject_id", "user_id", "customer_id", "email"))
                    ]

                    if subject_columns and total_consents > 0:
                        subject_col = subject_columns[0]
                        print(f"\n  [6/7] CONSENT DATABASE — {total_consents:,} consent record(s)")
                        print("  " + "-" * 40)
                        print(f"    Matching on column: {subject_col}")

                        if confirm_yes_no("  Filter rows without consent?", False):
                            # Fetch all consented subject IDs
                            cursor.execute("SELECT subject_id FROM consent WHERE consented = 1")
                            consented_ids = {row[0] for row in cursor.fetchall()}

                            before_count = len(df)
                            df = df[df[subject_col].astype(str).isin(
                                {str(cid) for cid in consented_ids}
                            )]
                            blocked = before_count - len(df)
                            summary["consent_blocked_rows"] = blocked
                            summary["checks_applied"] += 1

                            print(f"    Blocked {blocked:,} row(s) without consent.")
                            gov.transformation_applied("CONSENT_FILTER_APPLIED", {
                                "subject_column": subject_col,
                                "rows_before": before_count,
                                "rows_after": len(df),
                                "rows_blocked": blocked,
                            })
                        else:
                            summary["checks_skipped"] += 1
                            print("    Skipped — all rows retained.")
                    else:
                        if total_consents == 0:
                            print("\n  [6/7] Consent database : empty (no records)")
                        else:
                            print("\n  [6/7] Consent database : no matchable subject column in DataFrame")
                else:
                    print("\n  [6/7] Consent database : no 'consent' table found")
        except Exception as exc:
            logger.error("Consent database check failed: %s", exc)
            print(f"\n  [6/7] Consent database check error: {exc}")
            summary["checks_aborted"] += 1
    else:
        print("\n  [6/7] Consent database : no consent.db file")

    # ── 7. Prior violations (informational) ──────────────────────────────

    violations_path = CONFIG_DIR / "contract_violations.jsonl"
    if violations_path.exists():
        summary["checks_discovered"] += 1
        try:
            records: list[dict] = []
            for line in violations_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    # Filter to violations relevant to this source
                    if src_label in str(rec.get("source", "")) or src_label in str(rec.get("contract", "")):
                        records.append(rec)
                except json.JSONDecodeError:
                    pass

            if records:
                print(f"\n  [7/7] PRIOR VIOLATIONS — {len(records)} record(s) for this source")
                print("  " + "-" * 40)
                # Show the most recent 5
                for rec in records[-5:]:
                    ts = rec.get("timestamp", "?")[:19]
                    failures = rec.get("failure_count", 0)
                    warnings = rec.get("warning_count", 0)
                    contract = rec.get("contract", "?")
                    print(f"    {ts}  {contract}  failures={failures}  warnings={warnings}")
                if len(records) > 5:
                    print(f"    ... and {len(records) - 5} more")
                summary["checks_applied"] += 1
            else:
                print(f"\n  [7/7] Prior violations : none for '{src_label}'")
                summary["checks_applied"] += 1
        except Exception as exc:
            logger.error("Violation history check failed: %s", exc)
            print(f"\n  [7/7] Violation history check error: {exc}")
            summary["checks_aborted"] += 1
    else:
        print("\n  [7/7] Prior violations : no violations log file")

    # ── Summary ──────────────────────────────────────────────────────────

    print("\n" + "=" * 64)
    print("  PRE-FLIGHT SUMMARY")
    print("  " + "-" * 40)
    print(f"    Checks discovered : {summary['checks_discovered']}")
    print(f"    Checks applied    : {summary['checks_applied']}")
    print(f"    Checks skipped    : {summary['checks_skipped']}")
    print(f"    Checks aborted    : {summary['checks_aborted']}")
    if summary["columns_dropped"]:
        print(f"    Columns dropped   : {', '.join(summary['columns_dropped'])}")
    if summary["consent_blocked_rows"]:
        print(f"    Consent blocked   : {summary['consent_blocked_rows']:,} rows")
    if summary["schema_drift"]:
        drift = summary["schema_drift"]
        print(f"    Schema drift      : +{len(drift.get('added', []))} / -{len(drift.get('removed', []))}")
    if summary["anomalies"]:
        print(f"    Anomalies         : {len(summary['anomalies'])}")
    if summary["contract_violations"]:
        print(f"    Contract issues   : {len(summary['contract_violations'])}")
    print("=" * 64)

    gov.transformation_applied("PREFLIGHT_GATE_COMPLETE", {
        "source_label": src_label,
        "checks_discovered": summary["checks_discovered"],
        "checks_applied": summary["checks_applied"],
        "checks_skipped": summary["checks_skipped"],
        "checks_aborted": summary["checks_aborted"],
        "columns_dropped": len(summary["columns_dropped"]),
        "consent_blocked_rows": summary["consent_blocked_rows"],
    })

    return df, summary
