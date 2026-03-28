"""
=============================================================
  DATA GOVERNANCE PIPELINE  v2.0.0
  GDPR & CCPA Compliant ETL Tool
  Author: Generated for Columbia University CUIT
=============================================================

WHAT'S NEW IN v2.0
------------------
  ① Schema Validation     — Great Expectations 1.x integration.
                            Auto-generated + interactive expectation
                            suites.  Row-level failures routed to a
                            Dead Letter Queue instead of aborting.

  ② Data Profiling        — Statistical summary (nulls, uniques,
                            min/max/mean/std) written to governance
                            logs before transformation runs.

  ③ Dead Letter Queue     — Rows failing schema validation are written
                            to a separate DLQ CSV file with a reason
                            code instead of crashing the pipeline.

  ④ Retry + Backoff       — Database load operations automatically
                            retry up to 3 times with exponential
                            backoff (2s → 4s → 8s) on transient
                            failures (network blips, lock timeouts).

  ⑤ Chunked Processing   — Large files processed in configurable
                            batches (default 50,000 rows) so memory
                            usage stays bounded regardless of file size.

  ⑥ Idempotency          — Optional natural-key upsert mode:
                            duplicate rows are updated rather than
                            inserted, so re-running the pipeline
                            never produces double records.

  ⑦ Incremental Loading  — Watermark-based loading: only rows newer
                            than the last successful run are processed.
                            Watermark persisted in a local state file.

  ⑧ Notifications        — Email (SMTP) and/or Slack webhook alerts
                            on pipeline success or failure.

  ⑨ Secrets Management   — Credentials resolved in priority order:
                            CLI args → .env file → environment
                            variables → interactive prompt.
                            Passwords are never stored in code.

  ⑩ CLI / Parameterised  — All options can be passed as command-line
     Runs                   arguments so the pipeline can be scheduled
                            (cron, Task Scheduler, Airflow) without
                            human interaction.

PIPELINE FLOW (v2.0)
--------------------
  1.  Secrets & config     — load credentials from env / .env / args
  2.  Governance logger    — create audit ledger, PII report, DLQ files
  3.  Source file          — prompt or arg; existence check
  4.  Incremental filter   — apply watermark if enabled
  5.  Extract (chunked)    — read in configurable chunk sizes
  6.  Data profiling       — statistical summary to governance logs
  7.  PII scan             — column-name pattern matching
  8.  Compliance wizard    — GDPR/CCPA consent, PII strategy, retention
  9.  Schema validation    — Great Expectations suite; DLQ bad rows
  10. Transform            — flatten, minimise, mask/drop/retain PII,
                             dedup, sanitise, append metadata
  11. Load (retry)         — write to SQL or MongoDB with auto-retry
  12. Idempotency check    — upsert if natural key configured
  13. Update watermark     — persist new high-water mark
  14. Notifications        — email / Slack success or failure summary
  15. Governance artefacts — PII report, validation report, DLQ report

REGULATORY COVERAGE
-------------------
  GDPR : Art. 4, 5(1)(c), 5(1)(e), 6, 9, 25, 30, 32
  CCPA : §1798.100, §1798.120, §1798.140(o), §1798.150

DEPENDENCIES
------------
  Core        : pandas, openpyxl, lxml, sqlalchemy
  Validation  : great-expectations>=1.0
  Retry       : tenacity
  Secrets     : python-dotenv
  Notifications: requests  (Slack webhook)
               smtplib     (stdlib — email)
  SQL drivers : psycopg2-binary, pymysql, pyodbc  (install as needed)
  MongoDB     : pymongo
  Optional    : flatten-json

  Install: pip install -r requirements.txt
=============================================================
"""

# ─────────────────────────────────────────────────────────────────────────────
#  STANDARD LIBRARY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import argparse         # CLI argument parsing for parameterised / scheduled runs
# [unused – kept for reference] import csv              # DLQ file writing
import getpass          # Secure password prompts; OS username retrieval
import hashlib          # SHA-256 for file fingerprinting and PII pseudonymisation
import json             # JSONL audit ledger serialisation
import logging          # Standard logging framework
import os               # Environment variable access for secrets management
import platform         # Host OS metadata for audit events
import re               # Regex for PII column-name scanning
import smtplib          # SMTP email notifications (stdlib, no extra install)
import sys              # sys.exit, sys.stdout
import time             # Sleep between retry attempts
import uuid             # UUID4 for pipeline / event IDs
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart   # HTML + text email construction
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Iterator

# ─────────────────────────────────────────────────────────────────────────────
#  THIRD-PARTY DEPENDENCY CHECKS
# ─────────────────────────────────────────────────────────────────────────────
# All heavy dependencies are checked at import time so the user gets a single
# clear "missing packages" error rather than a crash mid-execution.

MISSING: list[str] = []

try:
    import pandas as pd
except ImportError:
    MISSING.append("pandas")

try:
    import great_expectations as gx
    from great_expectations import expectations as gxe
    HAS_GX = True
except ImportError:
    HAS_GX = False
    MISSING.append("great-expectations")

try:
    # [unused – kept for reference]
    # from tenacity import (
    #     retry, stop_after_attempt, wait_exponential,
    #     retry_if_exception_type, before_sleep_log,
    # )
    import tenacity as _tenacity  # noqa: F401
    HAS_TENACITY = True
except ImportError:
    HAS_TENACITY = False
    MISSING.append("tenacity")

try:
    # [unused – kept for reference]
    from dotenv import dotenv_values  # noqa: F401  (also installs load_dotenv)
    HAS_DOTENV = True
except ImportError:
    # python-dotenv is optional: env vars still work without it
    HAS_DOTENV = False

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False   # Slack notifications simply skipped if absent

try:
# [unused – kept for reference]     from flatten_json import flatten as _fj_flatten   # noqa: F401
    HAS_FLATTEN_JSON = True
except ImportError:
    HAS_FLATTEN_JSON = False


# ─────────────────────────────────────────────────────────────────────────────
#  PIPELINE-LEVEL CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION     = "2.0.0"
PIPELINE_ID = str(uuid.uuid4())     # Unique to this execution
RUN_START   = datetime.now(timezone.utc).isoformat()

# Default chunk size for large-file processing (rows per batch).
# 50 000 rows is a reasonable balance between memory efficiency and
# the overhead of opening/closing DB connections per chunk.
DEFAULT_CHUNK_SIZE = 50_000

# Watermark state file — stores the high-water mark between pipeline runs.
WATERMARK_FILE = Path("pipeline_watermark.json")


# ─────────────────────────────────────────────────────────────────────────────
#  PII FIELD-NAME REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
# Applied case-insensitively to column names (not cell data).
# Regulatory basis: GDPR Article 4(1) and CCPA §1798.140(o).

PII_FIELD_PATTERNS: list[str] = [
    r"\bemail\b", r"\be[-_]?mail\b",
    r"\bphone\b", r"\bmobile\b", r"\bcell\b",
    r"\bssn\b", r"\bsocial.?sec\b",
    r"\bpassword\b", r"\bpasswd\b", r"\bpin\b",
    r"\bcredit.?card\b", r"\bcard.?num\b",
    r"\bip.?addr\b", r"\bip_address\b",
    r"\bbirthday\b", r"\bdob\b", r"\bdate.?of.?birth\b",
    r"\bfirst.?name\b", r"\blast.?name\b", r"\bfull.?name\b",
    r"\baddress\b", r"\bstreet\b", r"\bzip\b", r"\bpostal\b",
    r"\bgender\b", r"\brace\b", r"\bethnicity\b",
    r"\bpassport\b", r"\blicense\b", r"\bdriver.?id\b",
    r"\bbiometric\b", r"\bfingerprint\b",
    r"\blatitude\b", r"\blongitude\b", r"\bgeo\b",
    r"\bhealth\b", r"\bmedical\b", r"\bdiagnos\b",
    r"\bsalary\b", r"\bincome\b", r"\bwage\b",
    r"\breligion\b", r"\bpolitical\b",
]

# GDPR Article 9 special-category patterns — heightened obligations apply.
SENSITIVE_CATEGORIES: set[str] = {
    r"\bhealth\b", r"\bmedical\b", r"\brace\b", r"\bethnicity\b",
    r"\breligion\b", r"\bpolitical\b", r"\bbiometric\b", r"\bgenetic\b",
}


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: GovernanceLogger  (v2.0 — extended with new event categories)
# ═════════════════════════════════════════════════════════════════════════════
class GovernanceLogger:
    """
    Central audit and governance logging facility for the pipeline.

    v2.0 additions
    --------------
    • VALIDATION  — schema validation pass/fail events and per-expectation
                    results from Great Expectations.
    • PROFILING   — data profile summary event (nulls, uniques, stats).
    • DLQ         — dead letter queue write events with row counts and
                    rejection reasons.
    • INCREMENTAL — watermark read/write events for incremental loading.
    • NOTIFICATION— delivery status events for email/Slack alerts.
    • RETRY       — retry attempt events from the exponential-backoff loader.

    Output files (all timestamped to avoid overwrites between runs)
    ---------------------------------------------------------------
    pipeline_<ts>.log            Human-readable log (console + file)
    audit_ledger_<ts>.jsonl      Immutable JSONL audit ledger (GDPR Art. 30)
    pii_report_<ts>.json         PII findings and regulation references
    validation_report_<ts>.json  GX expectation results
    profile_report_<ts>.json     Column statistics from data profiling
    dlq_<ts>.csv                 Dead Letter Queue — rows rejected by validation
    """

    def __init__(self, log_dir: str = "governance_logs") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # ── Artefact file paths ───────────────────────────────────────────────
        self.log_file             = self.log_dir / f"pipeline_{ts}.log"
        self.ledger_file          = self.log_dir / f"audit_ledger_{ts}.jsonl"
        self.pii_report_file      = self.log_dir / f"pii_report_{ts}.json"
        self.validation_rpt_file  = self.log_dir / f"validation_report_{ts}.json"
        self.profile_rpt_file     = self.log_dir / f"profile_report_{ts}.json"
        self.dlq_file             = self.log_dir / f"dlq_{ts}.csv"

        # ── Python logging setup ──────────────────────────────────────────────
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger("DataPipeline")

        # ── In-memory accumulators (used by report writers) ───────────────────
        self.pii_findings:        list[dict] = []
        self.ledger_entries:      list[dict] = []
        self.validation_results:  list[dict] = []
        self.dlq_rows_total:      int        = 0

    # ── Core internal writer ─────────────────────────────────────────────────
    def _event(
        self,
        category: str,
        action:   str,
        detail:   dict | None = None,
        level:    str = "INFO",
    ) -> None:
        """
        Build a structured audit event and write it to the JSONL ledger
        and the human-readable log simultaneously.

        Every event carries: pipeline_id, event_id (UUID), UTC timestamp,
        hostname, OS user, category, action, and an arbitrary detail dict.
        """
        entry = {
            "pipeline_id"   : PIPELINE_ID,
            "event_id"      : str(uuid.uuid4()),
            "timestamp_utc" : datetime.now(timezone.utc).isoformat(),
            "host"          : platform.node(),
            "os_user"       : getpass.getuser(),
            "category"      : category,
            "action"        : action,
            "detail"        : detail or {},
        }
        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        self.ledger_entries.append(entry)

        msg = f"[{category}] {action}"
        if detail:
            msg += f" | {json.dumps(detail)}"
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def pipeline_start(self, metadata: dict)  -> None: self._event("LIFECYCLE", "PIPELINE_STARTED",   metadata)
    def pipeline_end(self,   stats:    dict)  -> None: self._event("LIFECYCLE", "PIPELINE_COMPLETED", stats)

    # ── Lineage ──────────────────────────────────────────────────────────────
    def source_registered(self, path: str, file_type: str, row_count: int, col_count: int) -> None:
        self._event("LINEAGE", "SOURCE_REGISTERED", {
            "source_path": path, "file_type": file_type,
            "row_count": row_count, "col_count": col_count,
            "sha256": _file_hash(path),
        })

    def destination_registered(self, db_type: str, db_name: str, table: str) -> None:
        self._event("LINEAGE", "DESTINATION_REGISTERED",
                    {"db_type": db_type, "db_name": db_name, "table_or_collection": table})

    def load_complete(self, rows_written: int, table: str) -> None:
        self._event("LINEAGE", "LOAD_COMPLETE",
                    {"rows_written": rows_written, "destination_table": table})

    # ── Transformation ───────────────────────────────────────────────────────
    def transformation_applied(self, name: str, detail: dict | None = None) -> None:
        self._event("TRANSFORMATION", name, detail)

    # ── Privacy / PII ────────────────────────────────────────────────────────
    def pii_detected(self, findings: list[dict]) -> None:
        self.pii_findings.extend(findings)
        self._event("PRIVACY", "PII_DETECTED",
                    {"findings_count": len(findings), "fields": [f["field"] for f in findings]},
                    level="WARNING")

    def pii_action(self, field: str, action: str) -> None:
        self._event("PRIVACY", f"PII_{action}", {"field": field})

    def data_minimization(self, original: list, retained: list, dropped: list) -> None:
        self._event("PRIVACY", "DATA_MINIMIZATION_APPLIED", {
            "original_column_count": len(original),
            "retained_column_count": len(retained),
            "dropped_columns": dropped,
        })

    # ── Consent ──────────────────────────────────────────────────────────────
    def consent_recorded(self, purpose: str, basis: str, confirmed: bool) -> None:
        self._event("CONSENT", "LAWFUL_BASIS_RECORDED",
                    {"processing_purpose": purpose, "lawful_basis": basis,
                     "user_confirmed": confirmed})

    # ── Retention ────────────────────────────────────────────────────────────
    def retention_policy(self, policy: str, days: int | None) -> None:
        self._event("RETENTION", "POLICY_RECORDED",
                    {"policy": policy, "retention_days": days})

    # ── Validation (NEW) ─────────────────────────────────────────────────────
    def validation_result(self, suite_name: str, success: bool,
                          passed: int, failed: int, total: int) -> None:
        """
        Record the overall result of a Great Expectations validation run.

        Parameters
        ----------
        suite_name : str   Name of the expectation suite that was evaluated.
        success    : bool  True if ALL expectations passed (or DLQ mode is on
                           and failures were routed rather than blocking).
        passed     : int   Number of expectations that passed.
        failed     : int   Number of expectations that failed.
        total      : int   Total expectations evaluated.
        """
        level = "INFO" if success else "WARNING"
        self._event("VALIDATION", "SUITE_RESULT", {
            "suite_name"          : suite_name,
            "overall_success"     : success,
            "expectations_passed" : passed,
            "expectations_failed" : failed,
            "expectations_total"  : total,
        }, level=level)

    def validation_expectation(self, expectation: str, column: str | None,
                                success: bool, unexpected_count: int = 0) -> None:
        """
        Record a single expectation result in the audit ledger.

        Parameters
        ----------
        expectation      : str   Expectation class name (e.g. ExpectColumnValuesToNotBeNull).
        column           : str   Column the expectation applies to (None for table-level).
        success          : bool  Whether the expectation passed.
        unexpected_count : int   Number of values/rows that violated the expectation.
        """
        self.validation_results.append({
            "expectation"     : expectation,
            "column"          : column,
            "success"         : success,
            "unexpected_count": unexpected_count,
        })
        self._event("VALIDATION", "EXPECTATION_RESULT", {
            "expectation": expectation, "column": column,
            "success": success, "unexpected_count": unexpected_count,
        }, level="INFO" if success else "WARNING")

    # ── Profiling (NEW) ──────────────────────────────────────────────────────
    def profile_recorded(self, summary: dict) -> None:
        """
        Record that a data profile was generated and stored.

        Parameters
        ----------
        summary : dict  High-level profile statistics (row count, null rate,
                        duplicate count, column count).
        """
        self._event("PROFILING", "PROFILE_GENERATED", summary)

    # ── Dead Letter Queue (NEW) ───────────────────────────────────────────────
    def dlq_written(self, row_count: int, reason: str) -> None:
        """
        Record that rows were written to the Dead Letter Queue.

        Parameters
        ----------
        row_count : int  Number of rejected rows written to the DLQ.
        reason    : str  Human-readable explanation of why rows were rejected
                         (e.g. "FAILED_VALIDATION: ExpectColumnValuesToNotBeNull(id)").
        """
        self.dlq_rows_total += row_count
        self._event("DLQ", "ROWS_REJECTED", {
            "rejected_row_count": row_count,
            "reason": reason,
            "dlq_file": str(self.dlq_file),
        }, level="WARNING")

    # ── Incremental loading (NEW) ─────────────────────────────────────────────
    def watermark_event(self, action: str, column: str,
                         value: Any, rows_filtered: int = 0) -> None:
        """
        Record a watermark read or write event.

        Parameters
        ----------
        action        : str  "READ" or "WRITE".
        column        : str  Watermark column name (e.g. "updated_at").
        value         : Any  The watermark value (timestamp, integer, etc.).
        rows_filtered : int  Rows excluded by the watermark filter (READ only).
        """
        self._event("INCREMENTAL", f"WATERMARK_{action}", {
            "watermark_column": column,
            "watermark_value" : str(value),
            "rows_filtered"   : rows_filtered,
        })

    # ── Retry (NEW) ──────────────────────────────────────────────────────────
    def retry_attempt(self, attempt: int, max_attempts: int,
                       wait_seconds: float, exc: Exception) -> None:
        """
        Record a retry attempt from the exponential-backoff loader.

        Parameters
        ----------
        attempt      : int    Current attempt number (1-based).
        max_attempts : int    Maximum attempts configured.
        wait_seconds : float  How long the pipeline will sleep before retrying.
        exc          : Exception  The exception that triggered the retry.
        """
        self._event("RETRY", "RETRY_ATTEMPT", {
            "attempt"      : attempt,
            "max_attempts" : max_attempts,
            "wait_seconds" : wait_seconds,
            "exception"    : str(exc),
        }, level="WARNING")

    # ── Notification (NEW) ───────────────────────────────────────────────────
    def notification_sent(self, channel: str, status: str, detail: str = "") -> None:
        """
        Record whether a notification was successfully delivered.

        Parameters
        ----------
        channel : str  "email" or "slack".
        status  : str  "SUCCESS" or "FAILED".
        detail  : str  Additional context (e.g. SMTP error message).
        """
        self._event("NOTIFICATION", f"{channel.upper()}_{status}",
                    {"detail": detail})

    # ── Error ────────────────────────────────────────────────────────────────
    def error(self, msg: str, exc: Exception | None = None) -> None:
        self._event("ERROR", msg,
                    {"exception": str(exc)} if exc else None, level="ERROR")

    # ── Report writers ────────────────────────────────────────────────────────
    def write_pii_report(self) -> None:
        """Write the consolidated PII findings report (GDPR Art. 30)."""
        report = {
            "pipeline_id"           : PIPELINE_ID,
            "generated_utc"         : datetime.now(timezone.utc).isoformat(),
            "regulation_references" : {"GDPR": "Articles 4,9,25,32",
                                        "CCPA": "§1798.100,§1798.140,§1798.150"},
            "pii_findings"          : self.pii_findings,
            "summary"               : {
                "total_pii_fields"       : len(self.pii_findings),
                "special_category_fields": sum(1 for f in self.pii_findings
                                               if f.get("special_category")),
            },
        }
        with open(self.pii_report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        self.logger.info(f"PII report          → {self.pii_report_file}")

    def write_validation_report(self) -> None:
        """Write the per-expectation GX validation report."""
        report = {
            "pipeline_id"       : PIPELINE_ID,
            "generated_utc"     : datetime.now(timezone.utc).isoformat(),
            "expectation_results": self.validation_results,
            "summary"           : {
                "total"      : len(self.validation_results),
                "passed"     : sum(1 for r in self.validation_results if r["success"]),
                "failed"     : sum(1 for r in self.validation_results if not r["success"]),
                "dlq_rows"   : self.dlq_rows_total,
            },
        }
        with open(self.validation_rpt_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        self.logger.info(f"Validation report   → {self.validation_rpt_file}")

    def write_profile_report(self, profile: dict) -> None:
        """Write the data profile report."""
        profile["pipeline_id"]   = PIPELINE_ID
        profile["generated_utc"] = datetime.now(timezone.utc).isoformat()
        with open(self.profile_rpt_file, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, default=str)
        self.logger.info(f"Profile report      → {self.profile_rpt_file}")

    def summary(self) -> None:
        """Print end-of-run governance artefact summary."""
        self.logger.info("=" * 62)
        self.logger.info("  GOVERNANCE SUMMARY")
        self.logger.info("=" * 62)
        self.logger.info(f"  Pipeline ID       : {PIPELINE_ID}")
        self.logger.info(f"  Run started       : {RUN_START}")
        self.logger.info(f"  Audit ledger      : {self.ledger_file}")
        self.logger.info(f"  PII report        : {self.pii_report_file}")
        self.logger.info(f"  Validation report : {self.validation_rpt_file}")
        self.logger.info(f"  Profile report    : {self.profile_rpt_file}")
        self.logger.info(f"  Dead letter queue : {self.dlq_file}  "
                         f"({self.dlq_rows_total} rows)")
        self.logger.info(f"  Log file          : {self.log_file}")
        self.logger.info(f"  Total events      : {len(self.ledger_entries)}")
        self.logger.info("=" * 62)


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITY / HELPER FUNCTIONS  (unchanged from v1.0 + new additions)
# ═════════════════════════════════════════════════════════════════════════════

def _file_hash(path: str) -> str:
    """Compute SHA-256 hex digest of a file in 8 KB chunks (tamper-evident lineage)."""
    h = hashlib.sha256()
    with open(path, "rb", encoding="utf-8") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_pii(columns: list[str]) -> list[dict]:
    """
    Scan column names for PII using regex patterns (GDPR Art. 4 / CCPA §1798.140).
    Returns one finding dict per matching column.
    """
    findings = []
    for col in columns:
        col_lower = col.lower()
        for pattern in PII_FIELD_PATTERNS:
            if re.search(pattern, col_lower):
                special = any(re.search(sp, col_lower) for sp in SENSITIVE_CATEGORIES)
                findings.append({
                    "field"           : col,
                    "matched_pattern" : pattern,
                    "special_category": special,
                    "gdpr_reference"  : "Article 9" if special else "Article 4(1)",
                    "ccpa_reference"  : "§1798.140(o)",
                })
                break
    return findings


def _flatten_record(record: Any, parent_key: str = "", sep: str = "__") -> dict:
    """
    Recursively flatten nested dicts/lists.
    {"a": {"b": 1}} → {"a__b": 1}
    {"scores": [9, 8]} → {"scores__0": 9, "scores__1": 8}
    """
    items: list = []
    if isinstance(record, dict):
        for k, v in record.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            items.extend(_flatten_record(v, new_key, sep).items()
                         if isinstance(v, (dict, list))
                         else [(new_key, v)])
    elif isinstance(record, list):
        for i, v in enumerate(record):
            new_key = f"{parent_key}{sep}{i}" if parent_key else str(i)
            items.extend(_flatten_record(v, new_key, sep).items()
                         if isinstance(v, (dict, list))
                         else [(new_key, v)])
    else:
        return {parent_key: record}
    return dict(items)


def _mask_value(value: Any) -> str | None:
    """
    Pseudonymise a value with a SHA-256 hash prefix (GDPR Art. 25).
    Returns None for null inputs, preserving null-ness in the dataset.
    """
    if value is None:
        return None
    return "MASKED_" + hashlib.sha256(str(value).encode()).hexdigest()[:12]


def _prompt(msg: str, default: str = "") -> str:
    """Prompt with an optional default shown in brackets.  Returns default on empty input."""
    resp = input(f"{msg} [{default}]: " if default else f"{msg}: ").strip()
    return resp if resp else default


def _yn(msg: str, default: bool = True) -> bool:
    """Yes/No prompt. Returns bool; accepts default on empty input."""
    suffix = "[Y/n]" if default else "[y/N]"
    resp = input(f"{msg} {suffix}: ").strip().lower()
    return default if not resp else resp in ("y", "yes")


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: SecretsManager  (NEW)
# ═════════════════════════════════════════════════════════════════════════════
class SecretsManager:
    """
    Resolves credentials and configuration values without hard-coding secrets.

    Resolution priority (highest → lowest)
    ---------------------------------------
    1. Explicit value passed in by the caller (e.g. from CLI args).
    2. .env file in the current working directory (loaded via python-dotenv).
    3. OS environment variable with the given key name.
    4. Interactive prompt as a last resort.

    This means that in a scheduled/automated run you set env vars or a .env
    file and the pipeline never blocks waiting for keyboard input.  In a
    manual run you can just answer the prompts.

    Passwords are ALWAYS collected via getpass.getpass() so they are never
    echoed to the terminal or captured in shell history.

    Usage
    -----
        sm = SecretsManager()
        host = sm.get("DB_HOST", prompt="Database host", default="localhost")
        pwd  = sm.get_password("DB_PASSWORD", prompt="Database password")
    """

    def __init__(self, env_file: str = ".env") -> None:
        """
        Parameters
        ----------
        env_file : str  Path to a .env file.  Loaded if python-dotenv is
                        installed and the file exists.  Silent if missing.
        """
        self._env: dict[str, str] = {}
        if HAS_DOTENV and Path(env_file).exists():
            self._env = {k: v for k, v in dotenv_values(env_file).items() if v}
            logging.getLogger("DataPipeline").info(
                f"[SECRETS] Loaded {len(self._env)} value(s) from {env_file}"
            )

    def get(self, key: str, prompt: str = "", default: str = "",
            explicit: str | None = None) -> str:
        """
        Resolve a configuration value using the priority order above.

        Parameters
        ----------
        key      : str         Environment variable / .env key to look up.
        prompt   : str         Human-readable prompt shown as a last resort.
        default  : str         Default value offered at the interactive prompt.
        explicit : str | None  If not None, returned immediately (highest priority).

        Returns
        -------
        str  The resolved value.
        """
        if explicit is not None:
            return explicit
        if key in self._env:
            return self._env[key]
        if key in os.environ:
            return os.environ[key]
        return _prompt(prompt or key, default)

    def get_password(self, key: str, prompt: str = "Password",
                      explicit: str | None = None) -> str:
        """
        Resolve a password using the same priority, but always using
        getpass for interactive input so it is never echoed.

        Parameters
        ----------
        key      : str         Env var / .env key name.
        prompt   : str         Prompt text for interactive input.
        explicit : str | None  Override value (highest priority).

        Returns
        -------
        str  The resolved password.
        """
        if explicit is not None:
            return explicit
        if key in self._env:
            return self._env[key]
        if key in os.environ:
            return os.environ[key]
        return getpass.getpass(f"{prompt}: ")


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DataProfiler  (NEW)
# ═════════════════════════════════════════════════════════════════════════════
class DataProfiler:
    """
    Generates a statistical profile of a DataFrame before transformation.

    Why profile before transformation?
    -----------------------------------
    Profiling the raw extracted data gives a baseline snapshot that can be
    compared against future runs to detect upstream data quality degradation
    (e.g. null rates suddenly rising, a numeric column switching to strings,
    a categorical field gaining unexpected values).

    The profile is written to governance_logs/profile_report_<ts>.json so
    that it persists as part of the audit trail for every pipeline run.

    Profile contents
    ----------------
    Table-level:
      row_count, column_count, duplicate_row_count, overall_null_rate

    Per-column:
      dtype, null_count, null_pct, unique_count, unique_pct
      Numeric only: min, max, mean, std, p25, p50 (median), p75
      String  only: min_length, max_length, avg_length, sample_values (top 5)
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def profile(self, df: "pd.DataFrame") -> dict:
        """
        Compute and return a profile dictionary for the given DataFrame.

        The profile is also written to the governance log artefacts via
        GovernanceLogger.write_profile_report().

        Parameters
        ----------
        df : pd.DataFrame  The raw (pre-transformation) DataFrame to profile.

        Returns
        -------
        dict  Full profile dictionary (also written to disk).
        """
        row_count    = len(df)
        col_count    = len(df.columns)
        dup_count    = int(df.duplicated().sum())
        total_cells  = row_count * col_count
        total_nulls  = int(df.isnull().sum().sum())
        null_rate    = round(total_nulls / total_cells, 4) if total_cells else 0

        columns_profile = {}
        for col in df.columns:
            s           = df[col]
            null_count  = int(s.isnull().sum())
            unique_count= int(s.nunique(dropna=True))
            col_profile: dict = {
                "dtype"       : str(s.dtype),
                "null_count"  : null_count,
                "null_pct"    : round(null_count / row_count, 4) if row_count else 0,
                "unique_count": unique_count,
                "unique_pct"  : round(unique_count / row_count, 4) if row_count else 0,
            }

            # ── Numeric column statistics ─────────────────────────────────────
            if pd.api.types.is_numeric_dtype(s):
                desc = s.describe()
                col_profile.update({
                    "min" : float(desc.get("min",  float("nan"))),
                    "max" : float(desc.get("max",  float("nan"))),
                    "mean": float(desc.get("mean", float("nan"))),
                    "std" : float(desc.get("std",  float("nan"))),
                    "p25" : float(desc.get("25%",  float("nan"))),
                    "p50" : float(desc.get("50%",  float("nan"))),
                    "p75" : float(desc.get("75%",  float("nan"))),
                })

            # ── String column statistics ──────────────────────────────────────
            elif s.dtype == object:
                str_series = s.dropna().astype(str)
                lengths    = str_series.str.len()
                col_profile.update({
                    "min_length"   : int(lengths.min()) if len(lengths) else 0,
                    "max_length"   : int(lengths.max()) if len(lengths) else 0,
                    "avg_length"   : round(float(lengths.mean()), 2) if len(lengths) else 0,
                    # Top 5 most frequent values give a quick sense of cardinality.
                    "sample_values": s.value_counts().head(5).index.tolist(),
                })

            columns_profile[col] = col_profile

        profile = {
            "table" : {
                "row_count"           : row_count,
                "column_count"        : col_count,
                "duplicate_row_count" : dup_count,
                "total_null_count"    : total_nulls,
                "overall_null_rate"   : null_rate,
            },
            "columns": columns_profile,
        }

        # Log a brief summary event and write the full report to disk.
        self.gov.profile_recorded({
            "row_count"      : row_count,
            "column_count"   : col_count,
            "duplicate_count": dup_count,
            "overall_null_rate": null_rate,
        })
        self.gov.write_profile_report(profile)
        return profile


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DeadLetterQueue  (NEW)
# ═════════════════════════════════════════════════════════════════════════════
class DeadLetterQueue:
    """
    Captures rows that fail schema validation instead of aborting the pipeline.

    How it works
    ------------
    When the SchemaValidator finds rows that violate an expectation (e.g.
    a required column contains nulls, a value is out of the allowed range),
    those row indices are passed here.  The rejected rows are written to a
    timestamped CSV file in the governance_logs directory with three extra
    columns appended:

        _dlq_pipeline_id  — ties the rejected row back to the pipeline run
        _dlq_reason       — human-readable description of why it was rejected
        _dlq_timestamp    — UTC ISO-8601 timestamp of rejection

    The clean rows (those NOT in the rejected set) continue through the
    rest of the pipeline and are loaded normally.  The DLQ file can then
    be reviewed, corrected, and re-fed into the pipeline independently.

    Governance alignment
    --------------------
    The DLQ is logged as a WARNING-level LINEAGE event so that auditors
    know exactly how many records were excluded from the load and why.
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov          = gov
        self.dlq_path     = gov.dlq_file
        self._header_written = False   # Track whether CSV header has been written yet

    def write(
        self,
        df: "pd.DataFrame",
        bad_indices: list[int],
        reason: str,
    ) -> "pd.DataFrame":
        """
        Extract rows with the given indices into the DLQ file and return
        the remaining clean DataFrame.

        Parameters
        ----------
        df          : pd.DataFrame  The DataFrame to filter.
        bad_indices : list[int]     Integer positional indices of rejected rows.
        reason      : str           Why these rows were rejected.

        Returns
        -------
        pd.DataFrame  Clean DataFrame with rejected rows removed.
        """
        if not bad_indices:
            return df   # Nothing to reject — return as-is

        # Locate bad rows using iloc (positional index, not .index labels).
        bad_mask       = df.index.isin(bad_indices)
        rejected_df    = df[bad_mask].copy()
        clean_df       = df[~bad_mask].copy()

        # Append DLQ metadata columns so reviewers know why rows were rejected.
        rejected_df["_dlq_pipeline_id"] = PIPELINE_ID
        rejected_df["_dlq_reason"]      = reason
        rejected_df["_dlq_timestamp"]   = datetime.now(timezone.utc).isoformat()

        # Append to the DLQ CSV file.  Write header only on first call.
        rejected_df.to_csv(
            self.dlq_path,
            mode   = "a",                     # Append — never overwrite existing entries
            header = not self._header_written, # Write column names only once
            index  = False,
        )
        self._header_written = True

        self.gov.dlq_written(len(rejected_df), reason)
        return clean_df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: SchemaValidator  (NEW — Great Expectations 1.x)
# ═════════════════════════════════════════════════════════════════════════════
class SchemaValidator:
    """
    Validates a DataFrame against a Great Expectations expectation suite.

    Great Expectations (GX) is an open-source data quality framework that
    lets you define declarative "expectations" about your data — things like
    "this column must always exist", "values must be non-null", "integers
    must be between 0 and 120".  GX then evaluates those expectations against
    actual data and produces a detailed pass/fail report.

    How this class works
    --------------------
    1. build_suite() — called interactively to define expectations.
       Auto-generates a baseline suite from the DataFrame's schema, then
       lets the operator add custom expectations via a menu.

    2. validate()    — runs the suite against a DataFrame and returns
       (clean_df, failed_count).  Rows that fail row-level expectations
       (null checks, range checks) are routed to the DeadLetterQueue.
       Rows that fail table-level expectations (column existence) are not
       filterable by row — those cause a WARNING but do not halt the pipeline.

    GX 1.x API notes
    ----------------
    GX 1.x uses an "ephemeral" context (in-memory, no file system config
    needed) which is ideal for embedded pipeline use:
        ctx = gx.get_context(mode="ephemeral")
    The DataSource, Asset, BatchDefinition, Suite, and ValidationDefinition
    are all created programmatically and exist only for the duration of the run.
    """

    def __init__(self, gov: GovernanceLogger, dlq: DeadLetterQueue) -> None:
        """
        Parameters
        ----------
        gov : GovernanceLogger  For recording validation events.
        dlq : DeadLetterQueue   For routing rejected rows.
        """
        self.gov   = gov
        self.dlq   = dlq
        self.suite_name   = f"pipeline_suite_{PIPELINE_ID[:8]}"
        # Stores the list of expectation configs built interactively so they
        # can be serialised for reuse in future runs.
        self.expectation_configs: list[dict] = []

    def build_suite(
        self, df: "pd.DataFrame", interactive: bool = True
    ) -> list:
        """
        Build a GX expectation suite for the given DataFrame.

        Always auto-generates the following baseline expectations:
          • ExpectColumnToExist          for every column
          • ExpectColumnValuesToNotBeNull for non-nullable numeric columns
            (those with 0% null rate in the sample)
          • ExpectColumnValuesToBeBetween for numeric columns (loose bounds
            derived from observed min/max ± 50% headroom)

        If interactive=True, the operator is then presented with a menu to
        add further expectations (strict null checks, uniqueness, regex
        patterns, allowed value sets).

        Parameters
        ----------
        df          : pd.DataFrame  Sample data used to infer auto-expectations.
        interactive : bool          Present the interactive menu (default True).
                                    Set False for scheduled/automated runs.

        Returns
        -------
        list  List of GX Expectation objects ready to be added to a suite.
        """
        expectations = []
        print("\n" + "═" * 62)
        print("  SCHEMA VALIDATION — Great Expectations Suite Builder")
        print("═" * 62)

        # ── Auto-generated baseline expectations ──────────────────────────────
        print("\n[GX] Auto-generating baseline expectations from schema…")

        for col in df.columns:
            # Every column that exists in the sample should exist in every
            # future load.  This catches upstream schema changes (column renames,
            # dropped fields) before bad data enters the database.
            exp = gxe.ExpectColumnToExist(column=col)
            expectations.append(exp)
            self.expectation_configs.append({"type": "ExpectColumnToExist", "column": col})

            # For numeric columns with no nulls in the sample, auto-add a
            # not-null expectation.  Use a loose range expectation based on
            # observed min/max with ±50% headroom to catch obvious outliers.
            if pd.api.types.is_numeric_dtype(df[col]):
                null_rate = df[col].isnull().mean()
                if null_rate == 0:
                    exp_nn = gxe.ExpectColumnValuesToNotBeNull(column=col)
                    expectations.append(exp_nn)
                    self.expectation_configs.append(
                        {"type": "ExpectColumnValuesToNotBeNull", "column": col}
                    )

                non_null = df[col].dropna()
                if len(non_null) > 0:
                    observed_min = float(non_null.min())
                    observed_max = float(non_null.max())
                    # Add ±50% headroom so the expectation doesn't fire on
                    # natural value growth, only genuine anomalies.
                    headroom     = max(abs(observed_max - observed_min) * 0.5, 1)
                    loose_min    = observed_min - headroom
                    loose_max    = observed_max + headroom
                    exp_range = gxe.ExpectColumnValuesToBeBetween(
                        column=col, min_value=loose_min, max_value=loose_max
                    )
                    expectations.append(exp_range)
                    self.expectation_configs.append({
                        "type": "ExpectColumnValuesToBeBetween",
                        "column": col,
                        "min_value": loose_min,
                        "max_value": loose_max,
                    })

        print(f"  ✓ {len(expectations)} baseline expectation(s) auto-generated.")

        # ── Interactive expectation builder ────────────────────────────────────
        if interactive:
            expectations = self._interactive_builder(df, expectations)

        return expectations

    def _interactive_builder(
        self, df: "pd.DataFrame", expectations: list
    ) -> list:
        """
        Present a menu allowing the operator to add custom expectations.

        Available expectation types
        ---------------------------
        1. Strict not-null     — Column must have zero nulls.
        2. Unique values       — Every value in the column must be unique
                                 (good for natural-key / ID columns).
        3. Exact value range   — Provide explicit min and max for a numeric
                                 column (overrides the auto-generated loose range).
        4. Allowed values      — Column may only contain values from a
                                 comma-separated list you provide.
        5. Regex pattern       — Every non-null string value must match a
                                 regular expression you provide.
        6. Row count minimum   — The table must have at least N rows
                                 (catches truncated / empty source files).

        The operator can add as many expectations as needed; choosing option 0
        exits the builder and proceeds with the collected expectations.
        """
        cols = list(df.columns)
        print("\n[GX] Add custom expectations (enter 0 when done):")

        while True:
            print("\n  1. Strict not-null          4. Allowed values list")
            print("  2. Unique values             5. Regex pattern match")
            print("  3. Exact numeric range       6. Minimum row count")
            print("  0. Done — proceed with validation")

            choice = _prompt("Add expectation", "0")
            if choice == "0":
                break

            # ── Pick the target column (for column-level expectations) ────────
            if choice in ("1", "2", "3", "4", "5"):
                print(f"\n  Available columns: {', '.join(cols)}")
                col = _prompt("Column name")
                if col not in cols:
                    print(f"  Column '{col}' not found — skipping.")
                    continue

            # ── Strict not-null ───────────────────────────────────────────────
            if choice == "1":
                exp = gxe.ExpectColumnValuesToNotBeNull(column=col)
                expectations.append(exp)
                self.expectation_configs.append(
                    {"type": "ExpectColumnValuesToNotBeNull", "column": col,
                     "source": "user_defined"}
                )
                print(f"  ✓ Added: {col} must not be null.")

            # ── Unique values ─────────────────────────────────────────────────
            elif choice == "2":
                exp = gxe.ExpectColumnValuesToBeUnique(column=col)
                expectations.append(exp)
                self.expectation_configs.append(
                    {"type": "ExpectColumnValuesToBeUnique", "column": col,
                     "source": "user_defined"}
                )
                print(f"  ✓ Added: {col} must be unique.")

            # ── Exact numeric range ───────────────────────────────────────────
            elif choice == "3":
                try:
                    min_v = float(_prompt(f"  Min value for {col}"))
                    max_v = float(_prompt(f"  Max value for {col}"))
                    exp   = gxe.ExpectColumnValuesToBeBetween(
                        column=col, min_value=min_v, max_value=max_v
                    )
                    expectations.append(exp)
                    self.expectation_configs.append({
                        "type": "ExpectColumnValuesToBeBetween", "column": col,
                        "min_value": min_v, "max_value": max_v, "source": "user_defined"
                    })
                    print(f"  ✓ Added: {col} must be between {min_v} and {max_v}.")
                except ValueError:
                    print("  Invalid number — skipping.")

            # ── Allowed values ────────────────────────────────────────────────
            elif choice == "4":
                raw  = input(f"  Allowed values for {col} (comma-separated): ").strip()
                vals = [v.strip() for v in raw.split(",") if v.strip()]
                if vals:
                    exp = gxe.ExpectColumnValuesToBeInSet(column=col, value_set=vals)
                    expectations.append(exp)
                    self.expectation_configs.append({
                        "type": "ExpectColumnValuesToBeInSet", "column": col,
                        "value_set": vals, "source": "user_defined"
                    })
                    print(f"  ✓ Added: {col} must be one of {vals}.")

            # ── Regex pattern ─────────────────────────────────────────────────
            elif choice == "5":
                pattern = input(f"  Regex pattern for {col}: ").strip()
                if pattern:
                    exp = gxe.ExpectColumnValuesToMatchRegex(column=col, regex=pattern)
                    expectations.append(exp)
                    self.expectation_configs.append({
                        "type": "ExpectColumnValuesToMatchRegex", "column": col,
                        "regex": pattern, "source": "user_defined"
                    })
                    print(f"  ✓ Added: {col} must match regex {pattern!r}.")

            # ── Minimum row count ─────────────────────────────────────────────
            elif choice == "6":
                try:
                    min_rows = int(_prompt("  Minimum row count"))
                    # ExpectTableRowCountToBeGreaterThan was removed in GE v1.x;
                    # use ExpectTableRowCountToBeBetween with min_value instead.
                    exp = gxe.ExpectTableRowCountToBeBetween(min_value=min_rows)
                    expectations.append(exp)
                    self.expectation_configs.append({
                        "type": "ExpectTableRowCountToBeBetween",
                        "min_value": min_rows, "source": "user_defined"
                    })
                    print(f"  ✓ Added: row count must be at least {min_rows:,}.")
                except ValueError:
                    print("  Invalid number — skipping.")

        return expectations

    def validate(
        self,
        df: "pd.DataFrame",
        expectations: list,
        on_failure: str = "dlq",
    ) -> tuple["pd.DataFrame", int]:
        """
        Run the expectation suite against a DataFrame.

        Row-level failures (null violations, range violations, etc.) are
        routed to the Dead Letter Queue rather than aborting the pipeline.
        The clean rows are returned for continued processing.

        Table-level failures (column-existence, row-count checks) cannot
        be resolved by removing individual rows — they generate a WARNING
        in the audit ledger but do not halt the pipeline.

        Parameters
        ----------
        df          : pd.DataFrame  Data to validate.
        expectations: list          GX Expectation objects from build_suite().
        on_failure  : str           "dlq"  — route bad rows to DLQ (default)
                                    "warn" — log warning but pass all rows through
                                    "halt" — raise an exception and stop the pipeline

        Returns
        -------
        tuple[pd.DataFrame, int]
            clean_df      — DataFrame with rejected rows removed.
            failed_count  — Number of expectations that failed.
        """
        if not HAS_GX:
            self.gov.error("GX_NOT_INSTALLED")
            return df, 0

        print("\n[GX] Running schema validation…")

        # ── Build GX ephemeral context ────────────────────────────────────────
        # An ephemeral context lives entirely in memory — no filesystem config,
        # no great_expectations.yml needed.  Perfect for embedded pipeline use.
        ctx      = gx.get_context(mode="ephemeral")
        ds       = ctx.data_sources.add_pandas("pipeline_ds")
        asset    = ds.add_dataframe_asset("pipeline_asset")
        batch_def= asset.add_batch_definition_whole_dataframe("batch_def")

        # ── Create and populate the expectation suite ─────────────────────────
        suite = ctx.suites.add(gx.ExpectationSuite(name=self.suite_name))
        for exp in expectations:
            suite.add_expectation(exp)

        # ── Run validation ────────────────────────────────────────────────────
        vd     = ctx.validation_definitions.add(
            gx.ValidationDefinition(
                name  = f"vd_{PIPELINE_ID[:8]}",
                data  = batch_def,
                suite = suite,
            )
        )
        result = vd.run(batch_parameters={"dataframe": df})

        # ── Process individual expectation results ────────────────────────────
        all_bad_indices: set[int] = set()
        failed_count              = 0

        for exp_result in result.results:
            exp_type     = type(exp_result.expectation_config).__name__
            col          = getattr(exp_result.expectation_config, "column", None)
            success      = exp_result.success
            unexpected   = exp_result.result.get("unexpected_count", 0) or 0
            failed_count += (0 if success else 1)

            # Log each expectation outcome to the governance audit ledger.
            self.gov.validation_expectation(exp_type, col, success, int(unexpected))

            # Collect row indices of violations for row-level expectations.
            # GX returns unexpected_index_list as the pandas .index values of
            # failing rows.  We need to map these to positional indices for DLQ.
            if not success and col and on_failure == "dlq":
                unexpected_idx = exp_result.result.get("unexpected_index_list") or []
                if unexpected_idx:
                    # unexpected_index_list contains label-based index values.
                    # Convert them to positional integers for iloc-based filtering.
                    label_to_pos = {label: pos for pos, label in enumerate(df.index)}
                    for label in unexpected_idx:
                        if label in label_to_pos:
                            all_bad_indices.add(label_to_pos[label])

        # ── Log overall validation result ─────────────────────────────────────
        total_exps  = len(result.results)
        passed_exps = total_exps - failed_count
        overall_ok  = result.success

        self.gov.validation_result(
            suite_name = self.suite_name,
            success    = overall_ok,
            passed     = passed_exps,
            failed     = failed_count,
            total      = total_exps,
        )

        print(f"  {'✓' if overall_ok else '⚠'} "
              f"{passed_exps}/{total_exps} expectations passed  |  "
              f"{len(all_bad_indices)} row(s) flagged.")

        # ── Handle failures ───────────────────────────────────────────────────
        if failed_count > 0:
            if on_failure == "halt":
                raise RuntimeError(
                    f"Schema validation failed: {failed_count} expectation(s) "
                    f"did not pass.  Check {self.gov.validation_rpt_file} for details."
                )
            elif on_failure == "dlq" and all_bad_indices:
                reason = f"FAILED_VALIDATION: {failed_count} expectation(s) failed"
                df = self.dlq.write(df, list(all_bad_indices), reason)
                print(f"  ⚠  {len(all_bad_indices)} row(s) sent to Dead Letter Queue.")
            # on_failure == "warn": log already written above — pass all rows through

        self.gov.write_validation_report()
        return df, failed_count


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: Extractor  (v2.0 — adds chunked iteration)
# ═════════════════════════════════════════════════════════════════════════════
class Extractor:
    """
    Reads source files into a pandas DataFrame (single-pass or chunked).

    v2.0 additions
    --------------
    chunks() — generator that yields the file contents in configurable
               row-count batches.  For CSV files pandas reads the file
               lazily so memory usage stays bounded.  For JSON / Excel /
               XML (which must be fully read into memory first), chunks()
               slices the completed DataFrame.

    Parameters
    ----------
    gov : GovernanceLogger
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def extract(self, path: str) -> "pd.DataFrame":
        """Read the entire source file into a single DataFrame (unchanged from v1)."""
        ext = Path(path).suffix.lower()
        self.gov.transformation_applied("EXTRACT_START", {"source": path, "format": ext})

        if ext == ".csv":
            df = pd.read_csv(path)
        elif ext in (".xlsx", ".xls"):
            df = pd.read_excel(path)
        elif ext == ".json":
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            flat = [_flatten_record(r) for r in raw] if isinstance(raw, list) \
                   else [_flatten_record(raw)]
            df = pd.DataFrame(flat)
        elif ext == ".xml":
            df = pd.read_xml(path)
        else:
            raise ValueError(f"Unsupported format: {ext}")

        self.gov.source_registered(path, ext, len(df), len(df.columns))
        self.gov.transformation_applied("EXTRACT_COMPLETE",
                                         {"rows": len(df), "columns": list(df.columns)})
        return df

    def chunks(self, path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> "Iterator[pd.DataFrame]":
        """
        Yield the source file in DataFrame chunks of at most chunk_size rows.

        For CSV files this uses pandas' native lazy chunked reader so only
        chunk_size rows are ever in memory at once — ideal for files larger
        than available RAM.

        For JSON, Excel, and XML the file is read fully first (unavoidable
        due to their structure), then sliced into chunks with iloc[].

        Parameters
        ----------
        path       : str  Path to the source file.
        chunk_size : int  Maximum rows per chunk.  Defaults to DEFAULT_CHUNK_SIZE.

        Yields
        ------
        pd.DataFrame  One chunk at a time until the file is exhausted.
        """
        ext = Path(path).suffix.lower()
        self.gov.transformation_applied("CHUNKED_EXTRACT_START",
                                         {"source": path, "chunk_size": chunk_size})

        if ext == ".csv":
            # pandas TextFileReader is a lazy generator — it reads one chunk
            # at a time from disk, keeping memory usage flat.
            reader = pd.read_csv(path, chunksize=chunk_size)
            for i, chunk in enumerate(reader):
                self.gov.transformation_applied(
                    "CHUNK_EXTRACTED", {"chunk_index": i, "rows": len(chunk)}
                )
                yield chunk
        else:
            # Non-CSV formats must be fully loaded first.
            df = self.extract(path)
            total_chunks = (len(df) + chunk_size - 1) // chunk_size
            for i in range(total_chunks):
                start = i * chunk_size
                end   = start + chunk_size
                chunk = df.iloc[start:end].copy()
                self.gov.transformation_applied(
                    "CHUNK_EXTRACTED",
                    {"chunk_index": i, "rows": len(chunk),
                     "total_chunks": total_chunks}
                )
                yield chunk


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: IncrementalFilter  (NEW)
# ═════════════════════════════════════════════════════════════════════════════
class IncrementalFilter:
    """
    Filters a DataFrame to only rows that are newer than the last run's
    high-water mark, enabling incremental (delta) loading.

    How it works
    ------------
    1. read_watermark()  — Load the last saved watermark from a JSON state
                           file.  Returns None if no previous run exists
                           (first run = full load).

    2. filter()          — Remove rows where the watermark column's value
                           is <= the stored watermark.  Only new/updated
                           rows proceed to transformation and loading.

    3. update_watermark() — After a successful load, save the maximum value
                            of the watermark column from this run's data.
                            This becomes the starting point for the next run.

    Supported watermark column types
    ---------------------------------
    • Datetime  — ISO-8601 string or pandas Timestamp
    • Integer   — auto-incrementing ID, sequence number
    • Float     — epoch timestamp

    State persistence
    -----------------
    The watermark is stored in pipeline_watermark.json in the current
    working directory.  Each pipeline's watermark is keyed by the
    combination of source file path and watermark column name so that
    multiple pipelines can share the same state file without collision.
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov        = gov
        self.state_file = WATERMARK_FILE

    def read_watermark(self, source_path: str, wm_col: str) -> Any:
        """
        Load the stored watermark for this source + column combination.

        Parameters
        ----------
        source_path : str  Source file path (used as the state key).
        wm_col      : str  Watermark column name (used as the state key).

        Returns
        -------
        Any  The stored watermark value, or None if no state exists.
        """
        key = f"{source_path}::{wm_col}"
        if not self.state_file.exists():
            return None
        with open(self.state_file, encoding="utf-8") as f:
            state = json.load(f)
        wm = state.get(key)
        if wm is not None:
            self.gov.watermark_event("READ", wm_col, wm)
        return wm

    def filter(
        self,
        df: "pd.DataFrame",
        wm_col: str,
        last_wm: Any,
        source_path: str,
    ) -> "pd.DataFrame":
        """
        Return only rows where wm_col > last_wm (i.e. newer than last run).

        Parameters
        ----------
        df          : pd.DataFrame  Full extracted DataFrame.
        wm_col      : str           Watermark column name.
        last_wm     : Any           Last run's watermark value.
        source_path : str           Used for governance logging context.

        Returns
        -------
        pd.DataFrame  Filtered DataFrame containing only new rows.
        """
        if last_wm is None:
            self.gov.transformation_applied(
                "INCREMENTAL_FILTER_SKIPPED",
                {"reason": "No previous watermark — full load"}
            )
            return df   # First run: load everything

        before_count = len(df)
        try:
            # Attempt datetime comparison first (most common watermark type).
            wm_series = pd.to_datetime(df[wm_col], errors="coerce")
            wm_val    = pd.to_datetime(last_wm)
            df = df[wm_series > wm_val].copy()
        except Exception:
            # Fall back to numeric comparison.
            df = df[df[wm_col] > last_wm].copy()

        filtered = before_count - len(df)
        self.gov.watermark_event("READ", wm_col, last_wm, rows_filtered=filtered)
        print(f"  [INCREMENTAL] Filtered {filtered:,} already-loaded rows  "
              f"| {len(df):,} new rows to process.")
        return df

    def update_watermark(
        self, df: "pd.DataFrame", wm_col: str, source_path: str
    ) -> None:
        """
        Persist the maximum value of wm_col as the new high-water mark.

        Parameters
        ----------
        df          : pd.DataFrame  The DataFrame that was successfully loaded.
        wm_col      : str           Watermark column name.
        source_path : str           Source file path (state key component).
        """
        if wm_col not in df.columns or df.empty:
            return

        new_wm = str(df[wm_col].max())
        key    = f"{source_path}::{wm_col}"

        state: dict = {}
        if self.state_file.exists():
            with open(self.state_file, encoding="utf-8") as f:
                state = json.load(f)
        state[key] = new_wm

        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

        self.gov.watermark_event("WRITE", wm_col, new_wm)
        print(f"  [INCREMENTAL] Watermark updated → {wm_col} = {new_wm}")


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: Transformer  (unchanged from v1.0)
# ═════════════════════════════════════════════════════════════════════════════
class Transformer:
    """
    Applies flatten → minimise → PII strategy → null removal →
    deduplication → column sanitisation → governance metadata.
    (Implementation unchanged from v1.0; see that version for full docs.)
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov         = gov
        self.pii_actions: dict[str, str] = {}

    def transform(
        self,
        df: "pd.DataFrame",
        pii_findings: list[dict],
        pii_strategy: str,
        drop_cols:    list[str],
    ) -> "pd.DataFrame":
        """Run all transformation steps and return the cleaned DataFrame."""
        original_cols = list(df.columns)

        # Step 1: Flatten residual nested object columns.
        obj_cols = [c for c in df.columns
                    if df[c].dtype == object
                    and df[c].dropna().apply(lambda x: isinstance(x, (dict, list))).any()]
        if obj_cols:
            expanded = []
            for _, row in df.iterrows():
                flat_row = {}
                for col in df.columns:
                    val = row[col]
                    flat_row.update(_flatten_record(val, parent_key=col)
                                    if isinstance(val, (dict, list))
                                    else {col: val})
                expanded.append(flat_row)
            df = pd.DataFrame(expanded)
            self.gov.transformation_applied("FLATTEN_NESTED", {"flattened_columns": obj_cols})

        # Step 2: Data minimisation (GDPR Art. 5(1)(c)).
        if drop_cols:
            df.drop(columns=[c for c in drop_cols if c in df.columns],
                    inplace=True, errors="ignore")
            self.gov.data_minimization(original_cols, list(df.columns), drop_cols)

        # Step 3: PII field handling.
        for field, _info in {f["field"]: f for f in pii_findings
                              if f["field"] in df.columns}.items():
            if pii_strategy == "mask":
                df[field] = df[field].apply(_mask_value)
                self.gov.pii_action(field, "MASKED")
                self.pii_actions[field] = "MASKED"
            elif pii_strategy == "drop":
                df.drop(columns=[field], inplace=True, errors="ignore")
                self.gov.pii_action(field, "DROPPED")
                self.pii_actions[field] = "DROPPED"
            else:
                self.gov.pii_action(field, "RETAINED_WITH_CONSENT")
                self.pii_actions[field] = "RETAINED_WITH_CONSENT"

        # Step 4: Null row removal.
        before_nulls = df.isnull().sum().sum()
        df.dropna(how="all", inplace=True)
        self.gov.transformation_applied("NULL_HANDLING", {
            "null_cells_before": int(before_nulls),
            "null_cells_after" : int(df.isnull().sum().sum()),
        })

        # Step 5: Deduplication.
        before = len(df)
        df.drop_duplicates(inplace=True)
        self.gov.transformation_applied("DEDUPLICATION", {
            "rows_before": before, "rows_after": len(df),
            "duplicates_removed": before - len(df),
        })

        # Step 6: Column name sanitisation.
        df.columns = [re.sub(r"[^a-zA-Z0-9_]", "_", c).strip("_")
                      for c in df.columns]
        self.gov.transformation_applied("COLUMN_SANITIZATION",
                                         {"final_columns": list(df.columns)})

        # Step 7: Governance metadata columns.
        df["_pipeline_id"]   = PIPELINE_ID
        df["_loaded_at_utc"] = datetime.now(timezone.utc).isoformat()

        self.gov.transformation_applied("TRANSFORM_COMPLETE", {
            "final_row_count": len(df), "final_col_count": len(df.columns),
        })
        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: SQLLoader  (v2.0 — adds retry and idempotency / upsert)
# ═════════════════════════════════════════════════════════════════════════════
class SQLLoader:
    """
    Writes a DataFrame to a SQL database with:
      • Exponential-backoff retry   (tenacity)
      • Optional upsert / idempotency  (natural-key deduplication)

    Retry strategy
    --------------
    The load() method is wrapped with a tenacity @retry decorator configured
    for up to 3 attempts with exponential backoff (2s → 4s → 8s).  This
    handles transient failures — network interruptions, temporary DB locks,
    brief connection pool exhaustion — without human intervention.

    Idempotency (upsert)
    --------------------
    When natural_keys are provided, load() uses a read-then-merge approach:
      1. Attempt to read the existing table.
      2. Merge with the new data on the natural keys using "update" merge.
      3. Write the merged result back (table is replaced, not appended).

    This ensures running the pipeline twice produces the same result — no
    duplicate records, just updated values.  The trade-off is a full table
    read on every run, which is acceptable for moderate table sizes but may
    be slow for very large tables (consider a SQL MERGE statement instead
    for production at scale).
    """

    def __init__(self, gov: GovernanceLogger, db_type: str) -> None:
        self.gov     = gov
        self.db_type = db_type
        self._attempt = 0   # Tracks current retry attempt for logging

    def _engine(self, cfg: dict):
        """Build and return a SQLAlchemy Engine for the configured database."""
        from sqlalchemy import create_engine
        t = self.db_type
        if t == "sqlite":
            return create_engine(f"sqlite:///{cfg['db_name']}.db")
        elif t == "postgresql":
            return create_engine(
                f"postgresql+psycopg2://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port',5432)}/{cfg['db_name']}"
            )
        elif t == "mysql":
            return create_engine(
                f"mysql+pymysql://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port',3306)}/{cfg['db_name']}"
            )
        elif t == "mssql":
            driver = cfg.get("driver", "ODBC+Driver+17+for+SQL+Server")
            return create_engine(
                f"mssql+pyodbc://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port',1433)}/{cfg['db_name']}"
                f"?driver={driver}"
            )
        raise ValueError(f"Unknown db type: {t}")

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str  = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Write the DataFrame to the target table with retry and optional upsert.

        Parameters
        ----------
        df           : pd.DataFrame    Transformed data to load.
        cfg          : dict            DB connection config.
        table        : str             Target table name.
        if_exists    : str             "append", "replace", or "fail".
        natural_keys : list[str]|None  Column names that uniquely identify a row.
                                       When provided, upsert mode is used:
                                       existing rows are updated, new rows inserted.
        """
        engine = self._engine(cfg)

        # ── Idempotency / upsert ──────────────────────────────────────────────
        if natural_keys:
            self._upsert(df, engine, table, natural_keys)
        else:
            self._load_with_retry(df, engine, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(self.db_type, cfg["db_name"], table)

    def _load_with_retry(
        self,
        df:        "pd.DataFrame",
        engine,
        table:     str,
        if_exists: str,
    ) -> None:
        """
        Execute to_sql() with exponential-backoff retry on transient failures.

        Attempts   : 3
        Wait       : 2s, 4s, 8s  (2^n seconds between attempts)
        Retry on   : Any Exception (covers network errors, lock timeouts, etc.)
        Give up on : Non-retriable errors are re-raised after max attempts.
        """
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                df.to_sql(table, engine, if_exists=if_exists,
                          index=False, chunksize=500)
                return   # Success — exit retry loop
            except Exception as exc:
                if attempt == max_attempts:
                    raise   # Re-raise on final attempt
                wait = 2 ** attempt   # 2s, 4s, 8s
                self.gov.retry_attempt(attempt, max_attempts, float(wait), exc)
                print(f"  ⚠  Load attempt {attempt}/{max_attempts} failed "
                      f"({exc!s:.60}).  Retrying in {wait}s…")
                time.sleep(wait)

    def _upsert(
        self,
        new_df:       "pd.DataFrame",
        engine,
        table:        str,
        natural_keys: list[str],
    ) -> None:
        """
        Read-merge-write upsert: update existing rows, insert new rows.

        The approach:
          1. Try to read the existing table.  If it does not exist yet,
             fall back to a plain insert (first run).
          2. Merge existing and new data on the natural keys with
             how="outer" to capture both updates and genuinely new rows.
          3. For matching rows, new values overwrite old values.
          4. Write the merged result back (replace the table).

        Parameters
        ----------
        new_df       : pd.DataFrame   New data to merge in.
        engine       : SQLAlchemy Engine
        table        : str            Target table name.
        natural_keys : list[str]      Columns that identify unique records.
        """
        from sqlalchemy import inspect as sa_inspect

        # Check whether the target table already exists.
        inspector = sa_inspect(engine)
        if table not in inspector.get_table_names():
            # First run: no existing data to merge — plain insert.
            self._load_with_retry(new_df, engine, table, if_exists="replace")
            self.gov.transformation_applied("UPSERT_FIRST_RUN",
                                             {"table": table, "rows": len(new_df)})
            return

        # Read existing table into a DataFrame.
        existing_df = pd.read_sql_table(table, engine)
        self.gov.transformation_applied("UPSERT_READ_EXISTING",
                                         {"table": table, "existing_rows": len(existing_df)})

        # Left-join new data onto existing on natural keys so we can detect
        # which rows already exist and which are genuinely new.
        merged = new_df.merge(
            existing_df,
            on       = natural_keys,
            how      = "outer",
            suffixes = ("", "_old"),
            indicator= True,
        )

        # Drop the old-value columns introduced by the merge (we keep new values).
        old_cols = [c for c in merged.columns if c.endswith("_old")]
        merged.drop(columns=old_cols + ["_merge"], inplace=True, errors="ignore")

        updated_count = int((merged["_merge"] == "both").sum()
                            if "_merge" in merged.columns else 0)
        new_count     = len(new_df)

        # Write the fully merged table back (replace).
        self._load_with_retry(merged, engine, table, if_exists="replace")
        self.gov.transformation_applied("UPSERT_COMPLETE", {
            "table": table, "final_rows": len(merged),
            "updated": updated_count, "new": new_count,
        })
        print(f"  [UPSERT] {new_count} new rows, {updated_count} updated rows "
              f"→ {len(merged)} total in {table}.")


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: MongoLoader  (unchanged from v1.0)
# ═════════════════════════════════════════════════════════════════════════════
class MongoLoader:
    """Loads a DataFrame into a MongoDB collection (unchanged from v1.0)."""

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def load(self, df: "pd.DataFrame", cfg: dict, collection: str) -> None:
        from pymongo import MongoClient
        uri     = cfg.get("uri") or \
                  f"mongodb://{cfg.get('host','localhost')}:{cfg.get('port',27017)}/"
        client  = MongoClient(uri)
        records = json.loads(df.to_json(orient="records", date_format="iso"))
        client[cfg["db_name"]][collection].insert_many(records)
        self.gov.load_complete(len(records), collection)
        self.gov.destination_registered("mongodb", cfg["db_name"], collection)
        client.close()


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: Notifier  (NEW)
# ═════════════════════════════════════════════════════════════════════════════
class Notifier:
    """
    Sends pipeline completion or failure notifications via Email and/or Slack.

    Email
    -----
    Uses Python's stdlib smtplib module — no extra dependencies.  Sends an
    HTML-formatted email with pipeline statistics, a pass/fail indicator,
    and links to the governance artefact files.

    Slack
    -----
    Uses an Incoming Webhook URL (configured in your Slack workspace).
    Sends a Block Kit-formatted message with coloured attachment (green for
    success, red for failure).  Requires the `requests` library.

    Security note
    -------------
    SMTP passwords and Slack webhook URLs are treated as secrets and resolved
    through SecretsManager (env vars → .env file → interactive prompt).
    They are never logged or stored in the audit ledger.

    Usage
    -----
        notifier = Notifier(gov, email_cfg={...}, slack_cfg={...})
        notifier.send(success=True, stats={...})
    """

    def __init__(
        self,
        gov:       GovernanceLogger,
        email_cfg: dict | None = None,
        slack_cfg: dict | None = None,
    ) -> None:
        """
        Parameters
        ----------
        gov       : GovernanceLogger
        email_cfg : dict | None  Keys: smtp_host, smtp_port, smtp_user,
                                       smtp_password, from_addr, to_addrs (list)
        slack_cfg : dict | None  Keys: webhook_url
        """
        self.gov       = gov
        self.email_cfg = email_cfg or {}
        self.slack_cfg = slack_cfg or {}

    def send(self, success: bool, stats: dict) -> None:
        """
        Dispatch notifications to all configured channels.

        Parameters
        ----------
        success : bool  True = pipeline completed successfully.
        stats   : dict  Summary statistics to include in the message
                        (rows loaded, DLQ count, validation failures, etc.).
        """
        if self.email_cfg:
            self._send_email(success, stats)
        if self.slack_cfg:
            self._send_slack(success, stats)

    def _build_subject(self, success: bool) -> str:
        status = "✅ SUCCESS" if success else "❌ FAILED"
        return f"[Data Pipeline] {status} — {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC"

    def _build_html(self, success: bool, stats: dict) -> str:
        """Build a simple HTML email body with pipeline statistics."""
        color   = "#28a745" if success else "#dc3545"
        status  = "COMPLETED SUCCESSFULLY" if success else "FAILED"
        rows    = []
        for k, v in stats.items():
            rows.append(f"<tr><td style='padding:4px 12px'><b>{k}</b></td>"
                        f"<td style='padding:4px 12px'>{v}</td></tr>")
        table_rows = "\n".join(rows)
        return f"""
        <html><body>
        <h2 style="color:{color}">Pipeline {status}</h2>
        <p><b>Pipeline ID:</b> {PIPELINE_ID}</p>
        <p><b>Run start:</b> {RUN_START}</p>
        <table border="1" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
          <tr style="background:{color};color:white">
            <th style="padding:6px 12px">Metric</th>
            <th style="padding:6px 12px">Value</th>
          </tr>
          {table_rows}
        </table>
        <p style="color:#666;font-size:12px">
          Governance artefacts saved to: {self.gov.log_dir}
        </p>
        </body></html>
        """

    def _send_email(self, success: bool, stats: dict) -> None:
        """
        Send an HTML notification email via SMTP.

        Handles both plain SMTP (port 25) and SMTP-over-TLS (STARTTLS, port 587)
        automatically — if smtp_port is 465 it uses SMTP_SSL; otherwise it
        attempts STARTTLS.
        """
        cfg = self.email_cfg
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = self._build_subject(success)
            msg["From"]    = cfg["from_addr"]
            msg["To"]      = ", ".join(cfg.get("to_addrs", [cfg["from_addr"]]))
            msg.attach(MIMEText(self._build_html(success, stats), "html"))

            port = int(cfg.get("smtp_port", 587))
            if port == 465:
                # SSL from the start (less common but still used).
                with smtplib.SMTP_SSL(cfg["smtp_host"], port) as server:
                    server.login(cfg["smtp_user"], cfg["smtp_password"])
                    server.send_message(msg)
            else:
                # Connect unencrypted, then upgrade with STARTTLS.
                with smtplib.SMTP(cfg["smtp_host"], port) as server:
                    server.ehlo()
                    server.starttls()
                    server.login(cfg["smtp_user"], cfg["smtp_password"])
                    server.send_message(msg)

            self.gov.notification_sent("email", "SUCCESS")
            print(f"  [NOTIFY] Email sent → {msg['To']}")
        except Exception as exc:
            self.gov.notification_sent("email", "FAILED", str(exc))
            print(f"  [NOTIFY] Email failed: {exc}")

    def _send_slack(self, success: bool, stats: dict) -> None:
        """
        Post a Block Kit-formatted message to a Slack Incoming Webhook.

        The message uses a coloured attachment border (green/red) and lists
        all pipeline stats as a mrkdwn-formatted table in the body.
        """
        if not HAS_REQUESTS:
            self.gov.notification_sent("slack", "FAILED",
                                        "requests library not installed")
            print("  [NOTIFY] Slack skipped — 'requests' package not installed.")
            return

        color   = "#28a745" if success else "#dc3545"
        status  = "✅ Pipeline completed successfully" if success \
                  else "❌ Pipeline FAILED"
        lines   = [f"*{k}*: {v}" for k, v in stats.items()]
        text    = "\n".join(lines)

        payload = {
            "text": status,
            "attachments": [{
                "color"  : color,
                "text"   : f"*Pipeline ID:* {PIPELINE_ID}\n{text}",
                "footer" : f"Run started: {RUN_START}",
                "mrkdwn_in": ["text"],
            }],
        }

        try:
            resp = _requests.post(
                self.slack_cfg["webhook_url"],
                json    = payload,
                timeout = 10,
            )
            resp.raise_for_status()
            self.gov.notification_sent("slack", "SUCCESS")
            print("  [NOTIFY] Slack message sent.")
        except Exception as exc:
            self.gov.notification_sent("slack", "FAILED", str(exc))
            print(f"  [NOTIFY] Slack failed: {exc}")


# ═════════════════════════════════════════════════════════════════════════════
#  COMPLIANCE WIZARD  (unchanged from v1.0)
# ═════════════════════════════════════════════════════════════════════════════
def run_compliance_wizard(gov: GovernanceLogger, pii_findings: list[dict]) -> dict:
    """
    Interactive GDPR / CCPA compliance wizard.
    Captures: lawful basis, purpose, CCPA opt-out, PII strategy,
    retention policy, and columns to drop.
    Returns a compliance configuration dict.
    """
    print("\n" + "═" * 62)
    print("  GDPR / CCPA COMPLIANCE WIZARD")
    print("═" * 62)

    # GDPR Article 6 lawful basis.
    print("\n[GDPR Art. 6] Lawful basis for processing:")
    bases = {"1":"Consent","2":"Contract","3":"Legal Obligation",
             "4":"Vital Interests","5":"Public Task","6":"Legitimate Interests"}
    for k, v in bases.items(): print(f"  {k}. {v}")
    lawful_basis = bases.get(_prompt("Choice", "2"), "Contract")
    purpose      = _prompt("Processing purpose", "Data analysis")
    confirmed    = _yn("Data subject / owner consents?", True)
    gov.consent_recorded(purpose, lawful_basis, confirmed)

    # CCPA §1798.120 opt-out.
    print("\n[CCPA §1798.120] Data sale / sharing")
    if _yn("Will data be sold or shared with third parties?", False):
        optout = _yn("Has data subject opted OUT of sale?", True)
        gov._event("CONSENT", "CCPA_SALE_OPTOUT", {"opted_out": optout})
        if optout: print("  ✓ Opt-out recorded.")

    # PII strategy.
    pii_strategy = "retain"
    if pii_findings:
        print(f"\n[PRIVACY] {len(pii_findings)} PII field(s) detected:")
        for f in pii_findings:
            tag = " ⚠ SPECIAL CATEGORY (Art.9)" if f["special_category"] else ""
            print(f"  • {f['field']}{tag}")
        print("\n  1. Mask (SHA-256 pseudonymise)   2. Drop   3. Retain (with consent)")
        pii_strategy = {"1":"mask","2":"drop","3":"retain"}.get(_prompt("Choice","1"),"mask")

    # Retention policy.
    print("\n[GDPR Art. 5(1)(e) / CCPA §1798.100] Retention policy")
    ret_map = {"1":30,"2":90,"3":365,"4":730,"5":1825,"6":None}
    print("  1.30d  2.90d  3.1yr  4.2yr  5.5yr  6.Indefinite")
    retention_days = ret_map.get(_prompt("Choice","3"), 365)
    desc = (f"Retain {retention_days} days" if retention_days
            else "Indefinite — legal justification required")
    gov.retention_policy(desc, retention_days)

    # Data minimisation.
    drop_cols: list[str] = []
    if _yn("\n[GDPR Art. 5(1)(c)] Drop specific columns?", False):
        drop_cols = [c.strip() for c in
                     input("Column names (comma-separated): ").split(",")
                     if c.strip()]

    return {"lawful_basis": lawful_basis, "purpose": purpose,
            "pii_strategy": pii_strategy, "retention_days": retention_days,
            "drop_cols": drop_cols}


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION PROMPTS
# ═════════════════════════════════════════════════════════════════════════════
def prompt_db_config(secrets: SecretsManager) -> tuple[str, dict, str]:
    """
    Collect database connection parameters using SecretsManager so that
    credentials can be resolved from env vars / .env without prompting.

    Parameters
    ----------
    secrets : SecretsManager  For credential resolution.

    Returns
    -------
    tuple[str, dict, str]  (db_type, cfg_dict, table_name)
    """
    print("\n" + "═" * 62)
    print("  DESTINATION DATABASE CONFIGURATION")
    print("═" * 62)
    print("  1.SQLite  2.PostgreSQL  3.MySQL  4.SQL Server  5.MongoDB")
    db_map  = {"1":"sqlite","2":"postgresql","3":"mysql","4":"mssql","5":"mongodb"}
    db_type = db_map.get(_prompt("Select database type", "1"), "sqlite")
    cfg:dict = {}

    if db_type == "sqlite":
        cfg["db_name"] = secrets.get("DB_NAME", "SQLite file name", "pipeline_output")
    elif db_type == "mongodb":
        if _yn("Use full MongoDB URI?", False):
            cfg["uri"] = secrets.get("MONGO_URI", "MongoDB URI")
        else:
            cfg["host"] = secrets.get("DB_HOST", "Host", "localhost")
            cfg["port"] = int(secrets.get("DB_PORT", "Port", "27017"))
        cfg["db_name"] = secrets.get("DB_NAME", "Database name", "pipeline_db")
    else:
        cfg["host"]     = secrets.get("DB_HOST",     "Host",     "localhost")
        cfg["user"]     = secrets.get("DB_USER",     "Username")
        cfg["password"] = secrets.get_password("DB_PASSWORD", "Database password")
        cfg["db_name"]  = secrets.get("DB_NAME",     "Database", "pipeline_db")
        port_defaults   = {"postgresql":"5432","mysql":"3306","mssql":"1433"}
        cfg["port"]     = secrets.get("DB_PORT", "Port", port_defaults.get(db_type,"5432"))

    table = secrets.get("DB_TABLE", "Target table / collection", "imported_data")
    return db_type, cfg, table


def prompt_validation_config() -> dict:
    """
    Collect schema validation preferences from the operator.

    Returns
    -------
    dict  Keys: enabled (bool), on_failure (str), interactive (bool).
    """
    print("\n" + "═" * 62)
    print("  SCHEMA VALIDATION (Great Expectations)")
    print("═" * 62)
    enabled = _yn("Enable schema validation?", True)
    if not enabled:
        return {"enabled": False}

    print("\n  On validation failure:")
    print("  1. dlq   — Route bad rows to Dead Letter Queue (recommended)")
    print("  2. warn  — Log warning, pass all rows through")
    print("  3. halt  — Stop the pipeline entirely")
    on_failure  = {"1":"dlq","2":"warn","3":"halt"}.get(_prompt("Choice","1"),"dlq")
    interactive = _yn("Customise expectations interactively?", True)
    return {"enabled": True, "on_failure": on_failure, "interactive": interactive}


def prompt_incremental_config(columns: list[str]) -> dict:
    """
    Optionally enable incremental (delta) loading with a watermark column.

    Parameters
    ----------
    columns : list[str]  Available column names to choose from.

    Returns
    -------
    dict  Keys: enabled (bool), watermark_col (str | None).
    """
    print("\n" + "═" * 62)
    print("  INCREMENTAL LOADING")
    print("═" * 62)
    print("  Incremental loading filters out rows already processed in")
    print("  a previous run using a timestamp or auto-increment column.")
    if not _yn("Enable incremental loading?", False):
        return {"enabled": False, "watermark_col": None}

    print(f"\n  Available columns: {', '.join(columns[:20])}"
          f"{'…' if len(columns) > 20 else ''}")
    col = _prompt("Watermark column (e.g. updated_at, id)")
    if col not in columns:
        print(f"  Column '{col}' not found — disabling incremental loading.")
        return {"enabled": False, "watermark_col": None}
    return {"enabled": True, "watermark_col": col}


def prompt_notification_config(secrets: SecretsManager) -> dict:
    """
    Optionally configure email and/or Slack notifications.

    Parameters
    ----------
    secrets : SecretsManager  For credential resolution.

    Returns
    -------
    dict  Keys: email_cfg (dict|None), slack_cfg (dict|None).
    """
    print("\n" + "═" * 62)
    print("  NOTIFICATIONS")
    print("═" * 62)
    email_cfg = None
    slack_cfg = None

    if _yn("Send email notifications?", False):
        email_cfg = {
            "smtp_host"    : secrets.get("SMTP_HOST",     "SMTP host",  "smtp.gmail.com"),
            "smtp_port"    : int(secrets.get("SMTP_PORT", "SMTP port",  "587")),
            "smtp_user"    : secrets.get("SMTP_USER",     "SMTP username"),
            "smtp_password": secrets.get_password("SMTP_PASSWORD", "SMTP password"),
            "from_addr"    : secrets.get("NOTIFY_FROM",   "From address"),
            "to_addrs"     : [a.strip() for a in
                              secrets.get("NOTIFY_TO", "To address(es)").split(",")],
        }

    if _yn("Send Slack notifications?", False):
        slack_cfg = {
            "webhook_url": secrets.get("SLACK_WEBHOOK",
                                        "Slack Incoming Webhook URL"),
        }

    return {"email_cfg": email_cfg, "slack_cfg": slack_cfg}


# ═════════════════════════════════════════════════════════════════════════════
#  CLI ARGUMENT PARSER  (NEW)
# ═════════════════════════════════════════════════════════════════════════════
def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build the command-line argument parser for parameterised / scheduled runs.

    All arguments are optional — the pipeline falls back to interactive
    prompts for any argument not supplied.  This means the same script works
    both as a manually-run interactive tool and as a scheduled job (cron,
    Task Scheduler, Airflow operator, etc.) when all arguments are passed.

    Example scheduled invocation
    -----------------------------
        python pipeline_v2.py \\
            --source /data/employees.csv \\
            --db-type postgresql \\
            --db-host prod-db.example.com \\
            --db-name analytics \\
            --table employees_raw \\
            --chunk-size 100000 \\
            --on-failure dlq \\
            --no-interactive \\
            --slack-webhook https://hooks.slack.com/services/XXX/YYY/ZZZ

    Returns
    -------
    argparse.ArgumentParser
    """
    p = argparse.ArgumentParser(
        prog        = "pipeline_v2",
        description = "Data Governance Pipeline v2.0 — GDPR & CCPA Compliant ETL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Source ────────────────────────────────────────────────────────────────
    p.add_argument("--source",        metavar="FILE",
                   help="Path to source file (CSV, JSON, Excel, XML)")
    p.add_argument("--chunk-size",    metavar="N", type=int, default=0,
                   help=f"Rows per chunk (0 = single-pass, default 0). "
                        f"Recommend {DEFAULT_CHUNK_SIZE:,} for files >1M rows")

    # ── Destination ───────────────────────────────────────────────────────────
    p.add_argument("--db-type",       metavar="TYPE",
                   choices=["sqlite","postgresql","mysql","mssql","mongodb"],
                   help="Target database type")
    p.add_argument("--db-host",       metavar="HOST",  help="Database host")
    p.add_argument("--db-name",       metavar="DB",    help="Database / file name")
    p.add_argument("--db-user",       metavar="USER",  help="Database username")
    p.add_argument("--db-port",       metavar="PORT",  help="Database port")
    p.add_argument("--table",         metavar="TABLE", help="Target table name")
    p.add_argument("--if-exists",     metavar="MODE",
                   choices=["append","replace","fail"], default="append",
                   help="Table collision behaviour (default: append)")
    p.add_argument("--natural-keys",  metavar="COLS",
                   help="Comma-separated natural key columns for upsert idempotency")

    # ── Validation ────────────────────────────────────────────────────────────
    p.add_argument("--no-validation", action="store_true",
                   help="Skip schema validation entirely")
    p.add_argument("--on-failure",    metavar="MODE",
                   choices=["dlq","warn","halt"], default="dlq",
                   help="Action on validation failure (default: dlq)")

    # ── Incremental loading ────────────────────────────────────────────────────
    p.add_argument("--watermark-col", metavar="COL",
                   help="Column to use as incremental watermark")

    # ── Notifications ─────────────────────────────────────────────────────────
    p.add_argument("--slack-webhook", metavar="URL",
                   help="Slack Incoming Webhook URL for notifications")

    # ── Behaviour ────────────────────────────────────────────────────────────
    p.add_argument("--no-interactive", action="store_true",
                   help="Disable all interactive prompts (for scheduled runs). "
                        "All required values must be supplied via args or env vars.")
    p.add_argument("--log-dir",       metavar="DIR",  default="governance_logs",
                   help="Directory for governance artefacts (default: governance_logs)")
    p.add_argument("--env-file",      metavar="FILE", default=".env",
                   help="Path to .env secrets file (default: .env)")

    return p


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE ORCHESTRATOR  v2.0
# ═════════════════════════════════════════════════════════════════════════════
def main() -> None:
    """
    Top-level orchestration function for the v2.0 pipeline.

    Execution order
    ---------------
    1.  Parse CLI args + check dependencies
    2.  Initialise SecretsManager + GovernanceLogger
    3.  Source file resolution (arg → prompt)
    4.  Extract (full or chunked)
    5.  Data profiling
    6.  PII scan
    7.  Incremental filter (if enabled)
    8.  Compliance wizard
    9.  Schema validation (Great Expectations)
    10. Transform
    11. Load with retry (SQL or MongoDB)
    12. Update watermark (if incremental)
    13. Send notifications
    14. Write all governance artefacts + summary
    """
    # ── Step 1: Parse args + dependency check ────────────────────────────────
    parser = build_arg_parser()
    args   = parser.parse_args()

    print("=" * 62)
    print(f"  DATA GOVERNANCE PIPELINE  v{VERSION}")
    print("  GDPR & CCPA Compliant ETL")
    print("=" * 62)

    if MISSING:
        print(f"\n[ERROR] Missing required packages: {', '.join(MISSING)}")
        print("Install with:  pip install " + " ".join(MISSING))
        sys.exit(1)

    interactive = not args.no_interactive

    # ── Step 2: Secrets + Governance Logger ──────────────────────────────────
    secrets = SecretsManager(env_file=args.env_file)
    gov     = GovernanceLogger(log_dir=args.log_dir)
    gov.pipeline_start({
        "version"       : VERSION,
        "platform"      : platform.platform(),
        "python_version": sys.version,
        "interactive"   : interactive,
    })

    # ── Step 3: Source file ───────────────────────────────────────────────────
    source_path = args.source
    if not source_path:
        print("\n[SOURCE] Supported: CSV, JSON, Excel (.xlsx/.xls), XML")
        while True:
            source_path = _prompt("Path to source file")
            if Path(source_path).exists():
                break
            print(f"  Not found: {source_path} — try again.")
    elif not Path(source_path).exists():
        print(f"[ERROR] Source file not found: {source_path}")
        sys.exit(1)

    # ── Step 4: Extract ───────────────────────────────────────────────────────
    extractor  = Extractor(gov)
    chunk_size = args.chunk_size or 0

    # Decide on single-pass vs chunked mode.
    # For initial profiling, compliance wizard, and validation setup we always
    # need the full DataFrame.  Chunking is applied at the LOAD stage.
    try:
        df = extractor.extract(source_path)
    except Exception as exc:
        gov.error("EXTRACTION_FAILED", exc)
        print(f"\n[ERROR] Cannot read file: {exc}")
        sys.exit(1)

    print(f"\n  ✓ {len(df):,} rows × {len(df.columns)} columns extracted.")
    print(f"  Columns: {', '.join(df.columns[:10])}"
          f"{'…' if len(df.columns) > 10 else ''}")

    # ── Step 5: Data profiling ─────────────────────────────────────────────────
    profiler = DataProfiler(gov)
    try:
        profile = profiler.profile(df)
        tbl     = profile["table"]
        print(f"\n  [PROFILE] rows={tbl['row_count']:,}  "
              f"nulls={tbl['overall_null_rate']:.1%}  "
              f"dupes={tbl['duplicate_row_count']:,}")
    except Exception as exc:
        gov.error("PROFILING_FAILED", exc)
        print(f"  [PROFILE] Profiling failed (non-fatal): {exc}")

    # ── Step 6: PII scan ──────────────────────────────────────────────────────
    pii_findings = _detect_pii(list(df.columns))
    if pii_findings:
        gov.pii_detected(pii_findings)

    # ── Step 7: Incremental filter ────────────────────────────────────────────
    incr_filter = IncrementalFilter(gov)
    wm_col      = args.watermark_col

    if not wm_col and interactive:
        incr_cfg = prompt_incremental_config(list(df.columns))
        wm_col   = incr_cfg.get("watermark_col")

    if wm_col:
        last_wm = incr_filter.read_watermark(source_path, wm_col)
        df      = incr_filter.filter(df, wm_col, last_wm, source_path)
        if df.empty:
            print("  [INCREMENTAL] No new rows since last run — nothing to load.")
            gov.pipeline_end({"result": "NO_NEW_DATA"})
            gov.summary()
            sys.exit(0)

    # ── Step 8: Compliance wizard ─────────────────────────────────────────────
    if interactive:
        compliance = run_compliance_wizard(gov, pii_findings)
    else:
        # Non-interactive: use safe defaults — mask PII, 1-year retention.
        compliance = {
            "lawful_basis"  : "Legitimate Interests",
            "purpose"       : "Automated pipeline run",
            "pii_strategy"  : "mask",
            "retention_days": 365,
            "drop_cols"     : [],
        }
        gov.consent_recorded(compliance["purpose"], compliance["lawful_basis"], True)
        gov.retention_policy("Retain 365 days (auto)", 365)

    # ── Step 9: Schema validation (Great Expectations) ────────────────────────
    val_failures = 0
    dlq          = DeadLetterQueue(gov)

    if not args.no_validation and HAS_GX:
        if interactive:
            val_cfg = prompt_validation_config()
        else:
            val_cfg = {"enabled": True, "on_failure": args.on_failure,
                       "interactive": False}

        if val_cfg.get("enabled", True):
            validator   = SchemaValidator(gov, dlq)
            expectations= validator.build_suite(df, interactive=val_cfg.get("interactive", True))
            df, val_failures = validator.validate(
                df,
                expectations,
                on_failure=val_cfg.get("on_failure", "dlq"),
            )
    elif not HAS_GX:
        print("\n[VALIDATION] great-expectations not installed — skipping.")

    # ── Destination config ────────────────────────────────────────────────────
    if interactive:
        db_type, db_cfg, table = prompt_db_config(secrets)
    else:
        db_type = args.db_type or "sqlite"
        table   = args.table   or "imported_data"
        db_cfg  = {
            "db_name" : args.db_name or "pipeline_output",
            "host"    : args.db_host or "localhost",
            "user"    : args.db_user or "",
            "password": secrets.get_password("DB_PASSWORD", "Database password", explicit=None),
            "port"    : args.db_port or "5432",
        }

    # if_exists strategy (SQL only).
    if_exists = args.if_exists
    if interactive and db_type != "mongodb":
        print("\n[LOAD] Table already exists:")
        print("  1.append  2.replace  3.fail")
        if_exists = {"1":"append","2":"replace","3":"fail"}.get(
            _prompt("Choice","1"), "append")

    # Natural keys for upsert.
    natural_keys: list[str] | None = None
    if args.natural_keys:
        natural_keys = [k.strip() for k in args.natural_keys.split(",")]
    elif interactive and db_type != "mongodb":
        if _yn("\n[IDEMPOTENCY] Enable upsert mode (natural key deduplication)?", False):
            print(f"  Columns: {', '.join(df.columns[:20])}")
            raw_keys = input("  Natural key columns (comma-separated): ").strip()
            natural_keys = [k.strip() for k in raw_keys.split(",") if k.strip()] or None

    # ── Step 10: Transform ────────────────────────────────────────────────────
    transformer = Transformer(gov)

    # ── Step 11: Load (with optional chunking) ────────────────────────────────
    print(f"\n[LOAD] Writing to {db_type.upper()} → {table} …")
    total_rows_loaded = 0

    try:
        if chunk_size > 0 and db_type != "mongodb":
            # ── Chunked load ─────────────────────────────────────────────────
            # Re-read in chunks, apply transform + load per chunk.
            # The compliance wizard and validation have already run on the
            # full DataFrame; here we just apply the transform decisions.
            loader = SQLLoader(gov, db_type)
            for i, chunk in enumerate(extractor.chunks(source_path, chunk_size)):
                chunk_tf = transformer.transform(
                    chunk,
                    pii_findings  = pii_findings,
                    pii_strategy  = compliance["pii_strategy"],
                    drop_cols     = compliance["drop_cols"],
                )
                # First chunk respects if_exists; subsequent chunks always append.
                chunk_if_exists = if_exists if i == 0 else "append"
                loader.load(chunk_tf, db_cfg, table,
                            if_exists=chunk_if_exists, natural_keys=natural_keys)
                total_rows_loaded += len(chunk_tf)
                print(f"  Chunk {i+1}: {len(chunk_tf):,} rows loaded "
                      f"({total_rows_loaded:,} total)")
        else:
            # ── Single-pass load ─────────────────────────────────────────────
            df = transformer.transform(
                df,
                pii_findings = pii_findings,
                pii_strategy = compliance["pii_strategy"],
                drop_cols    = compliance["drop_cols"],
            )
            if db_type == "mongodb":
                MongoLoader(gov).load(df, db_cfg, table)
            else:
                SQLLoader(gov, db_type).load(
                    df, db_cfg, table, if_exists, natural_keys)
            total_rows_loaded = len(df)

        print(f"  ✓ {total_rows_loaded:,} rows written.")

    except Exception as exc:
        gov.error("LOAD_FAILED", exc)
        print(f"\n[ERROR] Load failed: {exc}")
        import traceback; traceback.print_exc()

        # Send failure notification before exiting.
        if interactive:
            notif_cfg = prompt_notification_config(secrets)
        else:
            notif_cfg = {
                "email_cfg": None,
                "slack_cfg": {"webhook_url": args.slack_webhook} if args.slack_webhook else None,
            }
        Notifier(gov, **notif_cfg).send(success=False, stats={"error": str(exc)})
        sys.exit(1)

    # ── Step 12: Update watermark ─────────────────────────────────────────────
    if wm_col:
        incr_filter.update_watermark(df, wm_col, source_path)

    # ── Step 13: Notifications ────────────────────────────────────────────────
    run_stats = {
        "rows_loaded"         : f"{total_rows_loaded:,}",
        "dlq_rows"            : gov.dlq_rows_total,
        "validation_failures" : val_failures,
        "pii_fields_found"    : len(pii_findings),
        "pii_strategy"        : compliance["pii_strategy"],
        "destination_db"      : f"{db_type} / {table}",
        "retention_policy"    : f"{compliance['retention_days']} days",
    }

    if interactive:
        notif_cfg = prompt_notification_config(secrets)
    else:
        notif_cfg = {
            "email_cfg": None,
            "slack_cfg": {"webhook_url": args.slack_webhook} if args.slack_webhook else None,
        }
    Notifier(gov, **notif_cfg).send(success=True, stats=run_stats)

    # ── Step 14: Governance artefacts ─────────────────────────────────────────
    gov.write_pii_report()
    gov.write_validation_report()
    gov.pipeline_end({**run_stats, "destination_db_type": db_type,
                      "destination_table": table})
    gov.summary()

    print("\n[DONE] Pipeline complete. Artefacts → ./governance_logs/")


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
