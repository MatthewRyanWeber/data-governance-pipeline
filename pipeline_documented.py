"""
=============================================================
  DATA GOVERNANCE PIPELINE
  GDPR & CCPA Compliant ETL Tool  |  Version 1.0.0
  Author: Generated for Columbia University CUIT
=============================================================

PURPOSE
-------
This module implements a complete Extract-Transform-Load (ETL) pipeline
that prioritises data governance, regulatory compliance, and full audit
traceability.  It is designed to be run interactively from the command
line; all configuration (source file, destination database, PII handling
strategy, retention policy, etc.) is collected via prompted input so that
no secrets or environment-specific values are hard-coded.

PIPELINE FLOW
-------------
  1. Extract   — Read source file (CSV / JSON / Excel / XML) into a
                 pandas DataFrame.  Compute a SHA-256 fingerprint of the
                 raw file for tamper-evident lineage tracking.

  2. PII Scan  — Inspect every column name against a library of regex
                 patterns derived from GDPR Article 4 and CCPA §1798.140
                 definitions of "personal information".  Flag GDPR Article 9
                 special-category fields (health, race, religion, etc.)
                 separately because they carry heightened obligations.

  3. Compliance Wizard — Interactive prompts capture:
       • GDPR Article 6 lawful basis and processing-purpose statement
       • CCPA §1798.120 opt-out status for data sale / sharing
       • PII handling strategy  (mask / drop / retain with consent)
       • Retention policy  (GDPR Art. 5(1)(e) / CCPA §1798.100)
       • Columns to drop for data minimisation  (GDPR Art. 5(1)(c))

  4. Transform — Flatten nested structures, apply PII strategy,
                 deduplicate, sanitise column names, append governance
                 metadata columns.

  5. Load      — Write the cleaned, compliant DataFrame to the user's
                 chosen database (SQLite / PostgreSQL / MySQL /
                 SQL Server / MongoDB).

  6. Governance Artefacts — Three files written to ./governance_logs/:
       • pipeline_<ts>.log           Human-readable run log
       • audit_ledger_<ts>.jsonl     Immutable per-event audit ledger
       • pii_report_<ts>.json        Structured PII findings with
                                     regulation article references

REGULATORY COVERAGE
-------------------
  GDPR : Art. 4 (personal data definition), Art. 5(1)(c) (minimisation),
         Art. 5(1)(e) (storage limitation), Art. 6 (lawful basis),
         Art. 9 (special categories), Art. 25 (privacy by design /
         pseudonymisation), Art. 30 (records of processing),
         Art. 32 (security of processing).

  CCPA : §1798.100 (right to know), §1798.120 (right to opt-out of sale),
         §1798.140(o) (personal information definition),
         §1798.150 (security obligations).

DEPENDENCIES
------------
  Required  : pandas, openpyxl, lxml, sqlalchemy
  SQL targets: psycopg2-binary (PostgreSQL), pymysql (MySQL),
               pyodbc (SQL Server)
  MongoDB   : pymongo
  Optional  : flatten-json  (fallback JSON flattener)

  Install all with:  pip install -r requirements.txt
=============================================================
"""

# ─────────────────────────────────────────────────────────────────────────────
#  STANDARD LIBRARY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
# These are all part of Python's built-in standard library and require no
# separate installation.  They are grouped by functional area for readability.

# [unused – kept for reference] import os           # Operating-system interface (not directly used here but
                    # commonly needed in ETL utility scripts)
import sys          # Access to interpreter internals: sys.exit(), sys.stdout
import json         # Serialise/deserialise JSON for audit ledger entries
# [unused – kept for reference] import csv          # Imported for completeness; pandas handles CSV reading
import uuid         # Generate universally-unique IDs for pipeline and events
import hashlib      # SHA-256 hashing for file fingerprinting and PII masking
import logging      # Standard Python logging framework
import re           # Regular expressions for PII column-name scanning
import getpass      # Securely prompt for passwords (hides input); also
                    # provides getuser() to record the OS-level username
import platform     # Retrieve OS / machine info for audit metadata

from datetime import datetime, timezone
# datetime  — create and format timestamps
# timezone  — ensure all timestamps are stored as UTC (not local time),
#             which is critical for GDPR Art. 30 audit records that may
#             be reviewed across time zones

from pathlib import Path
# Path provides an object-oriented, OS-agnostic way to work with file
# system paths, replacing fragile string concatenation.

from typing import Any
# Any is used in type hints where a value could legitimately be of any type
# (e.g. a cell value in a flattened record).


# ─────────────────────────────────────────────────────────────────────────────
#  OPTIONAL / HEAVY DEPENDENCY CHECKS
# ─────────────────────────────────────────────────────────────────────────────
# We attempt to import pandas at module load time so that we can give the
# user a clear "missing package" error before the pipeline tries to run,
# rather than crashing mid-execution with a cryptic ImportError.
#
# flatten_json is a third-party convenience library for flattening nested
# JSON structures.  We fall back to the hand-written _flatten_record()
# function if it is not installed, so it is truly optional.

MISSING: list[str] = []  # Accumulates names of required-but-absent packages

try:
    import pandas as pd
    # pandas is the core data manipulation library.  A DataFrame is used
    # throughout the pipeline as the canonical in-memory representation.
except ImportError:
    MISSING.append("pandas")

try:
# [unused – kept for reference]     from flatten_json import flatten as _fj_flatten  # noqa: F401
    # flatten_json.flatten() recursively collapses nested dicts using a
    # separator (default "_").  We import it as a private alias so that
    # callers always use our wrapper, which handles both cases.
    HAS_FLATTEN_JSON = True
except ImportError:
    # Not installed — _flatten_record() (defined below) will be used instead.
    HAS_FLATTEN_JSON = False


# ─────────────────────────────────────────────────────────────────────────────
#  PIPELINE-LEVEL CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"
# Semantic version of this pipeline script.  Increment when making breaking
# changes so that audit ledgers from different runs can be compared.

PIPELINE_ID = str(uuid.uuid4())
# A UUID4 (random) identifier that is unique to THIS run of the pipeline.
# Every audit event is tagged with this ID, making it trivial to correlate
# all log entries belonging to a single execution even when multiple
# concurrent runs write to the same log directory.

RUN_START = datetime.now(timezone.utc).isoformat()
# ISO-8601 UTC timestamp captured at the moment this module is first
# imported/executed.  Stored here rather than inside main() so it reflects
# the true start of the Python process, before any user prompts.


# ─────────────────────────────────────────────────────────────────────────────
#  PII FIELD-NAME REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
# These patterns are applied (case-insensitively) to column names — not to
# the cell data itself.  The goal is to identify fields that are LIKELY to
# contain personal information based on their names, triggering the
# compliance wizard before any data is loaded.
#
# Regulatory basis:
#   GDPR Article 4(1)  — "personal data" definition
#   CCPA §1798.140(o)  — "personal information" enumerated categories
#
# Word-boundary anchors (\b) prevent false positives on partial matches
# (e.g. the pattern \bemail\b would NOT match "email_verified" but would
# match "user_email").  Adjust these patterns to suit your organisation's
# naming conventions.

PII_FIELD_PATTERNS: list[str] = [
    # ── Contact information ──────────────────────────────────────────────────
    r"\bemail\b",           # "email", "Email"
    r"\be[-_]?mail\b",      # "e-mail", "e_mail"
    r"\bphone\b",           # "phone", "phone_number"
    r"\bmobile\b",          # "mobile", "mobile_number"
    r"\bcell\b",            # "cell", "cell_phone"

    # ── Government / national identifiers ────────────────────────────────────
    r"\bssn\b",             # Social Security Number (US)
    r"\bsocial.?sec\b",     # "social_security", "social-sec"
    r"\bpassport\b",        # Passport number
    r"\blicense\b",         # Driver's license, professional license
    r"\bdriver.?id\b",      # "driver_id", "driverid"

    # ── Authentication / credentials ─────────────────────────────────────────
    r"\bpassword\b",        # "password", "Password"
    r"\bpasswd\b",          # Common abbreviation
    r"\bpin\b",             # "pin", "PIN", "pin_number"

    # ── Financial identifiers ─────────────────────────────────────────────────
    r"\bcredit.?card\b",    # "credit_card", "creditcard"
    r"\bcard.?num\b",       # "card_number", "cardnum"
    r"\bsalary\b",          # Compensation data
    r"\bincome\b",          # Income / earnings
    r"\bwage\b",            # Hourly / weekly wage

    # ── Network / device identifiers ─────────────────────────────────────────
    r"\bip.?addr\b",        # "ip_addr", "ip-addr"
    r"\bip_address\b",      # Fully spelled out

    # ── Demographic / biographic ──────────────────────────────────────────────
    r"\bbirthday\b",        # "birthday"
    r"\bdob\b",             # Date of birth abbreviation
    r"\bdate.?of.?birth\b", # "date_of_birth", "date-of-birth"
    r"\bfirst.?name\b",     # "first_name", "firstname"
    r"\blast.?name\b",      # "last_name", "lastname"
    r"\bfull.?name\b",      # "full_name", "fullname"
    r"\bgender\b",          # Gender identity
    r"\brace\b",            # Race (GDPR Art. 9 special category)
    r"\bethnicity\b",       # Ethnicity (GDPR Art. 9 special category)

    # ── Location / address ────────────────────────────────────────────────────
    r"\baddress\b",         # Street address, mailing address
    r"\bstreet\b",          # "street", "street_address"
    r"\bzip\b",             # ZIP / postal code (can identify individuals)
    r"\bpostal\b",          # "postal_code", "postal"
    r"\blatitude\b",        # Precise GPS coordinates
    r"\blongitude\b",       # Precise GPS coordinates
    r"\bgeo\b",             # "geo", "geolocation", "geo_point"

    # ── Health / medical (GDPR Art. 9 special categories) ────────────────────
    r"\bbiometric\b",       # Biometric data
    r"\bfingerprint\b",     # Fingerprint / touch ID data
    r"\bhealth\b",          # Health status, health records
    r"\bmedical\b",         # Medical records, conditions
    r"\bdiagnos\b",         # "diagnosis", "diagnoses", "diagnostic"

    # ── Beliefs / affiliations (GDPR Art. 9 special categories) ─────────────
    r"\breligion\b",        # Religious belief
    r"\bpolitical\b",       # Political opinion
]

# ─────────────────────────────────────────────────────────────────────────────
#  GDPR ARTICLE 9 — SPECIAL CATEGORY FIELD PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
# Article 9 prohibits processing these categories by default and requires
# explicit consent or another specific exception.  We maintain them as a
# separate set so that fields matching these patterns are flagged with a
# heightened warning in the compliance wizard and PII report.

SENSITIVE_CATEGORIES: set[str] = {
    r"\bhealth\b",      # Physical or mental health
    r"\bmedical\b",     # Medical history / conditions
    r"\brace\b",        # Racial origin
    r"\bethnicity\b",   # Ethnic origin
    r"\breligion\b",    # Religious or philosophical belief
    r"\bpolitical\b",   # Political opinion
    r"\bbiometric\b",   # Biometric data used for unique identification
    r"\bgenetic\b",     # Genetic data
}


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: GovernanceLogger
# ═════════════════════════════════════════════════════════════════════════════
class GovernanceLogger:
    """
    Central audit and governance logging facility for the pipeline.

    Every significant action taken by the pipeline — from reading a source
    file to masking a PII column to completing a database write — is
    recorded here as a structured "event" with a consistent schema.

    This class writes to THREE output destinations simultaneously:

      1. Console (stdout) — so operators can monitor progress in real time.

      2. Human-readable log file  (pipeline_<timestamp>.log)
         Standard Python logging format with timestamps and severity levels.
         Intended for operators, auditors, and on-call engineers.

      3. JSONL audit ledger  (audit_ledger_<timestamp>.jsonl)
         One JSON object per line, appended atomically.  Machine-readable
         and suitable for ingestion into SIEM tools, data catalogues, or
         regulatory audit systems.  This is the authoritative record of
         processing for GDPR Article 30 (Records of Processing Activities).

      4. PII report  (pii_report_<timestamp>.json) — written at pipeline end.
         Structured summary of every PII field discovered, the action taken
         on it, and the specific regulation article that applies.

    GDPR / CCPA alignment:
      • Article 30 GDPR  — requires controllers to maintain records of
        processing activities.  The audit ledger fulfils this obligation.
      • Article 32 GDPR  — security of processing; logging access and
        transformations supports incident investigation.
      • CCPA §1798.100   — right to know; the PII report documents exactly
        what personal information was collected and how it was handled.
    """

    def __init__(self, log_dir: str = "governance_logs") -> None:
        """
        Initialise the logger and create all output artefact files.

        Parameters
        ----------
        log_dir : str
            Directory path where all governance files will be written.
            Created automatically (including any missing parent directories)
            if it does not already exist.  Defaults to "governance_logs"
            in the current working directory.
        """
        self.log_dir = Path(log_dir)
        # exist_ok=True means we won't crash if the directory already exists.
        # parents=True means we'll create intermediate directories too
        # (e.g. "output/run/governance_logs" if "output/run" doesn't exist).
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Build a timestamp string to append to every file name so that
        # multiple pipeline runs never overwrite each other's artefacts.
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # ── File paths for the three governance artefacts ────────────────────
        self.log_file = self.log_dir / f"pipeline_{ts}.log"
        # Human-readable run log — used by operators and support teams.

        self.ledger_file = self.log_dir / f"audit_ledger_{ts}.jsonl"
        # JSONL audit ledger — one JSON event per line, appended atomically.
        # This file is treated as append-only; we never overwrite or delete
        # existing entries so it can serve as an immutable audit trail.

        self.pii_report_file = self.log_dir / f"pii_report_{ts}.json"
        # Structured PII report — written once at pipeline end after all
        # PII findings have been collected.

        # ── Configure Python's standard logging framework ────────────────────
        logging.basicConfig(
            level=logging.INFO,
            # Format: "2025-01-15 14:30:01,234 [INFO] [LINEAGE] SOURCE_REGISTERED | {...}"
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(self.log_file),  # Write to .log file
                logging.StreamHandler(sys.stdout),    # Also print to terminal
            ],
        )
        self.logger = logging.getLogger("DataPipeline")
        # Using a named logger ("DataPipeline") rather than the root logger
        # means this pipeline's messages can be distinguished from those of
        # any other libraries that also use the logging framework.

        # ── In-memory accumulators ────────────────────────────────────────────
        self.pii_findings: list[dict] = []
        # Accumulates every PII finding throughout the run so that we can
        # write a single consolidated PII report at the end.

        self.ledger_entries: list[dict] = []
        # In-memory copy of every event written to the JSONL ledger.
        # Used at pipeline end to report total event count in the summary.


    # ─────────────────────────────────────────────────────────────────────────
    #  CORE INTERNAL EVENT WRITER
    # ─────────────────────────────────────────────────────────────────────────

    def _event(
        self,
        category: str,
        action: str,
        detail: dict | None = None,
        level: str = "INFO",
    ) -> None:
        """
        Build a structured audit event and write it to BOTH the JSONL
        ledger and the human-readable log file.

        This is the single choke-point through which every governance
        record flows.  All public methods on this class ultimately call
        _event() — this ensures a consistent event schema regardless of
        where in the pipeline the event originates.

        Event schema
        ------------
        {
          "pipeline_id"   : str  — UUID4 unique to this pipeline run
          "event_id"      : str  — UUID4 unique to this individual event
          "timestamp_utc" : str  — ISO-8601 UTC timestamp
          "host"          : str  — machine hostname (for multi-host audits)
          "os_user"       : str  — OS-level username running the process
          "category"      : str  — LIFECYCLE | LINEAGE | TRANSFORMATION |
                                   PRIVACY | CONSENT | RETENTION | ERROR
          "action"        : str  — specific action name within the category
          "detail"        : dict — event-specific key/value payload
        }

        Parameters
        ----------
        category : str
            High-level grouping for the event (see schema above).
        action   : str
            Specific name of the action being recorded.
        detail   : dict, optional
            Additional structured data relevant to this event.
        level    : str
            Python logging severity level.  One of: "DEBUG", "INFO",
            "WARNING", "ERROR", "CRITICAL".  Defaults to "INFO".
        """
        # Build the event dictionary with full audit metadata.
        entry = {
            "pipeline_id"   : PIPELINE_ID,
            "event_id"      : str(uuid.uuid4()),    # Unique per event
            "timestamp_utc" : datetime.now(timezone.utc).isoformat(),
            "host"          : platform.node(),       # Machine hostname
            "os_user"       : getpass.getuser(),     # Current OS user
            "category"      : category,
            "action"        : action,
            "detail"        : detail or {},          # Avoid mutable default arg
        }

        # Append to JSONL ledger.  We open in append mode ("a") so that:
        #   (a) No existing events are ever overwritten.
        #   (b) The file is created automatically on the first write.
        with open(self.ledger_file, "a") as f:
            f.write(json.dumps(entry) + "\n")   # "\n" = JSONL line delimiter

        # Keep an in-memory copy for the end-of-run summary.
        self.ledger_entries.append(entry)

        # Build the human-readable log message.
        msg = f"[{category}] {action}"
        if detail:
            msg += f" | {json.dumps(detail)}"

        # getattr(self.logger, "info") returns self.logger.info, etc.
        # The fallback to self.logger.info guards against a typo in `level`.
        getattr(self.logger, level.lower(), self.logger.info)(msg)


    # ─────────────────────────────────────────────────────────────────────────
    #  CONVENIENCE EVENT WRAPPERS  (public API)
    # ─────────────────────────────────────────────────────────────────────────
    # Each wrapper below is a semantically meaningful helper that calls
    # _event() with the correct category and action constants, and
    # structures the detail payload appropriately.  Using named wrappers
    # rather than calling _event() directly throughout the codebase keeps
    # the event taxonomy consistent and makes call sites easier to read.

    def pipeline_start(self, metadata: dict) -> None:
        """
        Record the very first event in the audit ledger: pipeline startup.

        Parameters
        ----------
        metadata : dict
            Context about the pipeline run — typically includes the script
            version, OS platform string, and Python version number.
        """
        self._event("LIFECYCLE", "PIPELINE_STARTED", metadata)

    def pipeline_end(self, stats: dict) -> None:
        """
        Record the final event: successful pipeline completion with summary
        statistics (rows loaded, destination, PII strategy, etc.).

        Parameters
        ----------
        stats : dict
            Run-end summary including row counts and configuration used.
        """
        self._event("LIFECYCLE", "PIPELINE_COMPLETED", stats)

    def source_registered(
        self, path: str, file_type: str, row_count: int, col_count: int
    ) -> None:
        """
        Record data lineage for the source file.

        A SHA-256 hash of the raw file is computed and stored alongside
        the file path.  This hash can later be used to prove the pipeline
        processed an unmodified copy of the original data — an important
        capability for data quality audits and legal discovery.

        Parameters
        ----------
        path       : str  Absolute or relative path to the source file.
        file_type  : str  File extension, e.g. ".csv", ".json".
        row_count  : int  Number of data rows loaded from the file.
        col_count  : int  Number of columns / fields in the file.
        """
        h = _file_hash(path)    # Compute SHA-256 fingerprint (see helper below)
        self._event("LINEAGE", "SOURCE_REGISTERED", {
            "source_path" : path,
            "file_type"   : file_type,
            "row_count"   : row_count,
            "col_count"   : col_count,
            "sha256"      : h,      # Tamper-evident fingerprint
        })

    def destination_registered(
        self, db_type: str, db_name: str, table: str
    ) -> None:
        """
        Record data lineage for the destination database and table.

        Together with source_registered(), this forms the complete lineage
        record: data flowed FROM <source_path> TO <db_type>/<db_name>/<table>.

        Parameters
        ----------
        db_type  : str  Database engine name ("sqlite", "postgresql", etc.).
        db_name  : str  Name of the target database or database file.
        table    : str  Name of the target table or MongoDB collection.
        """
        self._event("LINEAGE", "DESTINATION_REGISTERED", {
            "db_type"              : db_type,
            "db_name"              : db_name,
            "table_or_collection"  : table,
        })

    def transformation_applied(self, name: str, detail: dict | None = None) -> None:
        """
        Record that a named transformation step was executed.

        Called for every distinct transformation (EXTRACT_START,
        EXTRACT_COMPLETE, FLATTEN_NESTED, NULL_HANDLING, DEDUPLICATION,
        COLUMN_SANITIZATION, TRANSFORM_COMPLETE) so that the full
        transformation lineage is captured in the audit ledger.

        Parameters
        ----------
        name   : str           Human-readable transformation name.
        detail : dict, optional  Statistics about the transformation
                                 (e.g. rows before/after deduplication).
        """
        self._event("TRANSFORMATION", name, detail)

    def pii_detected(self, findings: list[dict]) -> None:
        """
        Record PII field detections as a WARNING-level audit event.

        WARNING level is used (rather than INFO) because the presence of
        PII fields requires human review and a decision about how to
        handle them before data is loaded.

        Parameters
        ----------
        findings : list[dict]
            List of PII finding dictionaries as returned by _detect_pii().
            Each dict contains: field, matched_pattern, special_category,
            gdpr_reference, ccpa_reference.
        """
        # Accumulate findings for the end-of-run PII report.
        self.pii_findings.extend(findings)
        self._event(
            "PRIVACY",
            "PII_DETECTED",
            {
                "findings_count" : len(findings),
                "fields"         : [f["field"] for f in findings],
            },
            level="WARNING",    # Elevate severity to attract operator attention
        )

    def consent_recorded(
        self, purpose: str, basis: str, user_confirmed: bool
    ) -> None:
        """
        Record the GDPR Article 6 lawful basis and processing purpose.

        GDPR requires controllers to identify a lawful basis for every
        processing activity BEFORE it occurs.  This event provides the
        auditable record of that determination.

        Parameters
        ----------
        purpose        : str   Plain-English description of why the data
                               is being processed.
        basis          : str   The Article 6 basis chosen (e.g. "Contract",
                               "Legitimate Interests", "Consent").
        user_confirmed : bool  Whether the operator confirmed consent at
                               the interactive prompt.
        """
        self._event("CONSENT", "LAWFUL_BASIS_RECORDED", {
            "processing_purpose" : purpose,
            "lawful_basis"       : basis,           # GDPR Art. 6
            "user_confirmed"     : user_confirmed,
        })

    def data_minimization(
        self,
        original_cols: list,
        retained_cols: list,
        dropped_cols: list,
    ) -> None:
        """
        Record a data minimisation action (GDPR Article 5(1)(c)).

        GDPR Art. 5(1)(c) requires that personal data be "adequate,
        relevant and limited to what is necessary in relation to the
        purposes for which they are processed."  When a user elects to
        drop columns this event documents the decision.

        Parameters
        ----------
        original_cols : list  All column names before minimisation.
        retained_cols : list  Column names kept after minimisation.
        dropped_cols  : list  Column names that were removed.
        """
        self._event("PRIVACY", "DATA_MINIMIZATION_APPLIED", {
            "original_column_count" : len(original_cols),
            "retained_column_count" : len(retained_cols),
            "dropped_columns"       : dropped_cols,
        })

    def pii_action(self, field: str, action: str) -> None:
        """
        Record what action was taken on a specific PII field.

        Parameters
        ----------
        field  : str  Column name that was processed.
        action : str  One of:
                      "MASKED"              — SHA-256 pseudonymised
                      "DROPPED"             — removed from dataset
                      "RETAINED_WITH_CONSENT" — kept raw with consent logged
        """
        # Action is incorporated into the event name: "PII_MASKED", etc.
        self._event("PRIVACY", f"PII_{action}", {"field": field})

    def retention_policy(self, policy: str, retention_days: int | None) -> None:
        """
        Record the data retention policy chosen by the operator.

        GDPR Art. 5(1)(e) requires that data be kept "no longer than is
        necessary for the purposes for which the personal data are
        processed."  CCPA §1798.100 also addresses data retention.
        Logging this decision makes the retention policy auditable.

        Parameters
        ----------
        policy         : str       Human-readable policy description.
        retention_days : int|None  Number of days data should be kept.
                                   None means indefinite (must be justified).
        """
        self._event("RETENTION", "POLICY_RECORDED", {
            "policy"         : policy,
            "retention_days" : retention_days,
        })

    def load_complete(self, rows_written: int, table: str) -> None:
        """
        Record the successful completion of a database write.

        Parameters
        ----------
        rows_written : int  Number of rows inserted into the target table.
        table        : str  Name of the table or collection that was written.
        """
        self._event("LINEAGE", "LOAD_COMPLETE", {
            "rows_written"      : rows_written,
            "destination_table" : table,
        })

    def error(self, msg: str, exc: Exception | None = None) -> None:
        """
        Record an ERROR-level event, optionally with exception details.

        Parameters
        ----------
        msg : str             Short description of what went wrong.
        exc : Exception, opt  The caught exception, if available.
                              Its string representation is stored in the
                              audit ledger for post-mortem debugging.
        """
        self._event(
            "ERROR",
            msg,
            {"exception": str(exc)} if exc else None,
            level="ERROR",
        )

    def write_pii_report(self) -> None:
        """
        Serialise all accumulated PII findings to a structured JSON report.

        This report is intended to be:
          • Retained as evidence of privacy-by-design implementation.
          • Reviewed by Data Protection Officers (DPOs) as part of GDPR
            Article 30 records-of-processing activities.
          • Used to satisfy CCPA §1798.100 right-to-know obligations.

        The report includes: pipeline ID, generation timestamp, relevant
        regulation article references, the full list of PII findings with
        their matched patterns, and a summary count.

        Called automatically at the end of main() after the load completes.
        """
        report = {
            "pipeline_id"          : PIPELINE_ID,
            "generated_utc"        : datetime.now(timezone.utc).isoformat(),
            # Regulation references are embedded so the report is self-contained.
            "regulation_references": {
                "GDPR" : "Articles 4, 9, 25, 32",
                "CCPA" : "§1798.100, §1798.140, §1798.150",
            },
            "pii_findings" : self.pii_findings,
            "summary"      : {
                "total_pii_fields"       : len(self.pii_findings),
                # Special category count for quick DPO review.
                "special_category_fields": sum(
                    1 for f in self.pii_findings if f.get("special_category")
                ),
            },
        }
        with open(self.pii_report_file, "w") as f:
            json.dump(report, f, indent=2)  # indent=2 for human readability
        self.logger.info(f"PII report written → {self.pii_report_file}")

    def summary(self) -> None:
        """
        Print and log a human-readable summary at the end of the run.

        Lists the paths of all generated governance artefacts so that
        the operator knows exactly where to find them.
        """
        self.logger.info("=" * 60)
        self.logger.info("  GOVERNANCE SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"  Pipeline ID  : {PIPELINE_ID}")
        self.logger.info(f"  Run started  : {RUN_START}")
        self.logger.info(f"  Audit ledger : {self.ledger_file}")
        self.logger.info(f"  PII report   : {self.pii_report_file}")
        self.logger.info(f"  Log file     : {self.log_file}")
        self.logger.info(f"  Total events : {len(self.ledger_entries)}")
        self.logger.info("=" * 60)


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITY / HELPER FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════

def _file_hash(path: str) -> str:
    """
    Compute and return the SHA-256 hex digest of a file's raw bytes.

    The file is read in 8 KB chunks rather than all at once so that
    very large source files do not exhaust available RAM.  SHA-256 is
    used because it is:
      • Collision-resistant enough for audit purposes
      • Deterministic — the same file always produces the same hash
      • Widely accepted in legal and forensic contexts

    This hash is stored in the SOURCE_REGISTERED audit event and can
    be used to prove — after the fact — that a specific version of
    a file was processed.

    Parameters
    ----------
    path : str  Path to the file to hash.

    Returns
    -------
    str  64-character lowercase hexadecimal SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        # iter(callable, sentinel) keeps calling f.read(8192) until it
        # returns b"" (empty bytes), signalling end of file.
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_pii(columns: list[str]) -> list[dict]:
    """
    Scan a list of column names for potential PII using regex pattern matching.

    Each column name is checked against every pattern in PII_FIELD_PATTERNS
    (case-insensitively).  If a match is found, the column is recorded as a
    PII finding.  A second check against SENSITIVE_CATEGORIES identifies
    GDPR Article 9 special-category fields.

    Only the first matching pattern is recorded per column (break after
    first match) to avoid duplicate findings for the same field.

    Parameters
    ----------
    columns : list[str]  List of DataFrame column names to inspect.

    Returns
    -------
    list[dict]  One dictionary per PII field found, containing:
        field            : str   The column name that matched.
        matched_pattern  : str   The regex pattern that triggered the match.
        special_category : bool  True if the field falls under GDPR Art. 9.
        gdpr_reference   : str   Applicable GDPR article.
        ccpa_reference   : str   Applicable CCPA section.
    """
    findings = []
    for col in columns:
        col_lower = col.lower()    # Normalise to lowercase for case-insensitive matching
        for pattern in PII_FIELD_PATTERNS:
            # re.search() looks for the pattern anywhere in the string
            # (as opposed to re.match() which only checks the start).
            if re.search(pattern, col_lower):
                # Check whether this field also matches a special-category pattern.
                special = any(
                    re.search(sp, col_lower) for sp in SENSITIVE_CATEGORIES
                )
                findings.append({
                    "field"           : col,
                    "matched_pattern" : pattern,
                    "special_category": special,
                    # Reference the exact regulation article for the PII report.
                    "gdpr_reference"  : "Article 9" if special else "Article 4(1)",
                    "ccpa_reference"  : "§1798.140(o)",
                })
                break   # One finding per column is enough — avoid duplicates


    return findings


def _flatten_record(record: Any, parent_key: str = "", sep: str = "__") -> dict:
    """
    Recursively flatten a nested dictionary or list into a single-level dict.

    Nested keys are joined with the separator.  For example:

        {"address": {"city": "NYC", "zip": "10001"}}
        → {"address__city": "NYC", "address__zip": "10001"}

        {"scores": [90, 85, 92]}
        → {"scores__0": 90, "scores__1": 85, "scores__2": 92}

    This is necessary because relational databases and most analytical
    tools cannot natively store nested objects in a single column — the
    structure must be normalised into flat key-value pairs.

    The double-underscore separator ("__") is chosen over a single
    underscore to minimise the risk of collision with existing column
    names (e.g. if the source data already has a field "address_city").

    Parameters
    ----------
    record     : Any   The value to flatten — dict, list, or scalar.
    parent_key : str   Accumulated key prefix from parent recursion levels.
    sep        : str   Separator inserted between nested key segments.

    Returns
    -------
    dict  Flat dictionary with all nested values promoted to top level.
    """
    items: list = []

    if isinstance(record, dict):
        for k, v in record.items():
            # Build the new compound key, e.g. "address" + "__" + "city"
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            if isinstance(v, (dict, list)):
                # Recurse: flatten the nested value, then add its pairs
                items.extend(_flatten_record(v, new_key, sep).items())
            else:
                # Leaf value — store as-is
                items.append((new_key, v))

    elif isinstance(record, list):
        # Use the numeric index as part of the key for list items
        for i, v in enumerate(record):
            new_key = f"{parent_key}{sep}{i}" if parent_key else str(i)
            if isinstance(v, (dict, list)):
                items.extend(_flatten_record(v, new_key, sep).items())
            else:
                items.append((new_key, v))

    else:
        # Scalar value (string, int, float, bool, None) — base case
        return {parent_key: record}

    return dict(items)


def _mask_value(value: Any) -> str | None:
    """
    Pseudonymise a single value using a one-way SHA-256 hash prefix.

    GDPR Article 25 (Data protection by design and by default) and
    Recital 26 specifically recognise pseudonymisation as an appropriate
    technical measure for protecting personal data.  A pseudonymised
    value:
      • Cannot trivially be reversed to the original value.
      • Preserves uniqueness — the same input always produces the same
        output — so records can still be joined on the masked field.
      • Retains a recognisable prefix ("MASKED_") so that analysts and
        auditors immediately know the value has been processed.

    The first 12 hex characters of the SHA-256 digest are used (48 bits),
    which provides sufficient uniqueness for most datasets while keeping
    the stored value short.  For very high-cardinality datasets (billions
    of unique values) consider using the full 64-character digest instead.

    Parameters
    ----------
    value : Any  The raw PII value to pseudonymise.  Will be converted
                 to a string before hashing if not already one.

    Returns
    -------
    str | None  Pseudonymised string like "MASKED_a3f8c1d2e4b5", or
                None if the input value was None (preserving null-ness).
    """
    if value is None:
        return None     # Do not hash NULLs — they carry no information
    # Encode as UTF-8 bytes before hashing; str() handles non-string inputs.
    return "MASKED_" + hashlib.sha256(str(value).encode()).hexdigest()[:12]


def _prompt(msg: str, default: str = "") -> str:
    """
    Display a prompt and return the user's input, falling back to a default.

    If the user presses Enter without typing anything, the default value
    is returned.  If no default is provided, the prompt loops until
    input is given (handled by callers — this function itself does not
    loop).

    Parameters
    ----------
    msg     : str  The prompt message shown to the user.
    default : str  Value to return if the user enters nothing.

    Returns
    -------
    str  The user's input, or the default value.
    """
    if default:
        # Show the default in square brackets so the user knows they can
        # accept it by pressing Enter: "Enter path to file [sample.csv]: "
        resp = input(f"{msg} [{default}]: ").strip()
    else:
        resp = input(f"{msg}: ").strip()
    return resp if resp else default


def _yn(msg: str, default: bool = True) -> bool:
    """
    Ask a yes/no question and return True for "yes", False for "no".

    The default answer is shown in uppercase: "[Y/n]" means default=yes.

    Parameters
    ----------
    msg     : str   The question to display.
    default : bool  What to return if the user presses Enter without input.

    Returns
    -------
    bool  True if the user answered yes (or accepted a default of True).
    """
    suffix = "[Y/n]" if default else "[y/N]"
    resp = input(f"{msg} {suffix}: ").strip().lower()
    if not resp:
        return default   # Accept the default on empty input
    return resp in ("y", "yes")


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: Extractor
# ═════════════════════════════════════════════════════════════════════════════
class Extractor:
    """
    Handles reading source files of various formats into a pandas DataFrame.

    Supported formats
    -----------------
    .csv   — Comma-separated values (pandas read_csv)
    .xlsx  — Excel 2007+ workbook (pandas read_excel via openpyxl)
    .xls   — Legacy Excel 97-2003 workbook (pandas read_excel)
    .json  — JSON array of objects or single object (custom flatten logic)
    .xml   — XML document (pandas read_xml via lxml)

    The Extractor also fires governance events before and after extraction
    so that the complete data lineage is captured in the audit ledger.

    Parameters
    ----------
    gov : GovernanceLogger
        The shared governance logger instance for this pipeline run.
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        """
        Parameters
        ----------
        gov : GovernanceLogger
            Shared governance logger.  All extraction events will be
            recorded through this instance.
        """
        self.gov = gov

    def extract(self, path: str) -> "pd.DataFrame":
        """
        Read the file at `path` and return its contents as a DataFrame.

        For JSON files, nested structures are flattened using _flatten_record()
        before DataFrame construction so that every row is a flat mapping
        of string column names to scalar values.

        Parameters
        ----------
        path : str  Path to the source file.  The file format is inferred
                    from the file extension.

        Returns
        -------
        pd.DataFrame  Tabular representation of the source file contents.

        Raises
        ------
        ValueError  If the file extension is not one of the supported formats.
        """
        # Infer format from the file extension (lower-cased for robustness).
        ext = Path(path).suffix.lower()
        self.gov.transformation_applied("EXTRACT_START", {"source": path, "format": ext})

        # ── Read based on detected format ─────────────────────────────────────
        if ext == ".csv":
            # read_csv handles encoding detection, quoting, and common
            # dialect variations automatically.
            df = pd.read_csv(path)

        elif ext in (".xlsx", ".xls"):
            # read_excel requires the `openpyxl` engine for .xlsx files.
            # Reads the first sheet by default; pass sheet_name= to override.
            df = pd.read_excel(path)

        elif ext == ".json":
            with open(path) as f:
                raw = json.load(f)
            # JSON sources may be either an array of objects (list)
            # or a single object (dict).  We normalise both cases to a
            # list of flat dictionaries before building the DataFrame.
            if isinstance(raw, list):
                # Each element is one record; flatten it individually.
                flat = [_flatten_record(r) for r in raw]
            else:
                # Single object — wrap in a list to make a single-row DataFrame.
                flat = [_flatten_record(raw)]
            df = pd.DataFrame(flat)

        elif ext == ".xml":
            # read_xml uses lxml under the hood and returns one row per
            # repeating element at the top level of the document.
            df = pd.read_xml(path)

        else:
            raise ValueError(
                f"Unsupported file format: '{ext}'. "
                "Supported formats are: .csv, .xlsx, .xls, .json, .xml"
            )

        # ── Register source in the governance audit ledger ───────────────────
        self.gov.source_registered(path, ext, len(df), len(df.columns))
        self.gov.transformation_applied(
            "EXTRACT_COMPLETE",
            {"rows": len(df), "columns": list(df.columns)},
        )
        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: Transformer
# ═════════════════════════════════════════════════════════════════════════════
class Transformer:
    """
    Applies a sequence of transformations to a raw extracted DataFrame.

    Transformation pipeline (in order)
    ------------------------------------
    1. Nested column flattening  — Any DataFrame cell that still contains
       a dict or list (possible with mixed-type JSON data) is expanded
       into individual columns using _flatten_record().

    2. Data minimisation         — Columns explicitly requested for removal
       by the operator are dropped (GDPR Art. 5(1)(c)).

    3. PII field handling        — Each detected PII field is processed
       according to the chosen strategy (mask / drop / retain).

    4. Null row removal          — Rows that are entirely empty are dropped.
       Individual null cells within non-empty rows are preserved so that
       the loader can handle them (NULL in a SQL column is valid).

    5. Deduplication             — Exact duplicate rows are removed.

    6. Column name sanitisation  — Characters outside [a-zA-Z0-9_] are
       replaced with underscores so that column names are safe for use as
       SQL identifiers and MongoDB field names.

    7. Governance metadata       — Two columns are appended to every row:
       _pipeline_id   : Ties each loaded row to the pipeline run that
                        loaded it, enabling row-level lineage queries.
       _loaded_at_utc : UTC ISO-8601 load timestamp for retention audits.

    Parameters
    ----------
    gov : GovernanceLogger
        The shared governance logger instance for this pipeline run.
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        """
        Parameters
        ----------
        gov : GovernanceLogger
            Shared governance logger.
        """
        self.gov = gov
        # Records what action was taken on each PII field, keyed by field name.
        # Useful for post-run debugging and can be serialised to a report.
        self.pii_actions: dict[str, str] = {}

    def transform(
        self,
        df: "pd.DataFrame",
        pii_findings: list[dict],
        pii_strategy: str,
        drop_cols: list[str],
    ) -> "pd.DataFrame":
        """
        Execute all transformation steps and return the cleaned DataFrame.

        Parameters
        ----------
        df           : pd.DataFrame  Raw DataFrame from the Extractor.
        pii_findings : list[dict]    PII findings from _detect_pii().
        pii_strategy : str           One of "mask", "drop", or "retain".
        drop_cols    : list[str]     Column names to remove for minimisation.

        Returns
        -------
        pd.DataFrame  Transformed, compliant DataFrame ready for loading.
        """
        original_cols = list(df.columns)   # Snapshot before any changes

        # ── Step 1: Flatten any remaining nested object columns ───────────────
        # pandas read_csv / read_excel will never produce dict-valued cells,
        # but read_json with complex sources sometimes does.  We detect these
        # by checking whether any non-null value in an object-dtype column is
        # a dict or list, then re-flatten the entire DataFrame row by row.
        obj_cols = [
            c for c in df.columns
            if df[c].dtype == object                        # string/object dtype
            and df[c].dropna()                              # ignore NaN
                      .apply(lambda x: isinstance(x, (dict, list)))
                      .any()                                # at least one dict/list cell
        ]
        if obj_cols:
            expanded = []
            for _, row in df.iterrows():
                flat_row = {}
                for col in df.columns:
                    val = row[col]
                    if isinstance(val, (dict, list)):
                        # Flatten the nested value, using col as the key prefix.
                        flat_row.update(_flatten_record(val, parent_key=col))
                    else:
                        flat_row[col] = val
                expanded.append(flat_row)
            df = pd.DataFrame(expanded)
            self.gov.transformation_applied("FLATTEN_NESTED", {"flattened_columns": obj_cols})

        # ── Step 2: Data minimisation — drop user-specified columns ───────────
        if drop_cols:
            # errors="ignore" means the drop won't crash if a column name
            # typed by the user doesn't actually exist in the DataFrame.
            df.drop(
                columns=[c for c in drop_cols if c in df.columns],
                inplace=True,
                errors="ignore",
            )
            self.gov.data_minimization(original_cols, list(df.columns), drop_cols)

        # ── Step 3: Apply PII handling strategy ───────────────────────────────
        # Build a dict of {field_name: finding_dict} for only the PII fields
        # that still exist in the DataFrame after minimisation in Step 2.
        pii_fields = {
            f["field"]: f
            for f in pii_findings
            if f["field"] in df.columns
        }

        for field, info in pii_fields.items():
            if pii_strategy == "mask":
                # Apply _mask_value() element-wise to pseudonymise each cell.
                df[field] = df[field].apply(_mask_value)
                self.gov.pii_action(field, "MASKED")
                self.pii_actions[field] = "MASKED"

            elif pii_strategy == "drop":
                # Remove the column entirely.
                df.drop(columns=[field], inplace=True, errors="ignore")
                self.gov.pii_action(field, "DROPPED")
                self.pii_actions[field] = "DROPPED"

            elif pii_strategy == "retain":
                # Keep the raw value — only permissible when explicit consent
                # or another GDPR Art. 6 lawful basis has been recorded.
                self.gov.pii_action(field, "RETAINED_WITH_CONSENT")
                self.pii_actions[field] = "RETAINED_WITH_CONSENT"

        # ── Step 4: Null row removal ──────────────────────────────────────────
        before_nulls = df.isnull().sum().sum()   # Total null cells before
        # how="all" drops only rows where EVERY cell is null.
        # We preserve rows that are only partially null because partial data
        # may still be meaningful (e.g. an optional phone field left blank).
        df.dropna(how="all", inplace=True)
        after_nulls = df.isnull().sum().sum()    # Total null cells after
        self.gov.transformation_applied("NULL_HANDLING", {
            "null_cells_before" : int(before_nulls),
            "null_cells_after"  : int(after_nulls),
        })

        # ── Step 5: Deduplication ─────────────────────────────────────────────
        before_dedup = len(df)
        # drop_duplicates() compares all columns; rows are kept in their
        # original order (keep="first" is the default).
        df.drop_duplicates(inplace=True)
        self.gov.transformation_applied("DEDUPLICATION", {
            "rows_before"       : before_dedup,
            "rows_after"        : len(df),
            "duplicates_removed": before_dedup - len(df),
        })

        # ── Step 6: Column name sanitisation ─────────────────────────────────
        # Replace any character that is not a letter, digit, or underscore
        # with "_", then strip leading/trailing underscores.  This makes
        # column names safe as SQL identifiers (no quoting required) and
        # as MongoDB field names (no dots or dollar signs allowed).
        df.columns = [
            re.sub(r"[^a-zA-Z0-9_]", "_", c).strip("_")
            for c in df.columns
        ]
        self.gov.transformation_applied(
            "COLUMN_SANITIZATION",
            {"final_columns": list(df.columns)},
        )

        # ── Step 7: Append governance metadata columns ────────────────────────
        # These columns are added to EVERY row so that records in the target
        # database can be traced back to the specific pipeline run that wrote
        # them.  This supports:
        #   • Purge operations (delete all rows from run <id> if a mistake
        #     was made)
        #   • Retention enforcement (find all rows loaded more than N days ago)
        #   • GDPR right-to-erasure requests (identify records added by a
        #     specific processing activity)
        df["_pipeline_id"]    = PIPELINE_ID
        df["_loaded_at_utc"]  = datetime.now(timezone.utc).isoformat()

        self.gov.transformation_applied("TRANSFORM_COMPLETE", {
            "final_row_count" : len(df),
            "final_col_count" : len(df.columns),
        })
        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: SQLLoader
# ═════════════════════════════════════════════════════════════════════════════
class SQLLoader:
    """
    Loads a transformed DataFrame into a SQL-family database.

    Supported engines
    -----------------
    sqlite      — File-based; no server required.  Great for development
                  and single-user deployments.
    postgresql  — Requires psycopg2-binary and a running PostgreSQL server.
    mysql       — Requires pymysql and a running MySQL / MariaDB server.
    mssql       — Requires pyodbc and Microsoft ODBC Driver 17 for SQL Server.

    All engines are accessed through SQLAlchemy's unified "engine" API so
    that the pandas DataFrame.to_sql() method can be used regardless of
    the target database.  This also means connection parameters are never
    passed directly to a database driver — reducing the risk of injection
    and simplifying future engine additions.

    Parameters
    ----------
    gov     : GovernanceLogger  Shared governance logger.
    db_type : str               One of "sqlite", "postgresql", "mysql", "mssql".
    """

    def __init__(self, gov: "GovernanceLogger", db_type: str) -> None:
        """
        Parameters
        ----------
        gov     : GovernanceLogger
        db_type : str  Target database flavour.
        """
        self.gov     = gov
        self.db_type = db_type

    def _engine(self, cfg: dict):
        """
        Construct and return a SQLAlchemy Engine for the configured database.

        The engine is the central point of database connectivity in
        SQLAlchemy.  It manages a connection pool and abstracts away the
        dialect-specific connection string format.

        Connection strings follow the SQLAlchemy URL format:
            dialect+driver://user:password@host:port/database

        Parameters
        ----------
        cfg : dict  Database configuration dict collected from user prompts.
                    Required keys vary by db_type (see prompt_db_config).

        Returns
        -------
        sqlalchemy.Engine

        Raises
        ------
        ValueError  If db_type is not one of the four supported dialects.
        """
        from sqlalchemy import create_engine   # Import here to defer the cost
                                               # until a SQL target is selected.
        t = self.db_type

        if t == "sqlite":
            # SQLite uses a file path instead of a host.  The database is
            # created automatically if the file does not already exist.
            return create_engine(f"sqlite:///{cfg['db_name']}.db")

        elif t == "postgresql":
            # psycopg2 is the standard PostgreSQL adapter for Python.
            return create_engine(
                f"postgresql+psycopg2://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 5432)}/{cfg['db_name']}"
            )

        elif t == "mysql":
            # pymysql is a pure-Python MySQL client (no C extension required).
            return create_engine(
                f"mysql+pymysql://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 3306)}/{cfg['db_name']}"
            )

        elif t == "mssql":
            # pyodbc requires that the Microsoft ODBC Driver 17 for SQL Server
            # be installed separately on the host machine.
            driver = cfg.get("driver", "ODBC+Driver+17+for+SQL+Server")
            return create_engine(
                f"mssql+pyodbc://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 1433)}/{cfg['db_name']}"
                f"?driver={driver}"
            )

        raise ValueError(f"Unknown SQL database type: '{t}'")

    def load(
        self,
        df: "pd.DataFrame",
        cfg: dict,
        table: str,
        if_exists: str = "append",
    ) -> None:
        """
        Write the DataFrame to the target SQL table.

        Uses pandas DataFrame.to_sql() which translates the DataFrame's
        schema into a CREATE TABLE statement (if the table doesn't exist)
        and then inserts rows in batches.

        Parameters
        ----------
        df        : pd.DataFrame  Transformed, compliant data to load.
        cfg       : dict          Database connection configuration.
        table     : str           Target table name.
        if_exists : str           Behaviour when the table already exists.
                                  "append"  — add rows to existing table.
                                  "replace" — drop and recreate the table.
                                  "fail"    — raise an error (default pandas
                                              behaviour for safety).
        """
        engine = self._engine(cfg)

        df.to_sql(
            table,
            engine,
            if_exists=if_exists,
            index=False,        # Do not write the pandas integer index
            chunksize=500,      # Insert 500 rows per batch — balances memory
                                # usage vs. round-trip latency for large files
        )

        # Record the successful write in the governance audit ledger.
        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(self.db_type, cfg["db_name"], table)


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: MongoLoader
# ═════════════════════════════════════════════════════════════════════════════
class MongoLoader:
    """
    Loads a transformed DataFrame into a MongoDB collection.

    MongoDB stores documents (JSON objects), so the DataFrame is first
    converted to a list of Python dicts via pandas to_json() → json.loads(),
    which ensures that types like datetime are properly serialised.

    Supports both a direct host:port connection and a full MongoDB URI
    (used for Atlas clusters, replica sets, or connections requiring TLS).

    Parameters
    ----------
    gov : GovernanceLogger  Shared governance logger.
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        """
        Parameters
        ----------
        gov : GovernanceLogger
        """
        self.gov = gov

    def load(self, df: "pd.DataFrame", cfg: dict, collection: str) -> None:
        """
        Insert all DataFrame rows as documents into a MongoDB collection.

        Parameters
        ----------
        df         : pd.DataFrame  Transformed, compliant data to load.
        cfg        : dict          MongoDB connection configuration.
                                   Keys: uri (optional), host, port,
                                   db_name.
        collection : str           Target MongoDB collection name.
        """
        from pymongo import MongoClient   # Deferred import (optional dependency)

        # Prefer a full URI if supplied (Atlas, replica set, TLS, etc.);
        # otherwise construct a minimal localhost connection string.
        uri = cfg.get("uri") or (
            f"mongodb://{cfg.get('host', 'localhost')}:{cfg.get('port', 27017)}/"
        )
        client = MongoClient(uri)
        db = client[cfg["db_name"]]

        # Convert the DataFrame to a list of plain Python dicts.
        # We use the JSON round-trip (to_json → json.loads) rather than
        # df.to_dict("records") because it correctly serialises pandas
        # Timestamp and NaT values into ISO-8601 strings that MongoDB
        # can store without further conversion.
        records = json.loads(df.to_json(orient="records", date_format="iso"))

        # insert_many() sends all documents in a single network round-trip,
        # which is significantly faster than calling insert_one() in a loop.
        db[collection].insert_many(records)

        # Governance events.
        self.gov.load_complete(len(records), collection)
        self.gov.destination_registered("mongodb", cfg["db_name"], collection)

        # Always close the connection explicitly to release the connection
        # pool resources and prevent socket leaks.
        client.close()


# ═════════════════════════════════════════════════════════════════════════════
#  COMPLIANCE WIZARD
# ═════════════════════════════════════════════════════════════════════════════
def run_compliance_wizard(
    gov: "GovernanceLogger", pii_findings: list[dict]
) -> dict:
    """
    Interactive GDPR / CCPA compliance configuration wizard.

    Walks the operator through a series of questions to capture the
    required compliance decisions before any data is transformed or
    loaded.  All decisions are logged to the governance audit ledger
    so there is an auditable record of who decided what and when.

    The wizard covers:
      Section 1 — GDPR Article 6 lawful basis and processing purpose.
      Section 2 — CCPA §1798.120 opt-out for data sale / sharing.
      Section 3 — PII handling strategy (mask / drop / retain).
      Section 4 — Data retention policy (GDPR Art. 5(1)(e)).
      Section 5 — Data minimisation — columns to drop (GDPR Art. 5(1)(c)).

    Parameters
    ----------
    gov          : GovernanceLogger  Shared governance logger.
    pii_findings : list[dict]        PII findings from _detect_pii().

    Returns
    -------
    dict  Compliance configuration containing:
        lawful_basis  : str        GDPR Art. 6 basis chosen.
        purpose       : str        Plain-English processing purpose.
        pii_strategy  : str        "mask", "drop", or "retain".
        retention_days: int|None   Days to retain data (None = indefinite).
        drop_cols     : list[str]  Columns to remove before loading.
    """
    print("\n" + "═" * 60)
    print("  GDPR / CCPA COMPLIANCE WIZARD")
    print("═" * 60)

    # ── Section 1: GDPR Article 6 Lawful Basis ────────────────────────────────
    # Processing personal data without a lawful basis is a violation of
    # GDPR Art. 6.  The six permissible bases are enumerated here; the
    # operator selects the most appropriate one for their use case.
    print("\n[GDPR Art. 6] Select lawful basis for processing:")
    bases = {
        "1": "Consent",             # Art. 6(1)(a) — explicit opt-in
        "2": "Contract",            # Art. 6(1)(b) — necessary for a contract
        "3": "Legal Obligation",    # Art. 6(1)(c) — required by law
        "4": "Vital Interests",     # Art. 6(1)(d) — protect life
        "5": "Public Task",         # Art. 6(1)(e) — public authority
        "6": "Legitimate Interests",# Art. 6(1)(f) — controller's interests
    }
    for k, v in bases.items():
        print(f"  {k}. {v}")

    basis_key  = _prompt("Choice", "2")
    lawful_basis = bases.get(basis_key, "Contract")

    # Free-text purpose statement — critical for Art. 30 records.
    purpose = _prompt(
        "Describe the processing purpose (e.g. 'HR analytics')",
        "Data analysis",
    )
    confirmed = _yn("Does the data subject / data owner consent to this processing?", True)
    gov.consent_recorded(purpose, lawful_basis, confirmed)

    # ── Section 2: CCPA §1798.120 — Right to Opt-Out of Sale ─────────────────
    # CCPA requires businesses to honour opt-out requests before selling or
    # sharing personal information with third parties.  If the operator
    # indicates the data will be sold/shared, we record the opt-out status.
    print("\n[CCPA §1798.120] Data Sale / Sharing")
    sell_data = _yn("Will any of this data be sold or shared with third parties?", False)
    if sell_data:
        optout = _yn("Has the data subject opted OUT of sale?", True)
        gov._event("CONSENT", "CCPA_SALE_OPTOUT", {"opted_out": optout})
        if optout:
            print("  ✓ Opt-out recorded. Data will NOT be forwarded to third parties.")

    # ── Section 3: PII Handling Strategy ─────────────────────────────────────
    # Present the detected PII fields and let the operator choose how to
    # handle them.  Default is "mask" because it is the safest option that
    # still preserves referential integrity (unlike "drop").
    pii_strategy = "retain"  # Default if no PII was found
    if pii_findings:
        print(f"\n[PRIVACY] {len(pii_findings)} PII field(s) detected:")
        for f in pii_findings:
            # Flag Art. 9 fields with a visible warning.
            tag = " ⚠ SPECIAL CATEGORY (GDPR Art.9)" if f["special_category"] else ""
            print(f"  • {f['field']}{tag}")

        print("\nHow should PII fields be handled?")
        print("  1. Mask   (pseudonymise — SHA-256 hash prefix, GDPR Art. 25 compliant)")
        print("  2. Drop   (remove from dataset entirely)")
        print("  3. Retain (keep raw — only if you have explicit consent/legal basis)")
        strat_key    = _prompt("Choice", "1")
        pii_strategy = {"1": "mask", "2": "drop", "3": "retain"}.get(strat_key, "mask")

    # ── Section 4: Retention Policy ───────────────────────────────────────────
    # GDPR Art. 5(1)(e) storage limitation principle: personal data must not
    # be kept longer than necessary.  We record the policy here; enforcement
    # (actually deleting old records) must be implemented as a separate
    # scheduled job using the _loaded_at_utc metadata column.
    print("\n[GDPR Art. 5(1)(e) / CCPA §1798.100] Retention Policy")
    print("  1. 30 days       4. 2 years")
    print("  2. 90 days       5. 5 years")
    print("  3. 1 year        6. Indefinite (must justify)")
    ret_map = {
        "1": 30,    # 30 days
        "2": 90,    # 90 days
        "3": 365,   # 1 year
        "4": 730,   # 2 years
        "5": 1825,  # 5 years
        "6": None,  # Indefinite — legal justification required
    }
    ret_key       = _prompt("Choice", "3")
    retention_days = ret_map.get(ret_key, 365)
    policy_desc = (
        f"Retain for {retention_days} days"
        if retention_days
        else "Indefinite retention — legal justification required"
    )
    gov.retention_policy(policy_desc, retention_days)

    # ── Section 5: Data Minimisation ─────────────────────────────────────────
    # GDPR Art. 5(1)(c): only collect data that is adequate, relevant,
    # and limited to what is necessary.  Give the operator a chance to
    # explicitly name any columns they want removed before loading.
    print("\n[GDPR Art. 5(1)(c)] Data Minimization")
    drop_extra = _yn("Do you want to drop specific columns before loading?", False)
    drop_cols: list[str] = []
    if drop_extra:
        cols_input = input("Enter comma-separated column names to drop: ").strip()
        # Split on comma, strip whitespace from each name, skip empty strings.
        drop_cols = [c.strip() for c in cols_input.split(",") if c.strip()]

    # Return all collected decisions as a single dictionary for the caller.
    return {
        "lawful_basis"  : lawful_basis,
        "purpose"       : purpose,
        "pii_strategy"  : pii_strategy,
        "retention_days": retention_days,
        "drop_cols"     : drop_cols,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  DATABASE CONFIGURATION PROMPTS
# ═════════════════════════════════════════════════════════════════════════════
def prompt_db_config() -> tuple[str, dict, str]:
    """
    Interactively collect all connection parameters for the target database.

    The function branches based on the database type selected by the user:
      • SQLite   — only needs a file name (no host or credentials).
      • MongoDB  — supports either a full URI or host:port separately.
      • All SQL  — needs host, username, password, database name, and port.

    Passwords are collected via getpass.getpass() which suppresses echo
    so that credentials are never displayed in the terminal or in any
    screen recordings of the session.

    Returns
    -------
    tuple[str, dict, str]
        db_type  : str   Database engine name (e.g. "postgresql").
        cfg      : dict  Connection parameters for the chosen engine.
        table    : str   Target table or collection name.
    """
    print("\n" + "═" * 60)
    print("  DESTINATION DATABASE CONFIGURATION")
    print("═" * 60)
    print("  1. SQLite       (no server required — file-based)")
    print("  2. PostgreSQL")
    print("  3. MySQL / MariaDB")
    print("  4. SQL Server (MSSQL)")
    print("  5. MongoDB")
    db_choice = _prompt("Select database type", "1")

    # Map menu choice to engine identifier string.
    db_map  = {"1": "sqlite", "2": "postgresql", "3": "mysql", "4": "mssql", "5": "mongodb"}
    db_type = db_map.get(db_choice, "sqlite")

    cfg: dict = {}   # Will be populated based on db_type below

    if db_type == "sqlite":
        # SQLite creates the database file automatically; we just need a name.
        cfg["db_name"] = _prompt("SQLite database file name (no extension)", "pipeline_output")

    elif db_type == "mongodb":
        use_uri = _yn("Use a full MongoDB URI (e.g. Atlas connection string)?", False)
        if use_uri:
            # Full URI covers Atlas, replica sets, and TLS-authenticated clusters.
            cfg["uri"] = _prompt("MongoDB URI")
        else:
            # Simple host:port for local or on-premise MongoDB installations.
            cfg["host"] = _prompt("Host", "localhost")
            cfg["port"] = int(_prompt("Port", "27017"))
        cfg["db_name"] = _prompt("Database name", "pipeline_db")

    else:
        # All other SQL engines need the same basic set of credentials.
        cfg["host"]     = _prompt("Host", "localhost")
        cfg["user"]     = _prompt("Username")
        cfg["password"] = getpass.getpass("Password: ")   # Hidden input
        cfg["db_name"]  = _prompt("Database name", "pipeline_db")

        # Each engine uses a different default port.
        if db_type == "postgresql":
            cfg["port"] = _prompt("Port", "5432")
        elif db_type == "mysql":
            cfg["port"] = _prompt("Port", "3306")
        elif db_type == "mssql":
            cfg["port"] = _prompt("Port", "1433")

    # Target table / collection name — used by both SQL and MongoDB loaders.
    table = _prompt("Target table / collection name", "imported_data")
    return db_type, cfg, table


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════
def main() -> None:
    """
    Top-level orchestration function that drives the full pipeline.

    Execution order
    ---------------
    0.  --help / isatty       — print usage or exit if not in a terminal.
    1.  Dependency check      — exit early with a clear error if pandas
                                is not installed.
    2.  Governance logger     — instantiate GovernanceLogger and fire
                                the PIPELINE_STARTED event.
    3.  Source file prompt    — loop until the user provides a path to
                                a file that actually exists.
    4.  Extract               — call Extractor.extract(); handle errors.
    5.  PII scan              — call _detect_pii() on column names.
    6.  Compliance wizard     — call run_compliance_wizard() to capture
                                all GDPR/CCPA decisions.
    7.  Destination config    — call prompt_db_config() for DB details.
    8.  if_exists strategy    — prompt for table-collision behaviour
                                (SQL only).
    9.  Transform             — call Transformer.transform(); handle errors.
    10. Load                  — call the appropriate loader; handle errors.
    11. Governance artefacts  — write PII report, fire PIPELINE_COMPLETED,
                                print summary.
    """
    import sys as _sys

    if any(a in ("-h", "--help") for a in _sys.argv[1:]):
        print("Usage: python pipeline_documented.py  (interactive wizard — requires terminal)")
        print("For scripted use, import classes from pipeline_v3.py instead.")
        return

    if not _sys.stdin.isatty():
        raise SystemExit(
            "pipeline_documented.py is an interactive wizard and requires a terminal.\n"
            "Use pipeline_v3.py classes directly for non-interactive runs."
        )

    print("=" * 60)
    print("  DATA GOVERNANCE PIPELINE  v" + VERSION)
    print("  GDPR & CCPA Compliant ETL")
    print("=" * 60)

    # ── Step 1: Dependency check ──────────────────────────────────────────────
    # MISSING was populated at module import time.  Exiting here (before
    # prompting for any user input) saves the operator from completing a long
    # configuration session only to hit an ImportError during extraction.
    if MISSING:
        print(f"\n[ERROR] Missing required packages: {', '.join(MISSING)}")
        print("Install with:  pip install " + " ".join(MISSING))
        sys.exit(1)

    # ── Step 2: Governance logger ─────────────────────────────────────────────
    gov = GovernanceLogger()    # Creates ./governance_logs/ and all artefact files
    gov.pipeline_start({
        "version"        : VERSION,
        "platform"       : platform.platform(),    # e.g. "Linux-6.1.0-amd64"
        "python_version" : sys.version,
    })

    # ── Step 3: Source file prompt ────────────────────────────────────────────
    # Loop until a valid file path is entered.  This prevents the pipeline
    # from reaching the extraction step only to fail with a FileNotFoundError.
    print("\n[SOURCE] Supported formats: CSV, JSON, Excel (.xlsx/.xls), XML")
    while True:
        source_path = _prompt("Enter path to source file")
        if Path(source_path).exists():
            break   # Valid path confirmed — proceed
        print(f"  File not found: {source_path}  — please try again.")

    # ── Step 4: Extract ───────────────────────────────────────────────────────
    extractor = Extractor(gov)
    try:
        df = extractor.extract(source_path)
    except Exception as e:
        # Log the failure to the governance ledger, then exit.
        gov.error("EXTRACTION_FAILED", e)
        print(f"\n[ERROR] Could not read file: {e}")
        sys.exit(1)

    print(f"\n  ✓ Extracted {len(df):,} rows × {len(df.columns)} columns")
    # Show up to 10 column names to give the operator a quick sense of the data.
    print(f"  Columns: {', '.join(df.columns[:10])}{'...' if len(df.columns) > 10 else ''}")

    # ── Step 5: PII scan ──────────────────────────────────────────────────────
    # Run BEFORE the compliance wizard so we can show the operator exactly
    # which fields were detected and prompt for an informed decision.
    pii_findings = _detect_pii(list(df.columns))
    if pii_findings:
        gov.pii_detected(pii_findings)  # WARNING-level audit event

    # ── Step 6: Compliance wizard ─────────────────────────────────────────────
    compliance = run_compliance_wizard(gov, pii_findings)

    # ── Step 7: Destination configuration ────────────────────────────────────
    db_type, db_cfg, table = prompt_db_config()

    # ── Step 8: Table-collision strategy (SQL only) ───────────────────────────
    # MongoDB collections are always append-only via insert_many(), so this
    # prompt is skipped for MongoDB destinations.
    if_exists = "append"    # Default: safe, non-destructive
    if db_type != "mongodb":
        print("\n[LOAD] Table already exists behaviour:")
        print("  1. append   — Add new rows to existing table (safe)")
        print("  2. replace  — DROP and recreate table (destructive!)")
        print("  3. fail     — Raise an error if table exists")
        ie = _prompt("Choice", "1")
        if_exists = {"1": "append", "2": "replace", "3": "fail"}.get(ie, "append")

    # ── Step 9: Transform ─────────────────────────────────────────────────────
    transformer = Transformer(gov)
    try:
        df = transformer.transform(
            df,
            pii_findings=pii_findings,
            pii_strategy=compliance["pii_strategy"],
            drop_cols=compliance["drop_cols"],
        )
    except Exception as e:
        gov.error("TRANSFORMATION_FAILED", e)
        print(f"\n[ERROR] Transformation failed: {e}")
        sys.exit(1)

    print(f"\n  ✓ Transformed → {len(df):,} rows × {len(df.columns)} columns")

    # ── Step 10: Load ─────────────────────────────────────────────────────────
    print(f"\n[LOAD] Writing to {db_type.upper()} → {table} …")
    try:
        if db_type == "mongodb":
            loader = MongoLoader(gov)
            loader.load(df, db_cfg, table)
        else:
            loader = SQLLoader(gov, db_type)
            loader.load(df, db_cfg, table, if_exists)
        print(f"  ✓ {len(df):,} rows written successfully.")
    except Exception as e:
        gov.error("LOAD_FAILED", e)
        print(f"\n[ERROR] Load failed: {e}")
        import traceback
        traceback.print_exc()   # Full stack trace helps diagnose driver issues
        sys.exit(1)

    # ── Step 11: Finalise governance artefacts ────────────────────────────────
    # Write the PII report (consolidates all findings collected during the run).
    gov.write_pii_report()

    # Fire the final LIFECYCLE event with summary statistics.
    gov.pipeline_end({
        "rows_loaded"           : len(df),
        "destination_db_type"   : db_type,
        "destination_table"     : table,
        "pii_strategy_applied"  : compliance["pii_strategy"],
        "retention_policy_days" : compliance["retention_days"],
    })

    # Print and log file paths of all governance artefacts.
    gov.summary()

    print("\n[DONE] Pipeline complete. Governance artefacts saved to ./governance_logs/")


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
# The "if __name__ == '__main__'" guard ensures that main() is only called
# when this script is executed directly (e.g. `python pipeline.py`).
# When the module is imported by another script or by the smoke-test suite,
# main() is NOT called automatically — preventing unintended side effects
# like unexpected console prompts during imports or unit tests.
if __name__ == "__main__":
    main()
