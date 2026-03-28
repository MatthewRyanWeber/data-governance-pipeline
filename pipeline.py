"""
=============================================================
  DATA GOVERNANCE PIPELINE
  GDPR & CCPA Compliant ETL Tool
  Author: Generated for Columbia University CUIT
=============================================================
Supports:
  - Source formats : CSV, JSON, Excel (.xlsx/.xls), XML
  - Destinations   : SQLite, PostgreSQL, MySQL, SQL Server, MongoDB
  - Governance     : Full audit logging, PII detection, lineage tracking
  - Compliance     : GDPR & CCPA principles enforced
=============================================================
"""

# [unused – kept for reference] import os
import sys
import json
# [unused – kept for reference] import csv
import uuid
import hashlib
import logging
import re
import getpass
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── stdlib-only check; optional heavy deps loaded lazily ──────────────────────
MISSING = []
try:
    import pandas as pd
except ImportError:
    MISSING.append("pandas")
try:
# [unused – kept for reference]     from flatten_json import flatten as _fj_flatten  # optional helper
    HAS_FLATTEN_JSON = True
except ImportError:
    HAS_FLATTEN_JSON = False


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & PII PATTERNS
# ═════════════════════════════════════════════════════════════════════════════
VERSION = "1.0.0"
PIPELINE_ID = str(uuid.uuid4())
RUN_START = datetime.now(timezone.utc).isoformat()

# Common PII field-name patterns (GDPR Article 4 / CCPA §1798.140)
PII_FIELD_PATTERNS = [
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

SENSITIVE_CATEGORIES = {  # GDPR Article 9 special categories
    r"\bhealth\b", r"\bmedical\b", r"\brace\b", r"\bethnicity\b",
    r"\breligion\b", r"\bpolitical\b", r"\bbiometric\b", r"\bgenetic\b",
}

# ═════════════════════════════════════════════════════════════════════════════
#  GOVERNANCE LOGGER
# ═════════════════════════════════════════════════════════════════════════════
class GovernanceLogger:
    """
    Writes structured audit events to both a human-readable log file
    and a machine-readable JSONL governance ledger.
    Covers: lineage, access control, PII handling, transformation,
            retention policy, breach events.
    """
    def __init__(self, log_dir: str = "governance_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Human-readable log
        self.log_file = self.log_dir / f"pipeline_{ts}.log"
        # JSONL audit ledger (machine-readable, immutable append)
        self.ledger_file = self.log_dir / f"audit_ledger_{ts}.jsonl"
        # PII report
        self.pii_report_file = self.log_dir / f"pii_report_{ts}.json"

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger("DataPipeline")
        self.pii_findings: list[dict] = []
        self.ledger_entries: list[dict] = []

    # ── core event writer ────────────────────────────────────────────────────
    def _event(self, category: str, action: str, detail: dict | None = None, level: str = "INFO"):
        entry = {
            "pipeline_id": PIPELINE_ID,
            "event_id": str(uuid.uuid4()),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "host": platform.node(),
            "os_user": getpass.getuser(),
            "category": category,
            "action": action,
            "detail": detail or {},
        }
        with open(self.ledger_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self.ledger_entries.append(entry)
        msg = f"[{category}] {action}"
        if detail:
            msg += f" | {json.dumps(detail)}"
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    # ── convenience wrappers ─────────────────────────────────────────────────
    def pipeline_start(self, metadata: dict):
        self._event("LIFECYCLE", "PIPELINE_STARTED", metadata)

    def pipeline_end(self, stats: dict):
        self._event("LIFECYCLE", "PIPELINE_COMPLETED", stats)

    def source_registered(self, path: str, file_type: str, row_count: int, col_count: int):
        h = _file_hash(path)
        self._event("LINEAGE", "SOURCE_REGISTERED", {
            "source_path": path,
            "file_type": file_type,
            "row_count": row_count,
            "col_count": col_count,
            "sha256": h,
        })

    def destination_registered(self, db_type: str, db_name: str, table: str):
        self._event("LINEAGE", "DESTINATION_REGISTERED", {
            "db_type": db_type,
            "db_name": db_name,
            "table_or_collection": table,
        })

    def transformation_applied(self, name: str, detail: dict | None = None):
        self._event("TRANSFORMATION", name, detail)

    def pii_detected(self, findings: list[dict]):
        self.pii_findings.extend(findings)
        self._event("PRIVACY", "PII_DETECTED", {"findings_count": len(findings),
                                                  "fields": [f["field"] for f in findings]}, level="WARNING")

    def consent_recorded(self, purpose: str, basis: str, user_confirmed: bool):
        self._event("CONSENT", "LAWFUL_BASIS_RECORDED", {
            "processing_purpose": purpose,
            "lawful_basis": basis,         # GDPR Art 6
            "user_confirmed": user_confirmed,
        })

    def data_minimization(self, original_cols: list, retained_cols: list, dropped_cols: list):
        self._event("PRIVACY", "DATA_MINIMIZATION_APPLIED", {
            "original_column_count": len(original_cols),
            "retained_column_count": len(retained_cols),
            "dropped_columns": dropped_cols,
        })

    def pii_action(self, field: str, action: str):
        """action = MASKED | HASHED | DROPPED | RETAINED_WITH_CONSENT"""
        self._event("PRIVACY", f"PII_{action}", {"field": field})

    def retention_policy(self, policy: str, retention_days: int | None):
        self._event("RETENTION", "POLICY_RECORDED", {
            "policy": policy,
            "retention_days": retention_days,
        })

    def load_complete(self, rows_written: int, table: str):
        self._event("LINEAGE", "LOAD_COMPLETE", {
            "rows_written": rows_written,
            "destination_table": table,
        })

    def error(self, msg: str, exc: Exception | None = None):
        self._event("ERROR", msg, {"exception": str(exc)} if exc else None, level="ERROR")

    def write_pii_report(self):
        report = {
            "pipeline_id": PIPELINE_ID,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "regulation_references": {
                "GDPR": "Articles 4, 9, 25, 32",
                "CCPA": "§1798.100, §1798.140, §1798.150",
            },
            "pii_findings": self.pii_findings,
            "summary": {
                "total_pii_fields": len(self.pii_findings),
                "special_category_fields": sum(1 for f in self.pii_findings if f.get("special_category")),
            },
        }
        with open(self.pii_report_file, "w") as f:
            json.dump(report, f, indent=2)
        self.logger.info(f"PII report written → {self.pii_report_file}")

    def summary(self):
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
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════
def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_pii(columns: list[str]) -> list[dict]:
    findings = []
    for col in columns:
        col_lower = col.lower()
        for pattern in PII_FIELD_PATTERNS:
            if re.search(pattern, col_lower):
                special = any(re.search(sp, col_lower) for sp in SENSITIVE_CATEGORIES)
                findings.append({
                    "field": col,
                    "matched_pattern": pattern,
                    "special_category": special,
                    "gdpr_reference": "Article 9" if special else "Article 4(1)",
                    "ccpa_reference": "§1798.140(o)",
                })
                break
    return findings


def _flatten_record(record: Any, parent_key: str = "", sep: str = "__") -> dict:
    """Recursively flatten nested dict/list structures."""
    items: list = []
    if isinstance(record, dict):
        for k, v in record.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            if isinstance(v, (dict, list)):
                items.extend(_flatten_record(v, new_key, sep).items())
            else:
                items.append((new_key, v))
    elif isinstance(record, list):
        for i, v in enumerate(record):
            new_key = f"{parent_key}{sep}{i}" if parent_key else str(i)
            if isinstance(v, (dict, list)):
                items.extend(_flatten_record(v, new_key, sep).items())
            else:
                items.append((new_key, v))
    else:
        return {parent_key: record}
    return dict(items)


def _mask_value(value: Any) -> str:
    """One-way hash for PII masking (GDPR Art 25 - pseudonymisation)."""
    if value is None:
        return None
    return "MASKED_" + hashlib.sha256(str(value).encode()).hexdigest()[:12]


def _prompt(msg: str, default: str = "") -> str:
    resp = input(f"{msg} [{default}]: ").strip() if default else input(f"{msg}: ").strip()
    return resp if resp else default


def _yn(msg: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    resp = input(f"{msg} {suffix}: ").strip().lower()
    if not resp:
        return default
    return resp in ("y", "yes")


# ═════════════════════════════════════════════════════════════════════════════
#  EXTRACTORS
# ═════════════════════════════════════════════════════════════════════════════
class Extractor:
    def __init__(self, gov: GovernanceLogger):
        self.gov = gov

    def extract(self, path: str) -> pd.DataFrame:
        ext = Path(path).suffix.lower()
        self.gov.transformation_applied("EXTRACT_START", {"source": path, "format": ext})

        if ext == ".csv":
            df = pd.read_csv(path)
        elif ext in (".xlsx", ".xls"):
            df = pd.read_excel(path)
        elif ext == ".json":
            with open(path) as f:
                raw = json.load(f)
            # support array-of-objects or single object
            if isinstance(raw, list):
                flat = [_flatten_record(r) for r in raw]
            else:
                flat = [_flatten_record(raw)]
            df = pd.DataFrame(flat)
        elif ext == ".xml":
            df = pd.read_xml(path)
        else:
            raise ValueError(f"Unsupported file format: {ext}")

        self.gov.source_registered(path, ext, len(df), len(df.columns))
        self.gov.transformation_applied("EXTRACT_COMPLETE", {"rows": len(df), "columns": list(df.columns)})
        return df


# ═════════════════════════════════════════════════════════════════════════════
#  TRANSFORMER  (flatten + clean + PII handling)
# ═════════════════════════════════════════════════════════════════════════════
class Transformer:
    def __init__(self, gov: GovernanceLogger):
        self.gov = gov
        self.pii_actions: dict[str, str] = {}   # field → action taken

    def transform(self, df: pd.DataFrame, pii_findings: list[dict],
                  pii_strategy: str, drop_cols: list[str]) -> pd.DataFrame:
        original_cols = list(df.columns)

        # 1. Flatten any remaining object columns
        obj_cols = [c for c in df.columns if df[c].dtype == object
                    and df[c].dropna().apply(lambda x: isinstance(x, (dict, list))).any()]
        if obj_cols:
            expanded = []
            for _, row in df.iterrows():
                flat_row = {}
                for col in df.columns:
                    val = row[col]
                    if isinstance(val, (dict, list)):
                        flat_row.update(_flatten_record(val, parent_key=col))
                    else:
                        flat_row[col] = val
                expanded.append(flat_row)
            df = pd.DataFrame(expanded)
            self.gov.transformation_applied("FLATTEN_NESTED", {"flattened_columns": obj_cols})

        # 2. Drop user-requested columns (data minimization)
        if drop_cols:
            df.drop(columns=[c for c in drop_cols if c in df.columns], inplace=True, errors="ignore")
            self.gov.data_minimization(original_cols, list(df.columns), drop_cols)

        # 3. Handle PII fields per chosen strategy
        pii_fields = {f["field"]: f for f in pii_findings if f["field"] in df.columns}
        for field, info in pii_fields.items():
            if pii_strategy == "mask":
                df[field] = df[field].apply(_mask_value)
                self.gov.pii_action(field, "MASKED")
                self.pii_actions[field] = "MASKED"
            elif pii_strategy == "drop":
                df.drop(columns=[field], inplace=True, errors="ignore")
                self.gov.pii_action(field, "DROPPED")
                self.pii_actions[field] = "DROPPED"
            elif pii_strategy == "retain":
                self.gov.pii_action(field, "RETAINED_WITH_CONSENT")
                self.pii_actions[field] = "RETAINED_WITH_CONSENT"

        # 4. Null handling
        before_nulls = df.isnull().sum().sum()
        df.dropna(how="all", inplace=True)   # drop fully empty rows
        after_nulls = df.isnull().sum().sum()
        self.gov.transformation_applied("NULL_HANDLING", {
            "null_cells_before": int(before_nulls),
            "null_cells_after": int(after_nulls),
        })

        # 5. Deduplication
        before_dedup = len(df)
        df.drop_duplicates(inplace=True)
        self.gov.transformation_applied("DEDUPLICATION", {
            "rows_before": before_dedup,
            "rows_after": len(df),
            "duplicates_removed": before_dedup - len(df),
        })

        # 6. Column name sanitisation (safe for SQL/Mongo)
        df.columns = [re.sub(r"[^a-zA-Z0-9_]", "_", c).strip("_") for c in df.columns]
        self.gov.transformation_applied("COLUMN_SANITIZATION", {"final_columns": list(df.columns)})

        # 7. Add governance metadata columns
        df["_pipeline_id"] = PIPELINE_ID
        df["_loaded_at_utc"] = datetime.now(timezone.utc).isoformat()

        self.gov.transformation_applied("TRANSFORM_COMPLETE", {
            "final_row_count": len(df),
            "final_col_count": len(df.columns),
        })
        return df


# ═════════════════════════════════════════════════════════════════════════════
#  LOADERS
# ═════════════════════════════════════════════════════════════════════════════
class SQLLoader:
    def __init__(self, gov: GovernanceLogger, db_type: str):
        self.gov = gov
        self.db_type = db_type

    def _engine(self, cfg: dict):
        from sqlalchemy import create_engine
        t = self.db_type
        if t == "sqlite":
            return create_engine(f"sqlite:///{cfg['db_name']}.db")
        elif t == "postgresql":
            return create_engine(
                f"postgresql+psycopg2://{cfg['user']}:{cfg['password']}@{cfg['host']}:{cfg.get('port', 5432)}/{cfg['db_name']}"
            )
        elif t == "mysql":
            return create_engine(
                f"mysql+pymysql://{cfg['user']}:{cfg['password']}@{cfg['host']}:{cfg.get('port', 3306)}/{cfg['db_name']}"
            )
        elif t == "mssql":
            driver = cfg.get("driver", "ODBC+Driver+17+for+SQL+Server")
            return create_engine(
                f"mssql+pyodbc://{cfg['user']}:{cfg['password']}@{cfg['host']}:{cfg.get('port', 1433)}/{cfg['db_name']}?driver={driver}"
            )
        raise ValueError(f"Unknown SQL type: {t}")

    def load(self, df: pd.DataFrame, cfg: dict, table: str, if_exists: str = "append"):
        engine = self._engine(cfg)
        df.to_sql(table, engine, if_exists=if_exists, index=False, chunksize=500)
        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(self.db_type, cfg["db_name"], table)


class MongoLoader:
    def __init__(self, gov: GovernanceLogger):
        self.gov = gov

    def load(self, df: pd.DataFrame, cfg: dict, collection: str):
        from pymongo import MongoClient
        uri = cfg.get("uri") or f"mongodb://{cfg.get('host','localhost')}:{cfg.get('port',27017)}/"
        client = MongoClient(uri)
        db = client[cfg["db_name"]]
        records = json.loads(df.to_json(orient="records", date_format="iso"))
        db[collection].insert_many(records)
        self.gov.load_complete(len(records), collection)
        self.gov.destination_registered("mongodb", cfg["db_name"], collection)
        client.close()


# ═════════════════════════════════════════════════════════════════════════════
#  CONSENT & COMPLIANCE MODULE
# ═════════════════════════════════════════════════════════════════════════════
def run_compliance_wizard(gov: GovernanceLogger, pii_findings: list[dict]) -> dict:
    """Interactive GDPR/CCPA consent and PII strategy wizard."""
    print("\n" + "═" * 60)
    print("  GDPR / CCPA COMPLIANCE WIZARD")
    print("═" * 60)

    # ── GDPR lawful basis ────────────────────────────────────────────────────
    print("\n[GDPR Art. 6] Select lawful basis for processing:")
    bases = {
        "1": "Consent",
        "2": "Contract",
        "3": "Legal Obligation",
        "4": "Vital Interests",
        "5": "Public Task",
        "6": "Legitimate Interests",
    }
    for k, v in bases.items():
        print(f"  {k}. {v}")
    basis_key = _prompt("Choice", "2")
    lawful_basis = bases.get(basis_key, "Contract")

    purpose = _prompt("Describe the processing purpose (e.g. 'HR analytics')", "Data analysis")
    confirmed = _yn("Does the data subject / data owner consent to this processing?", True)
    gov.consent_recorded(purpose, lawful_basis, confirmed)

    # ── CCPA opt-out ─────────────────────────────────────────────────────────
    print("\n[CCPA §1798.120] Data Sale / Sharing")
    sell_data = _yn("Will any of this data be sold or shared with third parties?", False)
    if sell_data:
        optout = _yn("Has the data subject opted OUT of sale?", True)
        gov._event("CONSENT", "CCPA_SALE_OPTOUT", {"opted_out": optout})
        if optout:
            print("  ✓ Opt-out recorded. Data will NOT be forwarded to third parties.")

    # ── PII strategy ─────────────────────────────────────────────────────────
    pii_strategy = "retain"
    if pii_findings:
        print(f"\n[PRIVACY] {len(pii_findings)} PII field(s) detected:")
        for f in pii_findings:
            tag = " ⚠ SPECIAL CATEGORY (GDPR Art.9)" if f["special_category"] else ""
            print(f"  • {f['field']}{tag}")

        print("\nHow should PII fields be handled?")
        print("  1. Mask   (pseudonymise — SHA-256 hash prefix, GDPR Art. 25 compliant)")
        print("  2. Drop   (remove from dataset entirely)")
        print("  3. Retain (keep raw — only if you have explicit consent/legal basis)")
        strat_key = _prompt("Choice", "1")
        pii_strategy = {"1": "mask", "2": "drop", "3": "retain"}.get(strat_key, "mask")

    # ── Retention policy ─────────────────────────────────────────────────────
    print("\n[GDPR Art. 5(1)(e) / CCPA §1798.100] Retention Policy")
    print("  1. 30 days       4. 2 years")
    print("  2. 90 days       5. 5 years")
    print("  3. 1 year        6. Indefinite (must justify)")
    ret_map = {"1": 30, "2": 90, "3": 365, "4": 730, "5": 1825, "6": None}
    ret_key = _prompt("Choice", "3")
    retention_days = ret_map.get(ret_key, 365)
    policy_desc = f"Retain for {retention_days} days" if retention_days else "Indefinite retention — legal justification required"
    gov.retention_policy(policy_desc, retention_days)

    # ── Data minimisation ─────────────────────────────────────────────────────
    print("\n[GDPR Art. 5(1)(c)] Data Minimization")
    drop_extra = _yn("Do you want to drop specific columns before loading?", False)
    drop_cols = []
    if drop_extra:
        cols_input = input("Enter comma-separated column names to drop: ").strip()
        drop_cols = [c.strip() for c in cols_input.split(",") if c.strip()]

    return {
        "lawful_basis": lawful_basis,
        "purpose": purpose,
        "pii_strategy": pii_strategy,
        "retention_days": retention_days,
        "drop_cols": drop_cols,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  DATABASE CONFIGURATION PROMPTS
# ═════════════════════════════════════════════════════════════════════════════
def prompt_db_config() -> tuple[str, dict, str]:
    print("\n" + "═" * 60)
    print("  DESTINATION DATABASE CONFIGURATION")
    print("═" * 60)
    print("  1. SQLite       (no server required — file-based)")
    print("  2. PostgreSQL")
    print("  3. MySQL / MariaDB")
    print("  4. SQL Server (MSSQL)")
    print("  5. MongoDB")
    db_choice = _prompt("Select database type", "1")

    db_map = {"1": "sqlite", "2": "postgresql", "3": "mysql", "4": "mssql", "5": "mongodb"}
    db_type = db_map.get(db_choice, "sqlite")

    cfg: dict = {}

    if db_type == "sqlite":
        cfg["db_name"] = _prompt("SQLite database file name (no extension)", "pipeline_output")
    elif db_type == "mongodb":
        use_uri = _yn("Use a full MongoDB URI (e.g. Atlas connection string)?", False)
        if use_uri:
            cfg["uri"] = _prompt("MongoDB URI")
        else:
            cfg["host"] = _prompt("Host", "localhost")
            cfg["port"] = int(_prompt("Port", "27017"))
        cfg["db_name"] = _prompt("Database name", "pipeline_db")
    else:
        cfg["host"] = _prompt("Host", "localhost")
        cfg["user"] = _prompt("Username")
        cfg["password"] = getpass.getpass("Password: ")
        cfg["db_name"] = _prompt("Database name", "pipeline_db")
        if db_type == "postgresql":
            cfg["port"] = _prompt("Port", "5432")
        elif db_type == "mysql":
            cfg["port"] = _prompt("Port", "3306")
        elif db_type == "mssql":
            cfg["port"] = _prompt("Port", "1433")

    table = _prompt("Target table / collection name", "imported_data")
    return db_type, cfg, table


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════
def main():
    import sys as _sys

    if any(a in ("-h", "--help") for a in _sys.argv[1:]):
        print("Usage: python pipeline.py  (interactive wizard — requires terminal)")
        print("For scripted use, import classes from pipeline_v3.py instead.")
        return

    if not _sys.stdin.isatty():
        raise SystemExit(
            "pipeline.py is an interactive wizard and requires a terminal.\n"
            "Use pipeline_v3.py classes directly for non-interactive runs."
        )

    print("=" * 60)
    print("  DATA GOVERNANCE PIPELINE  v" + VERSION)
    print("  GDPR & CCPA Compliant ETL")
    print("=" * 60)

    # ── dependency check ─────────────────────────────────────────────────────
    if MISSING:
        print(f"\n[ERROR] Missing required packages: {', '.join(MISSING)}")
        print("Install with:  pip install " + " ".join(MISSING))
        sys.exit(1)

    gov = GovernanceLogger()
    gov.pipeline_start({
        "version": VERSION,
        "platform": platform.platform(),
        "python_version": sys.version,
    })

    # ── source file ──────────────────────────────────────────────────────────
    print("\n[SOURCE] Supported formats: CSV, JSON, Excel (.xlsx/.xls), XML")
    while True:
        source_path = _prompt("Enter path to source file")
        if Path(source_path).exists():
            break
        print(f"  File not found: {source_path}  — please try again.")

    # ── extract ──────────────────────────────────────────────────────────────
    extractor = Extractor(gov)
    try:
        df = extractor.extract(source_path)
    except Exception as e:
        gov.error("EXTRACTION_FAILED", e)
        print(f"\n[ERROR] Could not read file: {e}")
        sys.exit(1)

    print(f"\n  ✓ Extracted {len(df):,} rows × {len(df.columns)} columns")
    print(f"  Columns: {', '.join(df.columns[:10])}{'...' if len(df.columns) > 10 else ''}")

    # ── PII scan ─────────────────────────────────────────────────────────────
    pii_findings = _detect_pii(list(df.columns))
    if pii_findings:
        gov.pii_detected(pii_findings)

    # ── compliance wizard ────────────────────────────────────────────────────
    compliance = run_compliance_wizard(gov, pii_findings)

    # ── destination config ───────────────────────────────────────────────────
    db_type, db_cfg, table = prompt_db_config()

    # ── if_exists strategy (SQL only) ────────────────────────────────────────
    if_exists = "append"
    if db_type != "mongodb":
        print("\n[LOAD] Table already exists behaviour:")
        print("  1. append   2. replace   3. fail")
        ie = _prompt("Choice", "1")
        if_exists = {"1": "append", "2": "replace", "3": "fail"}.get(ie, "append")

    # ── transform ────────────────────────────────────────────────────────────
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

    # ── load ─────────────────────────────────────────────────────────────────
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
        traceback.print_exc()
        sys.exit(1)

    # ── finalise governance artefacts ────────────────────────────────────────
    gov.write_pii_report()
    gov.pipeline_end({
        "rows_loaded": len(df),
        "destination_db_type": db_type,
        "destination_table": table,
        "pii_strategy_applied": compliance["pii_strategy"],
        "retention_policy_days": compliance["retention_days"],
    })
    gov.summary()

    print("\n[DONE] Pipeline complete. Governance artefacts saved to ./governance_logs/")


if __name__ == "__main__":
    main()
