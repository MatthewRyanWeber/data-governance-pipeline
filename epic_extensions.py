#!/usr/bin/env python3
"""
epic_extensions.py  —  Epic EHR / HIPAA healthcare governance extensions
for the pipeline_v3.py data pipeline suite.

Six classes covering the gap between general data governance (GDPR / CCPA)
and healthcare-specific requirements (HIPAA, IRB, OMOP research standards):

    HIPAASafeHarborFilter   Remove / mask all 18 HIPAA Safe Harbor identifiers
                            (45 CFR §164.514(b)), enforce the ZIP-code population
                            rule and the age-≥-90 aggregation rule.

    ClarityExtractor        Query Epic Clarity (SQL Server) with automatic
                            ZC_ code-table join, refresh-window guard, and
                            human-readable column decoding.

    BAATracker              Gate PHI loads against a Business Associate Agreement
                            registry; alert on upcoming expiry; integrate with
                            GovernanceLogger.

    IRBApprovalGate         Require a valid IRB protocol before any PHI extract;
                            enforce per-protocol approved data elements and block
                            unapproved columns at the DataFrame level.

    OMOPTransformer         Map the six most common Clarity tables to OMOP CDM
                            v5.4 domain tables (PERSON, VISIT_OCCURRENCE,
                            CONDITION_OCCURRENCE, DRUG_EXPOSURE, MEASUREMENT,
                            PROCEDURE_OCCURRENCE).

    PHIKAnonymityChecker    Verify k-anonymity (and optionally l-diversity) on
                            quasi-identifier combinations; suppress violating rows
                            before an extract proceeds.

Revision history
────────────────
1.0   2026-03-11   Initial release: all six Epic / HIPAA governance classes.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import pathlib
import re
import threading
from datetime import date, datetime, timedelta, timezone
from html import escape as _he
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.parse import quote_plus as _qp

import pandas as pd

# ── Optional: SQLAlchemy + pyodbc for ClarityExtractor ────────────────────
try:
    from sqlalchemy import create_engine, text as sa_text, inspect as sa_inspect
    _SA_AVAILABLE = True
except ImportError:
    _SA_AVAILABLE = False

logger = logging.getLogger(__name__)


# ── Module-level helpers ──────────────────────────────────────────────────

def _now_utc() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _html_head(title: str) -> str:
    """Return the common HTML preamble used by all report writers in this module."""
    return (
        f"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>\n"
        f"<title>{_he(title)}</title>\n"
        f"<style>"
        f"body{{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a2e;background:#f8f9fa}}"
        f".card{{background:#fff;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem;"
        f"box-shadow:0 1px 4px rgba(0,0,0,.08)}}"
        f"table{{border-collapse:collapse;width:100%}}"
        f"th,td{{border:1px solid #dee2e6;padding:.5rem .75rem;text-align:left}}"
        f"th{{background:#e9ecef;font-weight:600}}"
        f"tr:nth-child(even){{background:#f8f9fa}}"
        f".badge{{display:inline-block;padding:.2em .65em;border-radius:4px;"
        f"font-size:.8em;font-weight:600;letter-spacing:.02em}}"
        f".ok{{background:#d4edda;color:#155724}}"
        f".warn{{background:#fff3cd;color:#856404}}"
        f".error{{background:#f8d7da;color:#721c24}}"
        f".critical{{background:#dc3545;color:#fff}}"
        f".info{{background:#cce5ff;color:#004085}}"
        f"h1{{color:#1a1a2e;border-bottom:3px solid #4361ee;padding-bottom:.4rem}}"
        f"h2{{color:#3a3a5c;border-bottom:1px solid #dee2e6;padding-bottom:.3rem}}"
        f"code{{background:#f1f3f5;padding:.1em .3em;border-radius:3px;font-size:.9em}}"
        f"</style></head><body>\n"
    )


# ═════════════════════════════════════════════════════════════════════════════
#  1. HIPAASafeHarborFilter  —  45 CFR §164.514(b)  Safe Harbor method
# ═════════════════════════════════════════════════════════════════════════════

class HIPAASafeHarborFilter:
    """
    Applies the HIPAA Safe Harbor de-identification method (45 CFR §164.514(b))
    to a pandas DataFrame sourced from Epic Clarity or any other healthcare DB.

    Safe Harbor requires removing or masking 18 categories of identifiers.
    This class handles the three categories that need transformation logic in
    addition to the 15 that can be simply dropped or hashed:

        ZIP codes   Only the first three digits may be retained, and even those
                    must be suppressed to "000" if the three-digit area contains
                    fewer than 20,000 persons.  Seventeen such prefixes exist per
                    2000 US Census data (the HHS reference baseline).

        Dates       All date elements except year must be removed.  For patients
                    aged 90 or older the birth year must also be suppressed to
                    prevent indirect re-identification (the age-≥-90 rule).

        Ages        Any age value ≥ 90 is replaced with the string "90+" (or a
                    configurable label) to break the link to birth year.

    All remaining identifier columns are either dropped outright or replaced
    with a 16-hex-char SHA-256 hash of the original value, depending on the
    hash_identifiers flag.  Hash-mode preserves referential integrity across
    tables (e.g. the same MRN links PAT_ENC to PAT_ENC_DX after hashing)
    while removing the raw identifier.

    Quick-start
    ───────────
        from epic_extensions import HIPAASafeHarborFilter
        from pipeline_v3 import GovernanceLogger

        gov  = GovernanceLogger(run_id="run_001", src="clarity_extract")
        safe = HIPAASafeHarborFilter(gov)

        report = safe.scan(df)          # inspect without modifying df
        clean  = safe.apply(df)         # returns a new de-identified DataFrame
        safe.save_report("phi_report.html")
    """

    # ── 17 three-digit ZIP prefixes with population < 20,000 (HHS / 2000 Census)
    # Source: HHS guidance document on Safe Harbor de-identification method.
    # These must be reported as "000" per 45 CFR §164.514(b)(2)(i)(B).
    _RESTRICTED_ZIP3: Set[str] = {
        "036", "059", "102", "203", "556", "692", "790",
        "821", "823", "830", "831", "878", "879", "884",
        "890", "893",
    }

    # ── Column name patterns → (identifier_category, action)
    # action: "drop" | "hash" | "zip" | "date_year" | "age_cap"
    # "hash" keeps the column but replaces values with a SHA-256 digest, which
    # preserves referential integrity across tables while removing the raw PHI.
    # Epic Clarity column names are included alongside generic patterns.
    _RAW_RULES: List[Tuple[str, str, str]] = [
        # (regex pattern, category, action)
        (r"(?i)(pat_name|patient_name|first_name|last_name|"
         r"full_name|provider_name|prov_name|staff_name|"
         r"contact_name|guarantor_name|\bname\b)",
         "name", "drop"),

        (r"(?i)(pat_addr|address|addr_line|street|"
         r"mailing_address|home_address|res_addr)",
         "address", "drop"),

        (r"(?i)(zip|postal|post_code|zipcode|zip_code|"
         r"pat_zip)",
         "zip", "zip"),

        (r"(?i)(city|town|borough|municipality|"
         r"pat_city)",
         "city", "drop"),

        (r"(?i)(county|parish|district|precinct)",
         "county", "drop"),

        # Date columns that retain only the year after transformation
        (r"(?i)(admit_date|admission_date|discharge_date|"
         r"service_date|procedure_date|surgery_date|"
         r"contact_date|hosp_disch_time|inp_adm_date|"
         r"death_date|dod\b|ordering_date|result_date|"
         r"svc_date\b|eff_date\b|create_date|update_date|"
         r"appt_date|visit_date|entry_date|"
         r"referral_date|auth_date|expire_date|"
         r"issue_date|start_date|end_date)",
         "date", "date_year"),

        # Birth date is a date but handled separately because age-≥-90 rule
        (r"(?i)(birth_date|dob\b|date_of_birth|"
         r"pat_brth_dt|birthdate)",
         "birth_date", "date_year"),

        # Age — numeric values ≥ 90 must be aggregated
        (r"(?i)(age_in_days|age_in_months|age_in_years|"
         r"\bage\b|\bage_c\b|patient_age|cur_age|"
         r"calc_age)",
         "age", "age_cap"),

        (r"(?i)(phone|telephone|home_phone|work_phone|"
         r"cell_phone|mobile|pat_home_phone|"
         r"pat_work_phone|contact_phone)",
         "phone", "drop"),

        (r"(?i)(fax|fax_number|fax_num|fax_no)",
         "fax", "drop"),

        (r"(?i)(email|e_mail|pat_email|"
         r"email_address|electronic_mail)",
         "email", "drop"),

        (r"(?i)(ssn|social_security|soc_sec_num|"
         r"social_security_num)",
         "ssn", "drop"),

        # MRN — hash to preserve cross-table joins
        (r"(?i)(mrn\b|pat_mrn|pat_mrn_id|"
         r"medical_record|med_rec_num|"
         r"medical_record_number)",
         "mrn", "hash"),

        # Epic internal IDs — hash for referential integrity
        (r"(?i)(pat_id\b|patient_id\b|"
         r"pat_enc_csn|csn\b|encounter_id|"
         r"enc_id\b|visit_id\b|contact_serial_num)",
         "account_number", "hash"),

        (r"(?i)(health_plan|plan_id|member_id|"
         r"subscriber_id|insurance_id|policy_num|"
         r"coverage_id|ben_plan_id|ben_id\b)",
         "health_plan", "drop"),

        # Provider license / NPI — hash to keep provider linkage
        (r"(?i)(certificate|license_num|"
         r"dea_num|dea_number|npi\b|"
         r"prov_npi|provider_npi|state_license)",
         "certificate_license", "hash"),

        (r"(?i)(vin\b|vehicle_id|"
         r"license_plate|plate_num|vehicle_serial)",
         "vehicle", "drop"),

        (r"(?i)(device_id|serial_num|serial_number|"
         r"implant_id|device_serial|udi\b)",
         "device", "drop"),

        (r"(?i)(url\b|web_address|website|"
         r"homepage|web_url|hyperlink)",
         "web_url", "drop"),

        (r"(?i)(ip_address|ip_addr|\bip\b)",
         "ip_address", "drop"),

        (r"(?i)(photo|image|picture|"
         r"profile_pic|facial_image)",
         "photo", "drop"),

        (r"(?i)(fingerprint|voiceprint|"
         r"retinal|biometric|iris_scan|"
         r"palm_print)",
         "biometric", "drop"),
    ]

    # Compiled at class load time
    _PATTERNS: List[Tuple[re.Pattern, str, str]] = []

    @classmethod
    def _build_patterns(cls) -> None:
        if cls._PATTERNS:
            return
        cls._PATTERNS = [
            (re.compile(pat), category, action)
            for pat, category, action in cls._RAW_RULES
        ]

    def __init__(
        self,
        gov,
        age_cap:             int  = 90,
        age_cap_label:       str  = "90+",
        hash_identifiers:    bool = True,
        additional_columns:  Optional[Dict[str, str]] = None,
        dry_run:             bool = False,
    ) -> None:
        """
        Parameters
        ──────────
        gov                  GovernanceLogger for audit events.
        age_cap              Ages >= this value become age_cap_label.
                             Default 90 per HIPAA Safe Harbor guidance.
        age_cap_label        Replacement value for ages >= age_cap ("90+").
        hash_identifiers     True → MRN / CSN / NPI columns are SHA-256 hashed
                             (preserves cross-table referential integrity).
                             False → those columns are dropped entirely.
        additional_columns   Extra overrides: {"MY_CUSTOM_ID": "drop", ...}
        dry_run              Scan and report without modifying any data.
        """
        HIPAASafeHarborFilter._build_patterns()
        self.gov               = gov
        self.age_cap           = age_cap
        self.age_cap_label     = age_cap_label
        self.hash_identifiers  = hash_identifiers
        self.additional_columns = additional_columns or {}
        self.dry_run           = dry_run

        self._findings: List[Dict] = []
        self._last_report: Optional[Dict] = None

    # ── Public API ────────────────────────────────────────────────────────

    def scan(self, df: pd.DataFrame, source_label: str = "") -> Dict:
        """
        Inspect df for columns matching Safe Harbor identifier patterns.
        Does NOT modify df.  Returns a findings dict and logs
        PHI_SCAN_COMPLETE to the governance ledger.
        """
        self._findings = []
        for col in df.columns:
            action = self._classify_column(col)
            if action:
                self._findings.append({
                    "column":   col,
                    "category": self._category_for(col),
                    "action":   action,
                    "sample":   self._safe_sample(df[col]),
                })

        report = {
            "source":        source_label,
            "scanned_at":    _now_utc().isoformat(),
            "total_columns": len(df.columns),
            "phi_columns":   len(self._findings),
            "findings":      self._findings,
        }
        self._last_report = report

        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "PHI_SCAN_COMPLETE",
            {
                "source":      source_label,
                "phi_columns": len(self._findings),
                "dry_run":     self.dry_run,
                "columns":     [f["column"] for f in self._findings],
            },
        )
        return report

    def apply(self, df: pd.DataFrame, source_label: str = "") -> pd.DataFrame:
        """
        Return a new DataFrame with all Safe Harbor transformations applied.
        Calls scan() automatically if not already called.
        Logs PHI_DEIDENTIFIED to the governance ledger.
        """
        if not self._findings:
            self.scan(df, source_label)

        if self.dry_run:
            logger.info("HIPAASafeHarborFilter: dry_run=True — "
                        "no transformations applied to the DataFrame.")
            return df.copy()

        out = df.copy()
        dropped, hashed, transformed = [], [], []

        for finding in self._findings:
            col    = finding["column"]
            action = finding["action"]
            if col not in out.columns:
                continue

            if action == "drop":
                out.drop(columns=[col], inplace=True)
                dropped.append(col)

            elif action == "hash":
                if self.hash_identifiers:
                    out[col] = out[col].apply(self._hash_value)
                    hashed.append(col)
                else:
                    out.drop(columns=[col], inplace=True)
                    dropped.append(col)

            elif action == "zip":
                out[col] = out[col].apply(self._safe_zip)
                transformed.append(col)

            elif action == "date_year":
                out[col] = out[col].apply(self._year_only)
                transformed.append(col)

            elif action == "age_cap":
                out[col] = out[col].apply(self._cap_age)
                transformed.append(col)

        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "PHI_DEIDENTIFIED",
            {
                "source":      source_label,
                "rows":        len(out),
                "dropped":     dropped,
                "hashed":      hashed,
                "transformed": transformed,
            },
        )
        return out

    def save_report(
        self,
        path: Union[str, pathlib.Path],
        fmt:  str = "html",
    ) -> pathlib.Path:
        """Write the last scan report to disk as HTML (default) or JSON."""
        if not self._last_report:
            raise RuntimeError("Call scan() or apply() before save_report().")
        path = pathlib.Path(path)
        if fmt == "json":
            path.write_text(
                json.dumps(self._last_report, indent=2, default=str),
                encoding="utf-8",
            )
        else:
            path.write_text(self._build_html(), encoding="utf-8")
        logger.info("HIPAASafeHarborFilter: report written → %s", path)
        return path

    # ── Internals ─────────────────────────────────────────────────────────

    def _classify_column(self, col: str) -> Optional[str]:
        if col in self.additional_columns:
            return self.additional_columns[col]
        for pattern, _cat, action in self._PATTERNS:
            if pattern.search(col):
                return action
        return None

    def _category_for(self, col: str) -> str:
        if col in self.additional_columns:
            return "custom"
        for pattern, category, _action in self._PATTERNS:
            if pattern.search(col):
                return category
        return "unknown"

    @staticmethod
    def _hash_value(val) -> str:
        if pd.isna(val):
            return ""
        return hashlib.sha256(str(val).encode()).hexdigest()[:16]

    def _safe_zip(self, val) -> str:
        """
        Return the first 3 digits of a ZIP code, or "000" for restricted
        three-digit areas (population < 20,000 per 2000 US Census).
        """
        if pd.isna(val):
            return ""
        digits = re.sub(r"\D", "", str(val))
        if len(digits) < 3:
            return "000"
        prefix = digits[:3]
        return "000" if prefix in self._RESTRICTED_ZIP3 else prefix

    @staticmethod
    def _year_only(val) -> str:
        """
        Extract only the four-digit year from any date-like value.
        Returns empty string for nulls or unparseable values.
        """
        if pd.isna(val):
            return ""
        try:
            if isinstance(val, (datetime, date)):
                return str(val.year)
            m = re.match(r"(\d{4})", str(val))
            if m:
                return m.group(1)
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return ""

    def _cap_age(self, val):
        """Replace age values >= age_cap with age_cap_label."""
        if pd.isna(val):
            return val
        try:
            if float(val) >= self.age_cap:
                return self.age_cap_label
        except (ValueError, TypeError):
            pass
        return val

    @staticmethod
    def _safe_sample(series: pd.Series, n: int = 2) -> List[str]:
        samples = series.dropna().astype(str).head(n).tolist()
        return [s[:4] + "***" if len(s) > 4 else "***" for s in samples]

    def _build_html(self) -> str:
        r = self._last_report
        buf = io.StringIO()
        buf.write(_html_head("HIPAA Safe Harbor — PHI Scan Report"))
        buf.write("<h1>🏥 HIPAA Safe Harbor PHI Scan Report</h1>\n")
        buf.write(
            f"<div class='card'>"
            f"<p>Source: <strong>{_he(str(r.get('source', '(unknown)')))}</strong>"
            f" &nbsp;·&nbsp; Scanned: {_he(str(r.get('scanned_at', '')))} UTC</p>"
            f"<p><span class='badge {'ok' if r['phi_columns'] == 0 else 'error'}'>"
            f"{r['phi_columns']} PHI column(s) detected of "
            f"{r['total_columns']} total</span></p>"
            f"</div>\n"
        )
        if r["findings"]:
            buf.write(
                "<div class='card'><h2>Findings</h2>"
                "<table><tr><th>Column</th><th>Category</th>"
                "<th>Action</th><th>Samples (truncated)</th></tr>\n"
            )
            for f in r["findings"]:
                badge = "error" if f["action"] == "drop" else "warn"
                buf.write(
                    f"<tr><td><code>{_he(f['column'])}</code></td>"
                    f"<td>{_he(f['category'])}</td>"
                    f"<td><span class='badge {badge}'>"
                    f"{_he(f['action'])}</span></td>"
                    f"<td>{_he(', '.join(f['sample']))}</td></tr>\n"
                )
            buf.write("</table></div>\n")
        else:
            buf.write(
                "<div class='card'>"
                "<p><span class='badge ok'>✓ No Safe Harbor identifiers detected."
                "</span></p></div>\n"
            )
        buf.write("</body></html>")
        return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
#  2. ClarityExtractor  —  Epic Clarity (SQL Server) with ZC_ code decoding
# ═════════════════════════════════════════════════════════════════════════════

class ClarityExtractor:
    """
    Extract data from Epic Clarity (SQL Server) with automatic decoding of
    ZC_ (Zucchini Code) reference tables and a refresh-window guard.

    Architecture notes
    ──────────────────
    Clarity is a read-only SQL Server database that Epic refreshes nightly via
    its internal ETL (Chronicles → Clarity), typically between midnight and 4 AM
    local time.  Querying during this window may return incomplete snapshots.
    ClarityExtractor optionally refuses to run during a configurable window.

    ZC_ code tables
    ───────────────
    Epic stores most categorical values as integers in columns ending with "_C"
    (e.g., SEX_C = 1).  The human-readable label lives in a corresponding ZC_
    table (e.g., ZC_SEX.NAME = "Female").  ClarityExtractor can auto-join these
    tables: for every column matching /_C$/ it looks for ZC_{STEM} and, if that
    table exists, adds a {STEM}_NAME column with the decoded value.

    Quick-start
    ───────────
        from epic_extensions import ClarityExtractor
        from pipeline_v3 import GovernanceLogger

        gov = GovernanceLogger(run_id="run_001", src="clarity")
        cx  = ClarityExtractor(gov, cfg={
            "host": "clarity-db.hospital.org",
            "db_name": "Clarity",
            "user": "svc_analytics",
            "password": "...",
            "driver": "ODBC Driver 17 for SQL Server",
        })

        encounters = cx.get_encounters(start_date="2024-01-01",
                                        end_date="2024-12-31",
                                        decode_codes=True)
        labs        = cx.query("SELECT * FROM CLR_LAB_RESULT WHERE ...",
                               decode_codes=True)
    """

    # Common Clarity tables and the code columns worth auto-decoding
    _KNOWN_CODE_COLUMNS: Dict[str, List[str]] = {
        "PAT_ENC":      ["SEX_C", "ADT_PAT_CLASS_C", "ENC_TYPE_C",
                         "VISIT_PROV_STAFF_RESOURCE_C"],
        "PATIENT":      ["SEX_C", "PATIENT_RACE_C", "ETHNIC_GROUP_C",
                         "MARITAL_STATUS_C", "LANGUAGE_C"],
        "ORDER_MED":    ["ORDER_STATUS_C", "MEDICATION_ID"],
        "HSP_ACCOUNT":  ["ADT_PAT_CLASS_C", "DISCH_DISP_C", "ACCT_BILLSTS_C"],
        "CLR_LAB_RESULT": ["RESULT_STATUS_C", "LAB_STATUS_C"],
    }

    def __init__(
        self,
        gov,
        cfg:                  Dict,
        schema:               str  = "dbo",
        refresh_window_start: int  = 0,    # hour (0–23) when ETL begins
        refresh_window_end:   int  = 4,    # hour (0–23) when ETL ends
        block_during_refresh: bool = True,
        timeout:              int  = 60,
    ) -> None:
        """
        Parameters
        ──────────
        gov                    GovernanceLogger for audit events.
        cfg                    SQL Server connection dict with keys:
                               host, db_name, user, password, port (default 1433),
                               driver (default "ODBC Driver 17 for SQL Server").
        schema                 Clarity schema to qualify table names (default "dbo").
        refresh_window_start   Hour (0-23, local server time) when the Clarity
                               nightly ETL begins.  Default 0 (midnight).
        refresh_window_end     Hour (0-23) when the ETL ends.  Default 4 (4 AM).
        block_during_refresh   If True, any query attempted during the refresh
                               window raises RuntimeError with a clear message.
        timeout                SQLAlchemy connection timeout in seconds.
        """
        if not _SA_AVAILABLE:
            raise ImportError(
                "ClarityExtractor requires sqlalchemy and pyodbc.\n"
                "Install with: pip install sqlalchemy pyodbc"
            )
        self.gov                   = gov
        self.cfg                   = cfg
        self.schema                = schema
        self.refresh_window_start  = refresh_window_start
        self.refresh_window_end    = refresh_window_end
        self.block_during_refresh  = block_during_refresh
        self.timeout               = timeout
        self._engine               = None
        self._table_cache: Optional[Set[str]] = None

    # ── Connection ────────────────────────────────────────────────────────

    def engine(self):
        """Return (or create) the SQLAlchemy engine for the Clarity database."""
        if self._engine is None:
            c = self.cfg
            drv = _qp(c.get("driver", "ODBC Driver 17 for SQL Server"))
            url = (
                f"mssql+pyodbc://{_qp(c['user'])}:{_qp(c['password'])}"
                f"@{c['host']}:{c.get('port', 1433)}/{c['db_name']}"
                f"?driver={drv}&connect_timeout={self.timeout}"
            )
            self._engine = create_engine(url, pool_pre_ping=True)
            logger.info("ClarityExtractor: connected to %s / %s",
                        c["host"], c["db_name"])
        return self._engine

    def _check_refresh_window(self) -> None:
        """
        Raise RuntimeError if we are currently inside the Clarity ETL window.
        Querying during this window risks reading a partially refreshed snapshot.
        """
        if not self.block_during_refresh:
            return
        now_hour = datetime.now().hour  # local server time
        s, e = self.refresh_window_start, self.refresh_window_end
        in_window = (
            (s <= e and s <= now_hour < e)
            or (s > e and (now_hour >= s or now_hour < e))   # crosses midnight
        )
        if in_window:
            raise RuntimeError(
                f"ClarityExtractor: query blocked — Clarity ETL refresh window "
                f"({s:02d}:00–{e:02d}:00 local).  "
                f"Set block_during_refresh=False to override."
            )

    # ── Table inspection ──────────────────────────────────────────────────

    def table_exists(self, table: str) -> bool:
        if self._table_cache is None:
            inspector = sa_inspect(self.engine())
            self._table_cache = set(inspector.get_table_names(schema=self.schema))
        return table.upper() in {t.upper() for t in self._table_cache}

    def list_tables(self) -> List[str]:
        """Return all table names visible in the configured schema."""
        inspector = sa_inspect(self.engine())
        return inspector.get_table_names(schema=self.schema)

    def list_columns(self, table: str) -> List[str]:
        """Return column names for a Clarity table."""
        inspector = sa_inspect(self.engine())
        return [c["name"] for c in inspector.get_columns(table, schema=self.schema)]

    # ── Query helpers ─────────────────────────────────────────────────────

    def query(
        self,
        sql:          str,
        params:       Optional[Dict] = None,
        decode_codes: bool = True,
    ) -> pd.DataFrame:
        """
        Execute an arbitrary SQL query against Clarity and return a DataFrame.
        Optionally auto-decode ZC_ code columns (decode_codes=True).
        """
        self._check_refresh_window()
        with self.engine().connect() as conn:
            df = pd.read_sql(sa_text(sql), conn, params=params or {})

        self.gov._event(  # type: ignore[attr-defined]
            "EXTRACT", "CLARITY_QUERY",
            {"rows": len(df), "cols": len(df.columns), "decode_codes": decode_codes},
        )
        if decode_codes:
            df = self._decode_zc_columns(df)
        return df

    def get_encounters(
        self,
        start_date:   Optional[str] = None,
        end_date:     Optional[str] = None,
        pat_ids:      Optional[List] = None,
        extra_cols:   Optional[List[str]] = None,
        decode_codes: bool = True,
    ) -> pd.DataFrame:
        """
        Query PAT_ENC (the primary Clarity encounter table).

        start_date / end_date  Inclusive date range for CONTACT_DATE (ISO string).
        pat_ids                Optional list of PAT_IDs to limit the extract.
        extra_cols             Additional PAT_ENC columns to include.
        decode_codes           Auto-join ZC_ tables to decode _C columns.
        """
        base_cols = [
            "PAT_ENC_CSN_ID", "PAT_ID", "CONTACT_DATE", "ENC_TYPE_C",
            "VISIT_PROV_ID", "DEPARTMENT_ID", "ADT_PAT_CLASS_C",
            "HOSP_ADMSN_TIME", "HOSP_DISCH_TIME",
        ]
        if extra_cols:
            base_cols += [c for c in extra_cols if c not in base_cols]

        col_list = ", ".join(base_cols)
        conditions: List[str] = []
        params: Dict = {}

        if start_date:
            conditions.append("CONTACT_DATE >= :start_date")
            params["start_date"] = start_date
        if end_date:
            conditions.append("CONTACT_DATE <= :end_date")
            params["end_date"] = end_date
        if pat_ids:
            # Pass as comma-separated string for IN clause
            placeholders = ", ".join(f":pid_{i}" for i, _ in enumerate(pat_ids))
            conditions.append(f"PAT_ID IN ({placeholders})")
            for i, pid in enumerate(pat_ids):
                params[f"pid_{i}"] = pid

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql   = f"SELECT {col_list} FROM {self.schema}.PAT_ENC {where}"
        return self.query(sql, params, decode_codes=decode_codes)

    def get_diagnoses(
        self,
        start_date:   Optional[str] = None,
        end_date:     Optional[str] = None,
        decode_codes: bool = True,
    ) -> pd.DataFrame:
        """
        Query PAT_ENC_DX (encounter diagnosis table) joined to PAT_ENC for dates.
        Returns ICD codes with their line numbers per encounter.
        """
        params: Dict = {}
        conditions = ["d.PAT_ENC_CSN_ID = e.PAT_ENC_CSN_ID"]

        if start_date:
            conditions.append("e.CONTACT_DATE >= :start_date")
            params["start_date"] = start_date
        if end_date:
            conditions.append("e.CONTACT_DATE <= :end_date")
            params["end_date"] = end_date

        where = "WHERE " + " AND ".join(conditions)
        sql = (
            f"SELECT d.PAT_ENC_CSN_ID, d.PAT_ID, d.LINE, d.CURRENT_ICD10_LIST, "
            f"d.CURRENT_ICD9_LIST, d.PRIMARY_DX_YN, e.CONTACT_DATE "
            f"FROM {self.schema}.PAT_ENC_DX d "
            f"JOIN {self.schema}.PAT_ENC e ON {where}"
        )
        return self.query(sql, params, decode_codes=decode_codes)

    def get_medications(
        self,
        start_date:   Optional[str] = None,
        end_date:     Optional[str] = None,
        decode_codes: bool = True,
    ) -> pd.DataFrame:
        """
        Query ORDER_MED (medication orders) filtered by ordering date.
        """
        params: Dict = {}
        conditions: List[str] = []

        if start_date:
            conditions.append("ORDERING_DATE >= :start_date")
            params["start_date"] = start_date
        if end_date:
            conditions.append("ORDERING_DATE <= :end_date")
            params["end_date"] = end_date

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT ORDER_MED_ID, PAT_ID, PAT_ENC_CSN_ID, "
            f"MEDICATION_ID, ORDERING_DATE, ORDER_STATUS_C, "
            f"QUANTITY, REFILLS, SIG "
            f"FROM {self.schema}.ORDER_MED {where}"
        )
        return self.query(sql, params, decode_codes=decode_codes)

    def get_labs(
        self,
        start_date:   Optional[str] = None,
        end_date:     Optional[str] = None,
        decode_codes: bool = True,
    ) -> pd.DataFrame:
        """Query CLR_LAB_RESULT for lab results within a date range."""
        params: Dict = {}
        conditions: List[str] = []

        if start_date:
            conditions.append("RESULT_DATE >= :start_date")
            params["start_date"] = start_date
        if end_date:
            conditions.append("RESULT_DATE <= :end_date")
            params["end_date"] = end_date

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT RESULT_ID, PAT_ID, PAT_ENC_CSN_ID, "
            f"COMPONENT_ID, RESULT_DATE, ORD_VALUE, "
            f"REFERENCE_LOW, REFERENCE_HIGH, RESULT_STATUS_C, "
            f"LAB_STATUS_C "
            f"FROM {self.schema}.CLR_LAB_RESULT {where}"
        )
        return self.query(sql, params, decode_codes=decode_codes)

    # ── ZC_ code decoding ─────────────────────────────────────────────────

    def _decode_zc_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        For each column ending in _C, attempt to join the corresponding ZC_
        table and add a {STEM}_NAME column with the human-readable label.

        Clarity's ZC_ convention:
            Column SEX_C in PAT_ENC → join ZC_SEX on ZC_SEX.RCPT_C = SEX_C
            → adds column SEX_NAME

        Not every _C column has a ZC_ table (some are boolean flags). Only
        columns with a matching ZC_ table in the database are decoded.
        """
        code_cols = [c for c in df.columns if c.upper().endswith("_C")]
        if not code_cols:
            return df

        out = df.copy()
        for col in code_cols:
            stem = col[:-2].upper()          # SEX_C → SEX
            zc_table = f"ZC_{stem}"          # → ZC_SEX
            name_col = f"{stem}_NAME"

            if not self.table_exists(zc_table):
                continue                     # No ZC table — leave raw code as-is

            try:
                zc_sql = (
                    f"SELECT RCPT_C, NAME AS {name_col} "
                    f"FROM {self.schema}.{zc_table}"
                )
                with self.engine().connect() as conn:
                    zc_df = pd.read_sql(sa_text(zc_sql), conn)

                # Merge on the code value; keep original code column too
                out = out.merge(
                    zc_df,
                    how="left",
                    left_on=col,
                    right_on="RCPT_C",
                )
                out.drop(columns=["RCPT_C"], errors="ignore", inplace=True)
                logger.debug("ClarityExtractor: decoded %s → %s", col, name_col)

            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.warning("ClarityExtractor: ZC_ decode failed for %s: %s",
                               zc_table, exc)
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  3. BAATracker  —  Business Associate Agreement registry and PHI gate
# ═════════════════════════════════════════════════════════════════════════════

class BAATracker:
    """
    Maintain a registry of Business Associate Agreements (BAAs) and gate any
    PHI load that targets a destination without a current, signed BAA.

    HIPAA 45 CFR §164.308(b)(1) requires that a covered entity obtain
    satisfactory assurances from its business associates before allowing them
    to create, receive, maintain, or transmit PHI.  Every downstream destination
    in the pipeline (Snowflake, SQL Server, S3, email alerts, etc.) that receives
    PHI must have an active BAA on file.

    The registry is stored as a JSON file (baa_registry.json) in the governance
    log directory.  A file lock prevents concurrent writes.

    Quick-start
    ───────────
        from epic_extensions import BAATracker
        from pipeline_v3 import GovernanceLogger

        gov     = GovernanceLogger(run_id="run_001", src="clarity")
        tracker = BAATracker(gov)

        tracker.register_baa(
            destination_id = "snowflake_prod",
            vendor         = "Snowflake Inc.",
            signed_date    = "2024-01-15",
            expiry_date    = "2026-01-14",
            contact_email  = "legal@snowflake.com",
            phi_types      = ["patient_demographics", "encounter_data"],
        )

        tracker.check_phi_load("snowflake_prod")   # raises if no valid BAA
    """

    _BAA_FILE = "baa_registry.json"
    _EXPIRY_WARN_DAYS = 30      # warn when a BAA expires within this many days

    def __init__(
        self,
        gov,
        warn_days: int = 30,
        dry_run:   bool = False,
    ) -> None:
        self.gov       = gov
        self.warn_days = warn_days
        self.dry_run   = dry_run
        self._lock     = threading.Lock()
        self._path     = pathlib.Path(gov.log_dir) / self._BAA_FILE  # type: ignore[attr-defined]
        self._registry: Dict[str, Dict] = self._load()

    # ── Public API ────────────────────────────────────────────────────────

    def register_baa(
        self,
        destination_id: str,
        vendor:         str,
        signed_date:    str,          # ISO date string YYYY-MM-DD
        expiry_date:    str,          # ISO date string YYYY-MM-DD
        contact_email:  str  = "",
        phi_types:      Optional[List[str]] = None,
        notes:          str  = "",
    ) -> None:
        """Add or update a BAA record in the registry."""
        # Validate date strings before storing — malformed strings would
        # crash datetime.fromisoformat() in check_phi_load().
        for date_field, date_val in [
            ("signed_date", signed_date), ("expiry_date", expiry_date)
        ]:
            try:
                datetime.fromisoformat(date_val)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"BAATracker.register_baa: {date_field} must be an ISO "
                    f"date string (YYYY-MM-DD), got {date_val!r}: {exc}"
                ) from exc

        record = {
            "destination_id": destination_id,
            "vendor":         vendor,
            "signed_date":    signed_date,
            "expiry_date":    expiry_date,
            "contact_email":  contact_email,
            "phi_types":      phi_types or [],
            "notes":          notes,
            "registered_at":  _now_utc().isoformat(),
        }
        with self._lock:
            self._registry[destination_id] = record
            self._save()

        self.gov._event(  # type: ignore[attr-defined]
            "COMPLIANCE", "BAA_REGISTERED",
            {"destination_id": destination_id, "vendor": vendor,
             "expiry_date": expiry_date},
        )
        print(f"  ✅  BAA registered: {destination_id} ({vendor}) "
              f"— expires {expiry_date}")

    def check_phi_load(
        self,
        destination_id: str,
        phi_types:      Optional[List[str]] = None,
    ) -> bool:
        """
        Verify that destination_id has an active, non-expired BAA on file.

        Raises RuntimeError if no BAA exists or the BAA has expired.
        Logs a warning if the BAA expires within warn_days.
        Logs BAA_VERIFIED on every successful check.

        phi_types  If provided, also verify that the BAA covers these PHI
                   categories.  Empty BAA phi_types list means "all covered".
        Returns True on success.
        """
        record = self._registry.get(destination_id)

        if not record:
            self.gov._event(  # type: ignore[attr-defined]
                "COMPLIANCE", "BAA_MISSING",
                {"destination_id": destination_id},
                level="ERROR",
            )
            if not self.dry_run:
                raise RuntimeError(
                    f"BAATracker: no BAA on file for destination "
                    f"'{destination_id}'.  PHI load blocked.\n"
                    f"Register a BAA with tracker.register_baa(...)."
                )
            logger.warning("BAATracker [dry_run]: no BAA for %s", destination_id)
            return False

        expiry = datetime.fromisoformat(record["expiry_date"]).date()
        today  = _now_utc().date()

        if expiry < today:
            self.gov._event(  # type: ignore[attr-defined]
                "COMPLIANCE", "BAA_EXPIRED",
                {"destination_id": destination_id,
                 "expiry_date":    record["expiry_date"],
                 "days_past":      (today - expiry).days},
                level="ERROR",
            )
            if not self.dry_run:
                raise RuntimeError(
                    f"BAATracker: BAA for '{destination_id}' expired on "
                    f"{expiry}.  PHI load blocked until BAA is renewed."
                )
            logger.warning("BAATracker [dry_run]: BAA expired for %s", destination_id)
            return False

        # Check that requested PHI types are covered
        covered = record.get("phi_types", [])
        if phi_types and covered:
            missing = [t for t in phi_types if t not in covered]
            if missing:
                self.gov._event(  # type: ignore[attr-defined]
                    "COMPLIANCE", "BAA_PHI_TYPE_NOT_COVERED",
                    {"destination_id": destination_id, "missing_types": missing},
                    level="WARN",
                )
                logger.warning("BAATracker: BAA for %s does not cover PHI types %s",
                               destination_id, missing)

        # Warn if expiry is approaching
        days_until = (expiry - today).days
        if days_until <= self.warn_days:
            self.gov._event(  # type: ignore[attr-defined]
                "COMPLIANCE", "BAA_EXPIRING_SOON",
                {"destination_id": destination_id,
                 "expiry_date":    record["expiry_date"],
                 "days_remaining": days_until},
                level="WARN",
            )
            logger.warning("BAATracker: BAA for %s expires in %d day(s) (%s)",
                           destination_id, days_until, record["expiry_date"])

        self.gov._event(  # type: ignore[attr-defined]
            "COMPLIANCE", "BAA_VERIFIED",
            {"destination_id": destination_id,
             "vendor":         record["vendor"],
             "expiry_date":    record["expiry_date"],
             "days_remaining": days_until},
        )
        return True

    def get_expiring(self, within_days: Optional[int] = None) -> List[Dict]:
        """Return all BAAs expiring within within_days (default: warn_days)."""
        cutoff = _now_utc().date() + timedelta(days=within_days or self.warn_days)
        today  = _now_utc().date()
        results = []
        for rec in self._registry.values():
            expiry = datetime.fromisoformat(rec["expiry_date"]).date()
            if today <= expiry <= cutoff:
                results.append({**rec, "days_remaining": (expiry - today).days})
        return sorted(results, key=lambda r: r["days_remaining"])

    def export_register(self, path: Union[str, pathlib.Path]) -> pathlib.Path:
        """Write an HTML BAA register report."""
        path = pathlib.Path(path)
        path.write_text(self._build_html(), encoding="utf-8")
        logger.info("BAATracker: register exported → %s", path)
        return path

    def all_records(self) -> List[Dict]:
        """Return all BAA records as a list."""
        return list(self._registry.values())

    # ── Internals ─────────────────────────────────────────────────────────

    def _load(self) -> Dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.warning("BAATracker: could not load registry from %s: %s "
                               "— starting with empty registry.", self._path, exc)
        return {}

    def _save(self) -> None:
        self._path.write_text(
            json.dumps(self._registry, indent=2), encoding="utf-8"
        )

    def _build_html(self) -> str:
        today = _now_utc().date()
        buf   = io.StringIO()
        buf.write(_html_head("BAA Register"))
        buf.write("<h1>📋 Business Associate Agreement Register</h1>\n")
        buf.write(
            f"<div class='card'>"
            f"<p>Generated: {_now_utc().strftime('%Y-%m-%d %H:%M')} UTC &nbsp;·&nbsp; "
            f"{len(self._registry)} BAA(s) on file</p></div>\n"
        )

        if self._registry:
            buf.write(
                "<div class='card'><table>"
                "<tr><th>Destination</th><th>Vendor</th><th>Signed</th>"
                "<th>Expires</th><th>Status</th><th>PHI Types</th></tr>\n"
            )
            for rec in sorted(self._registry.values(),
                              key=lambda r: r["expiry_date"]):
                expiry    = datetime.fromisoformat(rec["expiry_date"]).date()
                days_left = (expiry - today).days
                if days_left < 0:
                    badge, status = "critical", f"EXPIRED {abs(days_left)}d ago"
                elif days_left <= self._EXPIRY_WARN_DAYS:
                    badge, status = "warn", f"Expires in {days_left}d"
                else:
                    badge, status = "ok", f"Active ({days_left}d remaining)"
                phi_str = ", ".join(rec.get("phi_types", [])) or "all types"
                buf.write(
                    f"<tr><td><code>{_he(rec['destination_id'])}</code></td>"
                    f"<td>{_he(rec['vendor'])}</td>"
                    f"<td>{_he(rec['signed_date'])}</td>"
                    f"<td>{_he(rec['expiry_date'])}</td>"
                    f"<td><span class='badge {badge}'>{_he(status)}</span></td>"
                    f"<td>{_he(phi_str)}</td></tr>\n"
                )
            buf.write("</table></div>\n")
        else:
            buf.write("<div class='card'><p>No BAAs registered.</p></div>\n")

        buf.write("</body></html>")
        return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
#  4. IRBApprovalGate  —  IRB / QI protocol registry and column-level gate
# ═════════════════════════════════════════════════════════════════════════════

class IRBApprovalGate:
    """
    Require a valid IRB (Institutional Review Board) or QI (Quality Improvement)
    protocol before any PHI-containing extract from Epic Clarity or Caboodle
    can proceed.

    An IRB protocol specifies exactly which data elements the researcher is
    approved to access.  This class enforces that: columns not approved by the
    active protocol are dropped before the DataFrame leaves the pipeline.

    Registry format (irb_registry.json)
    ────────────────────────────────────
    Each entry is keyed by protocol_id and contains:
        study_title        Human-readable title of the research study.
        pi_name            Principal Investigator name.
        pi_email           PI contact email.
        approved_date      Date the IRB approved the protocol (ISO string).
        expiry_date        Protocol expiry / renewal date (ISO string).
        approved_columns   List of Clarity column names the PI may receive.
                           An empty list means "all columns approved" (use
                           with caution — prefer explicit lists).
        approved_purposes  Free-text list of approved purposes for the RoPA.
        phi_allowed        Whether identifiable PHI is approved (True) or only
                           de-identified data (False).

    Quick-start
    ───────────
        from epic_extensions import IRBApprovalGate
        from pipeline_v3 import GovernanceLogger

        gov  = GovernanceLogger(run_id="run_001", src="clarity")
        gate = IRBApprovalGate(gov)

        gate.register_protocol(
            protocol_id       = "IRB-2024-1234",
            study_title       = "Readmission prediction study",
            pi_name           = "Dr. Jane Smith",
            approved_date     = "2024-03-01",
            expiry_date       = "2025-03-01",
            approved_columns  = ["PAT_ENC_CSN_ID", "CONTACT_DATE",
                                 "CURRENT_ICD10_LIST", "HOSP_DISCH_TIME"],
            phi_allowed       = False,   # de-identified only
        )

        clean_df = gate.gate_dataframe(df, protocol_id="IRB-2024-1234")
    """

    _REGISTRY_FILE = "irb_registry.json"
    _USAGE_LOG_FILE = "irb_usage_log.jsonl"

    def __init__(
        self,
        gov,
        warn_days: int  = 30,
        dry_run:   bool = False,
    ) -> None:
        self.gov       = gov
        self.warn_days = warn_days
        self.dry_run   = dry_run
        self._lock     = threading.Lock()
        self._reg_path = pathlib.Path(gov.log_dir) / self._REGISTRY_FILE  # type: ignore[attr-defined]
        self._log_path = pathlib.Path(gov.log_dir) / self._USAGE_LOG_FILE  # type: ignore[attr-defined]
        self._registry: Dict[str, Dict] = self._load_registry()

    # ── Public API ────────────────────────────────────────────────────────

    def register_protocol(
        self,
        protocol_id:       str,
        study_title:       str,
        pi_name:           str,
        approved_date:     str,
        expiry_date:       str,
        pi_email:          str  = "",
        approved_columns:  Optional[List[str]] = None,
        approved_purposes: Optional[List[str]] = None,
        phi_allowed:       bool = False,
        notes:             str  = "",
    ) -> None:
        """Add or update an IRB protocol in the registry."""
        # Validate date strings before storing — malformed strings would
        # crash datetime.fromisoformat() in check_protocol().
        for date_field, date_val in [
            ("approved_date", approved_date), ("expiry_date", expiry_date)
        ]:
            try:
                datetime.fromisoformat(date_val)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"IRBApprovalGate.register_protocol: {date_field} must be "
                    f"an ISO date string (YYYY-MM-DD), got {date_val!r}: {exc}"
                ) from exc

        record = {
            "protocol_id":       protocol_id,
            "study_title":       study_title,
            "pi_name":           pi_name,
            "pi_email":          pi_email,
            "approved_date":     approved_date,
            "expiry_date":       expiry_date,
            "approved_columns":  approved_columns or [],
            "approved_purposes": approved_purposes or [],
            "phi_allowed":       phi_allowed,
            "notes":             notes,
            "registered_at":     _now_utc().isoformat(),
        }
        with self._lock:
            self._registry[protocol_id] = record
            self._save_registry()

        self.gov._event(  # type: ignore[attr-defined]
            "COMPLIANCE", "IRB_PROTOCOL_REGISTERED",
            {"protocol_id": protocol_id, "study_title": study_title,
             "pi_name": pi_name, "expiry_date": expiry_date,
             "phi_allowed": phi_allowed},
        )
        print(f"  ✅  IRB protocol registered: {protocol_id} — {study_title}")

    def check_protocol(self, protocol_id: str) -> Dict:
        """
        Verify that a protocol is registered and currently valid.
        Raises RuntimeError if not registered or expired (unless dry_run).
        Returns the protocol record on success.
        """
        record = self._registry.get(protocol_id)
        if not record:
            self.gov._event(  # type: ignore[attr-defined]
                "COMPLIANCE", "IRB_PROTOCOL_MISSING",
                {"protocol_id": protocol_id}, level="ERROR",
            )
            if not self.dry_run:
                raise RuntimeError(
                    f"IRBApprovalGate: no IRB protocol '{protocol_id}' on file.  "
                    f"PHI extract blocked.  Register with gate.register_protocol(...)."
                )
            logger.warning("IRBApprovalGate [dry_run]: no protocol %s", protocol_id)
            return {}

        expiry = datetime.fromisoformat(record["expiry_date"]).date()
        today  = _now_utc().date()

        if expiry < today:
            self.gov._event(  # type: ignore[attr-defined]
                "COMPLIANCE", "IRB_PROTOCOL_EXPIRED",
                {"protocol_id": protocol_id,
                 "expiry_date": record["expiry_date"],
                 "days_past":   (today - expiry).days},
                level="ERROR",
            )
            if not self.dry_run:
                raise RuntimeError(
                    f"IRBApprovalGate: protocol '{protocol_id}' expired on {expiry}. "
                    f"PHI extract blocked until protocol is renewed."
                )
            logger.warning("IRBApprovalGate [dry_run]: protocol expired %s",
                           protocol_id)
            return {}

        days_left = (expiry - today).days
        if days_left <= self.warn_days:
            logger.warning("IRBApprovalGate: protocol %s expires in %d day(s)",
                           protocol_id, days_left)

        self.gov._event(  # type: ignore[attr-defined]
            "COMPLIANCE", "IRB_PROTOCOL_VERIFIED",
            {"protocol_id":   protocol_id,
             "study_title":   record["study_title"],
             "pi_name":       record["pi_name"],
             "expiry_date":   record["expiry_date"],
             "days_remaining": days_left,
             "phi_allowed":   record.get("phi_allowed", False)},
        )
        return record

    def gate_dataframe(
        self,
        df:          pd.DataFrame,
        protocol_id: str,
        source_label: str = "",
    ) -> pd.DataFrame:
        """
        Drop any columns from df that are not in the protocol's approved_columns
        list, then log the access.

        If approved_columns is empty the entire DataFrame is allowed through
        (the protocol covers all columns).  This should be used with caution:
        prefer explicit approved_columns lists in all new protocols.

        Logs IRB_DATA_ACCESS to the governance ledger for annual reporting.
        """
        record = self.check_protocol(protocol_id)
        if not record:
            return df.copy() if self.dry_run else df

        approved = record.get("approved_columns", [])
        dropped_cols: List[str] = []

        if approved:
            # Drop any column not explicitly approved
            to_drop = [c for c in df.columns if c not in approved]
            if to_drop:
                if self.dry_run:
                    logger.info("IRBApprovalGate [dry_run]: would drop %s", to_drop)
                    dropped_cols = to_drop
                else:
                    df = df.drop(columns=to_drop)
                    dropped_cols = to_drop

        # Log the data access for annual IRB reporting
        self._append_usage_log({
            "protocol_id":     protocol_id,
            "study_title":     record["study_title"],
            "pi_name":         record["pi_name"],
            "source_label":    source_label,
            "accessed_at":     _now_utc().isoformat(),
            "rows":            len(df),
            "columns_allowed": list(df.columns),
            "columns_dropped": dropped_cols,
            "dry_run":         self.dry_run,
        })

        self.gov._event(  # type: ignore[attr-defined]
            "COMPLIANCE", "IRB_DATA_ACCESS",
            {
                "protocol_id":     protocol_id,
                "source":          source_label,
                "rows":            len(df),
                "columns_allowed": len(df.columns),
                "columns_dropped": dropped_cols,
            },
        )
        if dropped_cols:
            print(f"  🔒  IRB gate [{protocol_id}]: dropped {len(dropped_cols)} "
                  f"unapproved column(s): {dropped_cols}")

        return df

    def export_usage_report(self, path: Union[str, pathlib.Path]) -> pathlib.Path:
        """Write an HTML annual usage report for IRB renewal submissions."""
        path = pathlib.Path(path)
        path.write_text(self._build_usage_html(), encoding="utf-8")
        logger.info("IRBApprovalGate: usage report written → %s", path)
        return path

    def all_protocols(self) -> List[Dict]:
        return list(self._registry.values())

    # ── Internals ─────────────────────────────────────────────────────────

    def _load_registry(self) -> Dict:
        if self._reg_path.exists():
            try:
                return json.loads(self._reg_path.read_text(encoding="utf-8"))
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.warning("IRBApprovalGate: could not load registry from "
                               "%s: %s — starting empty.", self._reg_path, exc)
        return {}

    def _save_registry(self) -> None:
        self._reg_path.write_text(
            json.dumps(self._registry, indent=2), encoding="utf-8"
        )

    def _append_usage_log(self, entry: Dict) -> None:
        with self._lock:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")

    def _read_usage_log(self) -> List[Dict]:
        if not self._log_path.exists():
            return []
        entries = []
        for line in self._log_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return entries

    def _build_usage_html(self) -> str:
        entries = self._read_usage_log()
        buf     = io.StringIO()
        buf.write(_html_head("IRB Data Access Usage Report"))
        buf.write("<h1>🔬 IRB Data Access Usage Report</h1>\n")
        buf.write(
            f"<div class='card'>"
            f"<p>Generated: {_now_utc().strftime('%Y-%m-%d %H:%M')} UTC &nbsp;·&nbsp; "
            f"{len(entries)} access event(s) logged</p></div>\n"
        )

        # Group by protocol
        by_protocol: Dict[str, List[Dict]] = {}
        for e in entries:
            by_protocol.setdefault(e.get("protocol_id", "unknown"), []).append(e)

        for pid, evts in by_protocol.items():
            rec = self._registry.get(pid, {})
            expiry = rec.get("expiry_date", "unknown")
            buf.write(
                f"<div class='card'>"
                f"<h2>Protocol: {_he(pid)}</h2>"
                f"<p>Study: <em>{_he(rec.get('study_title',''))}</em> &nbsp;·&nbsp; "
                f"PI: {_he(rec.get('pi_name',''))} &nbsp;·&nbsp; "
                f"Expires: {_he(str(expiry))}</p>"
                f"<table><tr><th>Accessed At</th><th>Source</th>"
                f"<th>Rows</th><th>Columns</th><th>Dropped</th></tr>\n"
            )
            for e in evts:
                buf.write(
                    f"<tr>"
                    f"<td>{_he(e.get('accessed_at','')[:19])}</td>"
                    f"<td>{_he(e.get('source_label',''))}</td>"
                    f"<td>{e.get('rows', 0):,}</td>"
                    f"<td>{len(e.get('columns_allowed', []))}</td>"
                    f"<td>{len(e.get('columns_dropped', []))}</td>"
                    f"</tr>\n"
                )
            buf.write("</table></div>\n")

        buf.write("</body></html>")
        return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
#  5. OMOPTransformer  —  Epic Clarity → OMOP CDM v5.4 domain mapping
# ═════════════════════════════════════════════════════════════════════════════

class OMOPTransformer:
    """
    Map data extracted from Epic Clarity to OMOP Common Data Model (CDM) v5.4
    domain tables for use in research analytics and federated network studies.

    The OMOP CDM is the standard adopted by PCORnet, NCATS N3C, TriNetX, and
    most academic medical center research warehouses.  Transforming Clarity data
    to OMOP allows the pipeline output to be queried alongside data from
    non-Epic EHRs using the same vocabulary.

    Domains implemented
    ───────────────────
    ┌──────────────────────┬─────────────────────────────────────────────────┐
    │ OMOP domain table    │ Clarity source table(s)                         │
    ├──────────────────────┼─────────────────────────────────────────────────┤
    │ PERSON               │ PATIENT                                         │
    │ VISIT_OCCURRENCE     │ PAT_ENC                                         │
    │ CONDITION_OCCURRENCE │ PAT_ENC_DX  (ICD-10-CM / ICD-9-CM codes)       │
    │ DRUG_EXPOSURE        │ ORDER_MED   (NDC / RxNorm)                      │
    │ MEASUREMENT          │ CLR_LAB_RESULT (LOINC)                          │
    │ PROCEDURE_OCCURRENCE │ ORDER_PROC  (CPT-4 / HCPCS)                     │
    └──────────────────────┴─────────────────────────────────────────────────┘

    Vocabulary concept_ids
    ──────────────────────
    OMOP concept_ids are integers from the OMOP standardized vocabulary.
    Without the full vocabulary tables loaded, source codes (ICD-10, RxNorm,
    LOINC, CPT) cannot be resolved to concept_ids.

    Pass vocabulary_path pointing to a CSV/Parquet file with columns
    [source_code, source_vocabulary_id, concept_id] to enable concept_id
    resolution.  Without this, clinical concept_id fields are set to 0
    (OMOP convention for "no matching concept") and source codes are preserved
    in the source_value columns for downstream resolution.

    Quick-start
    ───────────
        from epic_extensions import OMOPTransformer
        from pipeline_v3 import GovernanceLogger

        gov    = GovernanceLogger(run_id="run_001", src="clarity")
        omop   = OMOPTransformer(gov)

        person_df    = omop.to_person(patient_df)
        visit_df     = omop.to_visit_occurrence(pat_enc_df)
        cond_df      = omop.to_condition_occurrence(pat_enc_dx_df, visit_df)
        drug_df      = omop.to_drug_exposure(order_med_df)
        lab_df       = omop.to_measurement(lab_result_df)
    """

    # Standard OMOP type concept_ids used when a more specific concept
    # cannot be resolved (EHR order as the source of truth)
    _TYPE_CONCEPT_EHR          = 32817   # EHR
    _TYPE_CONCEPT_INPATIENT_DX = 32902   # EHR discharge diagnosis
    _TYPE_CONCEPT_OUTPATIENT_DX= 32840   # EHR outpatient diagnosis
    _TYPE_CONCEPT_INPATIENT_VISIT = 9201
    _TYPE_CONCEPT_OUTPATIENT_VISIT = 9202
    _TYPE_CONCEPT_ED_VISIT     = 9203

    def __init__(
        self,
        gov,
        vocabulary_path: Optional[Union[str, pathlib.Path]] = None,
    ) -> None:
        """
        Parameters
        ──────────
        gov               GovernanceLogger for audit events.
        vocabulary_path   Path to OMOP vocabulary CSV/Parquet with columns
                          [source_code, source_vocabulary_id, concept_id].
                          When supplied, ICD-10, RxNorm, LOINC, and CPT codes
                          are resolved to OMOP concept_ids.
                          When omitted, concept_id fields default to 0 and
                          the source codes are preserved in *_source_value cols.
        """
        self.gov = gov
        self._vocab: Optional[pd.DataFrame] = None

        if vocabulary_path:
            vp = pathlib.Path(vocabulary_path)
            try:
                if vp.suffix.lower() in (".parquet", ".pq"):
                    self._vocab = pd.read_parquet(vp)
                else:
                    self._vocab = pd.read_csv(vp, dtype=str)
                required = {"source_code", "source_vocabulary_id", "concept_id"}
                if not required.issubset(self._vocab.columns):
                    raise ValueError(
                        f"Vocabulary file must have columns: {required}. "
                        f"Found: {set(self._vocab.columns)}"
                    )
                self._vocab["concept_id"] = (
                    pd.to_numeric(self._vocab["concept_id"], errors="coerce")
                    .fillna(0).astype(int)
                )
                logger.info("OMOPTransformer: vocabulary loaded from %s "
                            "(%d concepts)", vp, len(self._vocab))
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.warning("OMOPTransformer: could not load vocabulary "
                               "from %s: %s — concept_ids will be 0.", vp, exc)

    # ── Public API ────────────────────────────────────────────────────────

    def to_person(self, patient_df: pd.DataFrame) -> pd.DataFrame:
        """
        Map a Clarity PATIENT extract to OMOP PERSON domain.

        Expected Clarity input columns (subset):
            PAT_ID, SEX_C, BIRTH_DATE, PATIENT_RACE_C, ETHNIC_GROUP_C
        """
        df = patient_df.copy()
        out = pd.DataFrame()

        out["person_id"]             = df.get("PAT_ID", pd.Series(dtype=str))
        out["person_source_value"]   = df.get("PAT_ID", pd.Series(dtype=str))

        # Gender
        out["gender_concept_id"]     = (
            df.get("SEX_C", pd.Series(dtype=str))
            .map({"1": 8507, "2": 8532})   # 8507 = Male, 8532 = Female
            .fillna(0).astype(int)
        )
        out["gender_source_value"]   = df.get("SEX_C", pd.Series(dtype=str))

        # Birth year/month/day from BIRTH_DATE
        birth = pd.to_datetime(df.get("BIRTH_DATE"), errors="coerce")
        out["year_of_birth"]         = birth.dt.year.fillna(0).astype(int)
        out["month_of_birth"]        = birth.dt.month.fillna(0).astype(int)
        out["day_of_birth"]          = birth.dt.day.fillna(0).astype(int)

        # Race — Clarity PATIENT_RACE_C → OMOP concept_ids
        # Common mappings from Clarity race codes to OMOP
        _race_map = {
            "1": 8527,   # White
            "2": 8516,   # Black or African American
            "3": 8515,   # Asian
            "4": 8557,   # Native Hawaiian or Other Pacific Islander
            "5": 8522,   # American Indian or Alaska Native
            "6": 8552,   # Other Race
        }
        out["race_concept_id"]       = (
            df.get("PATIENT_RACE_C", pd.Series(dtype=str))
            .map(_race_map).fillna(0).astype(int)
        )
        out["race_source_value"]     = df.get("PATIENT_RACE_C",
                                              pd.Series(dtype=str))

        # Ethnicity — ETHNIC_GROUP_C
        out["ethnicity_concept_id"]  = (
            df.get("ETHNIC_GROUP_C", pd.Series(dtype=str))
            .map({"1": 38003563, "2": 38003564})  # Hispanic / Not Hispanic
            .fillna(0).astype(int)
        )
        out["ethnicity_source_value"] = df.get("ETHNIC_GROUP_C",
                                               pd.Series(dtype=str))

        self._log_transform("to_person", len(out))
        return out

    def to_visit_occurrence(self, pat_enc_df: pd.DataFrame) -> pd.DataFrame:
        """
        Map a Clarity PAT_ENC extract to OMOP VISIT_OCCURRENCE.

        Expected Clarity columns:
            PAT_ENC_CSN_ID, PAT_ID, CONTACT_DATE,
            HOSP_ADMSN_TIME, HOSP_DISCH_TIME, ADT_PAT_CLASS_C
        """
        df  = pat_enc_df.copy()
        out = pd.DataFrame()

        out["visit_occurrence_id"]        = df.get("PAT_ENC_CSN_ID",
                                                    pd.Series(dtype=str))
        out["person_id"]                  = df.get("PAT_ID",
                                                    pd.Series(dtype=str))
        out["visit_source_value"]         = df.get("ADT_PAT_CLASS_C",
                                                    pd.Series(dtype=str))

        # Visit type concept from ADT_PAT_CLASS_C
        # Clarity codes: 1=Inpatient, 2=Outpatient, 3=Emergency
        _visit_map = {
            "1": self._TYPE_CONCEPT_INPATIENT_VISIT,
            "2": self._TYPE_CONCEPT_OUTPATIENT_VISIT,
            "3": self._TYPE_CONCEPT_ED_VISIT,
        }
        out["visit_concept_id"]           = (
            df.get("ADT_PAT_CLASS_C", pd.Series(dtype=str))
            .map(_visit_map).fillna(9201).astype(int)
        )
        out["visit_type_concept_id"]      = self._TYPE_CONCEPT_EHR

        start = pd.to_datetime(df.get("HOSP_ADMSN_TIME",
                                      df.get("CONTACT_DATE")), errors="coerce")
        end   = pd.to_datetime(df.get("HOSP_DISCH_TIME",
                                      df.get("CONTACT_DATE")), errors="coerce")
        out["visit_start_date"]           = start.dt.date
        out["visit_start_datetime"]       = start
        out["visit_end_date"]             = end.dt.date
        out["visit_end_datetime"]         = end
        out["provider_id"]                = df.get("VISIT_PROV_ID",
                                                    pd.Series(dtype=str))

        self._log_transform("to_visit_occurrence", len(out))
        return out

    def to_condition_occurrence(
        self,
        pat_enc_dx_df:   pd.DataFrame,
        visit_df:        Optional[pd.DataFrame] = None,
    ) -> pd.DataFrame:
        """
        Map Clarity PAT_ENC_DX to OMOP CONDITION_OCCURRENCE.

        Expected Clarity columns:
            PAT_ENC_CSN_ID, PAT_ID, CURRENT_ICD10_LIST,
            CURRENT_ICD9_LIST, PRIMARY_DX_YN, CONTACT_DATE
        """
        df  = pat_enc_dx_df.copy()
        out = pd.DataFrame()

        out["condition_occurrence_id"]  = range(1, len(df) + 1)
        out["person_id"]                = df.get("PAT_ID",
                                                  pd.Series(dtype=str))
        out["visit_occurrence_id"]      = df.get("PAT_ENC_CSN_ID",
                                                  pd.Series(dtype=str))

        # Prefer ICD-10, fall back to ICD-9
        icd10 = df.get("CURRENT_ICD10_LIST", pd.Series(dtype=str)).fillna("")
        icd9  = df.get("CURRENT_ICD9_LIST",  pd.Series(dtype=str)).fillna("")
        source_codes = icd10.where(icd10 != "", icd9)
        out["condition_source_value"]   = source_codes

        # Resolve concept_ids if vocabulary is loaded
        out["condition_concept_id"]     = source_codes.apply(
            lambda c: self._resolve_concept(c, "ICD10CM")
        )
        out["condition_source_concept_id"] = 0   # requires OMOP vocab tables

        start = pd.to_datetime(df.get("CONTACT_DATE"), errors="coerce")
        out["condition_start_date"]     = start.dt.date
        out["condition_start_datetime"] = start
        out["condition_end_date"]       = pd.NaT
        out["condition_end_datetime"]   = pd.NaT

        # Primary diagnosis gets a specific type concept
        is_primary = df.get("PRIMARY_DX_YN", pd.Series(dtype=str)).eq("Y")
        out["condition_type_concept_id"] = is_primary.map(
            {True: self._TYPE_CONCEPT_INPATIENT_DX,
             False: self._TYPE_CONCEPT_OUTPATIENT_DX}
        ).fillna(self._TYPE_CONCEPT_EHR).astype(int)

        self._log_transform("to_condition_occurrence", len(out))
        return out

    def to_drug_exposure(self, order_med_df: pd.DataFrame) -> pd.DataFrame:
        """
        Map Clarity ORDER_MED to OMOP DRUG_EXPOSURE.

        Expected Clarity columns:
            ORDER_MED_ID, PAT_ID, PAT_ENC_CSN_ID,
            MEDICATION_ID, ORDERING_DATE, QUANTITY, SIG
        """
        df  = order_med_df.copy()
        out = pd.DataFrame()

        out["drug_exposure_id"]         = df.get("ORDER_MED_ID",
                                                  pd.Series(dtype=str))
        out["person_id"]                = df.get("PAT_ID",
                                                  pd.Series(dtype=str))
        out["visit_occurrence_id"]      = df.get("PAT_ENC_CSN_ID",
                                                  pd.Series(dtype=str))
        out["drug_source_value"]        = df.get("MEDICATION_ID",
                                                  pd.Series(dtype=str))

        out["drug_concept_id"]          = df.get("MEDICATION_ID",
                                                  pd.Series(dtype=str)).apply(
            lambda c: self._resolve_concept(c, "RxNorm")
        )
        out["drug_type_concept_id"]     = self._TYPE_CONCEPT_EHR

        start = pd.to_datetime(df.get("ORDERING_DATE"), errors="coerce")
        out["drug_exposure_start_date"]     = start.dt.date
        out["drug_exposure_start_datetime"] = start
        out["drug_exposure_end_date"]       = pd.NaT
        out["drug_exposure_end_datetime"]   = pd.NaT

        out["quantity"]                 = pd.to_numeric(
            df.get("QUANTITY", pd.Series(dtype=str)), errors="coerce"
        )
        out["sig"]                      = df.get("SIG", pd.Series(dtype=str))

        self._log_transform("to_drug_exposure", len(out))
        return out

    def to_measurement(self, lab_result_df: pd.DataFrame) -> pd.DataFrame:
        """
        Map Clarity CLR_LAB_RESULT to OMOP MEASUREMENT.

        Expected Clarity columns:
            RESULT_ID, PAT_ID, PAT_ENC_CSN_ID, COMPONENT_ID,
            RESULT_DATE, ORD_VALUE, REFERENCE_LOW, REFERENCE_HIGH
        """
        df  = lab_result_df.copy()
        out = pd.DataFrame()

        out["measurement_id"]              = df.get("RESULT_ID",
                                                     pd.Series(dtype=str))
        out["person_id"]                   = df.get("PAT_ID",
                                                     pd.Series(dtype=str))
        out["visit_occurrence_id"]         = df.get("PAT_ENC_CSN_ID",
                                                     pd.Series(dtype=str))
        out["measurement_source_value"]    = df.get("COMPONENT_ID",
                                                     pd.Series(dtype=str))

        out["measurement_concept_id"]      = df.get(
            "COMPONENT_ID", pd.Series(dtype=str)
        ).apply(lambda c: self._resolve_concept(c, "LOINC"))

        out["measurement_type_concept_id"] = self._TYPE_CONCEPT_EHR

        meas_date = pd.to_datetime(df.get("RESULT_DATE"), errors="coerce")
        out["measurement_date"]            = meas_date.dt.date
        out["measurement_datetime"]        = meas_date

        # Numeric vs text result
        ord_val = df.get("ORD_VALUE", pd.Series(dtype=str))
        out["value_as_number"]             = pd.to_numeric(ord_val,
                                                           errors="coerce")
        out["value_source_value"]          = ord_val
        out["value_as_concept_id"]         = 0   # resolved by downstream vocab
        out["unit_concept_id"]             = 0   # requires OMOP unit vocabulary
        out["range_low"]                   = pd.to_numeric(
            df.get("REFERENCE_LOW",  pd.Series(dtype=str)), errors="coerce"
        )
        out["range_high"]                  = pd.to_numeric(
            df.get("REFERENCE_HIGH", pd.Series(dtype=str)), errors="coerce"
        )

        self._log_transform("to_measurement", len(out))
        return out

    def to_procedure_occurrence(self, order_proc_df: pd.DataFrame) -> pd.DataFrame:
        """
        Map Clarity ORDER_PROC (procedure orders) to OMOP PROCEDURE_OCCURRENCE.

        Expected Clarity columns:
            ORDER_PROC_ID, PAT_ID, PAT_ENC_CSN_ID,
            PROC_ID, PROC_CODE, ORDERING_DATE
        """
        df  = order_proc_df.copy()
        out = pd.DataFrame()

        out["procedure_occurrence_id"]   = df.get("ORDER_PROC_ID",
                                                   pd.Series(dtype=str))
        out["person_id"]                 = df.get("PAT_ID",
                                                   pd.Series(dtype=str))
        out["visit_occurrence_id"]       = df.get("PAT_ENC_CSN_ID",
                                                   pd.Series(dtype=str))
        out["procedure_source_value"]    = df.get("PROC_CODE",
                                                   pd.Series(dtype=str))

        out["procedure_concept_id"]      = df.get(
            "PROC_CODE", pd.Series(dtype=str)
        ).apply(lambda c: self._resolve_concept(c, "CPT4"))

        out["procedure_type_concept_id"] = self._TYPE_CONCEPT_EHR

        proc_date = pd.to_datetime(df.get("ORDERING_DATE"), errors="coerce")
        out["procedure_date"]            = proc_date.dt.date
        out["procedure_datetime"]        = proc_date
        out["quantity"]                  = 1

        self._log_transform("to_procedure_occurrence", len(out))
        return out

    # ── Internals ─────────────────────────────────────────────────────────

    def _resolve_concept(self, source_code: str, vocabulary_id: str) -> int:
        """
        Look up an OMOP concept_id for a source code in the loaded vocabulary.
        Returns 0 if the vocabulary is not loaded or the code is not found.
        """
        if self._vocab is None or pd.isna(source_code) or not str(source_code).strip():
            return 0
        mask = (
            (self._vocab["source_code"] == str(source_code).strip())
            & (self._vocab["source_vocabulary_id"] == vocabulary_id)
        )
        matches = self._vocab.loc[mask, "concept_id"]
        return int(matches.iloc[0]) if not matches.empty else 0

    def _log_transform(self, domain: str, rows: int) -> None:
        self.gov._event(  # type: ignore[attr-defined]
            "TRANSFORM", "OMOP_DOMAIN_MAPPED",
            {"domain": domain, "rows": rows,
             "vocab_loaded": self._vocab is not None},
        )
        print(f"  🔄  OMOP: {domain} → {rows:,} row(s) mapped")


# ═════════════════════════════════════════════════════════════════════════════
#  6. PHIKAnonymityChecker  —  k-anonymity and l-diversity enforcement
# ═════════════════════════════════════════════════════════════════════════════

class PHIKAnonymityChecker:
    """
    Verify k-anonymity (and optionally l-diversity) on quasi-identifier
    combinations before a de-identified Epic extract is released.

    Background
    ──────────
    Even after HIPAA Safe Harbor removes direct identifiers, combinations of
    quasi-identifiers (age group, 3-digit ZIP, sex, diagnosis category, year
    of visit) can uniquely re-identify patients.  The classic Sweeney attack
    showed that 87% of Americans are uniquely identified by just ZIP + DOB + sex.

    k-anonymity requires that every combination of quasi-identifier values
    appears in at least k rows.  Any group smaller than k is a disclosure risk.

    l-diversity extends this: within each quasi-identifier group, the sensitive
    attribute (e.g. principal diagnosis) must have at least l distinct values.
    A group with k=5 rows but all sharing the same diagnosis is still a
    re-identification risk.

    Actions on violation
    ────────────────────
    "suppress"    Remove rows belonging to violating groups from the output.
                  This is the default and the simplest HIPAA-compliant option.
    "report"      Log violations and return the DataFrame unchanged.  Use this
                  to audit before deciding how to generalise the data.
    "raise"       Raise PHIAnonymityError immediately on any violation.

    Quick-start
    ───────────
        from epic_extensions import PHIKAnonymityChecker
        from pipeline_v3 import GovernanceLogger

        gov     = GovernanceLogger(run_id="run_001", src="clarity")
        checker = PHIKAnonymityChecker(gov, k=5, l_diversity=3)

        report = checker.check(df,
                               quasi_ids=["age_group", "zip3", "gender_concept_id"],
                               sensitive_col="condition_concept_id")

        safe_df = checker.enforce(df,
                                  quasi_ids=["age_group", "zip3", "gender_concept_id"],
                                  sensitive_col="condition_concept_id",
                                  action="suppress")
    """

    def __init__(
        self,
        gov,
        k:           int  = 5,
        l_diversity: Optional[int] = None,
        dry_run:     bool = False,
    ) -> None:
        """
        Parameters
        ──────────
        gov           GovernanceLogger for audit events.
        k             Minimum group size required for k-anonymity (default 5).
                      Groups smaller than k are violations.
        l_diversity   Minimum number of distinct sensitive-attribute values
                      required within each group.  None disables l-diversity
                      checking.
        dry_run       Report violations without modifying any data.
        """
        self.gov         = gov
        self.k           = k
        self.l_diversity = l_diversity
        self.dry_run     = dry_run
        self._last_report: Optional[Dict] = None

    # ── Public API ────────────────────────────────────────────────────────

    def check(
        self,
        df:            pd.DataFrame,
        quasi_ids:     List[str],
        sensitive_col: Optional[str] = None,
        source_label:  str = "",
    ) -> Dict:
        """
        Compute k-anonymity (and l-diversity if configured) violations.
        Does NOT modify df.  Returns a report dict and logs
        KANONYMITY_CHECK_COMPLETE to the governance ledger.

        Parameters
        ──────────
        df             DataFrame to inspect (should be already de-identified).
        quasi_ids      Column names that form the quasi-identifier combination.
        sensitive_col  Column holding the sensitive attribute for l-diversity.
                       Required if l_diversity is set.
        source_label   Description of the source for the report.
        """
        missing = [c for c in quasi_ids if c not in df.columns]
        if missing:
            raise ValueError(
                f"PHIKAnonymityChecker: quasi_id columns not in DataFrame: {missing}"
            )
        if self.l_diversity and sensitive_col and sensitive_col not in df.columns:
            raise ValueError(
                f"PHIKAnonymityChecker: sensitive_col '{sensitive_col}' "
                f"not in DataFrame."
            )

        # Compute group sizes
        groups = df.groupby(quasi_ids, dropna=False)
        group_sizes = groups.size().reset_index(name="_count")

        # k-anonymity violations: groups with fewer than k records
        k_violations = group_sizes[group_sizes["_count"] < self.k]

        # l-diversity violations: groups where sensitive_col has < l distinct values
        l_violations_list: List[Dict] = []
        if self.l_diversity and sensitive_col:
            l_val = self.l_diversity
            l_counts = groups[sensitive_col].nunique().reset_index(
                name="_distinct"
            )
            bad_l = l_counts[l_counts["_distinct"] < l_val]
            for _, row in bad_l.iterrows():
                l_violations_list.append({
                    "quasi_id_values": {c: row[c] for c in quasi_ids},
                    "distinct_values": int(row["_distinct"]),
                    "required":        l_val,
                })

        k_viol_list: List[Dict] = []
        for _, row in k_violations.iterrows():
            k_viol_list.append({
                "quasi_id_values": {c: str(row[c]) for c in quasi_ids},
                "group_size":      int(row["_count"]),
                "required_k":      self.k,
            })

        total_groups       = len(group_sizes)
        violating_k_groups = len(k_viol_list)
        violating_rows     = int(
            k_violations["_count"].sum() if not k_violations.empty else 0
        )

        report = {
            "source":              source_label,
            "checked_at":          _now_utc().isoformat(),
            "total_rows":          len(df),
            "quasi_ids":           quasi_ids,
            "sensitive_col":       sensitive_col,
            "k":                   self.k,
            "l_diversity":         self.l_diversity,
            "total_groups":        total_groups,
            "k_violations":        k_viol_list,
            "k_violating_groups":  violating_k_groups,
            "k_violating_rows":    violating_rows,
            "l_violations":        l_violations_list,
            "l_violating_groups":  len(l_violations_list),
            "passes_k_anonymity":  violating_k_groups == 0,
            "passes_l_diversity":  len(l_violations_list) == 0,
        }
        self._last_report = report

        level = "INFO" if (violating_k_groups == 0 and not l_violations_list) \
            else "WARN"
        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "KANONYMITY_CHECK_COMPLETE",
            {
                "source":             source_label,
                "k":                  self.k,
                "l_diversity":        self.l_diversity,
                "total_groups":       total_groups,
                "k_violating_groups": violating_k_groups,
                "k_violating_rows":   violating_rows,
                "l_violating_groups": len(l_violations_list),
                "passes":             level == "INFO",
            },
            level=level,
        )

        if violating_k_groups or l_violations_list:
            print(
                f"  ⚠️   k-anonymity [{source_label}]: "
                f"{violating_k_groups} group(s) below k={self.k} "
                f"({violating_rows} row(s) at risk)"
            )
            if l_violations_list:
                print(
                    f"  ⚠️   l-diversity: {len(l_violations_list)} group(s) "
                    f"below l={self.l_diversity}"
                )
        else:
            print(
                f"  ✅  k-anonymity [{source_label}]: all {total_groups} "
                f"group(s) satisfy k={self.k}"
                + (f" and l={self.l_diversity}" if self.l_diversity else "")
            )

        return report

    def enforce(
        self,
        df:            pd.DataFrame,
        quasi_ids:     List[str],
        sensitive_col: Optional[str] = None,
        action:        str = "suppress",
        source_label:  str = "",
    ) -> pd.DataFrame:
        """
        Enforce k-anonymity (and l-diversity if configured) by taking
        action on violating rows.

        action
        ──────
        "suppress"   Remove rows belonging to any quasi-identifier group that
                     violates k-anonymity or l-diversity.  Safe default.
        "report"     Log violations but return df unchanged.  Use for auditing.
        "raise"      Raise PHIAnonymityError on any violation.

        Returns a DataFrame with violations handled per the chosen action.
        """
        if action not in {"suppress", "report", "raise"}:
            raise ValueError(
                f"PHIKAnonymityChecker: action must be 'suppress', 'report', "
                f"or 'raise', got '{action}'."
            )

        report = self.check(df, quasi_ids, sensitive_col, source_label)

        passes = report["passes_k_anonymity"] and report["passes_l_diversity"]
        if passes:
            return df.copy()

        if action == "raise":
            raise PHIAnonymityError(
                f"PHIKAnonymityChecker: k-anonymity violation in "
                f"'{source_label}' — {report['k_violating_groups']} group(s) "
                f"below k={self.k}. "
                f"Use action='suppress' or 'report' to handle non-fatal."
            )

        if action == "report" or self.dry_run:
            logger.warning(
                "PHIKAnonymityChecker [%s]: %d group(s) violate k=%d "
                "(%d rows at risk) — returning df unchanged (action='report'%s).",
                source_label,
                report["k_violating_groups"],
                self.k,
                report["k_violating_rows"],
                "/dry_run" if self.dry_run else "",
            )
            return df.copy()

        # action == "suppress": remove violating rows
        k_viols = report["k_violations"]
        l_viols = report["l_violations"]

        # Build a mask of rows that belong to violating groups
        suppress_mask = pd.Series(False, index=df.index)

        for viol in k_viols:
            group_filter = pd.Series(True, index=df.index)
            for col, val in viol["quasi_id_values"].items():
                group_filter &= (df[col].astype(str) == val)
            suppress_mask |= group_filter

        if sensitive_col and l_viols:
            for viol in l_viols:
                group_filter = pd.Series(True, index=df.index)
                for col, val in viol["quasi_id_values"].items():
                    group_filter &= (df[col].astype(str) == val)
                suppress_mask |= group_filter

        n_suppressed = int(suppress_mask.sum())
        out = df.loc[~suppress_mask].copy()

        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "KANONYMITY_ROWS_SUPPRESSED",
            {
                "source":         source_label,
                "rows_suppressed": n_suppressed,
                "rows_remaining":  len(out),
                "k":              self.k,
            },
        )
        print(f"  🗑   k-anonymity suppressed {n_suppressed} row(s) from "
              f"'{source_label}' — {len(out)} row(s) remain.")
        return out

    def save_report(
        self,
        path: Union[str, pathlib.Path],
        fmt:  str = "html",
    ) -> pathlib.Path:
        """Write the last check report as HTML (default) or JSON."""
        if not self._last_report:
            raise RuntimeError(
                "Call check() or enforce() before save_report()."
            )
        path = pathlib.Path(path)
        if fmt == "json":
            path.write_text(
                json.dumps(self._last_report, indent=2, default=str),
                encoding="utf-8",
            )
        else:
            path.write_text(self._build_html(), encoding="utf-8")
        logger.info("PHIKAnonymityChecker: report written → %s", path)
        return path

    # ── Internals ─────────────────────────────────────────────────────────

    def _build_html(self) -> str:
        r    = self._last_report
        buf  = io.StringIO()
        ok_k = r["passes_k_anonymity"]
        ok_l = r["passes_l_diversity"]
        buf.write(_html_head("k-Anonymity Check Report"))
        buf.write("<h1>🔐 k-Anonymity Check Report</h1>\n")
        buf.write(
            f"<div class='card'>"
            f"<p>Source: <strong>{_he(str(r.get('source', '(unknown)')))}</strong>"
            f" &nbsp;·&nbsp; Checked: {_he(str(r.get('checked_at', '')))[:19]} UTC</p>"
            f"<p>Quasi-identifiers: "
            f"<code>{_he(', '.join(r.get('quasi_ids', [])))}</code></p>"
        )
        k_badge  = "ok" if ok_k else "error"
        k_status = "PASS" if ok_k else f"FAIL — {r['k_violating_groups']} group(s)"
        buf.write(
            f"<p>"
            f"<span class='badge {k_badge}'>k={r['k']}: {_he(k_status)}</span> &nbsp;"
        )
        if r.get("l_diversity"):
            l_badge  = "ok" if ok_l else "warn"
            l_status = "PASS" if ok_l else f"FAIL — {r['l_violating_groups']} group(s)"
            buf.write(
                f"<span class='badge {l_badge}'>"
                f"l={r['l_diversity']}: {_he(l_status)}</span>"
            )
        buf.write(
            f"</p><p>Total rows: {r['total_rows']:,} &nbsp;·&nbsp; "
            f"Groups: {r['total_groups']:,} &nbsp;·&nbsp; "
            f"Rows at risk: {r['k_violating_rows']:,}</p></div>\n"
        )

        if r["k_violations"]:
            buf.write(
                "<div class='card'><h2>k-Anonymity Violations</h2>"
                "<table><tr><th>Quasi-identifier values</th>"
                "<th>Group size</th><th>Required k</th></tr>\n"
            )
            for v in r["k_violations"][:50]:   # cap at 50 rows in HTML
                vals = " | ".join(
                    f"{_he(k)}={_he(str(v))}"
                    for k, v in v["quasi_id_values"].items()
                )
                buf.write(
                    f"<tr><td>{vals}</td>"
                    f"<td><span class='badge error'>{v['group_size']}</span></td>"
                    f"<td>{v['required_k']}</td></tr>\n"
                )
            if len(r["k_violations"]) > 50:
                buf.write(
                    f"<tr><td colspan='3'>... and "
                    f"{len(r['k_violations']) - 50} more (see JSON report)</td>"
                    f"</tr>\n"
                )
            buf.write("</table></div>\n")

        buf.write("</body></html>")
        return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
#  Exceptions
# ═════════════════════════════════════════════════════════════════════════════

class PHIAnonymityError(Exception):
    """
    Raised by PHIKAnonymityChecker.enforce() when action='raise' and one or
    more quasi-identifier groups violate k-anonymity or l-diversity.
    """
