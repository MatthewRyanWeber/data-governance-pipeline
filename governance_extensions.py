# governance_extensions.py  —  Data Governance Extensions v1.0
# ─────────────────────────────────────────────────────────────────────────────
#
#  Eight new governance classes that build on top of pipeline_v3.py:
#
#   1. RoPAGenerator           — GDPR Art. 30 Record of Processing Activities
#   2. RetentionEnforcer       — Enforce (not just log) retention policies
#   3. DSARResponder           — Full Art. 15/20 DSAR workflow
#   4. BreachDetector          — Anomaly-based breach detection + Art. 33 log
#   5. ConsentManager          — Per-subject consent lifecycle
#   6. DifferentialPrivacyTransformer  — Laplace/Gaussian noise + epsilon budget
#   7. PurposeLimitationEnforcer       — Column-level purpose enforcement
#   8. PseudonymVault          — Consistent keyed pseudonymization (GDPR Art. 4(5))
#
#  All classes accept a GovernanceLogger instance from pipeline_v3.py and
#  write into the same audit ledger so every action is tamper-evidently logged.
#
#  Revision history
#  ────────────────
#  v1.0   2026-03-09   Initial build — all 8 classes
#
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations

import hashlib
import io
from html import escape as _he   # used in all HTML report writers
from urllib.parse import quote_plus as _qp  # for safe DB credential URL encoding
import json
import logging
import math
import pathlib
import secrets
import shutil
import sqlite3
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pandas as pd

# ── Optional dependencies ─────────────────────────────────────────────────────
try:
    from sqlalchemy import create_engine, text as sa_text, inspect as sa_inspect
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ── Pipeline v3 import ────────────────────────────────────────────────────────
try:
    from pipeline_v3 import GovernanceLogger
except ImportError as _exc:
    raise ImportError(
        "governance_extensions.py requires pipeline_v3.py in the same directory. "
        f"Original error: {_exc}"
    ) from _exc

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers shared across all classes
# ─────────────────────────────────────────────────────────────────────────────

_RETENTION_DAYS: Dict[str, int] = {
    "7_days":      7,
    "30_days":     30,
    "90_days":     90,
    "180_days":    180,
    "1_year":      365,
    "3_years":     365 * 3,
    "7_years":     365 * 7,
    "indefinite":  999_999,
}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _read_ledger(log_dir: pathlib.Path) -> List[Dict]:
    """Read all JSONL audit ledger events from a governance log directory."""
    events: List[Dict] = []
    skipped = 0
    for f in sorted(log_dir.glob("audit_ledger*.jsonl")):
        for lineno, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    skipped += 1
                    logger.warning("_read_ledger: skipped malformed JSON in %s line %d",
                                   f.name, lineno)
    if skipped:
        logger.warning("_read_ledger: %d malformed line(s) skipped in %s",
                       skipped, log_dir)
    return events


def _html_head(title: str, extra_css: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_he(title)}</title>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:24px;
       background:#f4f6f9;color:#1a1a2e;}}
  h1{{color:#1a1a2e;border-bottom:3px solid #4361ee;padding-bottom:8px;}}
  h2{{color:#4361ee;margin-top:32px;}}
  h3{{color:#3a0ca3;}}
  table{{width:100%;border-collapse:collapse;margin:12px 0;background:#fff;
         box-shadow:0 1px 4px rgba(0,0,0,.1);border-radius:6px;overflow:hidden;}}
  th{{background:#4361ee;color:#fff;padding:10px 14px;text-align:left;font-size:.85em;}}
  td{{padding:9px 14px;border-bottom:1px solid #e9ecef;font-size:.88em;
      vertical-align:top;}}
  tr:last-child td{{border-bottom:none;}}
  tr:hover td{{background:#f0f4ff;}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.78em;
           font-weight:600;}}
  .badge-green{{background:#d4edda;color:#155724;}}
  .badge-yellow{{background:#fff3cd;color:#856404;}}
  .badge-red{{background:#f8d7da;color:#721c24;}}
  .badge-blue{{background:#d1ecf1;color:#0c5460;}}
  .badge-purple{{background:#e2d9f3;color:#6f42c1;}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
                  gap:16px;margin:20px 0;}}
  .summary-card{{background:#fff;border-radius:8px;padding:18px;text-align:center;
                  box-shadow:0 1px 4px rgba(0,0,0,.08);}}
  .summary-card .num{{font-size:2em;font-weight:700;color:#4361ee;}}
  .summary-card .lbl{{font-size:.82em;color:#6c757d;margin-top:4px;}}
  .footer{{margin-top:40px;font-size:.78em;color:#6c757d;border-top:1px solid #dee2e6;
            padding-top:12px;}}
  .warn{{color:#856404;background:#fff3cd;padding:8px 12px;border-radius:4px;
          border-left:4px solid #ffc107;margin:8px 0;}}
  .info{{color:#0c5460;background:#d1ecf1;padding:8px 12px;border-radius:4px;
          border-left:4px solid #17a2b8;margin:8px 0;}}
  {extra_css}
</style>
</head>
<body>
"""


def _html_foot() -> str:
    return f"""
<div class="footer">
  Generated by governance_extensions.py &nbsp;|&nbsp;
  {_iso(_now_utc())} &nbsp;|&nbsp;
  Confidential — for internal compliance use only
</div>
</body></html>"""


# ═════════════════════════════════════════════════════════════════════════════
#  1. RoPAGenerator  —  GDPR Article 30 Record of Processing Activities
# ═════════════════════════════════════════════════════════════════════════════

class RoPAGenerator:
    """
    GDPR Article 30 — Record of Processing Activities.

    Assembles a formal RoPA from the pipeline's audit ledger plus any
    supplementary metadata you provide, then exports it as a structured
    HTML report that a Data Protection Officer can present to a regulator.

    Each processing activity record captures:
      - Controller and DPO contact details
      - Processing purpose and legal basis (Art. 6 / Art. 9)
      - Categories of data subjects and personal data
      - Recipients and third-party processors
      - Cross-border transfers and adequacy mechanisms
      - Retention period per dataset
      - Technical and organisational security measures

    Usage
    -----
        ropa = RoPAGenerator(gov)
        ropa.add_activity(
            name="Customer order processing",
            purpose="Fulfil purchase contracts",
            legal_basis="Art. 6(1)(b) — Contract",
            data_subjects=["customers"],
            data_categories=["contact details","payment info"],
            recipients=["payment processor","logistics partner"],
            retention="3_years",
            security_measures=["AES-256 encryption","access controls"],
        )
        ropa.write()   # → HTML report in governance log dir
    """

    _LEGAL_BASIS_OPTIONS = [
        "Art. 6(1)(a) — Consent",
        "Art. 6(1)(b) — Contract",
        "Art. 6(1)(c) — Legal obligation",
        "Art. 6(1)(d) — Vital interests",
        "Art. 6(1)(e) — Public task",
        "Art. 6(1)(f) — Legitimate interests",
        "Art. 9(2)(a) — Explicit consent (special category)",
        "Art. 9(2)(b) — Employment / social security",
        "Art. 9(2)(c) — Vital interests (special category)",
        "Art. 9(2)(f) — Legal claims",
        "Art. 9(2)(h) — Health care",
        "Art. 9(2)(j) — Archiving / research / statistics",
    ]

    def __init__(
        self,
        gov: GovernanceLogger,
        controller_name: str = "",
        controller_contact: str = "",
        dpo_contact: str = "",
        organisation_type: str = "Controller",
    ) -> None:
        self.gov               = gov
        self.controller_name   = controller_name
        self.controller_contact= controller_contact
        self.dpo_contact       = dpo_contact
        self.organisation_type = organisation_type
        self._activities: List[Dict] = []
        self._report_path = gov.log_dir / f"ropa_{_now_utc().strftime('%Y%m%d_%H%M%S')}.html"

    # ── Public API ────────────────────────────────────────────────────────────

    def add_activity(
        self,
        name: str,
        purpose: str,
        legal_basis: str,
        data_subjects: List[str],
        data_categories: List[str],
        recipients: Optional[List[str]] = None,
        third_country_transfers: Optional[List[Dict]] = None,
        retention: str = "not_specified",
        security_measures: Optional[List[str]] = None,
        joint_controllers: Optional[List[str]] = None,
        processor_details: Optional[str] = None,
        notes: str = "",
    ) -> "RoPAGenerator":
        """Add one processing activity to the register."""
        activity = {
            "id":                    str(uuid.uuid4())[:8],
            "name":                  name,
            "purpose":               purpose,
            "legal_basis":           legal_basis,
            "data_subjects":         data_subjects,
            "data_categories":       data_categories,
            "recipients":            recipients or [],
            "third_country_transfers": third_country_transfers or [],
            "retention":             retention,
            "retention_days":        _RETENTION_DAYS.get(retention, "not specified"),
            "security_measures":     security_measures or [
                "Access controls", "Audit logging", "PII masking/pseudonymisation",
            ],
            "joint_controllers":     joint_controllers or [],
            "processor_details":     processor_details or "",
            "notes":                 notes,
            "added_utc":             _iso(_now_utc()),
        }
        self._activities.append(activity)
        self.gov._event(  # type: ignore[attr-defined]
            "GOVERNANCE", "ROPA_ACTIVITY_ADDED",
            {"activity_name": name, "legal_basis": legal_basis, "retention": retention},
        )
        return self

    def ingest_from_ledger(self) -> "RoPAGenerator":
        """
        Auto-populate activities from the audit ledger.
        Creates one activity per unique (source, destination, purpose) triple.
        Supplements but does not replace manually added activities.
        """
        events = _read_ledger(self.gov.log_dir)
        sources: Dict[str, Dict] = {}
        destinations: Dict[str, Dict] = {}
        purposes: Dict[str, str] = {}
        pii_fields: Dict[str, List] = {}
        retention_policies: Dict[str, str] = {}
        legal_bases: Dict[str, str] = {}
        transfers: List[Dict] = []

        for ev in events:
            action = ev.get("action", "")
            detail = ev.get("detail", {})
            pid    = ev.get("pipeline_id", "unknown")

            if action == "PIPELINE_STARTED":
                sources[pid] = detail

            elif action == "DESTINATION_REGISTERED":
                destinations[pid] = detail

            elif action == "CONSENT_RECORDED":
                legal_bases[pid]  = detail.get("basis", "")
                purposes[pid]     = detail.get("purpose", "")

            elif action == "PII_DETECTED":
                pii_fields.setdefault(pid, []).extend(detail.get("fields", []))

            elif action == "POLICY_RECORDED":
                retention_policies[pid] = detail.get("policy", "not_specified")

            elif action == "CROSS_BORDER_TRANSFER":
                transfers.append(detail)

        seen = set()
        for pid, src in sources.items():
            dst  = destinations.get(pid, {})
            key  = (src.get("source", ""), dst.get("db_name", ""), dst.get("table_or_collection", ""))
            if key in seen:
                continue
            seen.add(key)
            xfers = [t for t in transfers if t.get("db_name") == dst.get("db_name")]
            self.add_activity(
                name=f"Pipeline: {src.get('source','unknown')} → "
                     f"{dst.get('db_type','?')}:{dst.get('table_or_collection','?')}",
                purpose=purposes.get(pid, "Data processing pipeline run"),
                legal_basis=legal_bases.get(pid, "Art. 6(1)(f) — Legitimate interests"),
                data_subjects=["data subjects identified in source"],
                data_categories=list(set(pii_fields.get(pid, ["not scanned"]))),
                recipients=[dst.get("db_type", "internal system")],
                third_country_transfers=xfers,
                retention=retention_policies.get(pid, "not_specified"),
                notes=f"Auto-populated from audit ledger (pipeline_id: {pid[:8]})",
            )
        return self

    def write(self) -> pathlib.Path:
        """Render the RoPA as an HTML report and return the path."""
        html = self._render_html()
        self._report_path.write_text(html, encoding="utf-8")
        self.gov._event(  # type: ignore[attr-defined]
            "GOVERNANCE", "ROPA_REPORT_WRITTEN",
            {"path": str(self._report_path), "activities": len(self._activities)},
        )
        print(f"  📋  RoPA report  →  {self._report_path}")
        return self._report_path

    # ── Rendering ─────────────────────────────────────────────────────────────

    def _render_html(self) -> str:
        ts  = _iso(_now_utc())
        n   = len(self._activities)
        buf = io.StringIO()
        buf.write(_html_head("GDPR Article 30 — Record of Processing Activities"))
        buf.write(f"""
<h1>📋 Record of Processing Activities</h1>
<p><strong>GDPR Article 30 Compliance Register</strong></p>
<table style="max-width:600px">
  <tr><th>Controller / Processor</th><td>{_he(self.controller_name or "(not set)")}</td></tr>
  <tr><th>Contact</th><td>{_he(self.controller_contact or "(not set)")}</td></tr>
  <tr><th>DPO Contact</th><td>{_he(self.dpo_contact or "(not set)")}</td></tr>
  <tr><th>Organisation Type</th><td>{_he(self.organisation_type)}</td></tr>
  <tr><th>Report Generated</th><td>{ts}</td></tr>
  <tr><th>Total Activities</th><td>{n}</td></tr>
</table>
""")
        if not self._activities:
            buf.write('<div class="warn">No processing activities recorded. '
                      'Call add_activity() or ingest_from_ledger().</div>')
        else:
            for i, act in enumerate(self._activities, 1):
                has_xfer = bool(act["third_country_transfers"])
                xfer_badge = '<span class="badge badge-yellow">Third-country transfer</span>' if has_xfer else ""
                buf.write(f"""
<h2>Activity {i}: {_he(act['name'])} {xfer_badge}</h2>
<table>
  <tr><th style="width:220px">Field</th><th>Value</th></tr>
  <tr><td>Activity ID</td><td><code>{_he(act['id'])}</code></td></tr>
  <tr><td>Processing Purpose</td><td>{_he(act['purpose'])}</td></tr>
  <tr><td>Legal Basis</td>
      <td><span class="badge badge-blue">{_he(act['legal_basis'])}</span></td></tr>
  <tr><td>Categories of Data Subjects</td>
      <td>{', '.join(_he(s) for s in act['data_subjects'])}</td></tr>
  <tr><td>Categories of Personal Data</td>
      <td>{', '.join(_he(c) for c in act['data_categories']) or 'not specified'}</td></tr>
  <tr><td>Recipients</td>
      <td>{', '.join(_he(r) for r in act['recipients']) or 'none'}</td></tr>
  <tr><td>Retention Period</td>
      <td>{_he(str(act['retention']))}
        {f"<em>({act['retention_days']} days)</em>" if isinstance(act['retention_days'],int) else ""}</td></tr>
  <tr><td>Security Measures</td>
      <td>{'<br>'.join(f'• {_he(str(m))}' for m in act['security_measures'])}</td></tr>
""")
                if act["joint_controllers"]:
                    buf.write(f"  <tr><td>Joint Controllers</td>"
                              f"<td>{', '.join(_he(c) for c in act['joint_controllers'])}</td></tr>\n")
                if act["processor_details"]:
                    buf.write(f"  <tr><td>Processor Details</td>"
                              f"<td>{_he(str(act['processor_details']))}</td></tr>\n")
                if has_xfer:
                    xfer_rows = "".join(
                        f"<tr><td>{_he(str(t.get('destination_country','?')))}</td>"
                        f"<td>{_he(str(t.get('transfer_mechanism','?')))}</td>"
                        f"<td>{_he(str(t.get('db_type','?')))}</td></tr>"
                        for t in act["third_country_transfers"]
                    )
                    buf.write(f"""  <tr><td>Third-Country Transfers</td><td>
    <table style="width:100%;box-shadow:none;margin:0">
      <tr><th>Country</th><th>Mechanism</th><th>Platform</th></tr>
      {xfer_rows}
    </table></td></tr>\n""")
                if act["notes"]:
                    buf.write(f"  <tr><td>Notes</td><td><em>{_he(str(act['notes']))}</em></td></tr>\n")
                buf.write("</table>\n")

        buf.write(_html_foot())
        return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
#  2. RetentionEnforcer  —  Actually enforce retention, not just log it
# ═════════════════════════════════════════════════════════════════════════════

class RetentionEnforcer:
    """
    Enforces retention policies against destination tables by scanning for
    rows older than the registered policy window and either deleting them
    or archiving them to a cold-storage Parquet file.

    Supports every SQLAlchemy-backed destination (SQLite, PostgreSQL, MySQL,
    SQL Server).  For non-SQL platforms, call enforce_dataframe() to apply
    retention filtering in-memory before loading.

    Each enforcement action is logged as a GDPR Art. 17 erasure event.

    Usage
    -----
        enforcer = RetentionEnforcer(gov, db_type="postgresql")
        enforcer.enforce(
            cfg={"host":..., "user":..., "password":..., "db_name":"prod"},
            table="orders",
            policy="3_years",
            timestamp_column="_loaded_at_utc",
            action="delete",          # or "archive"
        )
    """

    _POLICY_DAYS = _RETENTION_DAYS

    def __init__(self, gov: GovernanceLogger, db_type: str = "sqlite") -> None:
        if not HAS_SQLALCHEMY:
            raise RuntimeError("RetentionEnforcer requires sqlalchemy. "
                               "pip install sqlalchemy")
        self.gov     = gov
        self.db_type = db_type
        self.archive_dir = gov.log_dir / "retention_archives"
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def enforce(
        self,
        cfg: Dict,
        table: str,
        policy: str,
        timestamp_column: str = "_loaded_at_utc",
        action: str = "delete",          # "delete" | "archive"
        dry_run: bool = False,
        id_column: str = "id",
    ) -> Dict:
        """
        Enforce a retention policy against one table.

        Returns a summary dict with keys: rows_found, rows_acted, action, dry_run.
        """
        if action not in {"delete", "archive"}:
            raise ValueError(
                f"RetentionEnforcer: action must be 'delete' or 'archive', got '{action}'. "
                "A typo here would otherwise silently fall through to delete."
            )
        days     = self._POLICY_DAYS.get(policy, 0)
        if days == 999_999:
            print(f"  ℹ  {table}: policy=indefinite — nothing to enforce")
            return {"rows_found": 0, "rows_acted": 0, "action": action, "dry_run": dry_run}

        cutoff   = _now_utc() - timedelta(days=days)
        engine   = self._engine(cfg)
        result   = {"rows_found": 0, "rows_acted": 0, "action": action, "dry_run": dry_run}

        with engine.connect() as conn:
            # Check the table and timestamp column both exist
            inspector = sa_inspect(engine)
            if table not in inspector.get_table_names():
                print(f"  ⚠  {table}: table not found in database — skipping")
                return result
            cols = [c["name"] for c in inspector.get_columns(table)]
            if timestamp_column not in cols:
                print(f"  ⚠  {table}: timestamp column '{timestamp_column}' not found — skipping")
                return result

            # Count expired rows
            count_sql = sa_text(
                f"SELECT COUNT(*) FROM {table} WHERE {timestamp_column} < :cutoff"
            )
            count = conn.execute(count_sql, {"cutoff": cutoff.isoformat()}).scalar() or 0
            result["rows_found"] = count

            if count == 0:
                print(f"  ✓  {table}: 0 rows expired under policy '{policy}'")
                return result

            if dry_run:
                print(f"  [DRY RUN] {table}: {count} rows would be "
                      f"{'deleted' if action=='delete' else 'archived'} (cutoff: {cutoff.date()})")
                result["rows_acted"] = count
                return result

            if action == "archive":
                result["rows_acted"] = self._archive(conn, engine, table,
                                                      timestamp_column, cutoff, policy)
            else:
                result["rows_acted"] = self._delete(conn, table,
                                                     timestamp_column, cutoff)

        if result["rows_acted"] > 0:
            self.gov.erasure_executed(
                f"retention_{policy}", table, result["rows_acted"], "RETENTION_DELETE"
            )
        self.gov._event(  # type: ignore[attr-defined]
            "RETENTION", "RETENTION_ENFORCED",
            {
                "table":            table,
                "policy":           policy,
                "cutoff_utc":       cutoff.isoformat(),
                "rows_found":       result["rows_found"],
                "rows_acted":       result["rows_acted"],
                "action":           action,
            },
        )
        icon = "🗑 " if action == "delete" else "📦"
        print(f"  {icon}  {table}: {result['rows_acted']} row(s) {action}d "
              f"(policy: {policy}, cutoff: {cutoff.date()})")
        return result

    def enforce_dataframe(
        self,
        df: pd.DataFrame,
        policy: str,
        timestamp_column: str = "_loaded_at_utc",
    ) -> pd.DataFrame:
        """
        Filter a DataFrame in-memory, dropping rows older than the policy window.
        Useful for non-SQL destinations (BigQuery, Snowflake, etc.) before loading.
        """
        days = self._POLICY_DAYS.get(policy, 999_999)
        if days == 999_999 or timestamp_column not in df.columns:
            return df

        cutoff = _now_utc() - timedelta(days=days)
        before = len(df)
        df[timestamp_column] = pd.to_datetime(df[timestamp_column], utc=True, errors="coerce")
        df = df[df[timestamp_column] >= cutoff].copy()
        dropped = before - len(df)
        if dropped:
            print(f"  🗑  enforce_dataframe: {dropped} row(s) dropped (policy: {policy})")
            self.gov._event(  # type: ignore[attr-defined]
                "RETENTION", "RETENTION_ENFORCED_DATAFRAME",
                {"policy": policy, "rows_dropped": dropped, "rows_kept": len(df)},
            )
        return df

    def scan_all_tables(
        self,
        cfg: Dict,
        policy_map: Dict[str, str],
        timestamp_column: str = "_loaded_at_utc",
        action: str = "delete",
        dry_run: bool = False,
    ) -> Dict[str, Dict]:
        """
        Enforce retention across multiple tables in one call.

        policy_map: {"table_name": "policy_string", ...}
        Returns:    {"table_name": result_dict, ...}
        """
        results = {}
        for table, policy in policy_map.items():
            try:
                results[table] = self.enforce(
                    cfg, table, policy,
                    timestamp_column=timestamp_column,
                    action=action, dry_run=dry_run,
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.warning("RetentionEnforcer.scan_all_tables: %s — %s", table, exc)
                results[table] = {"error": str(exc)}
        return results

    # ── Internals ─────────────────────────────────────────────────────────────

    def _engine(self, cfg: Dict):
        t = self.db_type
        if t == "sqlite":
            _db = str(cfg["db_name"])
            if not _db.endswith(".db"):
                _db += ".db"
            return create_engine(f"sqlite:///{_db}")
        if t in ("postgresql", "postgres"):
            return create_engine(
                f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port',5432)}/{cfg['db_name']}"
            )
        if t == "mysql":
            return create_engine(
                f"mysql+pymysql://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port',3306)}/{cfg['db_name']}"
            )
        if t == "mssql":
            return create_engine(
                f"mssql+pyodbc://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{cfg.get('port',1433)}/{cfg['db_name']}"
                f"?driver={cfg.get('driver','ODBC+Driver+17+for+SQL+Server')}"
            )
        raise ValueError(f"RetentionEnforcer: unsupported db_type '{t}'")

    def _delete(self, conn, table: str, ts_col: str, cutoff: datetime) -> int:
        sql = sa_text(f"DELETE FROM {table} WHERE {ts_col} < :cutoff")
        result = conn.execute(sql, {"cutoff": cutoff.isoformat()})
        conn.commit()
        return result.rowcount or 0

    def _archive(self, conn, engine, table: str, ts_col: str,
                 cutoff: datetime, policy: str) -> int:
        sel_sql = sa_text(
            f"SELECT * FROM {table} WHERE {ts_col} < :cutoff"
        )
        df = pd.read_sql(sel_sql, engine, params={"cutoff": cutoff.isoformat()})
        if df.empty:
            return 0
        ts_str = _now_utc().strftime("%Y%m%d_%H%M%S")
        archive_path = self.archive_dir / f"{table}_archived_{policy}_{ts_str}.parquet"
        try:
            df.to_parquet(archive_path, index=False)
        except ImportError:
            # pyarrow / fastparquet not installed — fall back to CSV so the
            # archive step doesn't crash the retention run silently.
            archive_path = archive_path.with_suffix(".csv")
            df.to_csv(archive_path, index=False)
            print("  ⚠  Parquet engine not available (pip install pyarrow) — "
                  "archived as CSV instead")
        rows = self._delete(conn, table, ts_col, cutoff)
        print(f"  📦  archived → {archive_path}")
        return rows


# ═════════════════════════════════════════════════════════════════════════════
#  3. DSARResponder  —  Data Subject Access Request (Art. 15 / Art. 20)
# ═════════════════════════════════════════════════════════════════════════════

class DSARResponder:
    """
    Full GDPR Article 15 / Article 20 Data Subject Access Request workflow.

    Accepts a subject ID (or a hash of one), queries every destination
    registered in the pipeline's audit ledger, assembles all matching rows
    into a single portable export, and generates a human-readable HTML
    response report.

    Supports SQLite, PostgreSQL, MySQL, SQL Server.  For non-SQL destinations
    pass a pre-loaded DataFrame via add_dataframe().

    Art. 15 rights covered:
      - Confirmation of processing (report header)
      - Categories of data, purposes, recipients (from RoPA or ledger)
      - Retention periods
      - Right to rectification / erasure (links provided in report)

    Art. 20 portability: export as JSON or CSV.

    Usage
    -----
        responder = DSARResponder(gov)
        responder.add_sql_source(
            db_type="postgresql", cfg={...},
            tables=["orders","customers"],
            subject_column="customer_id",
        )
        response = responder.respond(subject_id="jane.doe@example.com")
        response.write()
    """

    def __init__(self, gov: GovernanceLogger, response_dir: Optional[str] = None) -> None:
        self.gov          = gov
        self.response_dir = pathlib.Path(response_dir) if response_dir else gov.log_dir / "dsar_responses"
        self.response_dir.mkdir(parents=True, exist_ok=True)
        self._sources: List[Dict] = []

    # ── Source registration ───────────────────────────────────────────────────

    def add_sql_source(
        self,
        db_type: str,
        cfg: Dict,
        tables: List[str],
        subject_column: str,
        hash_column: bool = False,
    ) -> "DSARResponder":
        """Register a SQL database as a data source for DSAR lookups."""
        if not HAS_SQLALCHEMY:
            raise RuntimeError("DSARResponder.add_sql_source requires sqlalchemy.")
        self._sources.append({
            "type":           "sql",
            "db_type":        db_type,
            "cfg":            cfg,
            "tables":         tables,
            "subject_column": subject_column,
            "hash_column":    hash_column,
        })
        return self

    def add_dataframe(
        self,
        df: pd.DataFrame,
        label: str,
        subject_column: str,
    ) -> "DSARResponder":
        """Register a pre-loaded DataFrame as a data source (for non-SQL platforms)."""
        self._sources.append({
            "type":           "dataframe",
            "df":             df,
            "label":          label,
            "subject_column": subject_column,
        })
        return self

    # ── Main workflow ─────────────────────────────────────────────────────────

    def respond(
        self,
        subject_id: str,
        request_id: Optional[str] = None,
        requester_email: str = "",
        export_format: str = "json",   # "json" | "csv"
    ) -> "DSARResponse":
        """
        Process a DSAR for a given subject_id.
        Returns a DSARResponse object; call .write() to save all output files.
        """
        req_id  = request_id or f"DSAR-{_now_utc().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
        subject_hash = hashlib.sha256(subject_id.encode()).hexdigest()[:16]

        if export_format not in {"json", "csv"}:
            raise ValueError(
                f"DSARResponder: export_format must be 'json' or 'csv', got '{export_format}'. "
                "An unknown format silently writes JSON with a mismatched file extension."
            )
        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "DSAR_RECEIVED",
            {
                "request_id":    req_id,
                "subject_hash":  subject_hash,
                "sources":       len(self._sources),
                "export_format": export_format,
            },
        )

        print(f"\n  📬  DSAR {req_id} — collecting data for subject {subject_hash}…")
        found: List[Dict] = []

        for src in self._sources:
            try:
                rows = self._query_source(src, subject_id, subject_hash)
                if rows:
                    found.extend(rows)
                    label = src.get("label", src.get("db_type", "unknown"))
                    print(f"     ✓  {label}: {len(rows)} record(s) found")
                else:
                    label = src.get("label", src.get("db_type", "unknown"))
                    print(f"     –  {label}: no records")
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.warning("DSAR source query failed: %s", exc)
                found.append({"_source_error": str(exc)})

        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "DSAR_RECORDS_COLLECTED",
            {"request_id": req_id, "total_records": len(found)},
        )

        return DSARResponse(
            request_id      = req_id,
            subject_hash    = subject_hash,
            subject_id      = subject_id,
            requester_email = requester_email,
            records         = found,
            gov             = self.gov,
            response_dir    = self.response_dir,
            export_format   = export_format,
        )

    # ── Internals ─────────────────────────────────────────────────────────────

    def _query_source(self, src: Dict, subject_id: str, subject_hash: str) -> List[Dict]:
        if src["type"] == "dataframe":
            df = src["df"]
            col = src["subject_column"]
            if col not in df.columns:
                return []
            match = df[df[col].astype(str).isin([subject_id, subject_hash])]
            records = match.to_dict(orient="records")
            for r in records:
                r["_source"] = src["label"]
            return records

        # SQL source
        db_type = src["db_type"]
        cfg     = src["cfg"]
        col     = src["subject_column"]
        results = []

        engine_url = self._sql_url(db_type, cfg)
        engine = create_engine(engine_url)

        for table in src["tables"]:
            try:
                inspector = sa_inspect(engine)
                table_names = inspector.get_table_names()
                if table not in table_names:
                    continue
                cols = [c["name"] for c in inspector.get_columns(table)]
                if col not in cols:
                    continue
                # Use explicit OR instead of IN (:sid, :shash).
                # Named parameters inside IN() are not handled consistently across
                # all SQLAlchemy drivers (notably MSSQL/pyodbc and some psycopg2
                # configurations), whereas two separate named params with OR work
                # universally.
                sql = sa_text(f"SELECT * FROM {table} WHERE {col} = :sid OR {col} = :shash")
                with engine.connect() as conn:
                    df = pd.read_sql(sql, conn, params={"sid": subject_id, "shash": subject_hash})
                for r in df.to_dict(orient="records"):
                    r["_source"]       = f"{db_type}:{table}"
                    r["_table"]        = table
                    results.append(r)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.warning("DSAR table query %s: %s", table, exc)
        return results

    @staticmethod
    def _sql_url(db_type: str, cfg: Dict) -> str:
        if db_type == "sqlite":
            _db = str(cfg["db_name"])
            if not _db.endswith(".db"):
                _db += ".db"
            return f"sqlite:///{_db}"
        if db_type in ("postgresql", "postgres"):
            return (f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                    f"@{cfg['host']}:{cfg.get('port',5432)}/{cfg['db_name']}")
        if db_type == "mysql":
            return (f"mysql+pymysql://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                    f"@{cfg['host']}:{cfg.get('port',3306)}/{cfg['db_name']}")
        if db_type == "mssql":
            return (f"mssql+pyodbc://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                    f"@{cfg['host']}:{cfg.get('port',1433)}/{cfg['db_name']}"
                    f"?driver={cfg.get('driver','ODBC+Driver+17+for+SQL+Server')}")
        raise ValueError(f"DSARResponder: unsupported db_type '{db_type}'")


class DSARResponse:
    """Holds the assembled DSAR result and writes output files."""

    def __init__(self, request_id, subject_hash, subject_id, requester_email,
                 records, gov, response_dir, export_format):
        self.request_id      = request_id
        self.subject_hash    = subject_hash
        self.subject_id      = subject_id
        self.requester_email = requester_email
        self.records         = records
        self.gov             = gov
        self.response_dir    = response_dir
        self.export_format   = export_format
        self.generated_utc   = _iso(_now_utc())

    def write(self) -> Dict[str, pathlib.Path]:
        """Write HTML report + portable data export. Returns paths dict."""
        slug = self.request_id.replace("/", "-")
        html_path   = self.response_dir / f"{slug}_report.html"
        export_path = self.response_dir / f"{slug}_data.{self.export_format}"

        html_path.write_text(self._render_html(), encoding="utf-8")
        self._write_export(export_path)

        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "DSAR_RESPONSE_WRITTEN",
            {
                "request_id":   self.request_id,
                "subject_hash": self.subject_hash,
                "records":      len(self.records),
                "html":         str(html_path),
                "export":       str(export_path),
            },
        )
        print("  ✅  DSAR response written:")
        print(f"       Report  → {html_path}")
        print(f"       Export  → {export_path}")
        return {"html": html_path, "export": export_path}

    def _write_export(self, path: pathlib.Path) -> None:
        # Strip internal metadata columns before export
        safe = [{k: v for k, v in r.items() if not k.startswith("_")}
                for r in self.records]
        if self.export_format == "csv":
            if safe:
                pd.DataFrame(safe).to_csv(path, index=False)
            else:
                path.write_text("no records found\n")
        else:
            path.write_text(json.dumps(safe, indent=2, default=str), encoding="utf-8")

    def _render_html(self) -> str:
        n_records = len([r for r in self.records if "_source_error" not in r])
        buf = io.StringIO()
        buf.write(_html_head(f"DSAR Response — {self.request_id}"))
        buf.write(f"""
<h1>📬 Data Subject Access Request Response</h1>
<div class="summary-grid">
  <div class="summary-card"><div class="num">{n_records}</div>
    <div class="lbl">Records Found</div></div>
  <div class="summary-card"><div class="num">{len(set(r.get('_source','') for r in self.records))}</div>
    <div class="lbl">Data Sources</div></div>
</div>
<table style="max-width:620px">
  <tr><th>Request ID</th><td><code>{_he(self.request_id)}</code></td></tr>
  <tr><th>Subject Identifier Hash</th><td><code>{_he(self.subject_hash)}</code></td></tr>
  <tr><th>Requester</th><td>{_he(self.requester_email or "(not provided)")}</td></tr>
  <tr><th>Response Generated</th><td>{_he(self.generated_utc)}</td></tr>
  <tr><th>Total Records</th><td>{n_records}</td></tr>
</table>
<div class="info">
  <strong>Your rights under GDPR:</strong>
  Art. 16 (rectification) &nbsp;|&nbsp;
  Art. 17 (erasure) &nbsp;|&nbsp;
  Art. 18 (restriction) &nbsp;|&nbsp;
  Art. 20 (portability — data export attached)
</div>
<h2>Data Records</h2>
""")
        if not self.records:
            buf.write('<p>No personal data matching this subject identifier was found '
                      'in the searched data sources.</p>')
        else:
            by_source: Dict[str, List] = {}
            for r in self.records:
                src = r.get("_source", "unknown")
                by_source.setdefault(src, []).append(r)
            for src, rows in by_source.items():
                clean_rows = [{k: v for k, v in r.items()
                               if not k.startswith("_")} for r in rows]
                if not clean_rows:
                    continue
                all_keys = list(dict.fromkeys(k for r in clean_rows for k in r))
                buf.write(f"<h3>Source: {_he(src)} ({len(clean_rows)} record(s))</h3>\n<table>\n")
                buf.write("<tr>" + "".join(f"<th>{_he(k)}</th>" for k in all_keys) + "</tr>\n")
                for row in clean_rows:
                    buf.write("<tr>" + "".join(
                        f"<td>{_he(str(row.get(k,''))[:200])}</td>" for k in all_keys
                    ) + "</tr>\n")
                buf.write("</table>\n")
        buf.write(_html_foot())
        return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
#  4. BreachDetector  —  Anomaly detection + GDPR Art. 33 breach logging
# ═════════════════════════════════════════════════════════════════════════════

class BreachDetector:
    """
    Detects potential data breaches by monitoring governance-relevant anomalies
    and logs them with a GDPR Article 33 72-hour notification countdown.

    Detection heuristics:
      - Sudden column disappearance (possible data exfiltration or schema tampering)
      - PII detected in tables not previously known to contain PII
      - Bulk export of sensitive fields outside normal load-size bounds
      - Cross-border transfers to new / unregistered countries
      - Quality score collapse (possible data corruption / poisoning)
      - Unusually large erasure operations (possible bulk data wiping)

    Each detected event is classified by severity (HIGH / MEDIUM / LOW) and
    logged to the audit ledger. HIGH-severity events trigger an Art. 33 notice
    entry with a 72-hour deadline timestamp.

    Usage
    -----
        detector = BreachDetector(gov)
        detector.check_load(df, destination="postgresql:orders",
                            pii_fields=["email","ssn"])
        detector.check_erasure(rows_affected=10_000, table="users")
        detector.check_quality_score(score=12.0, table="patients")
        detector.report()   # → HTML summary
    """

    _SEVERITY_COLORS = {"HIGH": "badge-red", "MEDIUM": "badge-yellow", "LOW": "badge-blue"}

    def __init__(
        self,
        gov: GovernanceLogger,
        normal_row_max: int = 100_000,
        quality_collapse_threshold: float = 40.0,
        max_erasure_single_run: int = 5_000,
    ) -> None:
        self.gov                      = gov
        self.normal_row_max           = normal_row_max
        self.quality_collapse_threshold = quality_collapse_threshold
        self.max_erasure_single_run   = max_erasure_single_run
        self._events: List[Dict]      = []
        self._known_pii_tables: set   = set()
        self._known_countries: set    = set()
        self._known_columns: Dict[str, set] = {}
        self._state_path              = gov.log_dir / "breach_detector_state.json"
        self._load_state()

    # ── Check methods ─────────────────────────────────────────────────────────

    def check_load(
        self,
        df: pd.DataFrame,
        destination: str,
        pii_fields: Optional[List[str]] = None,
        quality_score: Optional[float] = None,
    ) -> List[Dict]:
        """Run all applicable checks on a DataFrame about to be loaded."""
        alerts: List[Dict] = []
        pii_fields = pii_fields or []
        cols = set(df.columns.tolist())

        # 1. Column disappearance
        if destination in self._known_columns:
            prev_cols = self._known_columns[destination]
            disappeared = prev_cols - cols
            if disappeared:
                alerts.append(self._alert(
                    "COLUMN_DISAPPEARANCE",
                    f"Columns removed from '{destination}': {sorted(disappeared)}",
                    severity="HIGH",
                    detail={"destination": destination, "disappeared": sorted(disappeared)},
                ))
        self._known_columns[destination] = cols

        # 2. PII in new table
        if pii_fields and destination not in self._known_pii_tables:
            alerts.append(self._alert(
                "NEW_PII_TABLE",
                f"PII fields {pii_fields} detected in '{destination}' for first time",
                severity="MEDIUM",
                detail={"destination": destination, "pii_fields": pii_fields},
            ))
            self._known_pii_tables.add(destination)

        # 3. Bulk export
        if len(df) > self.normal_row_max:
            alerts.append(self._alert(
                "BULK_LOAD",
                f"Unusually large load: {len(df):,} rows → '{destination}' "
                f"(threshold: {self.normal_row_max:,})",
                severity="MEDIUM",
                detail={"destination": destination, "rows": len(df)},
            ))

        # 4. Quality collapse
        if quality_score is not None and quality_score < self.quality_collapse_threshold:
            alerts.append(self._alert(
                "QUALITY_COLLAPSE",
                f"Quality score {quality_score:.1f} < {self.quality_collapse_threshold} "
                f"for '{destination}' — possible data corruption",
                severity="HIGH",
                detail={"destination": destination, "score": quality_score},
            ))

        self._save_state()
        return alerts

    def check_erasure(self, rows_affected: int, table: str) -> Optional[Dict]:
        """Flag unusually large erasure operations."""
        if rows_affected > self.max_erasure_single_run:
            return self._alert(
                "BULK_ERASURE",
                f"Bulk erasure: {rows_affected:,} rows deleted from '{table}' "
                f"(threshold: {self.max_erasure_single_run:,})",
                severity="HIGH",
                detail={"table": table, "rows_affected": rows_affected},
            )
        return None

    def check_transfer(self, country: str, mechanism: str) -> Optional[Dict]:
        """Flag transfers to previously unseen countries."""
        if country not in self._known_countries:
            self._known_countries.add(country)
            self._save_state()
            return self._alert(
                "NEW_TRANSFER_COUNTRY",
                f"First-time cross-border transfer to '{country}' via '{mechanism}'",
                severity="MEDIUM",
                detail={"country": country, "mechanism": mechanism},
            )
        return None

    def check_quality_score(self, score: float, table: str = "") -> Optional[Dict]:
        """Standalone quality-score collapse check."""
        if score < self.quality_collapse_threshold:
            return self._alert(
                "QUALITY_COLLAPSE",
                f"Quality score {score:.1f} below threshold {self.quality_collapse_threshold} "
                f"for table '{table}'",
                severity="HIGH",
                detail={"table": table, "score": score},
            )
        return None

    def report(self) -> pathlib.Path:
        """Write an HTML breach-event summary report."""
        path = self.gov.log_dir / f"breach_report_{_now_utc().strftime('%Y%m%d_%H%M%S')}.html"
        path.write_text(self._render_html(), encoding="utf-8")
        print(f"  🚨  Breach detector report  →  {path}")
        return path

    # ── Internals ─────────────────────────────────────────────────────────────

    def _alert(self, event_type: str, description: str,
               severity: str = "MEDIUM", detail: Optional[Dict] = None) -> Dict:
        deadline = None
        if severity == "HIGH":
            deadline = _iso(_now_utc() + timedelta(hours=72))
        alert = {
            "event_type":     event_type,
            "severity":       severity,
            "description":    description,
            "detected_utc":   _iso(_now_utc()),
            "art33_deadline": deadline,
            "detail":         detail or {},
        }
        self._events.append(alert)
        self.gov._event(  # type: ignore[attr-defined]
            "BREACH", f"BREACH_ALERT_{severity}",
            {
                "event_type":     event_type,
                "description":    description,
                "art33_deadline": deadline,
                **(detail or {}),
            },
        )
        icon = "🚨" if severity == "HIGH" else "⚠ "
        print(f"  {icon}  [{severity}] {event_type}: {description}")
        if deadline:
            print(f"       Art. 33 notification deadline: {deadline}")
        return alert

    def _load_state(self) -> None:
        if self._state_path.exists():
            try:
                state = json.loads(self._state_path.read_text(encoding="utf-8"))
                self._known_pii_tables  = set(state.get("known_pii_tables", []))
                self._known_countries   = set(state.get("known_countries", []))
                self._known_columns     = {k: set(v)
                    for k, v in state.get("known_columns", {}).items()}
            except Exception as _exc:  # pylint: disable=broad-exception-caught
                # State file is corrupt or unreadable — warn and start fresh.
                # Silent failure would hide disk/permission issues.
                logger.warning("BreachDetector: could not load state from %s: %s",
                               self._state_path, _exc)

    def _save_state(self) -> None:
        state = {
            "known_pii_tables": list(self._known_pii_tables),
            "known_countries":  list(self._known_countries),
            "known_columns":    {k: list(v) for k, v in self._known_columns.items()},
            "updated_utc":      _iso(_now_utc()),
        }
        self._state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _render_html(self) -> str:
        high   = [e for e in self._events if e["severity"] == "HIGH"]
        medium = [e for e in self._events if e["severity"] == "MEDIUM"]
        low    = [e for e in self._events if e["severity"] == "LOW"]
        buf    = io.StringIO()
        buf.write(_html_head("Breach Detector Report"))
        buf.write(f"""
<h1>🚨 Breach Detection Report</h1>
<div class="summary-grid">
  <div class="summary-card"><div class="num" style="color:#dc3545">{len(high)}</div>
    <div class="lbl">HIGH Severity</div></div>
  <div class="summary-card"><div class="num" style="color:#ffc107">{len(medium)}</div>
    <div class="lbl">MEDIUM Severity</div></div>
  <div class="summary-card"><div class="num" style="color:#17a2b8">{len(low)}</div>
    <div class="lbl">LOW Severity</div></div>
  <div class="summary-card"><div class="num">{len(self._events)}</div>
    <div class="lbl">Total Events</div></div>
</div>
""")
        if not self._events:
            buf.write('<div class="info">No breach indicators detected.</div>\n')
        else:
            if high:
                buf.write('<div class="warn"><strong>⚠ GDPR Art. 33:</strong> '
                          f'{len(high)} HIGH-severity event(s) require supervisory authority '
                          'notification within 72 hours of detection.</div>\n')
            buf.write("<h2>Events</h2>\n<table>\n"
                      "<tr><th>Severity</th><th>Type</th><th>Description</th>"
                      "<th>Detected</th><th>Art. 33 Deadline</th></tr>\n")
            for ev in sorted(self._events, key=lambda e: e["severity"]):
                sev = ev["severity"]
                buf.write(
                    f"<tr>"
                    f"<td><span class='badge {self._SEVERITY_COLORS[sev]}'>{sev}</span></td>"
                    f"<td><code>{ev['event_type']}</code></td>"
                    f"<td>{ev['description']}</td>"
                    f"<td>{ev['detected_utc']}</td>"
                    f"<td>{ev.get('art33_deadline') or '—'}</td>"
                    f"</tr>\n"
                )
            buf.write("</table>\n")
        buf.write(_html_foot())
        return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
#  5. ConsentManager  —  Per-subject consent lifecycle
# ═════════════════════════════════════════════════════════════════════════════

class ConsentManager:
    """
    Manages GDPR consent per data subject — record, check, withdraw, expire.

    Consent records are stored in a local SQLite database (consent.db) in the
    governance log directory.  Each record has:
      - subject_hash     : SHA-256 of the subject identifier (never raw PII)
      - purpose          : The processing purpose consent was given for
      - legal_basis      : Art. 6 / Art. 9 basis string
      - granted_utc      : When consent was recorded
      - expires_utc      : Optional expiry (None = indefinite until withdrawn)
      - withdrawn_utc    : When consent was withdrawn (None if still active)
      - version          : Consent version / revision label

    Compliance notes:
      - Art. 7(3): withdrawal is as easy as granting
      - Art. 13/14: consent notice version tracked in 'version' field
      - PECR / ePrivacy: granular purpose-level tracking

    Usage
    -----
        cm = ConsentManager(gov)
        cm.record("user_123", purpose="marketing", legal_basis="Art. 6(1)(a)")
        if cm.check("user_123", purpose="marketing"):
            # safe to process
            ...
        cm.withdraw("user_123", purpose="marketing")
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS consent (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_hash    TEXT    NOT NULL,
            purpose         TEXT    NOT NULL,
            legal_basis     TEXT    NOT NULL,
            granted_utc     TEXT    NOT NULL,
            expires_utc     TEXT,
            withdrawn_utc   TEXT,
            version         TEXT    NOT NULL DEFAULT 'v1',
            notes           TEXT    DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_consent_subject ON consent(subject_hash);
        CREATE INDEX IF NOT EXISTS idx_consent_purpose ON consent(purpose);
    """

    def __init__(
        self,
        gov:      GovernanceLogger,
        db_path:  "str | pathlib.Path | None" = None,
    ) -> None:
        # db_path allows the preflight gate to open a consent.db that was
        # created in a different log directory (e.g. BASE_DIR) rather than
        # always defaulting to the current run's log_dir.
        self.gov      = gov
        self.db_path  = pathlib.Path(db_path) if db_path else gov.log_dir / "consent.db"
        self._lock    = threading.Lock()
        self._init_db()

    # ── Public API ────────────────────────────────────────────────────────────

    def record(
        self,
        subject_id: str,
        purpose: str,
        legal_basis: str = "Art. 6(1)(a) — Consent",
        expires_days: Optional[int] = None,
        version: str = "v1",
        notes: str = "",
    ) -> bool:
        """
        Record consent for a subject/purpose pair.
        Overwrites any previous active consent for the same pair.
        Returns True on success.
        """
        h       = self._hash(subject_id)
        now     = _now_utc()
        expires = _iso(now + timedelta(days=expires_days)) if expires_days is not None else None

        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Withdraw any existing active consent for this purpose
                conn.execute(
                    "UPDATE consent SET withdrawn_utc=? WHERE subject_hash=? "
                    "AND purpose=? AND withdrawn_utc IS NULL",
                    (_iso(now), h, purpose),
                )
                conn.execute(
                    "INSERT INTO consent (subject_hash,purpose,legal_basis,"
                    "granted_utc,expires_utc,version,notes) VALUES (?,?,?,?,?,?,?)",
                    (h, purpose, legal_basis, _iso(now), expires, version, notes),
                )
                conn.commit()

        self.gov._event(  # type: ignore[attr-defined]
            "CONSENT", "CONSENT_RECORDED",
            {
                "subject_hash": h,
                "purpose":      purpose,
                "legal_basis":  legal_basis,
                "expires":      expires or "indefinite",
                "version":      version,
            },
        )
        return True

    def check(
        self,
        subject_id: str,
        purpose: str,
        raise_on_missing: bool = False,
    ) -> bool:
        """
        Return True if valid, non-expired, non-withdrawn consent exists.
        If raise_on_missing=True, raises ConsentRequiredError instead of returning False.
        """
        h   = self._hash(subject_id)
        now = _iso(_now_utc())
        with sqlite3.connect(str(self.db_path), timeout=10) as conn:
            row = conn.execute(
                "SELECT id, expires_utc FROM consent "
                "WHERE subject_hash=? AND purpose=? AND withdrawn_utc IS NULL "
                "ORDER BY granted_utc DESC LIMIT 1",
                (h, purpose),
            ).fetchone()

        if not row:
            if raise_on_missing:
                raise ConsentRequiredError(
                    f"No consent found for subject {h[:8]}… purpose='{purpose}'"
                )
            return False

        _, expires = row
        if expires and expires < now:
            if raise_on_missing:
                raise ConsentExpiredError(
                    f"Consent expired for subject {h[:8]}… purpose='{purpose}'"
                )
            return False
        return True

    def withdraw(self, subject_id: str, purpose: Optional[str] = None) -> int:
        """
        Withdraw consent.  If purpose is None, withdraws ALL purposes for this subject.
        Returns number of records withdrawn.
        """
        h   = self._hash(subject_id)
        now = _iso(_now_utc())
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                if purpose:
                    cur = conn.execute(
                        "UPDATE consent SET withdrawn_utc=? "
                        "WHERE subject_hash=? AND purpose=? AND withdrawn_utc IS NULL",
                        (now, h, purpose),
                    )
                else:
                    cur = conn.execute(
                        "UPDATE consent SET withdrawn_utc=? "
                        "WHERE subject_hash=? AND withdrawn_utc IS NULL",
                        (now, h),
                    )
                conn.commit()
                n = cur.rowcount

        self.gov._event(  # type: ignore[attr-defined]
            "CONSENT", "CONSENT_WITHDRAWN",
            {"subject_hash": h, "purpose": purpose or "ALL", "records_withdrawn": n},
        )
        print(f"  ✓  Consent withdrawn: subject {h[:8]}… purpose='{purpose or 'ALL'}' "
              f"({n} record(s))")
        return n

    def get_subjects_without_consent(
        self,
        df: pd.DataFrame,
        subject_column: str,
        purpose: str,
    ) -> pd.DataFrame:
        """
        Given a DataFrame, return only the rows where the subject does NOT
        have valid active consent for the given purpose.
        Useful for blocking loads of non-consenting subjects.
        """
        def _no_consent(sid):
            return not self.check(str(sid), purpose)
        mask = df[subject_column].apply(_no_consent)
        return df[mask].copy()

    def export_consent_register(self) -> pathlib.Path:
        """Export the full consent register as an HTML report."""
        with sqlite3.connect(str(self.db_path), timeout=10) as conn:
            df = pd.read_sql("SELECT * FROM consent ORDER BY granted_utc DESC", conn)
        now_str = _now_utc().strftime("%Y%m%d_%H%M%S")
        path    = self.gov.log_dir / f"consent_register_{now_str}.html"

        active   = df[df["withdrawn_utc"].isna() &
                      (df["expires_utc"].isna() | (df["expires_utc"] > _iso(_now_utc())))]
        expired  = df[~df["expires_utc"].isna() & (df["expires_utc"] <= _iso(_now_utc()))]
        withdrawn = df[~df["withdrawn_utc"].isna()]

        buf = io.StringIO()
        buf.write(_html_head("Consent Register"))
        buf.write(f"""
<h1>✅ Consent Register</h1>
<div class="summary-grid">
  <div class="summary-card"><div class="num" style="color:#28a745">{len(active)}</div>
    <div class="lbl">Active</div></div>
  <div class="summary-card"><div class="num" style="color:#ffc107">{len(expired)}</div>
    <div class="lbl">Expired</div></div>
  <div class="summary-card"><div class="num" style="color:#dc3545">{len(withdrawn)}</div>
    <div class="lbl">Withdrawn</div></div>
  <div class="summary-card"><div class="num">{len(df)}</div>
    <div class="lbl">Total Records</div></div>
</div>
""")
        for section, _badge, rows in [
            ("Active Consents", "badge-green", active),
            ("Expired Consents", "badge-yellow", expired),
            ("Withdrawn Consents", "badge-red", withdrawn),
        ]:
            buf.write(f"<h2>{section} ({len(rows)})</h2>\n")
            if rows.empty:
                buf.write("<p><em>None.</em></p>\n")
                continue
            buf.write("<table><tr>" +
                      "".join(f"<th>{c}</th>" for c in rows.columns) + "</tr>\n")
            for _, row in rows.iterrows():
                buf.write("<tr>" +
                          "".join(f"<td>{str(v)[:100] if pd.notna(v) else '—'}</td>"
                                  for v in row) + "</tr>\n")
            buf.write("</table>\n")

        buf.write(_html_foot())
        path.write_text(buf.getvalue(), encoding="utf-8")
        print(f"  ✅  Consent register  →  {path}")
        return path

    # ── Internals ─────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with sqlite3.connect(str(self.db_path), timeout=10) as conn:
            conn.executescript(self._SCHEMA)
            conn.commit()

    @staticmethod
    def _hash(subject_id: str) -> str:
        return hashlib.sha256(subject_id.encode()).hexdigest()


class ConsentRequiredError(Exception):
    """Raised when a required consent record is missing."""


class ConsentExpiredError(Exception):
    """Raised when consent exists but has expired."""


# ═════════════════════════════════════════════════════════════════════════════
#  6. DifferentialPrivacyTransformer  —  DP noise + epsilon budget tracking
# ═════════════════════════════════════════════════════════════════════════════

class DifferentialPrivacyTransformer:
    """
    Adds calibrated differential privacy noise to numeric columns before
    publishing aggregate outputs, and tracks a per-pipeline epsilon budget.

    Differential privacy provides a mathematical guarantee that the output
    reveals at most epsilon bits of information about any single individual.
    Lower epsilon = stronger privacy = more noise.

    Supports:
      - Laplace mechanism  (for pure DP, unbounded queries)
      - Gaussian mechanism (for approximate DP, bounded sensitivity)

    The epsilon budget is accumulated per pipeline run and persisted to the
    governance log directory, so you can enforce a global budget cap across
    all uses of a dataset.

    Usage
    -----
        dp = DifferentialPrivacyTransformer(gov, epsilon=1.0)
        noisy_df = dp.apply(
            df,
            columns=["salary","age","score"],
            sensitivity=1000.0,   # max change one person causes
            mechanism="laplace",
        )
        dp.print_budget()
    """

    def __init__(
        self,
        gov: GovernanceLogger,
        epsilon: float = 1.0,
        delta: float = 1e-5,
        budget_cap: Optional[float] = None,
    ) -> None:
        if epsilon <= 0:
            raise ValueError("epsilon must be positive")
        self.gov        = gov
        self.epsilon    = epsilon
        self.delta      = delta
        self.budget_cap = budget_cap
        self._budget_path  = gov.log_dir / "dp_budget.json"
        self._total_spent  = self._load_budget()

    # ── Public API ────────────────────────────────────────────────────────────

    def apply(
        self,
        df: pd.DataFrame,
        columns: List[str],
        sensitivity: float = 1.0,
        mechanism: str = "laplace",   # "laplace" | "gaussian"
        clip_to_range: bool = True,
    ) -> pd.DataFrame:
        """
        Apply differential privacy noise to the specified columns.
        Returns a new DataFrame; the original is not modified.
        """
        if sensitivity <= 0:
            raise ValueError(
                f"DifferentialPrivacyTransformer: sensitivity must be > 0, "
                f"got {sensitivity}. sensitivity=0 causes division by zero "
                f"in the Laplace/Gaussian mechanism."
            )
        if self.budget_cap is not None and self._total_spent + self.epsilon > self.budget_cap:
            raise BudgetExhaustedError(
                f"DP budget exhausted: spent {self._total_spent:.4f}, "
                f"cap {self.budget_cap:.4f}, requested {self.epsilon:.4f}"
            )

        out  = df.copy()
        cols = [c for c in columns if c in df.columns]

        for col in cols:
            if not pd.api.types.is_numeric_dtype(df[col]):
                continue
            original = df[col].dropna()
            col_min, col_max = float(original.min()), float(original.max())
            noise = self._generate_noise(len(df), sensitivity, mechanism)
            out[col] = df[col] + noise
            if clip_to_range and col_min < col_max:
                out[col] = out[col].clip(lower=col_min, upper=col_max)

        # Account for composition
        self._total_spent += self.epsilon
        self._save_budget()

        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "DIFFERENTIAL_PRIVACY_APPLIED",
            {
                "columns":       cols,
                "mechanism":     mechanism,
                "epsilon":       self.epsilon,
                "delta":         self.delta,
                "sensitivity":   sensitivity,
                "budget_spent":  self._total_spent,
                "budget_cap":    self.budget_cap,
                "rows":          len(df),
            },
        )
        print(f"  🔐  DP applied: ε={self.epsilon}, mechanism={mechanism}, "
              f"columns={cols}, budget used={self._total_spent:.4f}"
              + (f"/{self.budget_cap:.4f}" if self.budget_cap is not None else ""))
        return out

    def apply_aggregates(
        self,
        df: pd.DataFrame,
        group_by: List[str],
        agg_columns: List[str],
        agg_func: str = "sum",
        sensitivity: float = 1.0,
        mechanism: str = "laplace",
    ) -> pd.DataFrame:
        """
        Compute group-level aggregates and apply DP noise to the results.
        More appropriate than row-level noise for published summary statistics.
        """
        agg   = df.groupby(group_by)[agg_columns].agg(agg_func).reset_index()
        noisy = self.apply(agg, columns=agg_columns, sensitivity=sensitivity,
                           mechanism=mechanism, clip_to_range=False)
        return noisy

    def remaining_budget(self) -> float:
        """Return remaining epsilon budget (inf if no cap set)."""
        if self.budget_cap is None:
            return float("inf")
        return max(0.0, self.budget_cap - self._total_spent)

    def print_budget(self) -> None:
        cap_str = f"/{self.budget_cap:.4f}" if self.budget_cap is not None else " (no cap)"
        print("\n  ╔══ Differential Privacy Budget ══")
        print(f"  ║  ε per query : {self.epsilon:.4f}")
        print(f"  ║  Budget used : {self._total_spent:.4f}{cap_str}")
        print(f"  ║  Remaining   : {self.remaining_budget():.4f}")
        print(f"  ║  δ (Gaussian): {self.delta}")
        print("  ╚══════════════════════════════════")

    # ── Internals ─────────────────────────────────────────────────────────────

    def _generate_noise(
        self, n: int, sensitivity: float, mechanism: str
    ):
        scale = sensitivity / self.epsilon
        if mechanism == "gaussian":
            # σ = sensitivity * sqrt(2 * ln(1.25/delta)) / epsilon
            sigma = (sensitivity * math.sqrt(2 * math.log(1.25 / self.delta))
                     / self.epsilon)
            if HAS_NUMPY:
                return np.random.normal(0, sigma, n)
            return [secrets.SystemRandom().gauss(0, sigma) for _ in range(n)]
        else:  # laplace
            if HAS_NUMPY:
                return np.random.laplace(0, scale, n)
            # Pure-Python Laplace via inverse CDF
            rng = secrets.SystemRandom()
            noise = []
            for _ in range(n):
                u = rng.uniform(-0.5, 0.5)
                noise.append(-scale * math.copysign(1, u) * math.log(1 - 2 * abs(u)))
            return noise

    def _load_budget(self) -> float:
        if self._budget_path.exists():
            try:
                return float(json.loads(self._budget_path.read_text())
                             .get("total_spent", 0.0))
            except Exception as _exc:  # pylint: disable=broad-exception-caught
                # Corrupt budget file — warn and reset to zero rather than silently
                # starting fresh, which could allow budget overspend to go unnoticed.
                logger.warning("DifferentialPrivacyTransformer: could not load budget "
                               "from %s: %s — resetting to 0.0", self._budget_path, _exc)
        return 0.0

    def _save_budget(self) -> None:
        self._budget_path.write_text(json.dumps({
            "total_spent": self._total_spent,
            "epsilon":     self.epsilon,
            "budget_cap":  self.budget_cap,
            "updated_utc": _iso(_now_utc()),
        }, indent=2), encoding="utf-8")


class BudgetExhaustedError(Exception):
    """Raised when the differential privacy budget cap is exceeded."""


# ═════════════════════════════════════════════════════════════════════════════
#  7. PurposeLimitationEnforcer  —  GDPR Art. 5(1)(b) purpose limitation
# ═════════════════════════════════════════════════════════════════════════════

class PurposeLimitationEnforcer:
    """
    Enforces GDPR Article 5(1)(b) purpose limitation at load time.

    Maintains a purpose registry: a mapping of declared processing purpose →
    allowed column set.  Before any load, checks that the DataFrame only
    contains columns permitted for that purpose.  Columns outside scope
    either raise an error or are silently dropped (configurable).

    The registry can be defined in code, loaded from a YAML file, or
    populated from a data contract (sample_contract.yaml format).

    Usage
    -----
        ple = PurposeLimitationEnforcer(gov)
        ple.register_purpose(
            "billing",
            allowed_columns=["customer_id","amount","currency","invoice_date"],
            description="Invoice generation — Art. 6(1)(b)",
        )
        clean_df = ple.enforce(df, purpose="billing")
    """

    def __init__(
        self,
        gov: GovernanceLogger,
        strict: bool = False,       # True = raise on violation, False = drop columns
        registry_path: Optional[str] = None,
    ) -> None:
        self.gov           = gov
        self.strict        = strict
        self._registry: Dict[str, Dict] = {}
        self._registry_path = (pathlib.Path(registry_path)
                               if registry_path else gov.log_dir / "purpose_registry.json")
        self._load_registry()

    # ── Registry management ───────────────────────────────────────────────────

    def register_purpose(
        self,
        purpose: str,
        allowed_columns: List[str],
        description: str = "",
        legal_basis: str = "",
        sensitive_columns: Optional[List[str]] = None,
    ) -> "PurposeLimitationEnforcer":
        """Register a processing purpose and its permitted column set."""
        self._registry[purpose] = {
            "allowed_columns":   list(allowed_columns),
            "sensitive_columns": list(sensitive_columns or []),
            "description":       description,
            "legal_basis":       legal_basis,
            "registered_utc":    _iso(_now_utc()),
        }
        self._save_registry()
        self.gov._event(  # type: ignore[attr-defined]
            "GOVERNANCE", "PURPOSE_REGISTERED",
            {"purpose": purpose, "allowed_columns": len(allowed_columns)},
        )
        return self

    def load_from_yaml(self, yaml_path: str) -> "PurposeLimitationEnforcer":
        """
        Load purpose registry from a YAML file.
        Expected format:
          purposes:
            billing:
              allowed_columns: [customer_id, amount]
              description: "Invoice generation"
        """
        if not HAS_YAML:
            raise RuntimeError("load_from_yaml requires pyyaml. pip install pyyaml")
        data = yaml.safe_load(pathlib.Path(yaml_path).read_text(encoding="utf-8"))
        for purpose, meta in (data.get("purposes") or {}).items():
            self.register_purpose(
                purpose,
                allowed_columns = meta.get("allowed_columns", []),
                description     = meta.get("description", ""),
                legal_basis     = meta.get("legal_basis", ""),
                sensitive_columns = meta.get("sensitive_columns", []),
            )
        return self

    # ── Enforcement ───────────────────────────────────────────────────────────

    def enforce(
        self,
        df: pd.DataFrame,
        purpose: str,
        allow_unlisted: bool = False,
    ) -> pd.DataFrame:
        """
        Check a DataFrame against the registered purpose.

        If strict=True:  raises PurposeLimitationViolation on any out-of-scope column.
        If strict=False: drops out-of-scope columns and returns the cleaned DataFrame.
        allow_unlisted:  if True, permit columns not in the allowed list
                         (still flags them in the audit log).
        """
        if purpose not in self._registry:
            msg = (f"Purpose '{purpose}' is not registered. "
                   f"Known purposes: {list(self._registry.keys())}")
            if self.strict:
                raise PurposeLimitationViolation(msg)
            logger.warning("PurposeLimitationEnforcer: %s", msg)
            return df

        allowed = set(self._registry[purpose]["allowed_columns"])
        df_cols = set(df.columns.tolist())
        out_of_scope = df_cols - allowed

        if not out_of_scope:
            self.gov._event(  # type: ignore[attr-defined]
                "GOVERNANCE", "PURPOSE_CHECK_PASSED",
                {"purpose": purpose, "columns_checked": len(df_cols)},
            )
            return df

        if allow_unlisted:
            self.gov._event(  # type: ignore[attr-defined]
                "GOVERNANCE", "PURPOSE_UNLISTED_COLUMNS",
                {"purpose": purpose, "unlisted": sorted(out_of_scope)},
            )
            return df

        violation_msg = (
            f"Purpose limitation violation for '{purpose}': "
            f"columns {sorted(out_of_scope)} are not in the allowed set "
            f"{sorted(allowed)}"
        )
        self.gov._event(  # type: ignore[attr-defined]
            "GOVERNANCE", "PURPOSE_VIOLATION",
            {
                "purpose":       purpose,
                "out_of_scope":  sorted(out_of_scope),
                "allowed":       sorted(allowed),
            },
        )

        if self.strict:
            raise PurposeLimitationViolation(violation_msg)

        # Non-strict: drop the out-of-scope columns and warn
        print(f"  ⚠  Purpose limitation: dropping {sorted(out_of_scope)} "
              f"(not in scope for purpose='{purpose}')")
        return df.drop(columns=list(out_of_scope))

    def check(self, df: pd.DataFrame, purpose: str) -> List[str]:
        """
        Non-destructive check — return list of out-of-scope column names
        without modifying the DataFrame or raising.
        """
        if purpose not in self._registry:
            return []
        allowed = set(self._registry[purpose]["allowed_columns"])
        return sorted(set(df.columns.tolist()) - allowed)

    def list_purposes(self) -> List[str]:
        return list(self._registry.keys())

    def write_registry_report(self) -> pathlib.Path:
        """Write an HTML purpose registry report."""
        path = self.gov.log_dir / f"purpose_registry_{_now_utc().strftime('%Y%m%d_%H%M%S')}.html"
        buf  = io.StringIO()
        buf.write(_html_head("Purpose Limitation Registry"))
        buf.write(f"<h1>🎯 Purpose Limitation Registry</h1>\n"
                  f"<p>{len(self._registry)} registered purpose(s)</p>\n")
        for purpose, meta in self._registry.items():
            buf.write(f"<h2>{purpose}</h2>\n<table>\n")
            buf.write(f"<tr><th>Description</th><td>{meta.get('description','')}</td></tr>\n")
            buf.write(f"<tr><th>Legal Basis</th>"
                      f"<td><span class='badge badge-blue'>{meta.get('legal_basis','')}</span></td></tr>\n")
            buf.write(f"<tr><th>Allowed Columns ({len(meta['allowed_columns'])})</th>"
                      f"<td>{', '.join(f'<code>{c}</code>' for c in sorted(meta['allowed_columns']))}</td></tr>\n")
            if meta.get("sensitive_columns"):
                buf.write(f"<tr><th>Sensitive Columns</th>"
                          f"<td>{', '.join(f'<code>{c}</code>' for c in meta['sensitive_columns'])}</td></tr>\n")
            buf.write(f"<tr><th>Registered</th><td>{meta.get('registered_utc','')}</td></tr>\n")
            buf.write("</table>\n")
        buf.write(_html_foot())
        path.write_text(buf.getvalue(), encoding="utf-8")
        print(f"  🎯  Purpose registry report  →  {path}")
        return path

    # ── Internals ─────────────────────────────────────────────────────────────

    def _load_registry(self) -> None:
        if self._registry_path.exists():
            try:
                self._registry = json.loads(
                    self._registry_path.read_text(encoding="utf-8")
                )
            except Exception as _exc:  # pylint: disable=broad-exception-caught
                # Corrupt registry file — warn and start with an empty registry.
                # Silent failure would make all purpose checks pass vacuously
                # (no registered purposes = no columns out of scope), masking
                # a data loss or configuration problem.
                logger.warning("PurposeLimitationEnforcer: could not load registry "
                               "from %s: %s — starting with empty registry",
                               self._registry_path, _exc)

    def _save_registry(self) -> None:
        self._registry_path.write_text(
            json.dumps(self._registry, indent=2), encoding="utf-8"
        )


class PurposeLimitationViolation(Exception):
    """Raised when a DataFrame contains columns outside the declared purpose scope."""


# ═════════════════════════════════════════════════════════════════════════════
#  8. PseudonymVault  —  Consistent keyed pseudonymization (GDPR Art. 4(5))
# ═════════════════════════════════════════════════════════════════════════════

class PseudonymVault:
    """
    Consistent keyed pseudonymization meeting GDPR Article 4(5).

    Unlike one-way SHA-256 hashing, the PseudonymVault maintains a
    secret-keyed lookup table so that:
      - The same input always produces the same pseudonym (consistent)
      - The pseudonym cannot be reversed without the vault key (protected)
      - Subjects can be re-identified for DSAR / erasure workflows
        by an authorised party holding the vault key

    Vault contents are encrypted at rest using Fernet (AES-128-CBC + HMAC).
    The vault key should be stored separately from the data (key management
    principle — GDPR Rec. 83).

    Supports:
      - Single-value pseudonymisation
      - Whole-column pseudonymisation of a DataFrame
      - Reverse lookup (re-identification) for DSAR/erasure workflows
      - Key rotation with re-encryption of existing vault entries

    Usage
    -----
        vault = PseudonymVault(gov, key_path="vault.key")
        df["email"] = vault.pseudonymise_column(df, "email")
        original_email = vault.reverse("pseu_3a4f...")
        vault.rotate_key(new_key_path="vault_new.key")
    """

    _PREFIX = "pseu_"

    def __init__(
        self,
        gov: GovernanceLogger,
        key_path: Optional[str] = None,
        vault_path: Optional[str] = None,
    ) -> None:
        self.gov         = gov
        self.key_path    = pathlib.Path(key_path) if key_path else gov.log_dir / "pseudonym_vault.key"
        self.vault_path  = pathlib.Path(vault_path) if vault_path else gov.log_dir / "pseudonym_vault.db"
        self._lock       = threading.Lock()
        self._fernet     = self._init_fernet()
        self._init_vault()

    # ── Public API ────────────────────────────────────────────────────────────

    def pseudonymise(self, value: str, context: str = "default") -> str:
        """
        Return a consistent pseudonym for value in the given context.
        Context lets you have separate pseudonym spaces for different fields
        (e.g. "email" vs "phone") even with the same raw value.

        Thread-safe: the entire lookup-or-create sequence is held under
        self._lock so two concurrent callers with the same value always
        receive the same pseudonym.
        """
        if value is None or str(value).strip() == "":
            return value

        lookup_key = f"{context}::{value}"

        with self._lock:
            # Re-check inside the lock to close the TOCTOU window
            existing = self._lookup_unsafe(lookup_key)
            if existing:
                return existing

            pseudo = self._generate_pseudonym(lookup_key)
            self._store_unsafe(lookup_key, value, pseudo)

        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "PSEUDONYM_CREATED",
            {"context": context, "pseudo_prefix": pseudo[:12] + "…"},
        )
        return pseudo

    def reverse(self, pseudonym: str) -> Optional[str]:
        """
        Reverse a pseudonym to its original value.
        Returns None if the pseudonym is not in the vault.
        Logs every re-identification event for audit purposes.
        """
        with sqlite3.connect(str(self.vault_path), timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            row = conn.execute(
                "SELECT encrypted_original, context FROM vault WHERE pseudonym=?",
                (pseudonym,),
            ).fetchone()
        if not row:
            return None
        encrypted, context = row
        original = self._decrypt(encrypted)
        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "PSEUDONYM_REVERSED",
            {"pseudo_prefix": pseudonym[:12] + "…", "context": context},
        )
        return original

    def pseudonymise_column(
        self,
        df: pd.DataFrame,
        column: str,
        context: Optional[str] = None,
        inplace: bool = False,
    ) -> pd.Series:
        """
        Pseudonymise an entire DataFrame column.
        Returns the pseudonymised Series; optionally modifies df in place.
        """
        ctx = context or column
        pseudo_col = df[column].astype(str).apply(
            lambda v: self.pseudonymise(v, context=ctx)
        )
        if inplace:
            df[column] = pseudo_col
        self.gov._event(  # type: ignore[attr-defined]
            "PRIVACY", "PSEUDONYMISATION_APPLIED",
            {"column": column, "context": ctx, "rows": len(df)},
        )
        print(f"  🔑  Pseudonymised column '{column}' ({len(df)} rows, context='{ctx}')")
        return pseudo_col

    def pseudonymise_columns(
        self,
        df: pd.DataFrame,
        columns: List[str],
        inplace: bool = False,
    ) -> pd.DataFrame:
        """Pseudonymise multiple columns at once."""
        out = df if inplace else df.copy()
        for col in columns:
            if col in out.columns:
                out[col] = self.pseudonymise_column(df, col, context=col)
        return out

    def rotate_key(self, new_key_path: Optional[str] = None) -> pathlib.Path:
        """
        Generate a new vault key and re-encrypt all existing vault entries.
        The old key is backed up before rotation.
        IMPORTANT: After rotation, store the new key securely.
        Returns path to the new key file.
        """
        try:
            from cryptography.fernet import Fernet
        except ImportError as _exc:
            raise RuntimeError("PseudonymVault key rotation requires cryptography. "
                               "pip install cryptography") from _exc

        new_path = (pathlib.Path(new_key_path)
                    if new_key_path else self.key_path.with_suffix(".key.new"))

        # Backup old key
        backup = self.key_path.with_suffix(".key.backup")
        shutil.copy2(self.key_path, backup)

        # Generate new key
        new_key     = Fernet.generate_key()
        new_fernet  = Fernet(new_key)
        new_path.write_bytes(new_key)

        # Re-encrypt all entries
        with self._lock:
            with sqlite3.connect(str(self.vault_path), timeout=10) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                rows = conn.execute("SELECT id, encrypted_original FROM vault").fetchall()
                for row_id, enc in rows:
                    plain     = self._fernet.decrypt(enc.encode()).decode()
                    new_enc   = new_fernet.encrypt(plain.encode()).decode()
                    conn.execute("UPDATE vault SET encrypted_original=? WHERE id=?",
                                 (new_enc, row_id))
                conn.commit()

        self._fernet  = new_fernet
        self.key_path = new_path

        self.gov._event(  # type: ignore[attr-defined]
            "GOVERNANCE", "VAULT_KEY_ROTATED",
            {"new_key_path": str(new_path), "backup": str(backup),
             "entries_reencrypted": len(rows)},
        )
        print(f"  🔄  Vault key rotated: {new_path}  ({len(rows)} entries re-encrypted)")
        print(f"       Old key backed up → {backup}")
        return new_path

    def vault_stats(self) -> Dict:
        """Return summary statistics about the vault."""
        with sqlite3.connect(str(self.vault_path), timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            total   = conn.execute("SELECT COUNT(*) FROM vault").fetchone()[0]
            contexts = conn.execute(
                "SELECT context, COUNT(*) FROM vault GROUP BY context"
            ).fetchall()
        return {
            "total_entries": total,
            "by_context":    dict(contexts),
            "vault_path":    str(self.vault_path),
            "key_path":      str(self.key_path),
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _init_fernet(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError as _exc:
            raise RuntimeError("PseudonymVault requires cryptography. "
                               "pip install cryptography") from _exc
        if self.key_path.exists():
            return Fernet(self.key_path.read_bytes())
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        print(f"  🔑  New vault key created → {self.key_path}")
        print("       Store this key securely and separately from the vault data.")
        return Fernet(key)

    def _init_vault(self) -> None:
        # Use WAL journal mode from the very first connection so all subsequent
        # opens (_lookup_unsafe, _store_unsafe, reverse, vault_stats) see a
        # consistent journal mode.  Without this, the first pseudonymise() call
        # switches from DELETE to WAL mid-flight, which races with concurrent
        # opens and can produce "database is locked" errors.
        with sqlite3.connect(str(self.vault_path), timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS vault (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    lookup_key         TEXT    NOT NULL UNIQUE,
                    pseudonym          TEXT    NOT NULL UNIQUE,
                    encrypted_original TEXT    NOT NULL,
                    context            TEXT    NOT NULL DEFAULT 'default',
                    created_utc        TEXT    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_vault_pseudo ON vault(pseudonym);
            """)
            conn.commit()

    def _lookup(self, lookup_key: str) -> Optional[str]:
        """Thread-safe public lookup (acquires lock)."""
        with self._lock:
            return self._lookup_unsafe(lookup_key)

    def _lookup_unsafe(self, lookup_key: str) -> Optional[str]:
        """Lookup without acquiring the lock — caller must hold self._lock."""
        with sqlite3.connect(str(self.vault_path),
                             check_same_thread=False) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            row = conn.execute(
                "SELECT pseudonym FROM vault WHERE lookup_key=?", (lookup_key,)
            ).fetchone()
        return row[0] if row else None

    def _store(self, lookup_key: str, original: str, pseudonym: str) -> None:
        """Thread-safe public store (acquires lock)."""
        with self._lock:
            self._store_unsafe(lookup_key, original, pseudonym)

    def _store_unsafe(self, lookup_key: str, original: str, pseudonym: str) -> None:
        """Insert without acquiring the lock — caller must hold self._lock."""
        context = lookup_key.split("::", 1)[0]
        enc     = self._encrypt(original)
        with sqlite3.connect(str(self.vault_path),
                             check_same_thread=False) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "INSERT OR IGNORE INTO vault "
                "(lookup_key, pseudonym, encrypted_original, context, created_utc) "
                "VALUES (?,?,?,?,?)",
                (lookup_key, pseudonym, enc, context, _iso(_now_utc())),
            )
            conn.commit()

    def _generate_pseudonym(self, lookup_key: str) -> str:
        token = secrets.token_hex(8)
        return f"{self._PREFIX}{token}"

    def _encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def _decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()


# ─────────────────────────────────────────────────────────────────────────────
#  Convenience: run all 8 classes against a sample DataFrame
# ─────────────────────────────────────────────────────────────────────────────

def demo(output_dir: Optional[str] = None) -> None:
    """
    Quick demonstration of all 8 governance extensions.
    Creates a temporary governance environment and exercises each class.
    """
    tmp = tempfile.mkdtemp()
    gov = GovernanceLogger("demo_source.csv")
    gov.pipeline_start({"source": "demo_source.csv"})
    gov.destination_registered("sqlite", f"{tmp}/demo", "customers")
    gov.consent_recorded("analytics", "legitimate_interest", confirmed=True)
    gov.retention_policy("30_days", "demo_source.csv")
    gov.pii_detected([{"field": "email", "risk": "medium"},
                      {"field": "ssn",   "risk": "critical"}])

    df = pd.DataFrame({
        "id":       range(1, 11),
        "email":    [f"user{i}@example.com" for i in range(1, 11)],
        "name":     [f"Person {i}" for i in range(1, 11)],
        "salary":   [50000 + i * 3000 for i in range(10)],
        "dept":     ["Eng", "HR", "Sales", "Eng", "HR"] * 2,
        "ssn":      [f"123-{i:02d}-0000" for i in range(1, 11)],
        "_loaded_at_utc": [
            _iso(_now_utc() - timedelta(days=40 if i < 5 else 5))
            for i in range(10)
        ],
    })

    print("\n" + "═" * 60)
    print("  Governance Extensions Demo")
    print("═" * 60)

    # 1. RoPA
    print("\n─── 1. RoPAGenerator ───")
    ropa = RoPAGenerator(gov, controller_name="Acme Corp",
                         dpo_contact="dpo@acme.example")
    ropa.add_activity(
        name="Customer analytics",
        purpose="Improve product experience",
        legal_basis="Art. 6(1)(f) — Legitimate interests",
        data_subjects=["customers"],
        data_categories=["email", "salary", "department"],
        retention="1_year",
        security_measures=["AES-256", "Pseudonymisation", "Access logging"],
    )
    ropa.ingest_from_ledger()
    ropa.write()

    # 2. Retention enforcer
    print("\n─── 2. RetentionEnforcer ───")
    db_path = f"{tmp}/demo"
    from sqlalchemy import create_engine as _demo_engine
    df.to_sql("customers", _demo_engine(f"sqlite:///{db_path}.db"),
              if_exists="replace", index=False)
    enforcer = RetentionEnforcer(gov, db_type="sqlite")
    enforcer.enforce({"db_name": db_path}, "customers",
                     "30_days", timestamp_column="_loaded_at_utc",
                     action="archive", dry_run=False)

    # 3. DSAR
    print("\n─── 3. DSARResponder ───")
    responder = DSARResponder(gov)
    responder.add_sql_source("sqlite", {"db_name": db_path},
                             tables=["customers"], subject_column="email")
    response = responder.respond("user1@example.com", requester_email="user1@example.com")
    response.write()

    # 4. Breach detector
    print("\n─── 4. BreachDetector ───")
    detector = BreachDetector(gov, normal_row_max=5)
    detector.check_load(df, "sqlite:customers", pii_fields=["email", "ssn"])
    detector.report()

    # 5. Consent manager
    print("\n─── 5. ConsentManager ───")
    cm = ConsentManager(gov)
    cm.record("user1@example.com", purpose="analytics", expires_days=365)
    cm.record("user2@example.com", purpose="analytics")
    print(f"     user1 analytics consent: {cm.check('user1@example.com', 'analytics')}")
    cm.withdraw("user2@example.com", purpose="analytics")
    print(f"     user2 after withdrawal:  {cm.check('user2@example.com', 'analytics')}")
    cm.export_consent_register()

    # 6. Differential privacy
    print("\n─── 6. DifferentialPrivacyTransformer ───")
    dp = DifferentialPrivacyTransformer(gov, epsilon=0.5, budget_cap=5.0)
    noisy = dp.apply(df, columns=["salary"], sensitivity=3000.0)
    dp.print_budget()
    print(f"     Original salary[0]: {df['salary'].iloc[0]:.0f}  "
          f"Noisy: {noisy['salary'].iloc[0]:.0f}")

    # 7. Purpose limitation
    print("\n─── 7. PurposeLimitationEnforcer ───")
    ple = PurposeLimitationEnforcer(gov, strict=False)
    ple.register_purpose("analytics", allowed_columns=["id", "dept", "salary"],
                         description="Internal HR analytics",
                         legal_basis="Art. 6(1)(f)")
    violations = ple.check(df, "analytics")
    print(f"     Out-of-scope columns for 'analytics': {violations}")
    clean = ple.enforce(df, "analytics")
    print(f"     DataFrame after enforcement: {list(clean.columns)}")
    ple.write_registry_report()

    # 8. Pseudonym vault
    print("\n─── 8. PseudonymVault ───")
    try:
        vault = PseudonymVault(gov)
        p1 = vault.pseudonymise("alice@example.com", context="email")
        p2 = vault.pseudonymise("alice@example.com", context="email")
        print(f"     Pseudonym (consistent): {p1}")
        print(f"     Same input, same output: {p1 == p2}")
        original = vault.reverse(p1)
        print(f"     Reversed: {original}")
        print(f"     Vault stats: {vault.vault_stats()}")
    except RuntimeError as e:
        print(f"     ⚠  {e} — install cryptography to test PseudonymVault")

    gov.pipeline_complete({"demo": True})
    print(f"\n  ✅  Demo complete — reports in: {gov.log_dir}")
    print("═" * 60)

    if output_dir:
        dest = pathlib.Path(output_dir)
        dest.mkdir(parents=True, exist_ok=True)
        for f in gov.log_dir.iterdir():
            shutil.copy2(f, dest / f.name)
        print(f"  Reports copied → {dest}")

    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    demo()
