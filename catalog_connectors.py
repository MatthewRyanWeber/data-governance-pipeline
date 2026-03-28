"""
=============================================================
  CATALOG CONNECTORS  v1.0.0
  Data Catalog Integration for the Data Governance Pipeline
  Author: Data Governance Pipeline
=============================================================

PURPOSE
-------
Automatically registers every pipeline run's metadata with one or
more enterprise data catalogs after load completes.  Acts as a
"push" integration: the pipeline sends metadata to the catalog
rather than waiting for the catalog to discover it.

SUPPORTED CATALOGS
------------------
  ① Collibra DGC  — REST API (Collibra 2.0 REST)
                    Registers Table assets, Column assets, relations,
                    data quality scores, PII tags, retention policies,
                    and lineage graphs.

  ② Alation       — REST API (Alation v2 / Open Connector Framework)
                    Registers table and column metadata, custom fields
                    (PII flag, classification level), data quality info,
                    and trust flags.

  ③ Informatica   — REST API (Informatica CDGC / Axon Data Governance)
    Axon/CDGC       Registers assets, assigns business terms from the
                    Business Glossary, pushes quality scores, and logs
                    GDPR sensitivity metadata.

  ④ Atlan         — REST API + pyatlan SDK
                    Registers Table and Column assets with qualified names,
                    pushes PII custom metadata, data classification tags,
                    GX validation scores, lineage (Process assets), and
                    GDPR retention annotations.

WHAT GETS REGISTERED
--------------------
For every catalog, the following metadata is pushed after each pipeline run:

  Dataset registration
    • Table / dataset name and description
    • Source file path, format, SHA-256 fingerprint
    • Row count, column count
    • Pipeline ID and run timestamp

  Column-level metadata
    • Column name and inferred data type
    • PII flag (True/False)
    • Special-category flag (GDPR Art. 9)
    • Encryption status (encrypted / masked / plain)
    • Data classification level (RESTRICTED / CONFIDENTIAL / INTERNAL / PUBLIC)
    • Null rate and unique count (from profiling)

  Data quality
    • Number of GX expectations passed / failed / total
    • Overall validation result (pass / fail)
    • DLQ row count and rejection rate

  Lineage
    • Source file → pipeline process → destination table
    • Pipeline version, run ID, operator username

  GDPR / compliance
    • Lawful basis (GDPR Art. 6)
    • Processing purpose
    • Retention policy (days)
    • CCPA opt-out status
    • Cross-border transfer type and safeguard

ARCHITECTURE
------------
  BaseCatalogConnector (abstract)
    ├── CollibraConnector
    ├── AlationConnector
    ├── InformaticaAxonConnector
    └── AtlanConnector

  CatalogMetadataPayload  — immutable snapshot of all pipeline metadata
  CatalogManager          — orchestrates 1-N connectors in parallel
  build_catalog_payload() — constructs payload from GovernanceLogger state

AUTHENTICATION
--------------
Each catalog uses a different auth mechanism.  All credentials are resolved
via SecretsManager (env var → .env file → interactive prompt):

  Collibra   : COLLIBRA_URL, COLLIBRA_USER, COLLIBRA_PASSWORD
  Alation    : ALATION_URL, ALATION_API_TOKEN
  Axon/CDGC  : INFORMATICA_URL, INFORMATICA_CLIENT_ID, INFORMATICA_CLIENT_SECRET
               (OAuth2 client-credentials grant)
  Atlan      : ATLAN_URL, ATLAN_API_TOKEN

DEPENDENCIES
------------
  requests>=2.31  — all REST connectors
  pyatlan>=4.0    — Atlan SDK (optional; falls back to REST if absent)
  All standard library modules (json, logging, hashlib, etc.)

USAGE (standalone)
------------------
    from catalog_connectors import CatalogManager, build_catalog_payload

    payload  = build_catalog_payload(gov, source_path, db_type, db_cfg, table,
                                      pii_findings, compliance, profile, v_results)
    manager  = CatalogManager(secrets)
    manager.register_all(payload)

USAGE (integrated into pipeline_v3.py)
---------------------------------------
    # At the end of main(), after governance artefacts:
    if catalog_cfg:
        payload = build_catalog_payload(...)
        CatalogManager(secrets, catalog_cfg).register_all(payload)
=============================================================
"""

# ─────────────────────────────────────────────────────────────────────────────
#  STANDARD LIBRARY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import abc
# import base64  # noqa: unused
import hashlib
import json
import logging
# import os  # noqa: unused
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
#  THIRD-PARTY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from pyatlan.client.atlan import AtlanClient
    from pyatlan.model.assets import (
        Table   as AtlanTable,
    )
    from pyatlan.model.enums import (
        CertificateStatus,
    )
    HAS_PYATLAN = True
except ImportError:
    HAS_PYATLAN = False

log = logging.getLogger("CatalogConnectors")


# ═════════════════════════════════════════════════════════════════════════════
#  CATALOG METADATA PAYLOAD  (shared data contract between pipeline and catalogs)
# ═════════════════════════════════════════════════════════════════════════════
@dataclass
class ColumnMeta:
    """
    Metadata snapshot for a single column.

    Used by every catalog connector to register column-level attributes.
    """
    name:              str
    dtype:             str                # pandas dtype string (e.g. "object", "int64")
    is_pii:            bool   = False     # Matched a PII pattern
    is_special_category: bool = False     # GDPR Art. 9 special category
    gdpr_article:      str   = ""         # e.g. "Article 4(1)" or "Article 9"
    is_encrypted:      bool  = False      # Column-level AES-256 encryption applied
    is_masked:         bool  = False      # SHA-256 pseudonymisation applied
    classification:    str   = "PUBLIC"   # RESTRICTED / CONFIDENTIAL / INTERNAL / PUBLIC
    null_pct:          float = 0.0        # From DataProfiler (0.0 – 1.0)
    unique_count:      int   = 0          # From DataProfiler
    description:       str   = ""         # Auto-generated description
    # ⑤ Per-column GX quality (wired from ColumnQualityScorer in metadata_extensions)
    gx_pass_rate:      float | None = None  # 0.0–1.0 fraction of expectations passing
    gx_failures:       int   = 0            # Number of failed expectations for this column
    quality_score:     int   = 0            # 0-100 composite quality score (ColumnQualityScorer)


@dataclass
class DataQualityMeta:
    """
    Summary of Great Expectations validation results for a run.
    """
    suite_name:         str  = ""
    expectations_total: int  = 0
    expectations_passed:int  = 0
    expectations_failed:int  = 0
    overall_success:    bool = True
    dlq_rows:           int  = 0
    total_rows:         int  = 0

    @property
    def pass_rate(self) -> float:
        """Fraction of expectations that passed (0.0 – 1.0)."""
        return (self.expectations_passed / self.expectations_total
                if self.expectations_total else 1.0)

    @property
    def error_rate(self) -> float:
        """Fraction of rows sent to DLQ (0.0 – 1.0)."""
        return self.dlq_rows / self.total_rows if self.total_rows else 0.0


@dataclass
class LineageMeta:
    """
    Lineage information: source → pipeline process → destination.
    """
    source_path:       str  = ""
    source_format:     str  = ""
    source_sha256:     str  = ""
    pipeline_id:       str  = ""
    pipeline_version:  str  = "3.0.0"
    pipeline_name:     str  = "Data Governance Pipeline"
    operator:          str  = ""          # OS username who ran the pipeline
    run_timestamp:     str  = ""          # ISO-8601 UTC
    dest_db_type:      str  = ""
    dest_db_name:      str  = ""
    dest_table:        str  = ""
    rows_loaded:       int  = 0


@dataclass
class ComplianceMeta:
    """
    GDPR / CCPA compliance metadata for a pipeline run.
    """
    lawful_basis:         str         = ""
    processing_purpose:   str         = ""
    retention_days:       int | None  = None
    pii_strategy:         str         = "mask"
    data_classification:  str         = "CONFIDENTIAL"
    ccpa_opt_out:         bool        = False
    transfer_type:        str         = "DOMESTIC"
    transfer_safeguard:   str         = ""
    source_country:       str         = "US"
    dest_country:         str         = "US"
    gdpr_articles:        list[str]   = field(default_factory=lambda: ["Art. 5", "Art. 25", "Art. 30"])


@dataclass
class CatalogMetadataPayload:
    """
    Immutable snapshot of ALL pipeline metadata collected during a run.

    This is the single object passed to every catalog connector.  Building
    it once from the GovernanceLogger state decouples the connectors from
    the pipeline internals — each connector only sees this clean payload.

    Attributes
    ----------
    table_name    : str             Target table / collection name.
    database_name : str             Target database / file name.
    db_type       : str             Database type (sqlite, postgresql, etc.)
    description   : str             Auto-generated table description.
    columns       : list[ColumnMeta]  Per-column metadata.
    quality       : DataQualityMeta   GX validation summary.
    lineage       : LineageMeta       Source → pipeline → destination.
    compliance    : ComplianceMeta    GDPR / CCPA metadata.
    pipeline_id   : str             UUID of this run.
    run_timestamp : str             ISO-8601 UTC.
    tags          : list[str]       Free-form tags (e.g. "PII", "GDPR", "HR").
    """
    table_name:    str
    database_name: str
    db_type:       str
    description:   str
    columns:       list[ColumnMeta]
    quality:       DataQualityMeta
    lineage:       LineageMeta
    compliance:    ComplianceMeta
    pipeline_id:   str               = field(default_factory=lambda: str(uuid.uuid4()))
    run_timestamp: str               = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags:          list[str]         = field(default_factory=list)

    @property
    def pii_columns(self) -> list[ColumnMeta]:
        """Subset of columns that are flagged as PII."""
        return [c for c in self.columns if c.is_pii]

    @property
    def special_category_columns(self) -> list[ColumnMeta]:
        """Subset of columns that are GDPR Art. 9 special category."""
        return [c for c in self.columns if c.is_special_category]

    def to_dict(self) -> dict:
        """Serialise the entire payload to a plain dict for logging/debugging."""
        import dataclasses
        return dataclasses.asdict(self)


# ═════════════════════════════════════════════════════════════════════════════
#  PAYLOAD BUILDER  — constructs CatalogMetadataPayload from pipeline state
# ═════════════════════════════════════════════════════════════════════════════
def build_catalog_payload(
    gov,              # GovernanceLogger instance
    source_path:  str,
    db_type:      str,
    db_cfg:       dict,
    table:        str,
    pii_findings: list[dict],
    compliance:   dict,
    profile:      dict | None         = None,
    val_results:  list[dict] | None   = None,
    encrypted_cols: list[str]         = (),
    transfer_events: list[dict]       = (),
    rows_loaded:  int                 = 0,
    pipeline_version: str             = "3.0.0",
    col_quality_report: dict          = None,   # ⑤ from ColumnQualityScorer
) -> CatalogMetadataPayload:
    """
    Build a CatalogMetadataPayload from the runtime state of the pipeline.

    This function is the glue between the v3 pipeline's GovernanceLogger and
    the catalog connectors.  Call it once after the load completes and before
    any catalog registration calls.

    Parameters
    ----------
    gov             : GovernanceLogger  The pipeline's governance logger.
    source_path     : str               Path to the source file.
    db_type         : str               Database type string.
    db_cfg          : dict              Database config dict.
    table           : str               Target table name.
    pii_findings    : list[dict]        From _detect_pii().
    compliance      : dict              From run_compliance_wizard().
    profile         : dict|None         From DataProfiler.profile().
    val_results     : list[dict]|None   From GovernanceLogger.validation_results.
    encrypted_cols  : list[str]         Columns that were AES-256 encrypted.
    transfer_events : list[dict]        From GovernanceLogger.transfer_events.
    rows_loaded     : int               Total rows successfully loaded.
    pipeline_version: str               Pipeline version string.

    Returns
    -------
    CatalogMetadataPayload  Ready to pass to CatalogManager.register_all().
    """
    import getpass

    # ── Derive column metadata ─────────────────────────────────────────────
    pii_map     = {f["field"]: f for f in pii_findings}
    masked_cols = {f["field"] for f in pii_findings
                   if compliance.get("pii_strategy") == "mask"}
    cols_profile= (profile or {}).get("columns", {})

    columns: list[ColumnMeta] = []
    for col_name, col_stats in cols_profile.items():
        pii_info = pii_map.get(col_name, {})
        # Per-column GX results from ColumnQualityScorer (⑤).
        col_q = (col_quality_report or {}).get("columns", {}).get(col_name, {})
        # Derive per-column GX pass rate from validation results.
        col_vr = [r for r in (val_results or [])
                  if r.get("column") == col_name] if val_results else []
        gx_pass = (sum(1 for r in col_vr if r.get("success")) / len(col_vr)
                   if col_vr else None)
        col = ColumnMeta(
            name               = col_name,
            dtype              = col_stats.get("dtype", "object"),
            is_pii             = bool(pii_info),
            is_special_category= bool(pii_info.get("special_category", False)),
            gdpr_article       = pii_info.get("gdpr_reference", ""),
            is_encrypted       = col_name in list(encrypted_cols),
            is_masked          = col_name in masked_cols,
            classification     = (gov.classification_tags[-1]["classification_level"]
                                  if gov.classification_tags else "PUBLIC"),
            null_pct           = float(col_stats.get("null_pct", 0)),
            unique_count       = int(col_stats.get("unique_count", 0)),
            description        = _auto_describe_column(col_name, pii_info),
            gx_pass_rate       = gx_pass,
            gx_failures        = sum(1 for r in col_vr if not r.get("success")),
            quality_score      = int(col_q.get("score", 0)),
        )
        columns.append(col)

    # If profiling wasn't run, build minimal ColumnMeta from PII findings alone
    if not columns and pii_findings:
        for f in pii_findings:
            columns.append(ColumnMeta(
                name=f["field"], dtype="object",
                is_pii=True, is_special_category=f.get("special_category", False),
                gdpr_article=f.get("gdpr_reference",""),
                is_masked=f["field"] in masked_cols,
                description=_auto_describe_column(f["field"], f),
            ))

    # ── Data quality ────────────────────────────────────────────────────────
    vr   = val_results or []
    qual = DataQualityMeta(
        suite_name          = f"pipeline_suite_{gov.ledger_entries[0]['pipeline_id'][:8]}"
                              if gov.ledger_entries else "pipeline_suite",
        expectations_total  = len(vr),
        expectations_passed = sum(1 for r in vr if r.get("success")),
        expectations_failed = sum(1 for r in vr if not r.get("success")),
        overall_success     = all(r.get("success") for r in vr) if vr else True,
        dlq_rows            = gov.dlq_rows_total,
        total_rows          = rows_loaded,
    )

    # ── Lineage ────────────────────────────────────────────────────────────
    lin = LineageMeta(
        source_path      = source_path,
        source_format    = Path(source_path).suffix.lower(),
        source_sha256    = _safe_hash(source_path),
        pipeline_id      = gov.ledger_entries[0]["pipeline_id"]
                            if gov.ledger_entries else str(uuid.uuid4()),
        pipeline_version = pipeline_version,
        operator         = getpass.getuser(),
        run_timestamp    = datetime.now(timezone.utc).isoformat(),
        dest_db_type     = db_type,
        dest_db_name     = db_cfg.get("db_name", ""),
        dest_table       = table,
        rows_loaded      = rows_loaded,
    )

    # ── Compliance ─────────────────────────────────────────────────────────
    transfer = transfer_events[-1] if transfer_events else {}
    comp = ComplianceMeta(
        lawful_basis        = compliance.get("lawful_basis", "Legitimate Interests"),
        processing_purpose  = compliance.get("purpose", "Data pipeline"),
        retention_days      = compliance.get("retention_days"),
        pii_strategy        = compliance.get("pii_strategy", "mask"),
        data_classification = (gov.classification_tags[-1]["classification_level"]
                               if gov.classification_tags else "CONFIDENTIAL"),
        transfer_type       = transfer.get("transfer_type", "DOMESTIC"),
        transfer_safeguard  = transfer.get("safeguard", ""),
        source_country      = transfer.get("source_country", "US"),
        dest_country        = transfer.get("dest_country", "US"),
    )

    # ── Tags ───────────────────────────────────────────────────────────────
    tags = ["data-governance-pipeline", f"v{pipeline_version}"]
    if pii_findings:
        tags.append("contains-pii")
    if any(f.get("special_category") for f in pii_findings):
        tags.append("gdpr-article-9")
    tags.append(f"classification-{comp.data_classification.lower()}")
    tags.append(f"lawful-basis-{comp.lawful_basis.lower().replace(' ','-')}")

    # ── Description ────────────────────────────────────────────────────────
    pii_note = (f"Contains {len(pii_findings)} PII field(s), "
                f"strategy: {compliance.get('pii_strategy','mask')}. ")
    quality_note = (f"GX validation: {qual.pass_rate:.0%} pass rate. "
                    if qual.expectations_total else "")
    description = (
        f"Table loaded by Data Governance Pipeline v{pipeline_version} "
        f"from {Path(source_path).name}. "
        f"{pii_note}{quality_note}"
        f"Classification: {comp.data_classification}. "
        f"Retention: {comp.retention_days} days."
    )

    return CatalogMetadataPayload(
        table_name    = table,
        database_name = db_cfg.get("db_name", ""),
        db_type       = db_type,
        description   = description,
        columns       = columns,
        quality       = qual,
        lineage       = lin,
        compliance    = comp,
        pipeline_id   = lin.pipeline_id,
        run_timestamp = lin.run_timestamp,
        tags          = tags,
    )


def _auto_describe_column(name: str, pii_info: dict) -> str:
    """Generate a short description string for a column."""
    if not pii_info:
        return f"Column: {name}"
    art  = pii_info.get("gdpr_reference", "")
    note = " (GDPR Art. 9 special category)" if pii_info.get("special_category") else ""
    return f"PII field — {name}. {art}{note}. Handled per pipeline compliance config."


def _safe_hash(path: str) -> str:
    """Compute file SHA-256 hash, returning empty string if file unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb", encoding="utf-8") as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
        return h.hexdigest()
    except Exception:  # pylint: disable=broad-exception-caught
        return ""


# ═════════════════════════════════════════════════════════════════════════════
#  BASE CATALOG CONNECTOR  (abstract interface all connectors implement)
# ═════════════════════════════════════════════════════════════════════════════
class BaseCatalogConnector(abc.ABC):
    """
    Abstract base class for all data catalog connectors.

    Every connector must implement all abstract methods.  Non-abstract
    helper methods (_http_post, _http_patch, etc.) provide shared HTTP
    plumbing so concrete connectors stay focused on their API's specifics.

    Abstract methods
    ----------------
    connect()              — Authenticate and establish a session.
    register_dataset()     — Create or update the table/dataset asset.
    register_columns()     — Push column-level metadata.
    push_lineage()         — Register source → pipeline → destination lineage.
    push_data_quality()    — Push GX validation results as quality scores.
    push_pii_tags()        — Annotate PII columns.
    push_compliance()      — Push GDPR/CCPA metadata.
    disconnect()           — Close the session cleanly.

    All methods take a CatalogMetadataPayload as their primary argument.
    """

    def __init__(self, name: str, config: dict) -> None:
        """
        Parameters
        ----------
        name   : str   Human-readable connector name for logging.
        config : dict  Connector-specific configuration (URL, credentials, etc.)
        """
        self.name     = name
        self.config   = config
        self._session = None
        self.log      = logging.getLogger(f"CatalogConnectors.{name}")

    @abc.abstractmethod
    def connect(self) -> bool:
        """
        Authenticate with the catalog and establish a reusable session.

        Returns
        -------
        bool  True if authentication succeeded, False otherwise.
              If False, register_all() will skip this connector with a WARNING.
        """

    @abc.abstractmethod
    def register_dataset(self, payload: CatalogMetadataPayload) -> str:
        """
        Create or update the table/dataset asset in the catalog.

        Returns
        -------
        str  The catalog's internal asset ID for this table.
             Used by subsequent calls (register_columns, push_lineage, etc.)
             to associate related metadata with the correct asset.
        """

    @abc.abstractmethod
    def register_columns(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Push column-level metadata for all columns in the payload.

        Parameters
        ----------
        payload    : CatalogMetadataPayload
        dataset_id : str  Asset ID returned by register_dataset().
        """

    @abc.abstractmethod
    def push_lineage(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Register source file → pipeline process → destination table lineage.

        Parameters
        ----------
        payload    : CatalogMetadataPayload
        dataset_id : str  The destination table's catalog asset ID.
        """

    @abc.abstractmethod
    def push_data_quality(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Push Great Expectations validation results as data quality scores.

        Parameters
        ----------
        payload    : CatalogMetadataPayload
        dataset_id : str  The table's catalog asset ID.
        """

    @abc.abstractmethod
    def push_pii_tags(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Annotate PII columns with catalog tags / labels.

        Parameters
        ----------
        payload    : CatalogMetadataPayload
        dataset_id : str  The table's catalog asset ID.
        """

    @abc.abstractmethod
    def push_compliance(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Push GDPR / CCPA compliance metadata (lawful basis, retention, etc.).

        Parameters
        ----------
        payload    : CatalogMetadataPayload
        dataset_id : str  The table's catalog asset ID.
        """

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Close the session and release any held connections or tokens."""

    # ── Shared HTTP helpers ───────────────────────────────────────────────
    def _post(self, url: str, payload: dict, headers: dict = None,
               auth=None, timeout: int = 30) -> dict:
        """
        Execute an HTTP POST request and return the parsed JSON response.

        Retries once on 429 (rate-limited) and 503 (service unavailable).

        Parameters
        ----------
        url     : str   Full URL to POST to.
        payload : dict  JSON body.
        headers : dict  Additional HTTP headers (merged with Content-Type: application/json).
        auth    : tuple Basic auth credentials tuple or None.
        timeout : int   Request timeout in seconds.

        Returns
        -------
        dict  Parsed JSON response body, or {"error": str(e)} on failure.
        """
        if not HAS_REQUESTS:
            self.log.error("requests library not installed — cannot POST")
            return {}
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        for attempt in range(1, 3):
            try:
                resp = requests.post(url, json=payload, headers=hdrs,
                                     auth=auth, timeout=timeout)
                if resp.status_code in (429, 503) and attempt == 1:
                    self.log.warning("[%s] Rate limited (%s) — waiting 5s", self.name, resp.status_code)
                    time.sleep(5)
                    continue
                resp.raise_for_status()
                return resp.json() if resp.content else {}
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == 2:
                    self.log.error("[%s] POST %s failed: %s", self.name, url, exc)
                    return {"error": str(exc)}

    def _patch(self, url: str, payload: dict, headers: dict = None,
                auth=None, timeout: int = 30) -> dict:
        """Execute an HTTP PATCH request (for update operations)."""
        if not HAS_REQUESTS:
            return {}
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        try:
            resp = requests.patch(url, json=payload, headers=hdrs,
                                   auth=auth, timeout=timeout)
            resp.raise_for_status()
            return resp.json() if resp.content else {}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log.error("[%s] PATCH %s failed: %s", self.name, url, exc)
            return {"error": str(exc)}

    def _put(self, url: str, payload: dict, headers: dict = None,
              auth=None, timeout: int = 30) -> dict:
        """Execute an HTTP PUT request."""
        if not HAS_REQUESTS:
            return {}
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        try:
            resp = requests.put(url, json=payload, headers=hdrs,
                                 auth=auth, timeout=timeout)
            resp.raise_for_status()
            return resp.json() if resp.content else {}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log.error("[%s] PUT %s failed: %s", self.name, url, exc)
            return {"error": str(exc)}

    def _get(self, url: str, params: dict = None, headers: dict = None,
              auth=None, timeout: int = 30) -> dict:
        """Execute an HTTP GET request."""
        if not HAS_REQUESTS:
            return {}
        hdrs = {"Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        try:
            resp = requests.get(url, params=params, headers=hdrs,
                                 auth=auth, timeout=timeout)
            resp.raise_for_status()
            return resp.json() if resp.content else {}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log.error("[%s] GET %s failed: %s", self.name, url, exc)
            return {"error": str(exc)}


# ═════════════════════════════════════════════════════════════════════════════
#  COLLIBRA CONNECTOR
# ═════════════════════════════════════════════════════════════════════════════
class CollibraConnector(BaseCatalogConnector):
    """
    Registers pipeline metadata with Collibra DGC via the 2.0 REST API.

    Collibra concepts used
    ----------------------
    Asset types (built-in Collibra type IDs)
        00000000-0000-0000-0000-000000031007  Table
        00000000-0000-0000-0000-000000031008  Column
        00000000-0000-0000-0000-000000031106  Data File  (source)
        00000000-0000-0000-0000-000000007001  Technology Asset (pipeline)

    Attribute types
        00000000-0000-0000-0000-000000000222  Description
        00000000-0000-0000-0000-000000000238  Quality Score
        (custom attribute IDs configured via config["attribute_type_ids"])

    Relation types
        00000000-0000-0000-0000-000000007030  "has column"
        00000000-0000-0000-0000-000000007013  "has lineage to"
        (custom relation IDs configured via config["relation_type_ids"])

    Required config keys
    --------------------
    url            : str   Base URL, e.g. "https://myorg.collibra.com"
    username       : str   Collibra DGC username
    password       : str   Collibra DGC password
    community_id   : str   UUID of the Collibra community to place assets in
    domain_id      : str   UUID of the Collibra domain to place assets in

    Optional config keys
    --------------------
    attribute_type_ids : dict  Maps attribute name → Collibra attribute type UUID
                               Defaults to a built-in set for Description, Retention,
                               Classification, PII Flag, Quality Score.
    relation_type_ids  : dict  Maps relation name → Collibra relation type UUID
    """

    # ── Built-in Collibra type UUIDs (standard DGC 2.0 installation) ──────
    _ASSET_TYPE_TABLE     = "00000000-0000-0000-0000-000000031007"
    _ASSET_TYPE_COLUMN    = "00000000-0000-0000-0000-000000031008"
    _ASSET_TYPE_DATA_FILE = "00000000-0000-0000-0000-000000031106"
    _ASSET_TYPE_TECH      = "00000000-0000-0000-0000-000000007001"
    _ATTR_DESCRIPTION     = "00000000-0000-0000-0000-000000000222"
    _REL_HAS_COLUMN       = "00000000-0000-0000-0000-000000007030"
    _REL_LINEAGE          = "00000000-0000-0000-0000-000000007013"

    def __init__(self, config: dict) -> None:
        super().__init__("Collibra", config)
        self._base    = config["url"].rstrip("/") + "/rest/2.0"
        self._auth    = (config["username"], config["password"])
        self._token   = None   # JWT token if using token-based auth

        # Custom attribute type UUIDs — override in config if your DGC instance
        # has different IDs.  These are commonly-used defaults.
        self._attr_ids = {
            "description"      : self._ATTR_DESCRIPTION,
            "pii_flag"         : config.get("attr_pii_flag",         ""),
            "classification"   : config.get("attr_classification",    ""),
            "retention_days"   : config.get("attr_retention_days",    ""),
            "quality_score"    : config.get("attr_quality_score",     ""),
            "lawful_basis"     : config.get("attr_lawful_basis",      ""),
            "pipeline_id"      : config.get("attr_pipeline_id",       ""),
            "gdpr_article"     : config.get("attr_gdpr_article",      ""),
            **(config.get("attribute_type_ids", {})),
        }
        self._rel_ids = {
            "has_column": self._REL_HAS_COLUMN,
            "lineage"   : self._REL_LINEAGE,
            **(config.get("relation_type_ids", {})),
        }

    def connect(self) -> bool:
        """
        Authenticate with Collibra using Basic auth.

        Collibra's REST API supports Basic auth on every request; there is no
        separate session establishment.  We do a lightweight GET /ping to verify
        credentials and connectivity before proceeding.
        """
        resp = self._get(f"{self._base}/ping", auth=self._auth)
        if "error" in resp:
            self.log.error("[Collibra] Connection failed: %s", resp.get('error'))
            return False
        self.log.info("[Collibra] Connected successfully.")
        return True

    def register_dataset(self, payload: CatalogMetadataPayload) -> str:
        """
        Create a Table asset in Collibra DGC.

        POST /rest/2.0/assets
        The asset is placed in the community and domain configured in config.
        If an asset with the same name already exists in that domain, Collibra
        will return the existing asset ID (idempotent via externalEntityId).

        Returns the Collibra internal asset UUID.
        """
        body = {
            "name"       : payload.table_name,
            "displayName": payload.table_name,
            "typeId"     : self._ASSET_TYPE_TABLE,
            "domainId"   : self.config["domain_id"],
            "excludedFromAutoHyperlinking": False,
        }
        resp = self._post(f"{self._base}/assets", body, auth=self._auth)
        asset_id = resp.get("id", "")

        # Attach description attribute.
        if asset_id:
            self._set_attribute(asset_id, self._attr_ids["description"], payload.description)
            self.log.info("[Collibra] Registered Table asset: %s → %s", payload.table_name, asset_id)

        return asset_id

    def register_columns(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Create Column assets and relate them to the parent Table asset.

        For each column:
          1. POST /assets  — create Column asset
          2. POST /relations — relate it to the Table with "has column"
          3. Set attributes: description, pii_flag, classification, gdpr_article
        """
        for col in payload.columns:
            body = {
                "name"    : col.name,
                "typeId"  : self._ASSET_TYPE_COLUMN,
                "domainId": self.config["domain_id"],
            }
            resp = self._post(f"{self._base}/assets", body, auth=self._auth)
            col_id = resp.get("id", "")
            if not col_id:
                continue

            # Relate column to parent table.
            self._create_relation(dataset_id, col_id, self._rel_ids["has_column"])

            # Set column attributes.
            self._set_attribute(col_id, self._attr_ids["description"], col.description)
            if self._attr_ids.get("pii_flag"):
                self._set_attribute(col_id, self._attr_ids["pii_flag"], str(col.is_pii))
            if self._attr_ids.get("classification"):
                self._set_attribute(col_id, self._attr_ids["classification"],
                                     col.classification)
            if self._attr_ids.get("gdpr_article") and col.gdpr_article:
                self._set_attribute(col_id, self._attr_ids["gdpr_article"], col.gdpr_article)

        self.log.info("[Collibra] %s column(s) registered.", len(payload.columns))

    def push_lineage(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Register lineage: source Data File asset → pipeline Tech Asset → Table asset.

        Creates two assets (source file, pipeline process) and two lineage
        relations connecting them to the destination Table.
        """
        lin = payload.lineage

        # Create source file asset.
        src_body = {
            "name"    : Path(lin.source_path).name,
            "typeId"  : self._ASSET_TYPE_DATA_FILE,
            "domainId": self.config["domain_id"],
        }
        src_resp = self._post(f"{self._base}/assets", src_body, auth=self._auth)
        src_id   = src_resp.get("id", "")

        # Create pipeline process asset.
        pipe_body = {
            "name"    : f"Pipeline {lin.pipeline_version} ({lin.pipeline_id[:8]})",
            "typeId"  : self._ASSET_TYPE_TECH,
            "domainId": self.config["domain_id"],
        }
        pipe_resp = self._post(f"{self._base}/assets", pipe_body, auth=self._auth)
        pipe_id   = pipe_resp.get("id", "")

        # source file → pipeline.
        if src_id and pipe_id:
            self._create_relation(src_id, pipe_id, self._rel_ids["lineage"])
        # pipeline → destination table.
        if pipe_id and dataset_id:
            self._create_relation(pipe_id, dataset_id, self._rel_ids["lineage"])

        self.log.info("[Collibra] Lineage registered: source → pipeline → table.")

    def push_data_quality(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Set a quality score attribute on the Table asset.

        Quality score = GX pass_rate as a percentage (0 – 100).
        """
        if not self._attr_ids.get("quality_score") or not dataset_id:
            return
        score = round(payload.quality.pass_rate * 100, 1)
        self._set_attribute(dataset_id, self._attr_ids["quality_score"], str(score))
        self.log.info("[Collibra] Quality score set: %s%%", score)

    def push_pii_tags(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Tag the Table asset with "Contains PII" using Collibra Tags API.

        Also sets the pii_flag attribute on each PII column (done in
        register_columns — this method handles table-level tagging).
        """
        if not payload.pii_columns:
            return
        tag_body = {
            "tagNames"  : ["Contains PII", "GDPR-Protected"],
            "assetIds"  : [dataset_id],
        }
        self._post(f"{self._base}/tags/assets", tag_body, auth=self._auth)
        self.log.info("[Collibra] PII tags applied to table %s.", payload.table_name)

    def push_compliance(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Set compliance attributes (lawful basis, retention, classification) on
        the Table asset.
        """
        comp = payload.compliance
        if self._attr_ids.get("lawful_basis"):
            self._set_attribute(dataset_id, self._attr_ids["lawful_basis"],
                                 comp.lawful_basis)
        if self._attr_ids.get("retention_days") and comp.retention_days:
            self._set_attribute(dataset_id, self._attr_ids["retention_days"],
                                 str(comp.retention_days))
        if self._attr_ids.get("classification"):
            self._set_attribute(dataset_id, self._attr_ids["classification"],
                                 comp.data_classification)
        if self._attr_ids.get("pipeline_id"):
            self._set_attribute(dataset_id, self._attr_ids["pipeline_id"],
                                 payload.pipeline_id)
        self.log.info("[Collibra] Compliance metadata pushed.")

    def disconnect(self) -> None:
        """Collibra REST API is stateless — no session to close."""
        self.log.info("[Collibra] Disconnected.")

    # ── Private helpers ───────────────────────────────────────────────────
    def _set_attribute(self, asset_id: str, attr_type_id: str, value: str) -> None:
        """Create or overwrite an attribute on an asset."""
        if not attr_type_id or not asset_id:
            return
        self._post(f"{self._base}/attributes", {
            "assetId"           : asset_id,
            "typeId"            : attr_type_id,
            "value"             : value,
        }, auth=self._auth)

    def _create_relation(self, source_id: str, target_id: str, rel_type_id: str) -> None:
        """Create a directed relation between two assets."""
        if not rel_type_id:
            return
        self._post(f"{self._base}/relations", {
            "sourceId"  : source_id,
            "targetId"  : target_id,
            "typeId"    : rel_type_id,
        }, auth=self._auth)


# ═════════════════════════════════════════════════════════════════════════════
#  ALATION CONNECTOR
# ═════════════════════════════════════════════════════════════════════════════
class AlationConnector(BaseCatalogConnector):
    """
    Registers pipeline metadata with Alation via the v2 REST API.

    Alation concepts used
    ---------------------
    Data Source  — represents a database connection (must already exist;
                   this connector does NOT create data sources)
    Schema       — database schema (auto-created if absent)
    Table        — the target table (created or updated)
    Column       — per-column metadata

    Custom fields — Alation supports "custom fields" that can be attached
                    to any catalog object.  The connector uses custom fields
                    to push PII flags, classification, retention, and
                    quality scores.  Field IDs must be configured in config
                    because they vary per Alation instance.

    Required config keys
    --------------------
    url              : str   Base URL, e.g. "https://myorg.alation.com"
    api_token        : str   Alation API token (Settings → API Tokens)
    ds_id            : int   Alation data source ID (integer)
    schema_name      : str   Schema name (e.g. "public")

    Optional config keys
    --------------------
    custom_field_ids : dict  Maps field name → Alation custom field integer ID
                             Keys: "pii_flag", "classification", "retention_days",
                                   "lawful_basis", "quality_score", "pipeline_id"
    trust_flag_note  : str   Note to attach on the Alation Trust Check (default: auto)
    """

    def __init__(self, config: dict) -> None:
        super().__init__("Alation", config)
        self._base    = config["url"].rstrip("/")
        self._headers = {
            "TOKEN"          : config["api_token"],
            "Content-Type"   : "application/json",
            "Accept"         : "application/json",
        }
        self._ds_id   = config["ds_id"]
        self._schema  = config.get("schema_name", "public")
        self._cf_ids  = config.get("custom_field_ids", {})

    def connect(self) -> bool:
        """
        Verify the API token by hitting the /integration/v2/user/ endpoint.

        Alation tokens are per-user and expire; this check surfaces an
        expired token before any write operations attempt.
        """
        resp = self._get(f"{self._base}/integration/v2/user/",
                          headers=self._headers)
        if "error" in resp:
            self.log.error("[Alation] Connection failed: %s", resp.get('error'))
            return False
        self.log.info("[Alation] Connected successfully.")
        return True

    def register_dataset(self, payload: CatalogMetadataPayload) -> str:
        """
        Create or update a Table object in Alation.

        Uses the /integration/v2/table/ endpoint with a PUT (upsert semantics):
        if a table with the same ds_id + schema + name exists, it is updated;
        otherwise a new table is created.

        Returns the Alation table ID as a string.
        """
        body = [{
            "key"         : f"{self._ds_id}.{self._schema}.{payload.table_name}",
            "title"       : payload.table_name,
            "description" : payload.description,
            "ds_id"       : self._ds_id,
            "schema_name" : self._schema,
            "name"        : payload.table_name,
        }]
        resp = self._put(f"{self._base}/integration/v2/table/",
                          payload=body[0], headers=self._headers)
        table_id = str(resp.get("id", ""))
        if table_id:
            self.log.info("[Alation] Table registered: %s → id=%s", payload.table_name, table_id)
        return table_id

    def register_columns(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Upsert column objects and attach custom fields (PII, classification).

        Alation's /integration/v2/column/ endpoint accepts bulk column
        registration.  Custom field values are set via a separate
        PATCH /api/v1/custom_field_value/ call.
        """
        col_bodies = [{
            "key"        : f"{self._ds_id}.{self._schema}.{payload.table_name}.{col.name}",
            "name"       : col.name,
            "column_type": col.dtype,
            "description": col.description,
            "table_id"   : dataset_id,
        } for col in payload.columns]

        for cb in col_bodies:
            self._put(f"{self._base}/integration/v2/column/",
                       payload=cb, headers=self._headers)

        # Set custom field values for PII columns.
        for col in payload.pii_columns:
            if self._cf_ids.get("pii_flag"):
                self._set_custom_field(
                    obj_type="column",
                    obj_id  = f"{self._ds_id}.{self._schema}.{payload.table_name}.{col.name}",
                    field_id= self._cf_ids["pii_flag"],
                    value   = True,
                )
            if self._cf_ids.get("classification"):
                self._set_custom_field(
                    obj_type="column",
                    obj_id  = f"{self._ds_id}.{self._schema}.{payload.table_name}.{col.name}",
                    field_id= self._cf_ids["classification"],
                    value   = col.classification,
                )
        self.log.info("[Alation] %s column(s) registered.", len(payload.columns))

    def push_lineage(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Register lineage using Alation's Lineage V2 API.

        Alation Lineage V2 uses "DataflowItem" objects that describe a
        directed edge from a source object to a target object.
        """
        lin = payload.lineage
        body = {
            "dataflow_name"  : f"Pipeline {lin.pipeline_version}",
            "dataflow_id"    : lin.pipeline_id,
            "sources"        : [{"type": "file", "path": lin.source_path,
                                  "name": Path(lin.source_path).name}],
            "targets"        : [{"type": "table",
                                  "key": f"{self._ds_id}.{self._schema}.{payload.table_name}"}],
            "properties"     : {
                "pipeline_version": lin.pipeline_version,
                "operator"        : lin.operator,
                "rows_loaded"     : lin.rows_loaded,
                "source_sha256"   : lin.source_sha256,
            },
        }
        self._post(f"{self._base}/api/v1/lineage/", body, headers=self._headers)
        self.log.info("[Alation] Lineage registered.")

    def push_data_quality(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Post a Trust Check flag on the Table object in Alation.

        Alation "Trust Checks" (Signals) let users flag a table as
        "Verified", "Warning", or "Deprecation" with a note.  A high
        GX pass rate → "Verified"; a low rate → "Warning".
        """
        q    = payload.quality
        flag = "VERIFIED" if q.overall_success and q.pass_rate >= 0.95 else "WARNING"
        note = (f"Data quality: {q.pass_rate:.0%} pass rate "
                f"({q.expectations_passed}/{q.expectations_total} expectations). "
                f"DLQ rows: {q.dlq_rows}. Validated by Great Expectations.")

        body = {
            "flag_type" : flag,
            "reason"    : note,
            "subject"   : {"object_type": "table",
                            "object_id"  : dataset_id},
        }
        self._post(f"{self._base}/api/v1/flag/", body, headers=self._headers)

        # Also set quality_score custom field if configured.
        if self._cf_ids.get("quality_score"):
            self._set_custom_field("table", dataset_id,
                                    self._cf_ids["quality_score"],
                                    round(q.pass_rate * 100, 1))
        self.log.info("[Alation] Trust flag set: %s  quality=%s%%", flag, format(q.pass_rate, ".0%"))

    def push_pii_tags(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Apply "Contains PII" and GDPR classification tags to the table.

        Alation uses "Tags" (string labels) applied via POST /api/v1/tag/.
        """
        for tag in payload.tags:
            self._post(f"{self._base}/api/v1/tag/", {
                "object_type": "table",
                "object_id"  : dataset_id,
                "tag_name"   : tag,
            }, headers=self._headers)
        self.log.info("[Alation] %s tag(s) applied.", len(payload.tags))

    def push_compliance(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """Push GDPR / CCPA compliance custom fields to the Table object."""
        comp = payload.compliance
        cf   = self._cf_ids
        for field_key, value in [
            ("lawful_basis",   comp.lawful_basis),
            ("retention_days", str(comp.retention_days or "unspecified")),
            ("classification", comp.data_classification),
            ("pipeline_id",    payload.pipeline_id),
        ]:
            if cf.get(field_key):
                self._set_custom_field("table", dataset_id, cf[field_key], value)
        self.log.info("[Alation] Compliance metadata pushed.")

    def disconnect(self) -> None:
        """Alation is stateless (token auth) — no session to close."""
        self.log.info("[Alation] Disconnected.")

    # ── Private helpers ───────────────────────────────────────────────────
    def _set_custom_field(self, obj_type: str, obj_id: Any,
                           field_id: int, value: Any) -> None:
        """
        Set a custom field value on an Alation catalog object.

        Uses the PATCH /api/v1/custom_field_value/ endpoint.
        """
        body = {
            "field_id"   : field_id,
            "ts_updated" : datetime.now(timezone.utc).isoformat(),
            "value"      : value,
            "otype"      : obj_type,
            "oid"        : obj_id,
        }
        self._patch(f"{self._base}/api/v1/custom_field_value/",
                     body, headers=self._headers)


# ═════════════════════════════════════════════════════════════════════════════
#  INFORMATICA AXON / CDGC CONNECTOR
# ═════════════════════════════════════════════════════════════════════════════
class InformaticaAxonConnector(BaseCatalogConnector):
    """
    Registers pipeline metadata with Informatica Cloud Data Governance and
    Catalog (CDGC) — formerly Informatica Axon Data Governance.

    Informatica CDGC concepts
    -------------------------
    Asset         — base object (Technical Asset, Business Term, Policy, etc.)
    Technical Asset — represents a physical data object (table, column, file)
    Business Term   — entry in the Business Glossary
    Attribute       — name-value pair attached to any asset
    Relationship    — directed link between assets (lineage, contains, etc.)
    Quality Score   — numeric score attached to a technical asset

    Authentication
    --------------
    CDGC uses OAuth2 client-credentials grant.  The connector exchanges
    client_id + client_secret for a Bearer token using Informatica's
    Identity Service, then uses that token for all subsequent API calls.

    Required config keys
    --------------------
    url             : str  Informatica org URL, e.g. "https://dm-us.informaticacloud.com"
    client_id       : str  OAuth2 client ID
    client_secret   : str  OAuth2 client secret
    org_id          : str  Informatica organisation / pod ID

    Optional config keys
    --------------------
    technical_asset_type : str  Type of asset to create (default: "TABLE")
    glossary_terms       : dict  Maps classification level → business term name
                                 (e.g. {"CONFIDENTIAL": "Personal Data"})
    """

    _TOKEN_URL = "https://dm-us.informaticacloud.com/ma/api/v2/user/login"

    def __init__(self, config: dict) -> None:
        super().__init__("InformaticaAxon", config)
        self._base         = config["url"].rstrip("/")
        self._client_id    = config["client_id"]
        self._client_secret= config["client_secret"]
        self._org_id       = config.get("org_id", "")
        self._token: str   = ""
        self._asset_type   = config.get("technical_asset_type", "TABLE")
        self._glossary_map = config.get("glossary_terms", {
            "RESTRICTED"  : "Personal Data — Special Category",
            "CONFIDENTIAL": "Personal Data",
            "INTERNAL"    : "Internal Use",
            "PUBLIC"      : "Public Data",
        })

    def connect(self) -> bool:
        """
        Authenticate with Informatica Identity Service using client credentials.

        Exchanges client_id and client_secret for a short-lived Bearer token.
        The token is stored in self._token and prepended to all request headers.

        Returns False if the token endpoint is unreachable or credentials fail.
        """
        login_body = {
            "@type"   : "login",
            "username": self._client_id,
            "password": self._client_secret,
        }
        resp = self._post(self._TOKEN_URL, login_body)
        token = resp.get("userInfo", {}).get("sessionId", "")
        if not token:
            self.log.error("[InformaticaAxon] Authentication failed.")
            return False
        self._token = token
        self.log.info("[InformaticaAxon] Connected (token acquired).")
        return True

    def _auth_headers(self) -> dict:
        """Return headers with the Bearer token for authenticated requests."""
        return {
            "icSessionId" : self._token,
            "Content-Type": "application/json",
            "Accept"      : "application/json",
        }

    def register_dataset(self, payload: CatalogMetadataPayload) -> str:
        """
        Create a Technical Asset in Informatica CDGC for the target table.

        Uses POST /ccgf-assets/api/v1/assets to create the asset with
        core attributes (name, description, type, source).

        Returns the Informatica internal asset ID (string UUID).
        """
        body = {
            "assetType"  : self._asset_type,
            "core"       : {
                "name"        : payload.table_name,
                "description" : payload.description,
                "origin"      : payload.db_type,
            },
            "system"     : {
                "source"      : payload.lineage.source_path,
                "lastModified": payload.run_timestamp,
            },
        }
        resp = self._post(
            f"{self._base}/ccgf-assets/api/v1/assets",
            body, headers=self._auth_headers()
        )
        asset_id = resp.get("id", "")
        if asset_id:
            self.log.info("[InformaticaAxon] Asset created: %s → %s", payload.table_name, asset_id)
        return asset_id

    def register_columns(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Create child Column assets and attach them to the parent Table asset.

        Each column is registered as a COLUMN-type Technical Asset linked
        to the table via a "contains" relationship.  PII columns get an
        additional "Sensitivity" attribute.
        """
        for col in payload.columns:
            col_body = {
                "assetType" : "COLUMN",
                "core"      : {
                    "name"       : col.name,
                    "description": col.description,
                    "dataType"   : col.dtype,
                },
                "parentId"  : dataset_id,
            }
            resp = self._post(
                f"{self._base}/ccgf-assets/api/v1/assets",
                col_body, headers=self._auth_headers()
            )
            col_id = resp.get("id", "")
            if col_id and col.is_pii:
                # Attach sensitivity classification attribute.
                self._set_attribute(col_id, "Sensitivity",
                                     "SPECIAL_CATEGORY" if col.is_special_category
                                     else "PERSONAL_DATA")
                if col.is_masked:
                    self._set_attribute(col_id, "DataHandling", "PSEUDONYMISED")
                elif col.is_encrypted:
                    self._set_attribute(col_id, "DataHandling", "ENCRYPTED_AT_REST")

        self.log.info("[InformaticaAxon] %s column(s) registered.", len(payload.columns))

    def push_lineage(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Push lineage via CDGC's Lineage API.

        Creates a relationship from the source file asset to the destination
        table asset with the pipeline as the transformation step.
        """
        lin = payload.lineage
        # Register source file as a DATA_FILE asset.
        src_body = {
            "assetType": "DATA_FILE",
            "core"     : {"name": Path(lin.source_path).name,
                           "description": f"Source file for pipeline run {lin.pipeline_id[:8]}"},
        }
        src_resp = self._post(f"{self._base}/ccgf-assets/api/v1/assets",
                               src_body, headers=self._auth_headers())
        src_id   = src_resp.get("id", "")

        # Register pipeline process.
        pipe_body = {
            "assetType": "ETL_JOB",
            "core"     : {
                "name"       : f"Data Governance Pipeline {lin.pipeline_version}",
                "description": f"Pipeline ID: {lin.pipeline_id}  Operator: {lin.operator}",
            },
        }
        pipe_resp = self._post(f"{self._base}/ccgf-assets/api/v1/assets",
                                pipe_body, headers=self._auth_headers())
        pipe_id   = pipe_resp.get("id", "")

        # Create lineage relationships.
        for src, tgt, rel_type in [
            (src_id,  pipe_id,    "READS"),
            (pipe_id, dataset_id, "WRITES"),
        ]:
            if src and tgt:
                self._post(f"{self._base}/ccgf-assets/api/v1/relationships", {
                    "fromAssetId"   : src,
                    "toAssetId"     : tgt,
                    "relationshipType": rel_type,
                }, headers=self._auth_headers())

        self.log.info("[InformaticaAxon] Lineage pushed.")

    def push_data_quality(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Push a Data Quality Score to the table asset.

        CDGC accepts numeric quality scores (0 – 100) via the
        /ccgf-assets/api/v1/assets/{id}/qualityScore endpoint.
        """
        score = round(payload.quality.pass_rate * 100, 1)
        self._post(
            f"{self._base}/ccgf-assets/api/v1/assets/{dataset_id}/qualityScore",
            {"score": score, "dimension": "COMPLETENESS",
             "comment": (f"GX validation: {payload.quality.expectations_passed}/"
                         f"{payload.quality.expectations_total} expectations passed.")},
            headers=self._auth_headers()
        )
        self.log.info("[InformaticaAxon] Quality score pushed: %s%%", score)

    def push_pii_tags(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Link the table asset to Business Glossary terms for its classification.

        The glossary_terms config maps classification levels to term names.
        The connector looks up the term ID and creates a "related to" link.
        """
        term_name = self._glossary_map.get(payload.compliance.data_classification,
                                             "Personal Data")
        # Look up the term by name.
        terms = self._get(
            f"{self._base}/ccgf-assets/api/v1/assets",
            params={"assetType": "BUSINESS_TERM", "name": term_name},
            headers=self._auth_headers()
        )
        term_id = ""
        for item in terms.get("items", []):
            if item.get("core", {}).get("name") == term_name:
                term_id = item.get("id", "")
                break

        if term_id:
            self._post(f"{self._base}/ccgf-assets/api/v1/relationships", {
                "fromAssetId"     : dataset_id,
                "toAssetId"       : term_id,
                "relationshipType": "RELATED_TO",
            }, headers=self._auth_headers())
            self.log.info("[InformaticaAxon] Business term linked: %s", term_name)

    def push_compliance(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """Push GDPR compliance attributes to the table asset."""
        comp = payload.compliance
        for attr_name, value in [
            ("GDPR_LawfulBasis",        comp.lawful_basis),
            ("GDPR_RetentionDays",       str(comp.retention_days or "unspecified")),
            ("GDPR_ProcessingPurpose",   comp.processing_purpose),
            ("DataClassification",       comp.data_classification),
            ("PipelineID",               payload.pipeline_id),
        ]:
            self._set_attribute(dataset_id, attr_name, value)
        self.log.info("[InformaticaAxon] Compliance metadata pushed.")

    def disconnect(self) -> None:
        """Invalidate the Informatica session token."""
        if self._token:
            self._post(f"{self._base}/ma/api/v2/user/logout", {},
                        headers=self._auth_headers())
        self.log.info("[InformaticaAxon] Disconnected.")

    # ── Private helpers ───────────────────────────────────────────────────
    def _set_attribute(self, asset_id: str, attr_name: str, value: str) -> None:
        """Create or update a named attribute on an asset."""
        self._post(
            f"{self._base}/ccgf-assets/api/v1/assets/{asset_id}/attributes",
            {"attributeName": attr_name, "attributeValue": value},
            headers=self._auth_headers()
        )


# ═════════════════════════════════════════════════════════════════════════════
#  ATLAN CONNECTOR
# ═════════════════════════════════════════════════════════════════════════════
class AtlanConnector(BaseCatalogConnector):
    """
    Registers pipeline metadata with Atlan using the pyatlan SDK where
    available, falling back to direct REST API calls.

    Atlan concepts used
    -------------------
    Connection    — represents a database connection (must already exist in Atlan)
    Table         — physical table asset with a qualified name
    Column        — column asset with a qualified name
    Process       — lineage process connecting source and destination assets
    Custom Metadata — named key-value bundles attached to any asset;
                      used here for GDPR, PII, and quality metadata

    Qualified name format
    ---------------------
    Atlan identifies assets by a dot-separated "qualified name" that encodes
    the full path from connector to table:
        {connector_type}/{connection_name}/{db_name}/{schema_name}/{table_name}
    Example:
        sqlite/my-pipeline-db/pipeline_output/default/employees

    Required config keys
    --------------------
    url                 : str  Atlan tenant URL, e.g. "https://myorg.atlan.com"
    api_token           : str  Atlan API token (Settings → API Tokens)
    connection_qn       : str  Qualified name of the pre-existing Connection asset
                               e.g. "default/postgresql/1234567890"
    schema_name         : str  Schema name (e.g. "public" for Postgres, "default" for SQLite)

    Optional config keys
    --------------------
    connector_type_name : str  Atlan connector type string (default: "SQLITE")
                               Must be a valid value.
    custom_metadata_set : str  Name of the Custom Metadata set for GDPR fields
                               (default: "DataGovernancePipeline")
    certificate_status  : str  "DRAFT" | "VERIFIED" | "DEPRECATED" (default: "DRAFT")
    """

    def __init__(self, config: dict) -> None:
        super().__init__("Atlan", config)
        self._base        = config["url"].rstrip("/")
        self._api_token   = config["api_token"]
        self._conn_qn     = config["connection_qn"]
        self._schema      = config.get("schema_name", "default")
        self._cm_set      = config.get("custom_metadata_set", "DataGovernancePipeline")
        self._cert_status = config.get("certificate_status", "DRAFT")
        self._connector   = config.get("connector_type_name", "SQLITE")
        self._headers     = {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type" : "application/json",
            "Accept"       : "application/json",
        }
        self._client: Any = None   # AtlanClient instance (if pyatlan available)

    def connect(self) -> bool:
        """
        Authenticate with Atlan.

        If pyatlan is installed, create an AtlanClient instance (which
        validates the token on construction).  Otherwise, do a lightweight
        GET /api/meta/search/indexsearch to verify the token.
        """
        if HAS_PYATLAN:
            try:
                self._client = AtlanClient(
                    base_url = self._base,
                    api_key  = self._api_token,
                )
                self.log.info("[Atlan] Connected via pyatlan SDK.")
                return True
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.log.warning("[Atlan] pyatlan SDK init failed (%s) — using REST fallback.", exc)

        # REST fallback
        resp = self._get(f"{self._base}/api/meta/search/indexsearch",
                          params={"query": "_"}, headers=self._headers)
        if "error" in resp:
            self.log.error("[Atlan] Connection failed: %s", resp.get('error'))
            return False
        self.log.info("[Atlan] Connected via REST API.")
        return True

    def _build_qn(self, table_name: str) -> str:
        """
        Build an Atlan-format qualified name for a table.

        Format: {connection_qn}/{db_name}/{schema}/{table_name}
        """
        db   = self.config.get("db_name", "default")
        return f"{self._conn_qn}/{db}/{self._schema}/{table_name}"

    def _build_col_qn(self, table_name: str, col_name: str) -> str:
        """Build an Atlan-format qualified name for a column."""
        return f"{self._build_qn(table_name)}/{col_name}"

    def register_dataset(self, payload: CatalogMetadataPayload) -> str:
        """
        Upsert a Table asset in Atlan.

        Uses either the pyatlan SDK (preferred) or the /api/meta/entity/bulk
        REST endpoint.  The table is identified by its qualified name so
        re-running the pipeline updates the existing asset rather than
        creating a duplicate.

        Returns the Atlan GUID of the table asset.
        """
        table_qn = self._build_qn(payload.table_name)
        ts       = int(time.time() * 1000)  # epoch ms (Atlan convention)

        if self._client and HAS_PYATLAN:
            return self._sdk_upsert_table(payload, table_qn, ts)
        else:
            return self._rest_upsert_table(payload, table_qn)

    def _sdk_upsert_table(self, payload: CatalogMetadataPayload,
                           table_qn: str, _ts: int) -> str:
        """Create/update the Table asset using the pyatlan SDK."""
        try:
            table_asset               = AtlanTable()
            table_asset.name          = payload.table_name
            table_asset.qualified_name= table_qn
            table_asset.description   = payload.description
            table_asset.row_count     = payload.lineage.rows_loaded
            table_asset.column_count  = len(payload.columns)

            # Certificate status.
            cert_map = {
                "VERIFIED"  : CertificateStatus.VERIFIED,
                "DRAFT"     : CertificateStatus.DRAFT,
                "DEPRECATED": CertificateStatus.DEPRECATED,
            }
            table_asset.certificate_status = cert_map.get(
                self._cert_status, CertificateStatus.DRAFT
            )
            table_asset.certificate_status_message = (
                f"Pipeline {payload.lineage.pipeline_version} | "
                f"Run {payload.pipeline_id[:8]}"
            )

            # Push via SDK upsert.
            response = self._client.asset.upsert(entity=table_asset)
            guid     = ""
            if hasattr(response, "mutated_entities") and response.mutated_entities:
                entities = (response.mutated_entities.CREATE or  # pylint: disable=no-member
                            response.mutated_entities.UPDATE or [])  # pylint: disable=no-member
                if entities:
                    guid = getattr(entities[0], "guid", "")
            self.log.info("[Atlan] Table upserted via SDK: %s → %s", payload.table_name, guid)
            return guid
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log.warning("[Atlan] SDK upsert failed (%s) — using REST fallback.", exc)
            return self._rest_upsert_table(payload, table_qn)

    def _rest_upsert_table(self, payload: CatalogMetadataPayload, table_qn: str) -> str:
        """Create/update the Table asset using the Atlan REST API directly."""
        body = {
            "entities": [{
                "typeName"  : "Table",
                "attributes": {
                    "qualifiedName"          : table_qn,
                    "name"                   : payload.table_name,
                    "description"            : payload.description,
                    "rowCount"               : payload.lineage.rows_loaded,
                    "columnCount"            : len(payload.columns),
                    "certificateStatus"      : self._cert_status,
                    "certificateStatusMessage": (
                        f"Pipeline {payload.lineage.pipeline_version} "
                        f"| Run {payload.pipeline_id[:8]}"
                    ),
                },
            }],
        }
        resp = self._post(f"{self._base}/api/meta/entity/bulk",
                           body, headers=self._headers)
        guid = ""
        mutated = resp.get("mutatedEntities", {})
        for key in ("CREATE", "UPDATE"):
            entities = mutated.get(key, [])
            if entities:
                guid = entities[0].get("guid", "")
                break
        self.log.info("[Atlan] Table upserted via REST: %s → %s", payload.table_name, guid)
        return guid

    def register_columns(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Upsert Column assets and attach PII / classification custom metadata.

        Each column is upserted with its qualified name and a custom metadata
        bundle containing PII flags, GDPR article references, and masking status.
        """
        for col in payload.columns:
            col_qn = self._build_col_qn(payload.table_name, col.name)
            body   = {
                "entities": [{
                    "typeName"       : "Column",
                    "attributes"     : {
                        "qualifiedName": col_qn,
                        "name"         : col.name,
                        "description"  : col.description,
                        "dataType"     : col.dtype,
                        "order"        : payload.columns.index(col),
                    },
                    "businessAttributes": {
                        self._cm_set: self._build_col_cm(col),
                    },
                }],
            }
            self._post(f"{self._base}/api/meta/entity/bulk",
                        body, headers=self._headers)
        self.log.info("[Atlan] %s column(s) registered.", len(payload.columns))

    def push_lineage(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Create a Process asset linking source → pipeline → table.

        Atlan models lineage as Process assets with inputs[] and outputs[].
        The source file is represented as an S3Object or FileObject;
        the destination is the Table asset.
        """
        lin    = payload.lineage
        src_qn = (f"s3://pipeline-sources/{Path(lin.source_path).name}"
                  if lin.source_path else "unknown")
        tbl_qn = self._build_qn(payload.table_name)

        # Process qualified name must be deterministic so re-runs update it.
        process_qn = (f"pipeline/{lin.pipeline_version}/"
                      f"{hashlib.sha256(tbl_qn.encode()).hexdigest()[:12]}")

        body = {
            "entities": [{
                "typeName"  : "Process",
                "attributes": {
                    "qualifiedName": process_qn,
                    "name"         : (f"Data Governance Pipeline "
                                      f"{lin.pipeline_version} → {payload.table_name}"),
                    "description"  : (f"Pipeline run {lin.pipeline_id[:8]} by "
                                      f"{lin.operator} on {lin.run_timestamp}"),
                    "inputs"       : [{"typeName": "Column",  # Simplified — real lineage
                                       "uniqueAttributes": {"qualifiedName": src_qn}}],
                    "outputs"      : [{"typeName": "Table",
                                       "uniqueAttributes": {"qualifiedName": tbl_qn}}],
                    "rowCount"     : lin.rows_loaded,
                    "sourceURL"    : lin.source_path,
                },
                "businessAttributes": {
                    self._cm_set: {
                        "pipeline_id"     : lin.pipeline_id,
                        "pipeline_version": lin.pipeline_version,
                        "source_sha256"   : lin.source_sha256,
                        "rows_loaded"     : lin.rows_loaded,
                        "operator"        : lin.operator,
                    },
                },
            }],
        }
        self._post(f"{self._base}/api/meta/entity/bulk",
                    body, headers=self._headers)
        self.log.info("[Atlan] Lineage Process asset registered.")

    def push_data_quality(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Attach GX validation results as Custom Metadata on the Table asset.

        Atlan doesn't have a native "quality score" field on Table assets,
        so quality metrics are stored in the DataGovernancePipeline custom
        metadata bundle.
        """
        q    = payload.quality
        body = {
            "entities": [{
                "typeName"  : "Table",
                "attributes": {
                    "qualifiedName"          : self._build_qn(payload.table_name),
                    "certificateStatus"      : "VERIFIED" if q.overall_success else "DRAFT",
                    "certificateStatusMessage": (
                        f"GX: {q.pass_rate:.0%} ({q.expectations_passed}/"
                        f"{q.expectations_total}) | DLQ: {q.dlq_rows}"
                    ),
                },
                "businessAttributes": {
                    self._cm_set: {
                        "gx_pass_rate"         : round(q.pass_rate, 4),
                        "gx_expectations_total": q.expectations_total,
                        "gx_expectations_passed": q.expectations_passed,
                        "gx_dlq_rows"          : q.dlq_rows,
                        "gx_overall_success"   : q.overall_success,
                        # ⑤ Per-column quality scores.
                        "column_quality_scores": {
                            col.name: {
                                "quality_score": col.quality_score,
                                "gx_pass_rate" : round(col.gx_pass_rate, 4) if col.gx_pass_rate is not None else None,
                                "gx_failures"  : col.gx_failures,
                            }
                            for col in payload.columns if col.quality_score > 0 or col.gx_failures > 0
                        },
                    },
                },
            }],
        }
        self._post(f"{self._base}/api/meta/entity/bulk",
                    body, headers=self._headers)
        self.log.info("[Atlan] Quality metadata pushed — pass rate: %s%%", format(q.pass_rate, ".0%"))

    def push_pii_tags(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Apply Atlan Classification tags to PII columns.

        Atlan "Classifications" (formerly "labels") are propagated through
        lineage automatically.  We apply:
          "PII"                    → any PII column
          "GDPR_Special_Category"  → Art. 9 columns
          payload.tags             → to the Table asset
        """
        # Apply classification tags to PII columns using per-column qualified names.
        for col in payload.pii_columns:
            col_qn = self._build_col_qn(payload.table_name, col.name)
            tags   = ["PII"]
            if col.is_special_category:
                tags.append("GDPR_Special_Category")
            # Tag via the bulk entity endpoint using qualifiedName lookup.
            self._post(
                f"{self._base}/api/meta/entity/bulk/classification",
                {
                    "classification": {"typeName": "PII"},
                    "entityIds": [col_qn],
                },
                headers=self._headers,
            )
            if col.is_special_category:
                self._post(
                    f"{self._base}/api/meta/entity/bulk/classification",
                    {
                        "classification": {"typeName": "GDPR_Special_Category"},
                        "entityIds": [col_qn],
                    },
                    headers=self._headers,
                )

        # Apply classification tags to the table asset.
        if payload.tags:
            self._post(
                f"{self._base}/api/meta/entity/guid/{dataset_id}/classifications",
                [{"typeName": t} for t in payload.tags],
                headers=self._headers,
            )
        self.log.info("[Atlan] %s PII column(s) tagged.", len(payload.pii_columns))

    def push_compliance(self, payload: CatalogMetadataPayload, dataset_id: str) -> None:
        """
        Push GDPR/CCPA compliance metadata as Custom Metadata on the Table.

        Stores: lawful basis, purpose, retention days, transfer type,
        safeguard, data classification, and CCPA opt-out flag.
        """
        comp = payload.compliance
        body = {
            "entities": [{
                "typeName"  : "Table",
                "attributes": {"qualifiedName": self._build_qn(payload.table_name)},
                "businessAttributes": {
                    self._cm_set: {
                        "gdpr_lawful_basis"        : comp.lawful_basis,
                        "gdpr_purpose"             : comp.processing_purpose,
                        "gdpr_retention_days"      : comp.retention_days,
                        "gdpr_transfer_type"       : comp.transfer_type,
                        "gdpr_transfer_safeguard"  : comp.transfer_safeguard,
                        "data_classification"      : comp.data_classification,
                        "ccpa_opt_out"             : comp.ccpa_opt_out,
                        "pipeline_id"              : payload.pipeline_id,
                        "pipeline_run_timestamp"   : payload.run_timestamp,
                    },
                },
            }],
        }
        self._post(f"{self._base}/api/meta/entity/bulk",
                    body, headers=self._headers)
        self.log.info("[Atlan] Compliance custom metadata pushed.")

    def disconnect(self) -> None:
        """Atlan is stateless (token auth) — nothing to close."""
        self.log.info("[Atlan] Disconnected.")

    # ── Private helpers ───────────────────────────────────────────────────
    def _build_col_cm(self, col: ColumnMeta) -> dict:
        """Build the Custom Metadata dict for a single column."""
        return {
            "is_pii"              : col.is_pii,
            "is_special_category" : col.is_special_category,
            "gdpr_article"        : col.gdpr_article,
            "is_encrypted"        : col.is_encrypted,
            "is_masked"           : col.is_masked,
            "data_classification" : col.classification,
            "null_pct"            : col.null_pct,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  CATALOG MANAGER  (orchestrates all configured connectors)
# ═════════════════════════════════════════════════════════════════════════════
class CatalogManager:
    """
    Orchestrates metadata registration across one or more catalog connectors.

    The manager holds a list of configured connectors and calls them in
    parallel (or sequentially if parallel=False).  Each connector runs
    through the same sequence of registration steps:

      1. connect()             — authenticate
      2. register_dataset()    — create/update table asset
      3. register_columns()    — push column metadata
      4. push_lineage()        — source → pipeline → table lineage
      5. push_data_quality()   — GX validation scores
      6. push_pii_tags()       — PII annotations
      7. push_compliance()     — GDPR/CCPA metadata
      8. disconnect()          — close session

    A connector that fails at connect() is skipped (its other methods are
    not called) so a misconfigured catalog doesn't block the others.

    Usage
    -----
        manager = CatalogManager.from_config(catalog_cfg, secrets)
        manager.register_all(payload)

    Factory method
    --------------
    CatalogManager.from_config(config, secrets) — build from a config dict.
    config is a dict with keys "collibra", "alation", "axon", "atlan",
    each containing that catalog's own config dict (or absent if not enabled).
    """

    def __init__(self, connectors: list[BaseCatalogConnector],
                  parallel: bool = True) -> None:
        self._connectors = connectors
        self._parallel   = parallel
        self.log         = logging.getLogger("CatalogConnectors.Manager")

    @classmethod
    def from_config(cls, catalog_cfg: dict, secrets: Any,
                     parallel: bool = True) -> "CatalogManager":
        """
        Factory: build a CatalogManager from a nested config dict.

        Parameters
        ----------
        catalog_cfg : dict    Nested config — see module docstring for keys.
        secrets     : Any     SecretsManager instance for credential resolution.
        parallel    : bool    Run connectors in parallel threads (default True).

        Returns
        -------
        CatalogManager  Ready to call register_all() on.
        """
        connectors: list[BaseCatalogConnector] = []

        if "collibra" in catalog_cfg:
            cfg = catalog_cfg["collibra"]
            cfg.setdefault("url",      secrets.get("COLLIBRA_URL",      "Collibra URL"))
            cfg.setdefault("username", secrets.get("COLLIBRA_USER",     "Collibra username"))
            cfg.setdefault("password", secrets.get_password("COLLIBRA_PASSWORD", "Collibra password"))
            connectors.append(CollibraConnector(cfg))

        if "alation" in catalog_cfg:
            cfg = catalog_cfg["alation"]
            cfg.setdefault("url",       secrets.get("ALATION_URL",       "Alation URL"))
            cfg.setdefault("api_token", secrets.get("ALATION_API_TOKEN", "Alation API token"))
            connectors.append(AlationConnector(cfg))

        if "axon" in catalog_cfg:
            cfg = catalog_cfg["axon"]
            cfg.setdefault("url",           secrets.get("INFORMATICA_URL",           "Informatica URL"))
            cfg.setdefault("client_id",     secrets.get("INFORMATICA_CLIENT_ID",     "Informatica client ID"))
            cfg.setdefault("client_secret", secrets.get_password("INFORMATICA_CLIENT_SECRET",
                                                                   "Informatica client secret"))
            connectors.append(InformaticaAxonConnector(cfg))

        if "atlan" in catalog_cfg:
            cfg = catalog_cfg["atlan"]
            cfg.setdefault("url",           secrets.get("ATLAN_URL",       "Atlan tenant URL"))
            cfg.setdefault("api_token",     secrets.get("ATLAN_API_TOKEN", "Atlan API token"))
            cfg.setdefault("connection_qn", secrets.get("ATLAN_CONN_QN",   "Atlan connection qualified name"))
            connectors.append(AtlanConnector(cfg))

        return cls(connectors, parallel=parallel)

    def register_all(self, payload: CatalogMetadataPayload) -> dict[str, bool]:
        """
        Register the payload with all configured connectors.

        Runs each connector through the full 8-step registration sequence.
        If parallel=True, connectors run concurrently in a ThreadPoolExecutor
        (IO-bound — threads are appropriate here).

        Parameters
        ----------
        payload : CatalogMetadataPayload  Metadata to push.

        Returns
        -------
        dict[str, bool]  Maps connector name → True if all steps succeeded.
        """
        if not self._connectors:
            self.log.info("[CatalogManager] No connectors configured — skipping catalog registration.")
            return {}

        results: dict[str, bool] = {}

        if self._parallel and len(self._connectors) > 1:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(self._connectors),
                thread_name_prefix="catalog",
            ) as pool:
                futures = {
                    pool.submit(self._register_one, c, payload): c.name
                    for c in self._connectors
                }
                for future in concurrent.futures.as_completed(futures):
                    name = futures[future]
                    try:
                        results[name] = future.result()
                    except Exception as exc:  # pylint: disable=broad-exception-caught
                        self.log.error("[CatalogManager] %s failed: %s", name, exc)
                        results[name] = False
        else:
            for c in self._connectors:
                results[c.name] = self._register_one(c, payload)

        # Log summary.
        succeeded = sum(1 for v in results.values() if v)
        self.log.info(
            "[CatalogManager] Registration complete: %s/%s catalog(s) succeeded.",
            succeeded, len(results)
        )
        for name, ok in results.items():
            symbol = "✓" if ok else "✗"
            print(f"  {symbol}  [{name}] metadata registration {'succeeded' if ok else 'FAILED'}")

        return results

    def _register_one(self, connector: BaseCatalogConnector,
                        payload: CatalogMetadataPayload) -> bool:
        """
        Execute the full 8-step registration sequence for a single connector.

        Catches and logs exceptions at each step rather than aborting, so
        a partial failure (e.g. lineage API returns 500) doesn't prevent
        the subsequent steps (compliance metadata, PII tags, etc.) from running.

        Returns
        -------
        bool  True if all steps completed without exceptions.
        """
        name = connector.name
        ok   = True
        try:
            # Step 1: Authenticate.
            if not connector.connect():
                self.log.warning("[CatalogManager] %s: connection failed — skipping.", name)
                return False

            # Step 2: Register the table/dataset asset.
            dataset_id = connector.register_dataset(payload)
            if not dataset_id:
                self.log.warning("[CatalogManager] %s: register_dataset returned no ID.", name)
                ok = False

            # Steps 3–7: Enrich the asset with metadata.
            # Each step is individually guarded so a partial API failure
            # doesn't cascade.
            for step_name, step_fn in [
                ("register_columns", lambda: connector.register_columns(payload, dataset_id)),
                ("push_lineage",     lambda: connector.push_lineage(payload, dataset_id)),
                ("push_data_quality",lambda: connector.push_data_quality(payload, dataset_id)),
                ("push_pii_tags",    lambda: connector.push_pii_tags(payload, dataset_id)),
                ("push_compliance",  lambda: connector.push_compliance(payload, dataset_id)),
            ]:
                try:
                    step_fn()
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    self.log.error("[CatalogManager] %s.%s failed: %s", name, step_name, exc)
                    ok = False

            # Step 8: Clean disconnect.
            connector.disconnect()

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log.error("[CatalogManager] %s unexpected failure: %s", name, exc)
            ok = False

        return ok


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION PROMPT  (interactive catalog setup)
# ═════════════════════════════════════════════════════════════════════════════
def prompt_catalog_config() -> dict:
    """
    Interactive wizard to configure which catalogs to register with.

    Presented as part of the pipeline v3 feature configuration wizard.
    Returns a nested dict suitable for passing to CatalogManager.from_config().

    Example return value
    --------------------
    {
        "collibra": {
            "community_id"   : "abc-123",
            "domain_id"      : "def-456",
            "attr_pii_flag"  : "ghi-789",
            "attr_quality_score": "jkl-012",
        },
        "atlan": {
            "connection_qn": "default/sqlite/1234567890",
            "schema_name"  : "default",
        }
    }
    Credentials are intentionally NOT included — they are resolved at runtime
    via SecretsManager from environment variables or .env.
    """
    cfg: dict = {}
    print("\n" + "═" * 64)
    print("  DATA CATALOG INTEGRATION")
    print("═" * 64)
    print("  Register pipeline metadata with enterprise data catalogs.")
    print("  Credentials are read from env vars / .env file automatically.")
    print("  Set COLLIBRA_URL, ALATION_URL, INFORMATICA_URL, ATLAN_URL etc.")
    print("  in your .env file or environment.")

    # ── Collibra ──────────────────────────────────────────────────────────
    if _yn("\n[CATALOG] Register with Collibra DGC?", False):
        cfg["collibra"] = {
            "community_id"       : _prompt("  Community UUID"),
            "domain_id"          : _prompt("  Domain UUID"),
            "attr_pii_flag"      : _prompt("  'PII Flag' attribute type UUID (optional)", ""),
            "attr_quality_score" : _prompt("  'Quality Score' attribute type UUID (optional)", ""),
            "attr_classification": _prompt("  'Classification' attribute type UUID (optional)", ""),
            "attr_retention_days": _prompt("  'Retention Days' attribute type UUID (optional)", ""),
            "attr_lawful_basis"  : _prompt("  'Lawful Basis' attribute type UUID (optional)", ""),
            "attr_pipeline_id"   : _prompt("  'Pipeline ID' attribute type UUID (optional)", ""),
        }
        # Remove empty optional entries.
        cfg["collibra"] = {k: v for k, v in cfg["collibra"].items() if v}
        print("  ✓ Collibra configured. Set COLLIBRA_URL, COLLIBRA_USER, COLLIBRA_PASSWORD in .env")

    # ── Alation ───────────────────────────────────────────────────────────
    if _yn("\n[CATALOG] Register with Alation?", False):
        cfg["alation"] = {
            "ds_id"      : int(_prompt("  Data Source ID (integer)")),
            "schema_name": _prompt("  Schema name", "public"),
        }
        print("  ✓ Alation configured. Set ALATION_URL, ALATION_API_TOKEN in .env")

    # ── Informatica Axon / CDGC ───────────────────────────────────────────
    if _yn("\n[CATALOG] Register with Informatica Axon / CDGC?", False):
        cfg["axon"] = {
            "technical_asset_type": _prompt("  Technical asset type", "TABLE"),
            "org_id"              : _prompt("  Informatica org ID", ""),
        }
        print("  ✓ Informatica Axon configured. Set INFORMATICA_URL, INFORMATICA_CLIENT_ID,")
        print("    INFORMATICA_CLIENT_SECRET in .env")

    # ── Atlan ─────────────────────────────────────────────────────────────
    if _yn("\n[CATALOG] Register with Atlan?", False):
        cfg["atlan"] = {
            "connection_qn"      : _prompt("  Connection qualified name (e.g. default/postgresql/1234567890)"),
            "schema_name"        : _prompt("  Schema name", "default"),
            "custom_metadata_set": _prompt("  Custom Metadata set name", "DataGovernancePipeline"),
            "certificate_status" : _prompt("  Certificate status (DRAFT/VERIFIED)", "DRAFT"),
        }
        print("  ✓ Atlan configured. Set ATLAN_URL, ATLAN_API_TOKEN in .env")

    return cfg


def _yn(msg: str, default: bool = True) -> bool:
    """Yes/No prompt helper (duplicated here to keep module self-contained)."""
    suffix = "[Y/n]" if default else "[y/N]"
    resp = input(f"{msg} {suffix}: ").strip().lower()
    return default if not resp else resp in ("y", "yes")


def _prompt(msg: str, default: str = "") -> str:
    """Prompt helper (duplicated here to keep module self-contained)."""
    resp = input(f"{msg} [{default}]: " if default else f"{msg}: ").strip()
    return resp if resp else default


# ═════════════════════════════════════════════════════════════════════════════
#  CATALOG PAYLOAD SERIALISER  (for offline testing and audit trail)
# ═════════════════════════════════════════════════════════════════════════════
def save_catalog_payload(payload: CatalogMetadataPayload,
                          output_dir: str = "governance_logs") -> Path:
    """
    Serialise the catalog payload to a JSON file in the governance logs directory.

    This serves two purposes:
      1. Offline testing — you can inspect exactly what would be sent to each
         catalog without needing a live catalog instance.
      2. Audit trail — the serialised payload is a record of what metadata was
         published and when, independently of each catalog's own audit log.

    Parameters
    ----------
    payload    : CatalogMetadataPayload  Payload to serialise.
    output_dir : str                     Output directory path.

    Returns
    -------
    Path  Path to the written file.
    """
    import dataclasses
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path= out_dir / f"catalog_payload_{ts}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(dataclasses.asdict(payload), f, indent=2, default=str)
    log.info("[CatalogManager] Payload saved → %s", out_path)
    return out_path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE ENTRY POINT (for testing without the full pipeline)
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys as _sys
    if any(a in ("-h", "--help") for a in _sys.argv[1:]):
        print(
            "\n  catalog_connectors.py — Catalog Integration Module\n"
            "\n  Usage:\n"
            "    python catalog_connectors.py          # run smoke test\n"
            "    python catalog_connectors.py --help   # show this message\n"
            "\n  Import the classes into pipeline_v3.py for production use.\n"
        )
        raise SystemExit(0)

    # Minimal smoke test — builds a synthetic _smoke_payload and serialises it.
    # Does NOT make live catalog API calls (no credentials needed).
    # Run with:  python catalog_connectors.py
    logging.basicConfig(level=logging.INFO,
                         format="%(asctime)s [%(levelname)s] %(message)s")

    print("=" * 64)
    print("  CATALOG CONNECTORS v1.0 — Smoke Test")
    print("=" * 64)

    # Build a synthetic _smoke_payload (mirrors what build_catalog_payload() produces).
    _smoke_payload = CatalogMetadataPayload(
        table_name    = "employees",
        database_name = "pipeline_output",
        db_type       = "sqlite",
        description   = ("Table loaded by Data Governance Pipeline v3.0.0 "
                          "from sample_data_v3.json.  Contains 5 PII fields "
                          "(masked).  Classification: CONFIDENTIAL.  "
                          "Retention: 365 days."),
        columns       = [
            ColumnMeta("id",         "int64",  False, False, "", False, False, "INTERNAL"),
            ColumnMeta("first_name", "object", True,  False, "Article 4(1)", False, True,  "CONFIDENTIAL", 0.0, 4, "PII — first name, SHA-256 masked"),
            ColumnMeta("last_name",  "object", True,  False, "Article 4(1)", False, True,  "CONFIDENTIAL", 0.0, 4, "PII — last name, SHA-256 masked"),
            ColumnMeta("email",      "object", True,  False, "Article 4(1)", False, True,  "CONFIDENTIAL", 0.0, 4, "PII — email address, SHA-256 masked"),
            ColumnMeta("phone",      "object", True,  False, "Article 4(1)", False, True,  "CONFIDENTIAL", 0.0, 4, "PII — phone, E.164 normalised then masked"),
            ColumnMeta("salary",     "float64",True,  False, "Article 4(1)", False, True,  "CONFIDENTIAL", 0.25, 3, "PII — compensation data, SHA-256 masked"),
            ColumnMeta("department_id",  "int64",  False, False, "", False, False, "INTERNAL"),
            ColumnMeta("department_name","object", False, False, "", False, False, "INTERNAL"),
            ColumnMeta("country_code",   "object", False, False, "", False, False, "INTERNAL"),
            ColumnMeta("_pipeline_id",   "object", False, False, "", False, False, "PUBLIC"),
            ColumnMeta("_loaded_at_utc", "object", False, False, "", False, False, "PUBLIC"),
            ColumnMeta("_data_classification","object", False, False, "", False, False, "PUBLIC"),
        ],
        quality       = DataQualityMeta(
            suite_name          = "pipeline_suite_demo",
            expectations_total  = 22,
            expectations_passed = 22,
            expectations_failed = 0,
            overall_success     = True,
            dlq_rows            = 0,
            total_rows          = 4,
        ),
        lineage       = LineageMeta(
            source_path     = "sample_data_v3.json",
            source_format   = ".json",
            source_sha256   = "abc123def456",
            pipeline_id     = str(uuid.uuid4()),
            pipeline_version= "3.0.0",
            operator        = "pipeline_user",
            run_timestamp   = datetime.now(timezone.utc).isoformat(),
            dest_db_type    = "sqlite",
            dest_db_name    = "pipeline_output",
            dest_table      = "employees",
            rows_loaded     = 4,
        ),
        compliance    = ComplianceMeta(
            lawful_basis        = "Legitimate Interests",
            processing_purpose  = "HR data analysis",
            retention_days      = 365,
            pii_strategy        = "mask",
            data_classification = "CONFIDENTIAL",
            transfer_type       = "DOMESTIC",
            source_country      = "US",
            dest_country        = "US",
        ),
        tags = ["data-governance-pipeline","v3.0.0","contains-pii",
                "classification-confidential","gdpr-compliant"],
    )

    # Serialise the _smoke_payload (no live API calls).
    _smoke_out_path = save_catalog_payload(_smoke_payload, output_dir="test_catalog_logs")
    print(f"\n  ✓ Payload serialised → {_smoke_out_path}")
    print(f"  ✓ {len(_smoke_payload.columns)} columns  |  "
          f"{len(_smoke_payload.pii_columns)} PII  |  "
          f"quality={_smoke_payload.quality.pass_rate:.0%}")
    print(f"  ✓ Tags: {_smoke_payload.tags}")
    print("\n  To use with live catalogs, set env vars and call:")
    print("    manager = CatalogManager.from_config(catalog_cfg, secrets)")
    print("    manager.register_all(_smoke_payload)")
    print("\n[DONE] Catalog connectors smoke test passed ✓")
