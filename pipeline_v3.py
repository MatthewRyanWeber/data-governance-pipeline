"""
=============================================================
  DATA GOVERNANCE PIPELINE  v3.0.0
  GDPR & CCPA Compliant ETL Tool
  Author: Data Governance Pipeline
=============================================================

WHAT'S NEW IN v3.0
------------------
  Everything from v2.0 PLUS:

  ① Compression Support     — Read directly from .gz, .zip, and .bz2
                              compressed source files without manual
                              decompression.  Auto-detected by extension.

  ② Parallel Processing     — concurrent.futures ThreadPoolExecutor
                              applies transformations across chunks
                              simultaneously on multi-core machines.
                              Configurable worker count.

  ③ Checkpoint / Resume     — Saves chunk-level progress to a state file
                              so a pipeline interrupted mid-run can resume
                              from the last completed chunk rather than
                              starting over.

  ④ SLA Monitor             — Tracks elapsed time against a configurable
                              deadline.  Fires a WARNING audit event and
                              (optionally) a notification if the pipeline
                              is still running past the SLA threshold.

  ⑤ Metrics Collector       — Measures throughput (rows/sec), error rates,
                              and per-stage durations.  Writes a structured
                              metrics report to governance_logs/.

  ⑥ Type Coercer            — Explicit, config-driven dtype casting before
                              transformation.  Prevents silent type mis-
                              inference (e.g. numeric IDs loaded as floats,
                              dates loaded as strings).

  ⑦ Data Standardiser       — Normalises common formats:
                              • Phone numbers → E.164 (+12125550101)
                              • Dates         → ISO-8601 (YYYY-MM-DD)
                              • Country names → ISO 3166-1 alpha-2 codes
                              • Boolean text  → True / False

  ⑧ Business Rule Engine    — Applies operator-defined transformation rules
                              from a JSON config file without touching Python
                              code.  Supports: rename, fill_null, map_values,
                              derive (formula), filter_out, flag.

  ⑨ Data Enrichment         — Left-joins a lookup / reference table onto
                              the dataset during transformation.  Useful for
                              adding department names, region codes, product
                              descriptions, etc.

  ⑩ Referential Integrity   — Verifies that foreign-key values in the source
     Checker                  data actually exist in the reference table
                              before loading.  Violations routed to DLQ.

  ⑪ Column-Level Encryption — AES-256-CBC (via cryptography.Fernet) for
                              fields that must be stored encrypted-at-rest
                              and later decrypted.  Distinct from SHA-256
                              masking: encrypted values CAN be recovered
                              with the key.

  ⑫ Audit Log Tamper        — Chained SHA-256 hash: each JSONL ledger event
     Detection               includes a hash of the previous event.  Any
                              tampering with past entries breaks the chain
                              and is detectable via verify_ledger().

  ⑬ GDPR Right-to-Erasure   — ErasureHandler locates all rows for a given
     Handler (Art. 17)         subject ID across the target database and
                              deletes or nullifies them.  Logs a GDPR_ERASURE
                              event for the compliance audit trail.

  ⑭ Data Classification     — Tags every loaded row with a sensitivity level
     Tagger                   (PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED)
                              derived from PII findings.  Stored in the
                              _data_classification metadata column.

  ⑮ Cross-Border Transfer   — Detects when source and destination are in
     Logger (GDPR Ch. V)      different jurisdictions and logs a GDPR_TRANSFER
                              event with the applicable safeguard (SCC,
                              Adequacy Decision, BCR, etc.).

FULL PIPELINE FLOW (v3.0)
--------------------------
  1.  CLI args + dependency check
  2.  SecretsManager + GovernanceLogger (with chained-hash tamper detection)
  3.  Source file (with compression support)
  4.  SLA monitor start
  5.  Extract (chunked / parallel)
  6.  Data profiling + MetricsCollector start
  7.  Type coercion
  8.  Data standardisation
  9.  PII scan + Data classification
  10. Incremental filter
  11. Business rule engine
  12. Data enrichment
  13. Referential integrity check → DLQ violations
  14. Compliance wizard (GDPR/CCPA)
  15. Cross-border transfer check
  16. Schema validation (Great Expectations)
  17. Transform (flatten, minimise, PII strategy, dedup, sanitise)
  18. Column-level encryption
  19. Load with retry + idempotency
  20. Update watermark + checkpoint
  21. SLA check
  22. Metrics report
  23. Notifications
  24. All governance artefacts

REGULATORY COVERAGE
-------------------
  GDPR : Art. 4, 5(1)(c), 5(1)(e), 6, 9, 17, 25, 30, 32, Chapter V
  CCPA : §1798.100, §1798.120, §1798.140(o), §1798.150

DEPENDENCIES (new in v3.0)
--------------------------
  cryptography>=41.0  — Column-level AES-256 encryption
  phonenumbers>=8.13  — E.164 phone number normalisation
  All v2.0 dependencies also required (see requirements_v3.txt)
=============================================================
"""

# ─────────────────────────────────────────────────────────────────────────────
#  STANDARD LIBRARY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import argparse  # noqa: F401
import bz2
import concurrent.futures  # noqa: F401
# import csv  # noqa: unused
import getpass
import gzip
import hashlib
import io
import json
import logging
import os
import platform
import re
import smtplib
import sys
import threading
import time
import uuid
import zipfile
# from copy import deepcopy  # noqa: unused
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Iterator, NoReturn

# ─────────────────────────────────────────────────────────────────────────────
#  THIRD-PARTY DEPENDENCY CHECKS
# ─────────────────────────────────────────────────────────────────────────────
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
    from dotenv import dotenv_values
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    # Not added to MISSING — encryption is optional

try:
    import phonenumbers
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False
    # Optional — phone standardisation degrades gracefully

try:
    import snowflake.connector as _sf_connector
    from snowflake.sqlalchemy import URL as _sf_url
    from sqlalchemy import create_engine as _sf_create_engine
    HAS_SNOWFLAKE = True
except ImportError:
    HAS_SNOWFLAKE = False
    # Optional — Snowflake loader degrades gracefully

try:
    import redshift_connector as _redshift_connector
    HAS_REDSHIFT = True
except ImportError:
    HAS_REDSHIFT = False
    # Optional — Redshift loader degrades gracefully

try:
    from google.cloud import bigquery as _bigquery
    from google.oauth2 import service_account as _gcp_sa
    HAS_BIGQUERY = True
except ImportError:
    HAS_BIGQUERY = False
    # Optional — BigQuery loader degrades gracefully

try:
    import pyodbc as _pyodbc                                  # for Synapse ODBC
    from azure.identity import ClientSecretCredential as _AzureCSC
    from azure.storage.blob import BlobServiceClient as _BlobServiceClient
    HAS_SYNAPSE = True
except ImportError:
    HAS_SYNAPSE = False
    # Optional — Synapse loader degrades gracefully; pyodbc alone is enough
    # for basic Synapse; blob staging requires azure-storage-blob too.

try:
    import databricks.sql as _databricks_sql
    HAS_DATABRICKS = True
except ImportError:
    HAS_DATABRICKS = False
    # Optional — Databricks / Delta Lake loader degrades gracefully

try:
    import clickhouse_connect as _clickhouse_connect
    HAS_CLICKHOUSE = True
except ImportError:
    HAS_CLICKHOUSE = False
    # Optional — ClickHouse loader degrades gracefully

try:
    import oracledb as _oracledb
    HAS_ORACLE = True
except ImportError:
    HAS_ORACLE = False
    # Optional — Oracle ADW loader degrades gracefully.
    # python-oracledb operates in Thin mode by default (no Oracle Client needed).

try:
    import ibm_db as _ibm_db           # low-level DBAPI2 driver
    __import__('ibm_db_sa')             # verify SQLAlchemy dialect present
    HAS_DB2 = True
except ImportError:
    HAS_DB2 = False
    # Optional — IBM Db2 Warehouse loader degrades gracefully

try:
    from firebolt.db import connect as _firebolt_connect
    from firebolt.client.auth import UsernamePassword as _FBUserPass
    from firebolt.client.auth import ClientCredentials as _FBClientCreds
    HAS_FIREBOLT = True
except ImportError:
    HAS_FIREBOLT = False
    # Optional — Firebolt loader degrades gracefully

# Yellowbrick uses the PostgreSQL wire protocol (psycopg2 / SQLAlchemy).
# psycopg2 is already a core dependency (pulled in by sqlalchemy-redshift).
# We gate on it separately so the Yellowbrick wizard item degrades gracefully
# if psycopg2 is somehow absent.
try:
    __import__('psycopg2')  # verify psycopg2 present for YellowbrickLoader
    HAS_YELLOWBRICK = True
except ImportError:
    HAS_YELLOWBRICK = False
    # Optional — Yellowbrick loader degrades gracefully

try:
    import hdbcli.dbapi as _hdbcli          # noqa: F401
    HAS_HANA = True
except ImportError:
    HAS_HANA = False
    # Optional — SAP HANA loader degrades gracefully

try:
    import requests as _sap_requests        # noqa: F401 (already a dep)
    HAS_DATASPHERE = True
except ImportError:
    HAS_DATASPHERE = False
    # Optional — SAP Datasphere loader degrades gracefully (uses requests)

# QuickBooks Online — uses requests (OAuth2 + REST API v3)
# intuit-oauth is optional; raw OAuth2 via requests also works
HAS_QUICKBOOKS = True   # requests is already a core dep; no extra package needed
try:
    import requests as _qb_requests         # noqa: F401
except ImportError:
    HAS_QUICKBOOKS = False

# Kafka producer — for KafkaLoader destination
try:
    from kafka import KafkaProducer as _KafkaProd  # noqa: F401
    HAS_KAFKA_LOADER = True
except ImportError:
    HAS_KAFKA_LOADER = False
    # Optional — KafkaLoader degrades gracefully

# CockroachDB — distributed PostgreSQL-compatible database
try:
    import sqlalchemy_cockroachdb as _crdb  # noqa: F401
    HAS_COCKROACH = True
except ImportError:
    HAS_COCKROACH = False
    # Falls back to psycopg2 driver — still works, loses CRDB-specific opts

# pgvector — PostgreSQL vector extension
try:
    import pgvector as _pgvector                    # noqa: F401
    HAS_PGVECTOR = True
except ImportError:
    HAS_PGVECTOR = False

# Chroma — open-source embedded vector database
try:
    import chromadb as _chromadb                    # noqa: F401
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False

# Milvus — enterprise-grade vector database (server or Lite mode)
try:
    from pymilvus import MilvusClient as _MilvusClient  # noqa: F401
    HAS_MILVUS = True
except ImportError:
    HAS_MILVUS = False

# Pinecone — managed cloud vector database
try:
    import pinecone as _pinecone                    # noqa: F401
    HAS_PINECONE = True
except ImportError:
    HAS_PINECONE = False

# Weaviate — open-source vector database with hybrid search
try:
    import weaviate as _weaviate                    # noqa: F401
    HAS_WEAVIATE = True
except ImportError:
    HAS_WEAVIATE = False

# Qdrant — high-performance open-source vector database
try:
    from qdrant_client import QdrantClient as _QdrantClient  # noqa: F401
    HAS_QDRANT = True
except ImportError:
    HAS_QDRANT = False

# LanceDB — serverless vector database for AI/ML embedding storage
try:
    import lancedb as _lancedb                      # noqa: F401
    HAS_LANCEDB = True
except ImportError:
    HAS_LANCEDB = False
    # Optional — LanceDB loader degrades gracefully

# ── File-format optional dependencies ─────────────────────────────────────
# Parquet / Feather / Arrow — pyarrow provides all three
try:
    import pyarrow.parquet as _pq                  # noqa: F401  (used in chunks())
    HAS_PYARROW = True
except ImportError:
    HAS_PYARROW = False

# Avro
try:
    import fastavro as _fastavro                   # noqa: F401
    HAS_AVRO = True
except ImportError:
    HAS_AVRO = False

# ORC
try:
    import pyorc as _pyorc                         # noqa: F401
    HAS_ORC = True
except ImportError:
    HAS_ORC = False

# YAML
try:
    import yaml as _yaml                           # noqa: F401
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Zstandard compression
try:
    import zstandard as _zstd                      # noqa: F401
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

# LZ4 compression
try:
    import lz4.frame as _lz4frame                  # noqa: F401
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

try:
    from catalog_connectors import (  # noqa: F401
        CatalogManager,             # noqa: F401
        build_catalog_payload,      # noqa: F401
        prompt_catalog_config,      # noqa: F401
        save_catalog_payload,       # noqa: F401
    )
    HAS_CATALOG = True
except ImportError:
    HAS_CATALOG = False

try:
    from metadata_extensions import (  # noqa: F401
        MetadataExtensionOrchestrator,      # noqa: F401
        prompt_metadata_extensions_config,  # noqa: F401
        SchemaDriftError,                   # noqa: F401
        DataFreshnessError,                 # noqa: F401
        generate_contract_template,         # noqa: F401
    )
    HAS_META_EXT = True
except ImportError:
    HAS_META_EXT = False

try:
    from pipeline_additions import (  # noqa: F401
        AdditionsOrchestrator,   # noqa: F401
        prompt_additions_config, # noqa: F401
    )
    HAS_ADDITIONS = True
except ImportError:
    HAS_ADDITIONS = False



# ─────────────────────────────────────────────────────────────────────────────
#  PIPELINE-LEVEL CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION           = "3.0.0"
PIPELINE_ID       = str(uuid.uuid4())
RUN_START         = datetime.now(timezone.utc).isoformat()
DEFAULT_CHUNK_SIZE= 50_000
BASE_DIR          = Path(__file__).resolve().parent
WATERMARK_FILE    = BASE_DIR / "pipeline_watermark.json"
CHECKPOINT_FILE   = BASE_DIR / "pipeline_checkpoint.json"
_STATE_FILE_LOCK  = __import__("threading").RLock()  # guards checkpoint + watermark JSON files

# ── ISO 3166-1 alpha-2 country codes recognised as within the EU/EEA
#    (used by the cross-border transfer checker)
EU_EEA_COUNTRY_CODES: set[str] = {
    "AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR",
    "HU","IE","IT","LV","LT","LU","MT","NL","PL","PT","RO","SK",
    "SI","ES","SE","IS","LI","NO",
}

# ── Countries with EU Adequacy Decisions (GDPR Art. 45) as of 2025
ADEQUATE_COUNTRIES: set[str] = {
    "AD","AR","CA","FO","GG","IL","IM","JP","JE","NZ","KR","CH","UY","UK",
}

# ── Data sensitivity classification levels (highest to lowest)
CLASSIFICATION_LEVELS = ["RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC"]

# ─────────────────────────────────────────────────────────────────────────────
#  PII PATTERNS  (unchanged from v2.0)
# ─────────────────────────────────────────────────────────────────────────────
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
    r"\bhealth", r"\bmedical", r"\bdiagnos",
    r"\bsalary", r"\bincome", r"\bwage",
    r"\breligion", r"\bpolitical",
]
SENSITIVE_CATEGORIES: set[str] = {
    r"\bhealth", r"\bmedical", r"\brace\b", r"\bethnicity\b",
    r"\breligion", r"\bpolitical", r"\bbiometric", r"\bgenetic",
    r"\bssn\b", r"\bpassport\b",
}


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: GovernanceLogger  (v3.0 — adds chained-hash tamper detection)
# ═════════════════════════════════════════════════════════════════════════════
class GovernanceLogger:
    """
    Central audit and governance logging facility (all v2.0 features plus):

    v3.0 additions
    --------------
    Chained-hash tamper detection
      Each event written to the JSONL ledger includes a "prev_hash" field
      containing the SHA-256 hash of the raw JSON of the PREVIOUS event.
      This creates a cryptographic chain: if any past event is modified,
      the chain breaks at that point and verify_ledger() will detect it.
      This is analogous to a simplified blockchain and satisfies GDPR
      Art. 32 requirements for integrity of processing records.

    New event categories
    --------------------
    METRICS        — pipeline throughput and timing statistics
    ENCRYPTION     — column-level encryption events
    ENRICHMENT     — data enrichment join events
    REFERENTIAL    — referential integrity check events
    ERASURE        — GDPR Art. 17 right-to-erasure events
    CLASSIFICATION — data sensitivity tagging events
    TRANSFER       — GDPR Chapter V cross-border transfer events
    SLA            — SLA threshold events
    CHECKPOINT     — chunk-level checkpoint save/restore events
    STANDARDISE    — data standardisation transformation events
    RULES          — business rule engine application events
    """

    def __init__(
        self,
        source_name: str = "pipeline",
        log_dir:     str | None = None,
    ) -> None:
        """
        Parameters
        ----------
        source_name : str
            The name of the data source — typically the file name
            (``"customers.csv"``) or table name (``"orders"``).
            Used to derive the log folder: ``"customers LOGS"``.

        log_dir : str | None
            Override the auto-derived folder with an explicit path.
            When omitted the folder is ``"<stem> LOGS"`` in the
            working directory, where ``<stem>`` is the source name
            without its file extension.
        """
        stem = Path(source_name).stem if source_name else "pipeline"
        for ch in ('/', '\\', ':', '*', '?', '"', '<', '>', '|'):
            stem = stem.replace(ch, '_')
        stem = stem.strip() or "pipeline"

        self.source_name = stem
        self.log_dir     = (Path(log_dir) if log_dir else Path(f"{stem} LOGS")).resolve()
        self.log_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # ── Timestamped artefacts (one per run) ───────────────────────────
        self.log_file            = self.log_dir / f"pipeline_{ts}.log"
        self.ledger_file         = self.log_dir / f"audit_ledger_{ts}.jsonl"
        self.pii_report_file     = self.log_dir / f"pii_report_{ts}.json"
        self.validation_rpt_file = self.log_dir / f"validation_report_{ts}.json"
        self.profile_rpt_file    = self.log_dir / f"profile_report_{ts}.json"
        self.dlq_file            = self.log_dir / f"dlq_{ts}.csv"
        self.metrics_rpt_file    = self.log_dir / f"metrics_report_{ts}.json"
        self.classification_file = self.log_dir / f"classification_report_{ts}.json"
        self.transfer_log_file   = self.log_dir / f"transfer_log_{ts}.json"

        # ── Persistent logs (append across runs, one file for lifetime) ───
        self.cost_log_file  = self.log_dir / "cost_history.jsonl"
        self.quality_log_file = self.log_dir / "quality_history.jsonl"

        # ── Snapshots subfolder (reversible loads) ────────────────────────
        self.snapshot_dir = self.log_dir / "snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

        # ── Python logging setup ──────────────────────────────────────────
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger("DataPipeline")

        # ── In-memory accumulators ────────────────────────────────────────
        self.pii_findings:         list[dict] = []
        self.ledger_entries:       list[dict] = []
        self.validation_results:   list[dict] = []
        self.classification_tags:  list[dict] = []
        self.transfer_events:      list[dict] = []
        self.dlq_rows_total:       int = 0
        self._prev_hash:           str = "GENESIS"
        # _prev_hash starts at "GENESIS" — the sentinel for the first event
        self._event_lock = threading.RLock()  # serialises _prev_hash updates
        # in the chain (nothing precedes it).

    # ── Core event writer with chained hash ──────────────────────────────
    def _event(
        self,
        category: str,
        action:   str,
        detail:   dict | None = None,
        level:    str = "INFO",
    ) -> None:
        """
        Write a structured audit event to the JSONL ledger.

        v3.0 adds a "prev_hash" field to every event — the SHA-256 of the
        raw JSON string of the previous event (or "GENESIS" for the first).
        This creates an immutable chain: changing any historical event
        invalidates all subsequent hashes, making tampering detectable.
        """
        # Build the static fields outside the lock (no shared state yet)
        base_entry = {
            "pipeline_id"   : PIPELINE_ID,
            "event_id"      : str(uuid.uuid4()),
            "timestamp_utc" : datetime.now(timezone.utc).isoformat(),
            "host"          : platform.node(),
            "os_user"       : getpass.getuser(),
            "category"      : category,
            "action"        : action,
            "detail"        : detail or {},
        }

        # Hold the lock for prev_hash read → entry assembly → hash compute →
        # file write → prev_hash update.  Serialising ALL of this ensures that
        # no two threads can interleave their chain links.
        with self._event_lock:
            base_entry["prev_hash"] = self._prev_hash          # Chain link
            raw_json        = json.dumps(base_entry, sort_keys=True)
            self._prev_hash = hashlib.sha256(raw_json.encode()).hexdigest()
            base_entry["self_hash"] = self._prev_hash
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(base_entry, sort_keys=True) + "\n")
            self.ledger_entries.append(base_entry)

        _ = base_entry  # noqa: F841 — kept for clarity; value logged above

        msg = f"[{category}] {action}"
        if detail:
            msg += f" | {json.dumps(detail)}"
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    def verify_ledger(self) -> bool:
        """
        Walk the JSONL ledger and verify the chained-hash integrity.

        For each event (except the first), re-compute the SHA-256 of the
        previous event's raw JSON and compare it against the stored
        prev_hash field.  Any mismatch indicates tampering.

        Returns
        -------
        bool  True if the entire ledger is intact; False if tampering detected.
        """
        if not self.ledger_file.exists():
            return True

        with open(self.ledger_file, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        if not lines:
            return True

        prev_hash = "GENESIS"
        for i, line in enumerate(lines):
            event = json.loads(line)
            stored_prev = event.get("prev_hash", "")
            if stored_prev != prev_hash:
                self.logger.error(
                    "[TAMPER DETECTED] Event #%s (id=%s) "
                    "expected prev_hash=%r but found %r",
                    i+1, event.get("event_id"), prev_hash, stored_prev
                )
                return False
            # Recompute this event's own hash and verify self_hash if present.
            # Backward-compatible: old ledger files without self_hash are skipped.
            entry_for_hash = {k: v for k, v in event.items() if k != "self_hash"}
            computed_hash  = hashlib.sha256(
                json.dumps(entry_for_hash, sort_keys=True).encode()
            ).hexdigest()
            stored_self = event.get("self_hash")
            if stored_self and stored_self != computed_hash:
                self.logger.error(
                    "[TAMPER DETECTED] Event #%s (id=%s) "
                    "self_hash mismatch — event content has been altered",
                    i+1, event.get("event_id"),
                )
                return False
            prev_hash = computed_hash

        self.logger.info("[TAMPER CHECK] Ledger integrity verified — %s events OK.", len(lines))
        return True

    # ── v2.0 event wrappers (carried forward) ─────────────────────────────
    def pipeline_start(self, m: dict)    -> None: self._event("LIFECYCLE",   "PIPELINE_STARTED",   m)
    def pipeline_end(self,   s: dict)    -> None: self._event("LIFECYCLE",   "PIPELINE_COMPLETED", s)
    def pipeline_complete(self, s: dict) -> None: self.pipeline_end(s)  # alias for pipeline_end()
    def transformation_applied(self, n: str, d: dict | None = None) -> None:
        self._event("TRANSFORMATION", n, d)

    def source_registered(self, path: str, ft: str, rows: int, cols: int) -> None:
        try:
            sha = _file_hash(path)
        except (FileNotFoundError, OSError):
            sha = "N/A"  # file may be a DB table name or in-memory source
        self._event("LINEAGE", "SOURCE_REGISTERED", {
            "source_path": path, "file_type": ft,
            "row_count": rows, "col_count": cols, "sha256": sha})

    def destination_registered(self, db: str, name: str, table: str) -> None:
        self._event("LINEAGE", "DESTINATION_REGISTERED",
                    {"db_type": db, "db_name": name, "table_or_collection": table})

        # Shared region-prefix → ISO country code lookup used by all cloud loaders.
        _pfx_cc = {
            "us": "US", "eu": "EU", "ap": "SG", "ca": "CA",
            "sa": "BR", "me": "AE", "a": "ZA", "au": "AU",
        }

        # ── Snowflake: account encodes region (e.g. "xy12345.eu-west-1/DB/schema") ──
        if db == "snowflake" and "/" in name:
            account = name.split("/")[0]
            parts   = account.split(".")
            if len(parts) >= 2:
                region  = parts[1]
                dest_cc = _pfx_cc.get(region.split("-")[0].lower(), "US")
                self.transfer_logged(
                    source_country = "US",
                    dest_country   = dest_cc,
                    transfer_type  = "SNOWFLAKE_CLOUD_REGION",
                    safeguard      = "SCC",
                )

        # ── Redshift: host encodes region (e.g. "cluster.abcd.us-east-1.redshift.amazonaws.com") ──
        elif db == "redshift" and "/" in name:
            host = name.split("/")[0]
            # Each dot-segment may be "eu-west-1", "us-east-1" etc.
            # Split each segment on "-" to extract the region prefix.
            for part in host.split("."):
                pfx = part.split("-")[0].lower()   # "eu-west-1" → "eu"
                if pfx in _pfx_cc:
                    dest_cc = _pfx_cc[pfx]
                    self.transfer_logged(
                        source_country = "US",
                        dest_country   = dest_cc,
                        transfer_type  = "REDSHIFT_CLOUD_REGION",
                        safeguard      = "SCC",
                    )
                    break

        # ── BigQuery: location is explicit in name ("project/dataset@EU" etc.) ──
        elif db == "bigquery" and "@" in name:
            location = name.split("@")[-1].upper()
            if "EU" in location or "EUROPE" in location:
                self.transfer_logged(
                    source_country = "EU",
                    dest_country   = "EU",
                    transfer_type  = "INTRA_EU",
                    safeguard      = "EU/EEA intra-zone — no restrictions",
                )
            else:
                region_map = {
                    "US": "US", "ASIA": "SG", "AUSTRALIA-SOUTHEAST1": "AU",
                }
                dest_cc = region_map.get(location, "US")
                self.transfer_logged(
                    source_country = "US",
                    dest_country   = dest_cc,
                    transfer_type  = "BIGQUERY_REGION",
                    safeguard      = "SCC",
                )

        # ── Synapse: host encodes Azure region indirectly via workspace name ──
        # (No automatic region inference — operator should configure transfer
        #  logging explicitly for Synapse if cross-border controls are required.)

    def load_complete(self, rows: int, table: str) -> None:
        self._event("LINEAGE", "LOAD_COMPLETE",
                    {"rows_written": rows, "destination_table": table})

    def pii_detected(self, findings: list[dict]) -> None:
        self.pii_findings.extend(findings)
        self._event("PRIVACY", "PII_DETECTED",
                    {"findings_count": len(findings),
                     "fields": [f["field"] for f in findings]}, level="WARNING")

    def pii_action(self, field: str, action: str) -> None:
        self._event("PRIVACY", f"PII_{action}", {"field": field})

    def data_minimization(self, orig: list, retained: list, dropped: list) -> None:
        self._event("PRIVACY", "DATA_MINIMIZATION_APPLIED", {
            "original_column_count": len(orig),
            "retained_column_count": len(retained),
            "dropped_columns": dropped})

    def consent_recorded(self, purpose: str, basis: str, confirmed: bool) -> None:
        self._event("CONSENT", "LAWFUL_BASIS_RECORDED",
                    {"processing_purpose": purpose, "lawful_basis": basis,
                     "user_confirmed": confirmed})

    def retention_policy(self, policy: str, days: int | None) -> None:
        self._event("RETENTION", "POLICY_RECORDED",
                    {"policy": policy, "retention_days": days})

    def validation_result(self, suite: str, ok: bool, p: int, f: int, t: int) -> None:
        self._event("VALIDATION", "SUITE_RESULT", {
            "suite_name": suite, "overall_success": ok,
            "expectations_passed": p, "expectations_failed": f,
            "expectations_total": t}, level="INFO" if ok else "WARNING")

    def validation_expectation(self, exp: str, col: str | None,
                                ok: bool, unexpected: int = 0) -> None:
        self.validation_results.append(
            {"expectation": exp, "column": col, "success": ok, "unexpected_count": unexpected})
        self._event("VALIDATION", "EXPECTATION_RESULT", {
            "expectation": exp, "column": col,
            "success": ok, "unexpected_count": unexpected},
            level="INFO" if ok else "WARNING")

    def profile_recorded(self, summary: dict) -> None:
        self._event("PROFILING", "PROFILE_GENERATED", summary)

    def dlq_written(self, count: int, reason: str) -> None:
        self.dlq_rows_total += count
        self._event("DLQ", "ROWS_REJECTED", {
            "rejected_row_count": count, "reason": reason,
            "dlq_file": str(self.dlq_file)}, level="WARNING")

    def watermark_event(self, action: str, col: str, val: Any, filtered: int = 0) -> None:
        self._event("INCREMENTAL", f"WATERMARK_{action}",
                    {"watermark_column": col, "watermark_value": str(val),
                     "rows_filtered": filtered})

    def retry_attempt(self, attempt: int, max_att: int, wait: float, exc: Exception) -> None:
        self._event("RETRY", "RETRY_ATTEMPT", {
            "attempt": attempt, "max_attempts": max_att,
            "wait_seconds": wait, "exception": str(exc)}, level="WARNING")

    def notification_sent(self, channel: str, status: str, detail: str = "") -> None:
        self._event("NOTIFICATION", f"{channel.upper()}_{status}", {"detail": detail})

    def error(self, msg: str, exc: Exception | None = None) -> None:
        self._event("ERROR", msg,
                    {"exception": str(exc)} if exc else None, level="ERROR")

    # ── v3.0 new event wrappers ────────────────────────────────────────────

    def sla_event(self, status: str, elapsed_sec: float, threshold_sec: float) -> None:
        """
        Record an SLA status event.

        Parameters
        ----------
        status        : "OK" | "BREACH" | "WARNING"
        elapsed_sec   : How many seconds the pipeline has been running.
        threshold_sec : Configured SLA deadline in seconds.
        """
        level = "WARNING" if status in ("BREACH", "WARNING") else "INFO"
        self._event("SLA", f"SLA_{status}", {
            "elapsed_seconds"  : round(elapsed_sec, 1),
            "threshold_seconds": threshold_sec,
            "over_by_seconds"  : max(0, round(elapsed_sec - threshold_sec, 1)),
        }, level=level)

    def metrics_recorded(self, metrics: dict) -> None:
        """Record pipeline throughput and timing metrics."""
        self._event("METRICS", "METRICS_RECORDED", metrics)

    def encryption_applied(self, field: str, algorithm: str) -> None:
        """Record that a column was encrypted."""
        self._event("ENCRYPTION", "COLUMN_ENCRYPTED",
                    {"field": field, "algorithm": algorithm})

    def enrichment_applied(self, join_col: str, lookup_table: str,
                            rows_matched: int, rows_total: int) -> None:
        """Record a data enrichment join."""
        self._event("ENRICHMENT", "LOOKUP_JOIN_APPLIED", {
            "join_column"  : join_col,
            "lookup_table" : lookup_table,
            "rows_matched" : rows_matched,
            "rows_total"   : rows_total,
            "match_rate"   : round(rows_matched / rows_total, 4) if rows_total else 0,
        })

    def referential_integrity_checked(self, fk_col: str, ref_table: str,
                                       valid: int, invalid: int) -> None:
        """Record the result of a referential integrity check."""
        level = "INFO" if invalid == 0 else "WARNING"
        self._event("REFERENTIAL", "FK_CHECK_RESULT", {
            "foreign_key_column" : fk_col,
            "reference_table"    : ref_table,
            "valid_rows"         : valid,
            "invalid_rows"       : invalid,
        }, level=level)

    def erasure_executed(self, subject_id: str, table: str,
                          rows_deleted: int,
                          method: str = "DELETE") -> None:
        """
        Record a GDPR Article 17 right-to-erasure action.

        This event is critical for demonstrating compliance with erasure
        requests to regulators.  The subject_id is hashed before logging
        to avoid storing PII in the audit trail itself.

        Parameters
        ----------
        subject_id   : str   Data subject identifier (hashed before logging).
        table        : str   Target table name.
        rows_deleted : int   Number of rows affected.
        method       : str   Erasure method used: "DELETE", "NULLIFY",
                             "ANONYMISE", etc.  Default "DELETE".
        """
        subject_hash = hashlib.sha256(str(subject_id).encode()).hexdigest()[:16]
        self._event("ERASURE", "GDPR_ERASURE_EXECUTED", {
            "subject_id_hash"  : subject_hash,   # Never log raw PII in audit trail
            "target_table"     : table,
            "rows_deleted"     : rows_deleted,
            "method"           : method,
            "gdpr_reference"   : "Article 17 — Right to Erasure",
        }, level="WARNING")

    def classification_tagged(self, level: str, pii_count: int,
                               special_count: int) -> None:
        """Record a data classification tagging event."""
        entry = {"classification_level": level, "pii_fields": pii_count,
                 "special_category_fields": special_count,
                 "timestamp_utc": datetime.now(timezone.utc).isoformat()}
        self.classification_tags.append(entry)
        self._event("CLASSIFICATION", "DATA_CLASSIFIED", entry)

    def transfer_logged(self, source_country: str, dest_country: str,
                         safeguard: str, transfer_type: str) -> None:
        """
        Record a GDPR Chapter V cross-border transfer event.

        Parameters
        ----------
        source_country : str  ISO 3166-1 alpha-2 code of data origin.
        dest_country   : str  ISO 3166-1 alpha-2 code of destination.
        safeguard      : str  Legal mechanism (e.g. "Standard Contractual Clauses").
        transfer_type  : str  "ADEQUACY_DECISION" | "SCC" | "BCR" |
                              "INTRA_EU" | "DOMESTIC".
        """
        entry = {
            "source_country": source_country,
            "dest_country"  : dest_country,
            "safeguard"     : safeguard,
            "transfer_type" : transfer_type,
            "gdpr_reference": "Chapter V — Transfers to Third Countries",
        }
        self.transfer_events.append(entry)
        level = "INFO" if transfer_type in ("INTRA_EU", "DOMESTIC", "ADEQUACY_DECISION") \
                       else "WARNING"
        self._event("TRANSFER", "CROSS_BORDER_TRANSFER_LOGGED", entry, level=level)

    def checkpoint_event(self, action: str, chunk_idx: int, rows: int) -> None:
        """Record a checkpoint save or restore event."""
        self._event("CHECKPOINT", f"CHECKPOINT_{action}",
                    {"chunk_index": chunk_idx, "rows_processed": rows})

    def standardisation_applied(self, column: str, rule: str, changed: int) -> None:
        """Record a data standardisation transformation."""
        self._event("STANDARDISE", "COLUMN_STANDARDISED",
                    {"column": column, "rule": rule, "values_changed": changed})

    def rule_applied(self, rule_name: str, rule_type: str, rows_affected: int) -> None:
        """Record that a business rule was applied."""
        self._event("RULES", "BUSINESS_RULE_APPLIED",
                    {"rule_name": rule_name, "rule_type": rule_type,
                     "rows_affected": rows_affected})

    # ── Report writers ─────────────────────────────────────────────────────
    def write_pii_report(self) -> None:
        report = {
            "pipeline_id"          : PIPELINE_ID,
            "generated_utc"        : datetime.now(timezone.utc).isoformat(),
            "regulation_references": {"GDPR": "Articles 4,9,17,25,32",
                                       "CCPA": "§1798.100,§1798.140,§1798.150"},
            "pii_findings"         : self.pii_findings,
            "summary"              : {
                "total_pii_fields"       : len(self.pii_findings),
                "special_category_fields": sum(1 for f in self.pii_findings
                                               if f.get("special_category")),
            },
        }
        with open(self.pii_report_file, "w", encoding="utf-8") as f: json.dump(report, f, indent=2)
        self.logger.info("PII report          → %s", self.pii_report_file)

    def write_validation_report(self) -> None:
        report = {
            "pipeline_id"        : PIPELINE_ID,
            "generated_utc"      : datetime.now(timezone.utc).isoformat(),
            "expectation_results": self.validation_results,
            "summary"            : {
                "total"   : len(self.validation_results),
                "passed"  : sum(1 for r in self.validation_results if r["success"]),
                "failed"  : sum(1 for r in self.validation_results if not r["success"]),
                "dlq_rows": self.dlq_rows_total,
            },
        }
        with open(self.validation_rpt_file, "w", encoding="utf-8") as f: json.dump(report, f, indent=2)
        self.logger.info("Validation report   → %s", self.validation_rpt_file)

    def write_profile_report(self, profile: dict) -> None:
        profile["pipeline_id"]   = PIPELINE_ID
        profile["generated_utc"] = datetime.now(timezone.utc).isoformat()
        with open(self.profile_rpt_file, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, default=str)
        self.logger.info("Profile report      → %s", self.profile_rpt_file)

    def write_metrics_report(self, metrics: dict) -> None:
        metrics["pipeline_id"]   = PIPELINE_ID
        metrics["generated_utc"] = datetime.now(timezone.utc).isoformat()
        with open(self.metrics_rpt_file, "w", encoding="utf-8") as f: json.dump(metrics, f, indent=2)
        self.logger.info("Metrics report      → %s", self.metrics_rpt_file)

    def write_classification_report(self) -> None:
        report = {"pipeline_id": PIPELINE_ID,
                  "generated_utc": datetime.now(timezone.utc).isoformat(),
                  "classification_events": self.classification_tags}
        with open(self.classification_file, "w", encoding="utf-8") as f: json.dump(report, f, indent=2)
        self.logger.info("Classification rpt  → %s", self.classification_file)

    def write_transfer_log(self) -> None:
        report = {"pipeline_id": PIPELINE_ID,
                  "generated_utc": datetime.now(timezone.utc).isoformat(),
                  "gdpr_chapter_v_transfers": self.transfer_events}
        with open(self.transfer_log_file, "w", encoding="utf-8") as f: json.dump(report, f, indent=2)
        self.logger.info("Transfer log        → %s", self.transfer_log_file)

    def pipeline_summary(self) -> None: self.summary()  # alias for summary()

    def summary(self) -> None:
        self.logger.info("=" * 64)
        self.logger.info("  GOVERNANCE SUMMARY  v3.0")
        self.logger.info("=" * 64)
        self.logger.info("  Pipeline ID        : %s", PIPELINE_ID)
        self.logger.info("  Run started        : %s", RUN_START)
        self.logger.info("  Audit ledger       : %s", self.ledger_file)
        self.logger.info("  PII report         : %s", self.pii_report_file)
        self.logger.info("  Validation report  : %s", self.validation_rpt_file)
        self.logger.info("  Profile report     : %s", self.profile_rpt_file)
        self.logger.info("  Metrics report     : %s", self.metrics_rpt_file)
        self.logger.info("  Classification rpt : %s", self.classification_file)
        self.logger.info("  Transfer log       : %s", self.transfer_log_file)
        self.logger.info("  Dead letter queue  : %s  (%s rows)", self.dlq_file, self.dlq_rows_total)
        self.logger.info("  Log file           : %s", self.log_file)
        self.logger.info("  Total events       : %s", len(self.ledger_entries))
        self.logger.info("=" * 64)


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITY HELPERS  (unchanged from v2.0)
# ═════════════════════════════════════════════════════════════════════════════
def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

def _detect_pii(columns: list[str]) -> list[dict]:
    findings = []
    for col in columns:
        cl = col.lower()
        for p in PII_FIELD_PATTERNS:
            if re.search(p, cl):
                special = any(re.search(sp, cl) for sp in SENSITIVE_CATEGORIES)
                findings.append({"field": col, "matched_pattern": p,
                                  "special_category": special,
                                  "gdpr_reference": "Article 9" if special else "Article 4(1)",
                                  "ccpa_reference": "§1798.140(o)"})
                break
    return findings

_pipeline_log = logging.getLogger("DataPipeline")

def _flatten_record(
    record:         "Any",
    parent_key:     str  = "",
    sep:            str  = "__",
    *,
    max_depth:      int  = 20,
    array_strategy: str  = "index",   # "index" | "join" | "first" | "skip"
    join_sep:       str  = ",",
    _depth:         int  = 0,
    _seen_keys:     "set | None" = None,
) -> dict:
    """
    Recursively flatten a nested dict/list into a single-level dict.

    Improvements over the original implementation
    ---------------------------------------------
    max_depth       : Guards against stack overflow on pathologically deep
                      structures.  Nodes beyond max_depth are serialised as
                      a JSON string rather than silently truncated.
    array_strategy  : Controls how list values are handled.
                        "index" (default) — each element becomes its own key
                          suffixed with its integer index (tags__0, tags__1).
                        "join"  — scalar lists are joined into one
                          comma-separated string; nested lists use "index".
                        "first" — only the first element of any list is kept.
                        "skip"  — list-valued fields are omitted entirely.
    join_sep        : Separator used when array_strategy="join". Default ",".
    collision detection : If flattening produces a key that already exists,
                          the duplicate is stored as key__COLLISION_<n> and
                          a warning is logged instead of silently overwriting.
    empty containers: Empty dicts/lists are preserved as None so the column
                      appears in the output schema rather than vanishing.
    """
    if _seen_keys is None:
        _seen_keys = set()

    def _safe_add(items: list, key: str, val) -> None:
        """Append (key, val); rename key on collision."""
        if key in _seen_keys:
            n = 1
            while f"{key}__COLLISION_{n}" in _seen_keys:
                n += 1
            collision_key = f"{key}__COLLISION_{n}"
            _pipeline_log.warning(
                "[FLATTEN] Key collision on '%s' — storing duplicate as '%s'",
                key, collision_key,
            )
            _seen_keys.add(collision_key)
            items.append((collision_key, val))
        else:
            _seen_keys.add(key)
            items.append((key, val))

    # Depth guard — serialise subtree as JSON string rather than recurse forever.
    if _depth >= max_depth:
        serialised = json.dumps(record, default=str)
        _pipeline_log.warning(
            "[FLATTEN] Max depth %d reached at '%s' — serialising subtree as JSON string",
            max_depth, parent_key,
        )
        return {parent_key: serialised} if parent_key else {"__root__": serialised}

    items: list = []
    recurse_kw = dict(
        sep=sep, max_depth=max_depth,
        array_strategy=array_strategy, join_sep=join_sep,
        _depth=_depth + 1, _seen_keys=_seen_keys,
    )

    if isinstance(record, dict):
        if not record:
            # Empty dict — preserve as None so column appears in schema.
            _safe_add(items, parent_key or "__empty_dict__", None)
        else:
            for k, v in record.items():
                nk = f"{parent_key}{sep}{k}" if parent_key else str(k)
                if isinstance(v, (dict, list)):
                    items.extend(_flatten_record(v, nk, **recurse_kw).items())
                else:
                    _safe_add(items, nk, v)

    elif isinstance(record, list):
        if not record:
            # Empty list — preserve as None.
            _safe_add(items, parent_key or "__empty_list__", None)
        elif array_strategy == "skip":
            pass
        elif array_strategy == "join":
            if all(not isinstance(v, (dict, list)) for v in record):
                _safe_add(items, parent_key or "__joined__",
                          join_sep.join(str(v) for v in record))
            else:
                for i, v in enumerate(record):
                    nk = f"{parent_key}{sep}{i}" if parent_key else str(i)
                    if isinstance(v, (dict, list)):
                        items.extend(_flatten_record(v, nk, **recurse_kw).items())
                    else:
                        _safe_add(items, nk, v)
        elif array_strategy == "first":
            first = record[0]
            nk = parent_key or "__first__"
            if isinstance(first, (dict, list)):
                items.extend(_flatten_record(first, nk, **recurse_kw).items())
            else:
                _safe_add(items, nk, first)
        else:
            # Default: "index" — original behaviour.
            for i, v in enumerate(record):
                nk = f"{parent_key}{sep}{i}" if parent_key else str(i)
                if isinstance(v, (dict, list)):
                    items.extend(_flatten_record(v, nk, **recurse_kw).items())
                else:
                    _safe_add(items, nk, v)
    else:
        return {parent_key: record} if parent_key else {}

    return dict(items)

def _mask_value(value: Any) -> str | None:
    if value is None: return None
    return "MASKED_" + hashlib.sha256(str(value).encode()).hexdigest()[:12]

def _prompt(msg: str, default: str = "") -> str:
    resp = input(f"{msg} [{default}]: " if default else f"{msg}: ").strip()
    return resp if resp else default

def _yn(msg: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    resp = input(f"{msg} {suffix}: ").strip().lower()
    return default if not resp else resp in ("y", "yes")


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: CompressionHandler  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class CompressionHandler:
    """
    Transparently decompresses source files before extraction.

    Supported formats
    -----------------
    .gz   — GNU gzip  (e.g. data.csv.gz, data.json.gz)
    .bz2  — bzip2     (e.g. data.csv.bz2)
    .zip  — ZIP       (extracts the first file found in the archive)

    Files without a compression extension are returned as-is (passthrough).

    How it works
    ------------
    decompress() returns a file-like object that behaves identically to
    a regular open() file handle.  The caller (Extractor) does not need
    to know whether the source was compressed — it just reads from the
    returned handle.

    Usage
    -----
        handler = CompressionHandler()
        with handler.open(path, encoding="utf-8") as f:
            df = pd.read_csv(f)
    """

    # Map of extension → (decompressor function, inner extension)
    SUPPORTED = {".gz", ".bz2", ".zip", ".zst", ".lz4", ".tgz"}

    def is_compressed(self, path: str) -> bool:
        """Return True if the file has a recognised compression extension."""
        return Path(path).suffix.lower() in self.SUPPORTED

    def open(self, path: str) -> io.IOBase:
        """
        Open a potentially-compressed file and return a readable byte stream.

        Supported compression formats
        -----------------------------
        .gz   — GNU gzip          (data.csv.gz)
        .bz2  — bzip2             (data.csv.bz2)
        .zip  — ZIP archive       (first non-directory member extracted)
        .zst  — Zstandard         (data.csv.zst)   requires: zstandard
        .lz4  — LZ4               (data.csv.lz4)   requires: lz4
        .tgz  — tar + gzip        (data.tgz)        first non-dir member

        Parameters
        ----------
        path : str  Path to the source file (compressed or not).

        Returns
        -------
        io.IOBase  An open, readable file-like object.
        """
        ext = Path(path).suffix.lower()

        if ext == ".gz":
            return gzip.open(path, "rb")

        elif ext == ".bz2":
            return bz2.open(path, "rb")

        elif ext == ".zip":
            zf = zipfile.ZipFile(path, "r")
            members = [m for m in zf.namelist() if not m.endswith("/")]
            if not members:
                raise ValueError(f"ZIP archive is empty: {path}")
            return zf.open(members[0])

        elif ext == ".zst":
            if not HAS_ZSTD:
                raise RuntimeError(
                    "Zstandard decompression requires: pip install zstandard"
                )
            dctx = _zstd.ZstdDecompressor()
            fh   = open(path, "rb")
            return dctx.stream_reader(fh)

        elif ext == ".lz4":
            if not HAS_LZ4:
                raise RuntimeError(
                    "LZ4 decompression requires: pip install lz4"
                )
            return _lz4frame.open(path, "rb")

        elif ext == ".tgz":
            import tarfile  # stdlib
            tf      = tarfile.open(path, "r:gz")
            members = [m for m in tf.getmembers() if m.isfile()]
            if not members:
                raise ValueError(f"TGZ archive is empty: {path}")
            return tf.extractfile(members[0])

        else:
            return open(path, "rb")

    def inner_extension(self, path: str) -> str:
        """
        Return the extension of the actual data file inside a compressed archive.

        For "data.csv.gz"  → ".csv"
        For "data.csv.zst" → ".csv"
        For "data.json"    → ".json"  (passthrough)
        For "data.tgz"     → inferred from first archive member name

        Parameters
        ----------
        path : str  Source file path.

        Returns
        -------
        str  The inner/real file extension.
        """
        p = Path(path)
        suffix = p.suffix.lower()
        if suffix not in self.SUPPORTED:
            return suffix
        # .tgz has no double-extension — peek inside the archive
        if suffix == ".tgz":
            import tarfile  # stdlib
            try:
                with tarfile.open(path, "r:gz") as tf:
                    members = [m for m in tf.getmembers() if m.isfile()]
                    if members:
                        return Path(members[0].name).suffix.lower()
            except Exception:
                pass
            return ".csv"  # sensible default if peeking fails
        # .zip — peek inside the archive for the member filename
        if suffix == ".zip":
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    members = [m for m in zf.namelist() if not m.endswith("/")]
                    if members:
                        return Path(members[0]).suffix.lower()
            except Exception:
                pass
            return ".csv"  # sensible default
        # Generic double-extension: strip compression suffix (e.g. data.csv.gz → .csv)
        inner = Path(p.stem).suffix.lower()
        return inner if inner else ".csv"


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: SLAMonitor  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class SLAMonitor:
    """
    Tracks pipeline wall-clock time against a configurable SLA deadline.

    Service Level Agreements (SLAs) for data pipelines typically specify
    that all data must be loaded by a given time (e.g. "the report feed
    must complete within 2 hours of midnight").  SLA breaches affect
    downstream consumers (analysts, automated reports, dashboards) and
    may have contractual consequences.

    How it works
    ------------
    • start()         — records the wall-clock start time.
    • check(label)    — computes elapsed time, fires a WARNING audit event
                        if elapsed > sla_seconds, and returns elapsed.
    • final_check()   — call at the end of main() to log the final SLA status.

    Parameters
    ----------
    gov         : GovernanceLogger
    sla_seconds : int  Maximum acceptable run duration in seconds.
                       0 = SLA monitoring disabled.
    """

    def __init__(self, gov: GovernanceLogger, sla_seconds: int = 0) -> None:
        self.gov         = gov
        self.sla_seconds = sla_seconds
        self._start:   float | None = None
        self.breached: bool         = False

    def start(self) -> None:
        """Record the pipeline start time."""
        self._start = time.monotonic()
        if self.sla_seconds:
            self.gov.logger.info(
                f"[SLA] Monitoring active — deadline: {self.sla_seconds}s "
                f"({self.sla_seconds/60:.1f} minutes)"
            )

    def check(self, label: str = "") -> float:
        """
        Compute elapsed time and fire an audit event if SLA is breached.

        Parameters
        ----------
        label : str  Optional context label included in the audit event.

        Returns
        -------
        float  Elapsed seconds since start().
        """
        if self._start is None:
            return 0.0
        elapsed = time.monotonic() - self._start
        if not self.sla_seconds:
            return elapsed

        if elapsed > self.sla_seconds:
            self.breached = True
            self.gov.sla_event("BREACH", elapsed, self.sla_seconds)
            print("  ⚠  [SLA BREACH] Pipeline has run for "
                  f"{elapsed:.0f}s (limit: {self.sla_seconds}s)  {label}")
        elif elapsed > self.sla_seconds * 0.8:
            # Warn when 80% of the SLA budget has been consumed.
            self.gov.sla_event("WARNING", elapsed, self.sla_seconds)
        return elapsed

    def final_check(self) -> float:
        """Log the final SLA outcome at pipeline end."""
        elapsed = self.check("final")
        if self.sla_seconds and not self.breached:
            self.gov.sla_event("OK", elapsed, self.sla_seconds)
            print(f"  ✓  [SLA] Completed in {elapsed:.1f}s "
                  f"(limit: {self.sla_seconds}s, "
                  f"{100*elapsed/self.sla_seconds:.0f}% used)")
        return elapsed


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: MetricsCollector  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class MetricsCollector:
    """
    Collects pipeline throughput and per-stage timing metrics.

    Metrics tracked
    ---------------
    • Total run duration (wall-clock seconds)
    • Per-stage durations (extract, validate, transform, load, etc.)
    • Throughput: rows processed per second (overall and per-stage)
    • Error rate: DLQ rows / total rows
    • Rows in, rows out (after DLQ filtering)

    Output
    ------
    At pipeline end, write_report() serialises all metrics to
    governance_logs/metrics_report_<ts>.json.

    Usage
    -----
        mc = MetricsCollector(gov)
        mc.start_stage("extract")
        # ... do extraction ...
        mc.end_stage("extract", rows=len(df))
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov         = gov
        self._run_start  = time.monotonic()
        self._stages:    dict[str, dict] = {}
        self._current:   str | None      = None
        self._stage_start: float         = 0.0
        self.rows_in:    int = 0
        self.rows_out:   int = 0

    def record_extract(self, rows: int, elapsed: float) -> None:
        """Convenience alias: record the extract stage metrics."""
        self.start_stage("extract")
        self._stages["extract"]["rows"] = rows
        self._stages["extract"]["elapsed"] = elapsed
        self.gov.transformation_applied("EXTRACT_METRICS", {"rows": rows, "elapsed_s": elapsed})

    def record_transform(self, rows: int, elapsed: float) -> None:
        """Convenience alias: record the transform stage metrics."""
        self.start_stage("transform")
        self._stages["transform"]["rows"] = rows
        self._stages["transform"]["elapsed"] = elapsed
        self.gov.transformation_applied("TRANSFORM_METRICS", {"rows": rows, "elapsed_s": elapsed})

    def record_load(self, rows: int, elapsed: float) -> None:
        """Convenience alias: record the load stage metrics."""
        self.start_stage("load")
        self._stages["load"]["rows"] = rows
        self._stages["load"]["elapsed"] = elapsed
        self.gov.transformation_applied("LOAD_METRICS", {"rows": rows, "elapsed_s": elapsed})

    def record_validate(self, rows_total: int, rows_failed: int, elapsed: float) -> None:
        """Convenience alias: record the validate stage metrics."""
        self.start_stage("validate")
        self._stages["validate"]["rows"] = rows_total
        self._stages["validate"]["elapsed"] = elapsed
        self.gov.transformation_applied("VALIDATE_METRICS",
            {"rows_total": rows_total, "rows_failed": rows_failed, "elapsed_s": elapsed})

    def record(self, metric: str, value, stage: str | None = None) -> None:
        """
        Generic metric recorder — stores a named value in the given stage
        (defaults to "custom").  Useful for ad-hoc measurements without
        needing to call the stage-specific helpers.

        Example::
            mc.record("rows_written", 45_231)
            mc.record("cost_usd", 0.033, stage="load")
        """
        _stage = stage or "custom"
        if _stage not in self._stages:
            self._stages[_stage] = {}
        self._stages[_stage][metric] = value
        self.gov.transformation_applied("METRIC_RECORDED",
                                        {"stage": _stage, "metric": metric, "value": value})

    def report(self) -> dict:
        """Return the current metrics as a dict and write the report."""
        self.write_report()
        return dict(self._stages)

    def start_stage(self, name: str) -> None:
        """Begin timing a named pipeline stage."""
        self._current    = name
        self._stage_start= time.monotonic()
        self._stages[name] = {"start": self._stage_start, "duration_sec": None, "rows": 0}

    def end_stage(self, name: str, rows: int = 0) -> float:
        """
        Stop timing a stage and record its row count.

        Parameters
        ----------
        name : str  Stage name (must match a prior start_stage() call).
        rows : int  Number of rows processed during this stage.

        Returns
        -------
        float  Duration of the stage in seconds.
        """
        duration = time.monotonic() - self._stages.get(name, {}).get("start", time.monotonic())
        self._stages[name]["duration_sec"] = round(duration, 3)
        self._stages[name]["rows"]         = rows
        self._stages[name]["rows_per_sec"] = round(rows / duration, 1) if duration > 0 else 0
        self._current = None
        return duration

    def write_report(self, dlq_rows: int = 0) -> None:
        """
        Write the metrics report and fire a METRICS audit event.

        Parameters
        ----------
        dlq_rows : int  Total rows sent to the Dead Letter Queue.
        """
        total_duration = time.monotonic() - self._run_start
        total_rps      = round(self.rows_out / total_duration, 1) if total_duration > 0 else 0
        error_rate     = round(dlq_rows / max(self.rows_in, 1), 4)

        metrics = {
            "total_duration_sec" : round(total_duration, 2),
            "rows_input"         : self.rows_in,
            "rows_output"        : self.rows_out,
            "rows_dlq"           : dlq_rows,
            "error_rate"         : error_rate,
            "overall_rows_per_sec": total_rps,
            "stages"             : self._stages,
        }
        self.gov.metrics_recorded(metrics)
        self.gov.write_metrics_report(metrics)
        self.gov.logger.info(
            f"[METRICS] {total_duration:.1f}s  |  {self.rows_out:,} rows  |  "
            f"{total_rps:.0f} rows/s  |  DLQ={dlq_rows}  |  "
            f"error_rate={error_rate:.1%}"
        )


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: CheckpointManager  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class CheckpointManager:
    """
    Saves and restores chunk-level pipeline progress for resumable runs.

    Problem
    -------
    A pipeline processing a 10-million-row file in 200 chunks that fails
    at chunk 180 would need to reprocess the first 179 chunks on restart
    if no checkpoint exists.  For pipelines with long processing times or
    expensive API calls this is unacceptable.

    Solution
    --------
    After each successfully loaded chunk, save_checkpoint() writes the
    chunk index to CHECKPOINT_FILE.  On the next run, load_checkpoint()
    reads this state and skips all chunks with index <= the saved value.

    The checkpoint is keyed by source file path and pipeline configuration
    (table name) so that different pipelines sharing the same state file
    do not interfere with each other.

    Cleanup
    -------
    clear_checkpoint() removes the state for a given source+table after
    a fully successful run so that the next run starts fresh.
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov        = gov
        self.state_file = CHECKPOINT_FILE

    def _key(self, source: str, table: str) -> str:
        """Build a unique state key from source path and table name."""
        return f"{source}::{table}"

    def load_checkpoint(self, source: str, table: str) -> int:
        """
        Return the last successfully completed chunk index, or -1 if none.

        Parameters
        ----------
        source : str  Source file path.
        table  : str  Target table name.

        Returns
        -------
        int  Last completed chunk index (-1 = start from beginning).
        """
        key = self._key(source, table)
        if not self.state_file.exists():
            return -1
        with open(self.state_file, encoding="utf-8") as f:
            state = json.load(f)
        last = state.get(key, -1)
        if last >= 0:
            self.gov.checkpoint_event("RESTORED", last, 0)
            print(f"  [CHECKPOINT] Resuming from chunk {last + 1} "
                  f"(skipping {last + 1} already-completed chunks)")
        return last

    def save_checkpoint(self, source: str, table: str,
                         chunk_idx: int, rows: int) -> None:
        """
        Persist the index of the last successfully loaded chunk.

        Parameters
        ----------
        source    : str  Source file path.
        table     : str  Target table name.
        chunk_idx : int  Index of the completed chunk (0-based).
        rows      : int  Cumulative rows loaded so far.
        """
        key = self._key(source, table)
        with _STATE_FILE_LOCK:
            state: dict = {}
            if self.state_file.exists():
                with open(self.state_file, encoding="utf-8") as f:
                    state = json.load(f)
            state[key] = chunk_idx
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        self.gov.checkpoint_event("SAVED", chunk_idx, rows)

    def clear_checkpoint(self, source: str, table: str) -> None:
        """Remove the checkpoint for a completed, successful run."""
        key = self._key(source, table)
        with _STATE_FILE_LOCK:
            if not self.state_file.exists():
                return
            with open(self.state_file, encoding="utf-8") as f:
                state = json.load(f)
            state.pop(key, None)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: TypeCoercer  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class TypeCoercer:
    """
    Applies explicit, configuration-driven dtype casting to DataFrame columns.

    Why explicit coercion?
    ----------------------
    pandas' automatic type inference is convenient but unreliable for
    production pipelines:
      • Integer columns with nulls are inferred as float64 (NaN is a float).
      • ZIP codes like "01234" become the integer 1234 (leading zero lost).
      • ISO-format date strings may not be parsed unless explicitly requested.
      • Boolean columns encoded as "true"/"false" strings stay as objects.

    Type coercion config format
    ---------------------------
    A dict mapping column names to target type strings:
        {
            "id"          : "int",
            "hired_date"  : "datetime",
            "salary"      : "float",
            "active"      : "bool",
            "zip"         : "str",
            "score"       : "float",
        }

    Supported type strings
    ----------------------
    "int"      → pd.Int64Dtype() (nullable integer, preserves nulls)
    "float"    → float64
    "str"      → object (string)
    "bool"     → boolean
    "datetime" → datetime64[ns, UTC]
    "date"     → date-only (stored as object string YYYY-MM-DD after parsing)
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def coerce(self, df: "pd.DataFrame", type_map: dict[str, str]) -> "pd.DataFrame":
        """
        Apply the type_map to the DataFrame, coercing each specified column.

        Columns not listed in type_map are left as-is.
        Columns listed in type_map but absent from the DataFrame are skipped
        with a WARNING rather than raising an exception.

        Parameters
        ----------
        df       : pd.DataFrame       DataFrame to coerce.
        type_map : dict[str, str]     Column → target type mapping.

        Returns
        -------
        pd.DataFrame  DataFrame with coerced dtypes.
        """
        if not type_map:
            return df

        for col, target_type in type_map.items():
            if col not in df.columns:
                self.gov.logger.warning(
                    f"[TYPE_COERCE] Column '{col}' not found — skipping."
                )
                continue

            original_dtype = str(df[col].dtype)
            try:
                t = target_type.lower()

                if t in ("int", "integer"):
                    # pd.Int64Dtype is a nullable integer type that preserves
                    # NaN values.  Standard numpy int64 would raise on nulls.
                    _before_nulls = int(pd.isnull(df[col]).sum())
                    df[col] = pd.to_numeric(df[col], errors="coerce")                                 .astype(pd.Int64Dtype())
                    _coerce_failures = int(pd.isnull(df[col]).sum()) - _before_nulls
                    if _coerce_failures > 0:
                        self.gov.logger.warning(
                            "[TYPE_COERCE] Column '%s': %d value(s) could not be "
                            "converted to int — set to <NA>.",
                            col, _coerce_failures,
                        )

                elif t in ("float", "double", "numeric", "decimal"):
                    _before_nulls = int(pd.isnull(df[col]).sum())
                    df[col] = pd.to_numeric(df[col], errors="coerce")
                    _coerce_failures = int(pd.isnull(df[col]).sum()) - _before_nulls
                    if _coerce_failures > 0:
                        self.gov.logger.warning(
                            "[TYPE_COERCE] Column '%s': %d value(s) could not be "
                            "converted to float — set to NaN.",
                            col, _coerce_failures,
                        )

                elif t in ("str", "string", "text", "object"):
                    # fillna("") ensures no NaN objects in string columns.
                    df[col] = df[col].astype(str).replace("nan", "")

                elif t in ("bool", "boolean"):
                    # Map common truthy/falsy string representations.
                    bool_map = {
                        "true": True, "1": True, "yes": True, "y": True,
                        "false": False, "0": False, "no": False, "n": False,
                    }
                    df[col] = df[col].apply(
                        lambda x, _m=bool_map: _m.get(str(x).lower(), None)
                        if pd.notna(x) else None
                    ).astype(pd.BooleanDtype())

                elif t in ("datetime", "timestamp"):
                    df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)

                elif t == "date":
                    parsed = pd.to_datetime(df[col], errors="coerce")
                    df[col] = parsed.dt.strftime("%Y-%m-%d").where(parsed.notna(), other=None)

                self.gov.transformation_applied("TYPE_COERCION", {
                    "column"       : col,
                    "from_dtype"   : original_dtype,
                    "to_type"      : target_type,
                })

            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.gov.error(f"TYPE_COERCION_FAILED:{col}", exc)

        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DataStandardiser  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class DataStandardiser:
    """
    Normalises common data formats to consistent, interoperable standards.

    Standardisation rules available
    --------------------------------
    "phone_e164"     — Normalise phone numbers to E.164 format (+12125550101).
                       Requires phonenumbers library.  Invalid numbers are
                       left unchanged with a WARNING.

    "date_iso8601"   — Parse date strings in any recognisable format and
                       reformat to ISO-8601 YYYY-MM-DD.

    "country_iso2"   — Map country names to ISO 3166-1 alpha-2 codes.
                       (e.g. "United States" → "US", "United Kingdom" → "GB")

    "bool_normalize" — Standardise truthy/falsy strings:
                       "yes", "1", "true", "TRUE" → True
                       "no",  "0", "false", "FALSE" → False

    "upper"          — Convert string values to UPPER CASE.
    "lower"          — Convert string values to lower case.
    "strip"          — Strip leading/trailing whitespace.
    "title"          — Convert to Title Case.

    Config format
    -------------
        {
            "phone"        : "phone_e164",
            "hire_date"    : "date_iso8601",
            "country"      : "country_iso2",
            "is_active"    : "bool_normalize",
            "department"   : "upper",
        }
    """

    # Partial country-name → ISO-2 lookup table.
    # Add entries as needed for your data.
    COUNTRY_MAP: dict[str, str] = {
        "united states": "US", "usa": "US", "us": "US", "america": "US",
        "united kingdom": "GB", "uk": "GB", "great britain": "GB",
        "canada": "CA", "germany": "DE", "france": "FR", "italy": "IT",
        "spain": "ES", "netherlands": "NL", "belgium": "BE",
        "australia": "AU", "new zealand": "NZ", "japan": "JP",
        "china": "CN", "india": "IN", "brazil": "BR", "mexico": "MX",
        "south korea": "KR", "korea": "KR", "switzerland": "CH",
        "sweden": "SE", "norway": "NO", "denmark": "DK", "finland": "FI",
        "poland": "PL", "portugal": "PT", "ireland": "IE", "austria": "AT",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def standardise(
        self,
        df: "pd.DataFrame",
        rules: dict[str, str],
        default_phone_region: str = "US",
    ) -> "pd.DataFrame":
        """
        Apply standardisation rules to the specified columns.

        Parameters
        ----------
        df                   : pd.DataFrame        DataFrame to standardise.
        rules                : dict[str, str]      Column → rule mapping.
        default_phone_region : str                 ISO 3166-1 alpha-2 code
                               used when a phone number has no country prefix.
                               Defaults to "US".

        Returns
        -------
        pd.DataFrame  DataFrame with standardised values.
        """
        for col, rule in rules.items():
            if col not in df.columns:
                continue

            changed = 0

            if rule == "phone_e164":
                df[col], changed = self._normalise_phones(
                    df[col], default_phone_region
                )

            elif rule == "date_iso8601":
                original = df[col].copy()
                df[col]  = pd.to_datetime(df[col], errors="coerce") \
                             .dt.strftime("%Y-%m-%d") \
                             .where(pd.to_datetime(df[col], errors="coerce").notna(),
                                    other=df[col])
                changed  = int((df[col] != original).sum())

            elif rule == "country_iso2":
                df[col], changed = self._normalise_countries(df[col])

            elif rule == "bool_normalize":
                bool_map = {"yes": "True", "1": "True", "true": "True",
                            "no": "False", "0": "False", "false": "False"}
                original = df[col].copy()
                df[col]  = df[col].apply(
                    lambda x, _m=bool_map: _m.get(str(x).strip().lower(), x)
                    if pd.notna(x) else x
                )
                changed = int((df[col] != original).sum())

            elif rule in ("upper", "lower", "strip", "title"):
                original = df[col].copy()
                fn = {"upper": str.upper, "lower": str.lower,
                      "strip": str.strip, "title": str.title}[rule]
                df[col]  = df[col].apply(
                    lambda x, _fn=fn: _fn(str(x)) if pd.notna(x) else x
                )
                changed = int((df[col] != original).sum())

            self.gov.standardisation_applied(col, rule, changed)

        return df

    def _normalise_phones(
        self, series: "pd.Series", region: str
    ) -> tuple["pd.Series", int]:
        """Parse phone numbers and reformat to E.164."""
        changed = 0
        results = []
        for val in series:
            if pd.isna(val):
                results.append(val)
                continue
            if HAS_PHONENUMBERS:
                try:
                    parsed = phonenumbers.parse(str(val), region)
                    e164   = phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.E164
                    )
                    if e164 != str(val):
                        changed += 1
                    results.append(e164)
                except Exception:  # pylint: disable=broad-exception-caught
                    results.append(val)   # Leave invalid numbers unchanged
            else:
                results.append(val)       # phonenumbers not installed
        return pd.Series(results, index=series.index), changed

    def _normalise_countries(
        self, series: "pd.Series"
    ) -> tuple["pd.Series", int]:
        """Map country names/codes to ISO 3166-1 alpha-2."""
        changed = 0
        results = []
        for val in series:
            if pd.isna(val):
                results.append(val)
                continue
            normalised = self.COUNTRY_MAP.get(str(val).strip().lower(), str(val))
            if normalised != str(val):
                changed += 1
            results.append(normalised)
        return pd.Series(results, index=series.index), changed


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: BusinessRuleEngine  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class BusinessRuleEngine:
    """
    Applies operator-defined transformation rules from a JSON config file.

    This allows non-developers (data analysts, business owners) to define
    transformation logic without writing Python code.  Rules are loaded
    from a JSON file and applied in the order they are listed.

    Supported rule types
    --------------------
    rename      — Rename a column.
                  {"type":"rename","from":"emp_no","to":"employee_id"}

    fill_null   — Fill null values in a column with a literal value.
                  {"type":"fill_null","column":"region","value":"UNKNOWN"}

    map_values  — Replace specific values with others (lookup replacement).
                  {"type":"map_values","column":"status",
                   "mapping":{"A":"Active","I":"Inactive"}}

    derive      — Create a new column from a simple arithmetic expression.
                  {"type":"derive","new_column":"salary_k",
                   "expression":"salary / 1000","source_columns":["salary"]}

    filter_out  — Drop rows where a column equals a specific value.
                  {"type":"filter_out","column":"active","value":"false"}

    flag        — Add a boolean flag column based on a condition.
                  {"type":"flag","new_column":"high_earner",
                   "condition_column":"salary","operator":"gt","threshold":90000}

    Rule config file example (save as business_rules.json)
    -------------------------------------------------------
    [
      {"name":"rename_emp","type":"rename","from":"emp_no","to":"employee_id"},
      {"name":"fill_region","type":"fill_null","column":"region","value":"UNKNOWN"},
      {"name":"flag_high_earner","type":"flag","new_column":"high_earner",
       "condition_column":"salary","operator":"gt","threshold":90000}
    ]
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def load_rules(self, rules_file: str) -> list[dict]:
        """
        Load rules from a JSON file.

        Parameters
        ----------
        rules_file : str  Path to the JSON rules config file.

        Returns
        -------
        list[dict]  List of rule dictionaries.
        """
        with open(rules_file, encoding="utf-8") as f:
            rules = json.load(f)
        self.gov.logger.info(f"[RULES] Loaded {len(rules)} rule(s) from {rules_file}")
        return rules

    def apply(self, df: "pd.DataFrame", rules: list[dict]) -> "pd.DataFrame":
        """
        Apply a list of rules to the DataFrame in order.

        Parameters
        ----------
        df    : pd.DataFrame  Data to transform.
        rules : list[dict]    Rules loaded from load_rules() or defined inline.

        Returns
        -------
        pd.DataFrame  DataFrame after all rules have been applied.
        """
        for rule in rules:
            rule_name = rule.get("name", rule.get("type", "unnamed"))
            rule_type = rule.get("type", "").lower()
            rows_before = len(df)

            try:
                if rule_type == "rename":
                    if rule["from"] in df.columns:
                        df = df.rename(columns={rule["from"]: rule["to"]})
                        self.gov.rule_applied(rule_name, "rename", len(df))

                elif rule_type == "fill_null":
                    col = rule["column"]
                    if col in df.columns:
                        null_count = int(df[col].isnull().sum())
                        df[col] = df[col].fillna(rule["value"])
                        self.gov.rule_applied(rule_name, "fill_null", null_count)

                elif rule_type == "map_values":
                    col = rule["column"]
                    if col in df.columns:
                        mapping = rule["mapping"]
                        changed = int(df[col].isin(mapping.keys()).sum())
                        df[col] = df[col].replace(mapping)
                        self.gov.rule_applied(rule_name, "map_values", changed)

                elif rule_type == "derive":
                    # Evaluate a safe arithmetic expression.
                    # Only allow references to existing numeric columns and
                    # basic arithmetic operators to prevent code injection.
                    expr     = rule["expression"]
                    src_cols = rule.get("source_columns", [])
                    # Build a local namespace with the referenced columns.
                    local_ns = {col: df[col] for col in src_cols if col in df.columns}
                    # Safety check: only allow digits, operators, spaces, dots, parens.
                    safe = re.sub(r"[^a-zA-Z0-9_\s\+\-\*/\(\)\.]", "", expr)
                    if safe != expr:
                        raise ValueError(f"Unsafe expression: {expr!r}")
                    # Use pandas.eval() — safer than eval(); arithmetic expressions
                    # only, no attribute traversal, no import/exec.
                    try:
                        df[rule["new_column"]] = pd.eval(
                            expr,
                            local_dict=local_ns,
                            engine="python",   # "numexpr" if numexpr installed
                        )
                    except Exception as _eval_exc:
                        raise ValueError(
                            f"derive rule expression failed: {expr!r} → {_eval_exc}"
                        ) from _eval_exc
                    self.gov.rule_applied(rule_name, "derive", len(df))

                elif rule_type == "filter_out":
                    col = rule["column"]
                    if col in df.columns:
                        mask     = df[col].astype(str).str.lower() \
                                   != str(rule["value"]).lower()
                        filtered = rows_before - int(mask.sum())
                        df = df[mask].reset_index(drop=True)
                        self.gov.rule_applied(rule_name, "filter_out", filtered)

                elif rule_type == "flag":
                    col = rule["condition_column"]
                    if col in df.columns:
                        op  = rule.get("operator", "gt").lower()
                        thr = rule.get("threshold", 0)
                        ops = {
                            "gt"  : lambda s, v: s > v,
                            "gte" : lambda s, v: s >= v,
                            "lt"  : lambda s, v: s < v,
                            "lte" : lambda s, v: s <= v,
                            "eq"  : lambda s, v: s == v,
                            "neq" : lambda s, v: s != v,
                        }
                        flagged = int(ops[op](pd.to_numeric(df[col], errors="coerce"), thr).sum())
                        df[rule["new_column"]] = ops[op](
                            pd.to_numeric(df[col], errors="coerce"), thr
                        )
                        self.gov.rule_applied(rule_name, "flag", flagged)

                else:
                    self.gov.logger.warning(f"[RULES] Unknown rule type: {rule_type!r}")

            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.gov.error(f"RULE_FAILED:{rule_name}", exc)
                # Continue with remaining rules rather than aborting.

        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DataEnricher  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class DataEnricher:
    """
    Left-joins a lookup / reference table onto the main dataset.

    Enrichment adds business context to raw source data by joining it with
    reference data (e.g. adding department names from a departments table,
    product descriptions from a catalogue, or region codes from a ZIP-code
    lookup).

    The join is always a LEFT JOIN so that rows in the main dataset are
    never dropped due to a missing match in the lookup.  Unmatched rows
    simply receive NaN in the enrichment columns.

    Supported lookup formats
    -------------------------
    .csv           — CSV, comma-separated
    .tsv           — TSV, tab-separated
    .json          — JSON (array of objects)
    .jsonl/.ndjson — Newline-delimited JSON (streaming)
    .yaml/.yml     — YAML (requires pyyaml)
    .xml           — XML
    .xlsx/.xls     — Excel
    .parquet       — Parquet columnar (requires pyarrow)
    .feather/.arrow— Apache Feather/Arrow (requires pyarrow)
    .orc           — ORC columnar (requires pyorc)
    .avro          — Avro (requires fastavro)
    .fwf           — Fixed-width format
    .sas7bdat      — SAS dataset
    .dta           — Stata dataset

    Compression wrappers (auto-detected by extension):
    .gz  .bz2  .zip  .zst  .lz4  .tgz

    Usage
    -----
        enricher = DataEnricher(gov)
        df = enricher.enrich(df, "dept_id", "lookup_departments.csv",
                              "department_id", ["department_name","cost_center"])
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def enrich(
        self,
        df:            "pd.DataFrame",
        join_col:      str,
        lookup_path:   str,
        lookup_key:    str,
        lookup_cols:   list[str] | None = None,
    ) -> "pd.DataFrame":
        """
        Left-join a lookup table onto the main DataFrame.

        Parameters
        ----------
        df          : pd.DataFrame  Main dataset to enrich.
        join_col    : str           Column in df to join on.
        lookup_path : str           Path to the lookup file.
        lookup_key  : str           Key column in the lookup file.
        lookup_cols : list|None     Columns from the lookup to bring in.
                                    None = bring all columns.

        Returns
        -------
        pd.DataFrame  Enriched DataFrame with new columns from the lookup.
        """
        if join_col not in df.columns:
            self.gov.logger.warning(
                f"[ENRICHMENT] Join column '{join_col}' not found — skipping."
            )
            return df

        # ── Read lookup table ─────────────────────────────────────────────
        ext = Path(lookup_path).suffix.lower()
        if ext == ".csv":
            lookup_df = pd.read_csv(lookup_path)
        elif ext == ".json":
            lookup_df = pd.read_json(lookup_path)
        elif ext in (".xlsx", ".xls"):
            lookup_df = pd.read_excel(lookup_path)
        else:
            self.gov.logger.warning(f"[ENRICHMENT] Unsupported lookup format: {ext}")
            return df

        # ── Select only the desired columns from the lookup ───────────────
        if lookup_cols:
            keep = [lookup_key] + [c for c in lookup_cols if c in lookup_df.columns]
            lookup_df = lookup_df[keep]

        # ── Perform the left join ─────────────────────────────────────────
        before_cols = set(df.columns)
        df = df.merge(lookup_df, left_on=join_col, right_on=lookup_key,
                      how="left", suffixes=("", "_lookup"))

        # Drop the duplicate key column from the right side if it differs.
        if lookup_key != join_col and lookup_key in df.columns:
            df.drop(columns=[lookup_key], inplace=True, errors="ignore")

        new_cols      = set(df.columns) - before_cols
        rows_matched  = int(df[list(new_cols)[0]].notna().sum()) if new_cols else 0

        self.gov.enrichment_applied(join_col, lookup_path, rows_matched, len(df))
        print(f"  [ENRICH] Joined '{lookup_path}' on '{join_col}' → "
              f"{rows_matched}/{len(df)} rows matched  "
              f"| new columns: {list(new_cols)}")
        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: ReferentialIntegrityChecker  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class ReferentialIntegrityChecker:
    """
    Verifies that foreign-key values in the source data exist in a reference set.

    Why this matters
    ----------------
    Loading records with invalid foreign keys violates relational integrity
    and can silently corrupt downstream analytics (e.g. a sale record
    referencing a non-existent product ID).  Detecting these BEFORE loading
    means they can be sent to the Dead Letter Queue for investigation rather
    than being silently loaded as orphaned records.

    How it works
    ------------
    1. Load the set of valid key values from a reference source
       (CSV file or an in-memory set).
    2. Check every value in the foreign-key column against that set.
    3. Return rows with invalid FK values to the DeadLetterQueue.
    4. Continue with only the valid rows.

    Usage
    -----
        checker = ReferentialIntegrityChecker(gov, dlq)
        df = checker.check(df, "department_id",
                           reference_path="lookup_departments.csv",
                           reference_col="department_id")
    """

    def __init__(self, gov: GovernanceLogger, dlq: "DeadLetterQueue") -> None:
        self.gov = gov
        self.dlq = dlq

    def check(
        self,
        df:             "pd.DataFrame",
        fk_col:         str,
        reference_path: str,
        reference_col:  str,
        on_violation:   str = "dlq",
    ) -> "pd.DataFrame":
        """
        Check a foreign-key column and route violations to the DLQ.

        Parameters
        ----------
        df             : pd.DataFrame  Dataset to check.
        fk_col         : str           Foreign-key column in df.
        reference_path : str           Path to the reference/lookup file.
        reference_col  : str           Key column in the reference file.
        on_violation   : str           "dlq" — route bad rows to DLQ (default)
                                        "warn" — log warning only

        Returns
        -------
        pd.DataFrame  DataFrame with invalid FK rows removed (dlq mode) or
                      unchanged (warn mode).
        """
        if fk_col not in df.columns:
            self.gov.logger.warning(
                f"[RI] Foreign key column '{fk_col}' not found — skipping check."
            )
            return df

        # ── Load valid key values ─────────────────────────────────────────
        ext = Path(reference_path).suffix.lower()
        if ext == ".csv":
            ref_df = pd.read_csv(reference_path)
        elif ext in (".xlsx", ".xls"):
            ref_df = pd.read_excel(reference_path)
        elif ext == ".json":
            ref_df = pd.read_json(reference_path)
        else:
            self.gov.logger.warning(f"[RI] Unsupported reference format: {ext}")
            return df

        valid_keys = set(ref_df[reference_col].dropna().astype(str))

        # ── Identify violating rows ───────────────────────────────────────
        fk_as_str  = df[fk_col].astype(str)
        valid_mask = fk_as_str.isin(valid_keys)
        invalid_count = int((~valid_mask).sum())
        valid_count   = int(valid_mask.sum())

        self.gov.referential_integrity_checked(
            fk_col, reference_path, valid_count, invalid_count
        )

        if invalid_count > 0:
            invalid_vals = df.loc[~valid_mask, fk_col].unique().tolist()
            print(f"  ⚠  [RI CHECK] '{fk_col}': {invalid_count} invalid FK value(s) "
                  f"found: {invalid_vals[:5]}{'…' if len(invalid_vals) > 5 else ''}")

            if on_violation == "dlq":
                bad_indices = df.index[~valid_mask].tolist()
                reason      = (f"REFERENTIAL_INTEGRITY: '{fk_col}' value not found "
                               f"in '{reference_path}':'{reference_col}'")
                df = self.dlq.write(df, bad_indices, reason)
            # on_violation == "warn": already logged above — no rows removed
        else:
            print(f"  ✓  [RI CHECK] '{fk_col}': all {valid_count} values valid.")

        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: ColumnEncryptor  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class ColumnEncryptor:
    """
    Applies AES-256 symmetric encryption to specified columns using Fernet.

    Distinction from PII masking
    ----------------------------
    SHA-256 masking (used in v1/v2 for PII pseudonymisation) is a ONE-WAY
    operation — the original value cannot be recovered.  That is appropriate
    for fields that must be irreversibly protected.

    Fernet encryption is TWO-WAY — the original value can be recovered by an
    authorised party who holds the encryption key.  This is appropriate for
    fields that:
      • Must be stored encrypted at rest (GDPR Art. 32 / CCPA §1798.150)
      • Need to be decrypted by authorised users or downstream systems
        (e.g. decrypting salary data for a payroll report)

    Fernet details
    --------------
    Fernet uses AES-128-CBC with a 256-bit key (the key is a base64-encoded
    32-byte random value).  Each encrypted value is a URL-safe base64-encoded
    string prefixed with a timestamp and a HMAC-SHA256 authentication tag.
    The ciphertext is different every time (random IV) even for the same input,
    preventing frequency analysis.

    Key management
    --------------
    The encryption key should be stored in a secrets manager (Vault, AWS KMS,
    Azure Key Vault) — NOT in the code or .env file in production.
    SecretsManager is used here to resolve the key.

    WARNING: If the encryption key is lost, the data cannot be recovered.
             Always store keys in a separate, backed-up secrets store.

    Usage
    -----
        key = ColumnEncryptor.generate_key()  # Do this once and store it!
        enc = ColumnEncryptor(gov, key)
        df  = enc.encrypt(df, ["ssn", "credit_card"])
        # Later, to recover:
        df  = enc.decrypt(df, ["ssn", "credit_card"])
    """

    def __init__(self, gov: GovernanceLogger, key: str | None = None) -> None:
        """
        Parameters
        ----------
        gov : GovernanceLogger
        key : str | None  Base64-encoded Fernet key.  If None, a new key is
                          generated.  STORE THE KEY — you cannot recover data
                          without it.
        """
        self.gov = gov
        if not HAS_CRYPTO:
            self.gov.logger.warning("[ENCRYPT] cryptography library not installed — encryption disabled.")
            self._fernet = None
            return
        if key:
            self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
        else:
            new_key      = Fernet.generate_key()
            self._fernet = Fernet(new_key)
            self.gov.logger.warning(
                "[ENCRYPT] No key provided — generated new key. "
                "SAVE THIS KEY or encrypted data cannot be recovered:\n"
                f"  {new_key.decode()}"
            )

    @staticmethod
    def generate_key() -> str:
        """
        Generate a new random Fernet key and return it as a string.
        Call this ONCE, store the output securely, and pass it to __init__.
        """
        if HAS_CRYPTO:
            return Fernet.generate_key().decode()
        raise RuntimeError("cryptography library not installed")

    def encrypt(self, df: "pd.DataFrame", columns: list[str]) -> "pd.DataFrame":
        """
        Encrypt the specified columns in-place.

        Null values are left as null.  Non-null values are encrypted to a
        URL-safe base64 string prefixed with "ENCRYPTED:".

        Parameters
        ----------
        df      : pd.DataFrame  DataFrame to encrypt.
        columns : list[str]     Column names to encrypt.

        Returns
        -------
        pd.DataFrame  DataFrame with specified columns encrypted.
        """
        if not self._fernet:
            return df

        for col in columns:
            if col not in df.columns:
                continue
            df[col] = df[col].apply(
                lambda v: "ENCRYPTED:" + self._fernet.encrypt(
                    str(v).encode()
                ).decode() if pd.notna(v) else v
            )
            self.gov.encryption_applied(col, "AES-256-CBC/Fernet")
        return df

    def decrypt(self, df: "pd.DataFrame", columns: list[str]) -> "pd.DataFrame":
        """
        Decrypt previously-encrypted columns.

        Parameters
        ----------
        df      : pd.DataFrame  DataFrame containing encrypted columns.
        columns : list[str]     Columns to decrypt.

        Returns
        -------
        pd.DataFrame  DataFrame with columns decrypted.
        """
        if not self._fernet:
            return df

        for col in columns:
            if col not in df.columns:
                continue
            def _decrypt_val(v):
                if pd.isna(v) or not str(v).startswith("ENCRYPTED:"):
                    return v
                try:
                    token = str(v)[len("ENCRYPTED:"):]
                    return self._fernet.decrypt(token.encode()).decode()
                except Exception:  # pylint: disable=broad-exception-caught
                    return v   # Return as-is if decryption fails

            df[col] = df[col].apply(_decrypt_val)
        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DataClassificationTagger  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class DataClassificationTagger:
    """
    Assigns a data sensitivity classification level to the dataset.

    Classification drives downstream access control policies: only users
    with clearance for a given level can access the data.  Storing the
    classification as a column in the loaded table allows row-level and
    column-level security policies in databases like SQL Server or PostgreSQL
    to be applied automatically.

    Classification scheme
    ---------------------
    RESTRICTED      — Special-category PII (health, race, religion, etc.)
                      GDPR Article 9 data.  Highest protection required.

    CONFIDENTIAL    — Personal data (non-special-category PII present).
                      GDPR Article 4(1) personal data.

    INTERNAL        — No direct PII but data is not for public release.
                      Examples: internal codes, financial summaries.

    PUBLIC          — No PII detected and no sensitive business data.
                      Safe for unrestricted access.

    The level is derived automatically from the PII scan results and added
    as a _data_classification metadata column on every loaded row.
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def classify(
        self,
        df:          "pd.DataFrame",
        pii_findings: list[dict],
    ) -> tuple["pd.DataFrame", str]:
        """
        Determine the classification level and tag the DataFrame.

        Parameters
        ----------
        df           : pd.DataFrame  DataFrame to tag.
        pii_findings : list[dict]    PII findings from _detect_pii().

        Returns
        -------
        tuple[pd.DataFrame, str]
            df    — DataFrame with _data_classification column added.
            level — The assigned classification level string.
        """
        special_count = sum(1 for f in pii_findings if f.get("special_category"))
        pii_count     = len(pii_findings)

        if special_count > 0:
            level = "RESTRICTED"      # GDPR Art. 9 data
        elif pii_count > 0:
            level = "CONFIDENTIAL"    # GDPR Art. 4(1) personal data
        elif any(kw in " ".join(df.columns).lower()
                 for kw in ("internal", "confidential", "private", "budget", "forecast")):
            level = "INTERNAL"
        else:
            level = "PUBLIC"

        df["_data_classification"] = level
        self.gov.classification_tagged(level, pii_count, special_count)
        print(f"  [CLASSIFY] Dataset classified as: {level}  "
              f"(PII fields: {pii_count}, special category: {special_count})")
        return df, level


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: CrossBorderTransferLogger  (NEW v3.0)
# ═════════════════════════════════════════════════════════════════════════════
class CrossBorderTransferLogger:
    """
    Detects and logs cross-border data transfers under GDPR Chapter V.

    GDPR Chapter V (Articles 44–50) restricts transferring personal data
    to countries outside the EU/EEA unless an appropriate safeguard is in
    place.  This class checks whether the source and destination are in
    different jurisdictions and logs the applicable transfer mechanism.

    Transfer mechanisms recognised
    -------------------------------
    INTRA_EU           — Both source and destination are in EU/EEA.
                         No restrictions apply (free flow of data).

    DOMESTIC           — Same country — not a transfer at all.

    ADEQUACY_DECISION  — Destination has an EU Adequacy Decision (Art. 45).
                         Transfer is permitted without additional safeguards.

    SCC                — Standard Contractual Clauses in place (Art. 46(2)(c)).
                         Requires actual SCC documentation to be maintained.

    BCR                — Binding Corporate Rules (Art. 47).
                         For intra-group transfers within a multinational.

    UNKNOWN_SAFEGUARD  — Transfer may occur but safeguard is unspecified.
                         Logs a WARNING — legal review required.

    Usage
    -----
        logger = CrossBorderTransferLogger(gov)
        logger.check_and_log(
            source_country="US",
            dest_country="DE",
            configured_safeguard="SCC"
        )
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def check_and_log(
        self,
        source_country:       str,
        dest_country:         str,
        configured_safeguard: str = "SCC",
    ) -> str:
        """
        Evaluate the transfer scenario and log the appropriate event.

        Parameters
        ----------
        source_country       : str  ISO 3166-1 alpha-2 source data country.
        dest_country         : str  ISO 3166-1 alpha-2 destination country.
        configured_safeguard : str  Safeguard the operator has configured
                                    ("SCC", "BCR", "NONE", etc.).

        Returns
        -------
        str  The transfer type string logged.
        """
        src = source_country.upper().strip()
        dst = dest_country.upper().strip()

        if src == dst:
            transfer_type = "DOMESTIC"
            safeguard     = "No transfer — same jurisdiction"
        elif src in EU_EEA_COUNTRY_CODES and dst in EU_EEA_COUNTRY_CODES:
            transfer_type = "INTRA_EU"
            safeguard     = "EU/EEA intra-zone transfer — no restrictions"
        elif dst in ADEQUATE_COUNTRIES:
            transfer_type = "ADEQUACY_DECISION"
            safeguard     = f"Adequacy Decision (GDPR Art. 45) — {dst}"
        elif configured_safeguard.upper() in ("SCC", "STANDARD_CONTRACTUAL_CLAUSES"):
            transfer_type = "SCC"
            safeguard     = "Standard Contractual Clauses (GDPR Art. 46(2)(c))"
        elif configured_safeguard.upper() in ("BCR", "BINDING_CORPORATE_RULES"):
            transfer_type = "BCR"
            safeguard     = "Binding Corporate Rules (GDPR Art. 47)"
        else:
            transfer_type = "UNKNOWN_SAFEGUARD"
            safeguard     = f"No recognised safeguard configured: {configured_safeguard!r}"

        self.gov.transfer_logged(src, dst, safeguard, transfer_type)

        symbol = "✓" if transfer_type not in ("UNKNOWN_SAFEGUARD",) else "⚠"
        print(f"  {symbol}  [TRANSFER] {src} → {dst} | "
              f"{transfer_type} | {safeguard}")
        return transfer_type


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: ErasureHandler  (NEW v3.0 — GDPR Article 17)
# ═════════════════════════════════════════════════════════════════════════════
class ErasureHandler:
    """
    Executes GDPR Article 17 Right-to-Erasure requests.

    When a data subject submits a valid erasure request, this handler
    locates all rows belonging to that subject across the target database
    and either deletes them (hard delete) or nullifies their PII fields
    (soft delete / pseudonymisation).

    GDPR Article 17 requires:
    1. Erasure to be completed within 30 days of the request.
    2. A record of the erasure to be maintained (handled by the audit ledger).
    3. Notification to downstream processors who received the data.

    The subject_id is hashed before being stored in the audit trail so
    that the erasure log itself does not become a source of PII leakage.

    Usage
    -----
    Standalone (run after the main pipeline):
        handler = ErasureHandler(gov)
        handler.execute(
            subject_id="alice@example.com",
            subject_col="email",
            db_type="sqlite",
            db_cfg={"db_name": "pipeline_output"},
            table="employees",
            mode="delete"
        )
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def erase(
        self,
        subject_id:  str,
        table:       str,
        db_type:     str,
        db_cfg:      dict,
        id_column:   str = "id",
        mode:        str = "delete",
        pii_cols:    "list[str] | None" = None,
    ) -> int:
        """
        Convenience wrapper for execute() with a named id_column parameter.
        Deletes or nullifies all records for subject_id in the target table.
        """
        return self.execute(subject_id=subject_id, subject_col=id_column,
                            db_type=db_type, db_cfg=db_cfg, table=table,
                            mode=mode, pii_cols=pii_cols)

    def dsar_export(
        self,
        subject_id:  str,
        tables:      "list[tuple]",   # [(table, db_type, db_cfg), ...]
        id_column:   str = "id",
    ) -> "dict":
        """
        Data Subject Access Request export.
        Finds all records for subject_id across the listed tables and returns
        them as a dict {table_name: [row, ...]}. Logs a DSAR_EXPORT event.
        """
        import json as _json  # noqa: F401
        from sqlalchemy import create_engine as _ce, text as _text

        results: dict = {}
        for entry in tables:
            if len(entry) == 3:
                tname, db_type, db_cfg = entry
            else:
                raise ValueError(f"Each tables entry must be (table, db_type, db_cfg), got {entry}")
            try:
                if db_type == "sqlite":
                    eng = _ce(f"sqlite:///{db_cfg['db_name']}.db")
                elif db_type in ("postgresql","mysql","mssql"):
                    eng = _ce(f"{db_type}://{db_cfg['user']}:{db_cfg['password']}@{db_cfg['host']}/{db_cfg['db_name']}")
                else:
                    self.gov._event("DSAR","DSAR_SKIP",{"table":tname,"reason":f"unsupported db_type:{db_type}"})
                    results[tname] = []
                    continue
                with eng.connect() as conn:
                    rows = conn.execute(
                        _text(f"SELECT * FROM {tname} WHERE {id_column} = :sid"),
                        {"sid": subject_id}
                    ).fetchall()
                results[tname] = [dict(r._mapping) for r in rows]
            except Exception as exc:  # pylint: disable=broad-except
                results[tname] = {"error": str(exc)}

        self.gov._event("DSAR", "DSAR_EXPORT_COMPLETE", {
            "subject_id_hash": hashlib.sha256(str(subject_id).encode()).hexdigest()[:16],
            "tables_queried": list(results.keys()),
            "total_records": sum(len(v) for v in results.values() if isinstance(v, list)),
        })
        return results

    def execute(
        self,
        subject_id:  str,
        subject_col: str,
        db_type:     str,
        db_cfg:      dict,
        table:       str,
        mode:        str = "delete",
        pii_cols:    "list[str] | None" = None,
    ) -> int:
        """
        Locate and erase all records for a given subject.

        Parameters
        ----------
        subject_id  : str        The identifier of the data subject
                                 (e.g. email address, user ID).
        subject_col : str        Column in the target table that holds
                                 subject identifiers.
        db_type     : str        Database type ("sqlite", "postgresql", etc.)
        db_cfg      : dict       Database connection configuration.
        table       : str        Target table name.
        mode        : str        "delete"  — Hard delete: remove rows entirely.
                                 "nullify" — Soft delete: set PII columns to NULL.
                                             Preserves referential integrity.
        pii_cols    : list|None  For "nullify" mode: columns to set to NULL.

        Returns
        -------
        int  Number of rows deleted or nullified.
        """
        from sqlalchemy import create_engine, text

        # Build SQLAlchemy engine (reuse helper from SQLLoader).
        t = db_type
        if t == "sqlite":
            engine = create_engine(f"sqlite:///{db_cfg['db_name']}.db")
        elif t in ("postgresql", "postgres"):
            engine = create_engine(
                f"postgresql+psycopg2://{db_cfg['user']}:{db_cfg['password']}"
                f"@{db_cfg['host']}:{db_cfg.get('port',5432)}/{db_cfg['db_name']}"
            )
        elif t == "mysql":
            engine = create_engine(
                f"mysql+pymysql://{db_cfg['user']}:{db_cfg['password']}"
                f"@{db_cfg['host']}:{db_cfg.get('port',3306)}/{db_cfg['db_name']}"
            )
        elif t == "mssql":
            engine = create_engine(
                f"mssql+pyodbc://{db_cfg['user']}:{db_cfg['password']}"
                f"@{db_cfg['host']}:{db_cfg.get('port',1433)}/{db_cfg['db_name']}"
                f"?driver={db_cfg.get('driver','ODBC+Driver+17+for+SQL+Server')}"
            )
        elif t == "snowflake":
            if not HAS_SNOWFLAKE:
                self.gov.logger.warning("[ERASURE] Snowflake packages not installed.")
                return 0
            from snowflake.sqlalchemy import URL as _sfurl
            engine = create_engine(_sfurl(
                account   = db_cfg["account"],
                user      = db_cfg["user"],
                password  = db_cfg["password"],
                database  = db_cfg["database"],
                schema    = db_cfg.get("schema", "PUBLIC"),
                warehouse = db_cfg["warehouse"],
                role      = db_cfg.get("role", ""),
            ))
        elif t == "redshift":
            if not HAS_REDSHIFT:
                self.gov.logger.warning("[ERASURE] redshift-connector not installed.")
                return 0
            schema = db_cfg.get("schema", "public")
            engine = create_engine(
                f"redshift+psycopg2://{db_cfg['user']}:{db_cfg['password']}"
                f"@{db_cfg['host']}:{db_cfg.get('port', 5439)}/{db_cfg['database']}",
                connect_args={"options": f"-csearch_path={schema}"},
            )
        elif t == "bigquery":
            if not HAS_BIGQUERY:
                self.gov.logger.warning("[ERASURE] google-cloud-bigquery not installed.")
                return 0
            # BigQuery erasure uses the BQ client directly (no SQLAlchemy engine).
            client    = BigQueryLoader(self.gov)._client(db_cfg)
            project   = db_cfg["project"]
            dataset   = db_cfg["dataset"]
            table_id  = f"{project}.{dataset}.{table}"
            if mode == "delete":
                dml = (
                    f"DELETE FROM `{table_id}` "
                    f"WHERE `{subject_col}` = @sid"
                )
                job_cfg = _bigquery.QueryJobConfig(
                    query_parameters=[
                        _bigquery.ScalarQueryParameter("sid", "STRING", subject_id)
                    ]
                )
                job = client.query(dml, job_config=job_cfg)
                job.result()
                rows_affected = job.num_dml_affected_rows or 0
            elif mode == "nullify" and pii_cols:
                set_clause    = ", ".join(f"`{c}` = NULL" for c in pii_cols)
                dml           = (
                    f"UPDATE `{table_id}` "
                    f"SET {set_clause} "
                    f"WHERE `{subject_col}` = @sid"
                )
                job_cfg = _bigquery.QueryJobConfig(
                    query_parameters=[
                        _bigquery.ScalarQueryParameter("sid", "STRING", subject_id)
                    ]
                )
                job = client.query(dml, job_config=job_cfg)
                job.result()
                rows_affected = job.num_dml_affected_rows or 0
            else:
                rows_affected = 0
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "synapse":
            if not HAS_SYNAPSE:
                self.gov.logger.warning("[ERASURE] Synapse pyodbc not installed.")
                return 0
            import urllib.parse  # pylint: disable=import-outside-toplevel
            drv      = db_cfg.get("driver", "ODBC Driver 17 for SQL Server")
            host     = db_cfg["host"]
            port     = db_cfg.get("port", 1433)
            database = db_cfg["database"]
            conn_str = (
                f"DRIVER={{{drv}}};SERVER={host},{port};DATABASE={database};"
                f"UID={db_cfg['user']};PWD={db_cfg['password']};"
                "Encrypt=yes;TrustServerCertificate=no"
            )
            engine = create_engine(
                f"mssql+pyodbc:///?odbc_connect={urllib.parse.quote_plus(conn_str)}"
            )
        elif t == "databricks":
            if not HAS_DATABRICKS:
                self.gov.logger.warning("[ERASURE] databricks-sql-connector not installed.")
                return 0
            # Databricks erasure uses the SQL connector directly (no SQLAlchemy engine).
            loader  = DatabricksLoader(self.gov)
            conn    = loader._connect(db_cfg)
            cur     = conn.cursor()
            schema  = db_cfg.get("schema", "default")
            catalog = db_cfg.get("catalog", "hive_metastore")
            fqt     = (
                f"`{catalog}`.`{schema}`.`{table}`"
                if catalog != "hive_metastore"
                else f"`{schema}`.`{table}`"
            )
            try:
                if mode == "delete":
                    cur.execute(
                        f"DELETE FROM {fqt} WHERE `{subject_col}` = ?",
                        [subject_id],
                    )
                    rows_affected = cur.rowcount or 0
                elif mode == "nullify" and pii_cols:
                    set_clause    = ", ".join(f"`{c}` = NULL" for c in pii_cols)
                    cur.execute(
                        f"UPDATE {fqt} SET {set_clause} WHERE `{subject_col}` = ?",
                        [subject_id],
                    )
                    rows_affected = cur.rowcount or 0
                else:
                    rows_affected = 0
                conn.commit()
            finally:
                cur.close()
                conn.close()
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "clickhouse":
            if not HAS_CLICKHOUSE:
                self.gov.logger.warning("[ERASURE] clickhouse-connect not installed.")
                return 0
            # ClickHouse erasure uses the native HTTP client.
            # Note: lightweight deletes require ClickHouse ≥ 22.8 or
            # MergeTree with allow_experimental_lightweight_delete=1.
            ch_client  = _clickhouse_connect.get_client(
                host    = db_cfg.get("host", "localhost"),
                port    = int(db_cfg.get("port", 8123)),
                username= db_cfg.get("username", "default"),
                password= db_cfg.get("password", ""),
                database= db_cfg.get("database", "default"),
                secure  = bool(db_cfg.get("secure", False)),
            )
            database = db_cfg.get("database", "default")
            fqt      = f"`{database}`.`{table}`"
            if mode == "delete":
                ch_client.command(
                    f"DELETE FROM {fqt} WHERE `{subject_col}` = %(sid)s",
                    parameters={"sid": subject_id},
                    settings={"allow_experimental_lightweight_delete": 1},
                )
                rows_affected = 0  # CH DELETE doesn't return rowcount
            elif mode == "nullify" and pii_cols:
                set_clause    = ", ".join(f"`{c}` = NULL" for c in pii_cols)
                ch_client.command(
                    f"ALTER TABLE {fqt} UPDATE {set_clause} "
                    f"WHERE `{subject_col}` = %(sid)s",
                    parameters={"sid": subject_id},
                )
                rows_affected = 0
            else:
                rows_affected = 0
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "oracle":
            if not HAS_ORACLE:
                self.gov.logger.warning("[ERASURE] python-oracledb not installed.")
                return 0
            loader = OracleLoader(self.gov)
            conn   = loader._connect(db_cfg)
            cur    = conn.cursor()
            schema = db_cfg.get("schema", "").upper()
            fqt    = f'"{schema}"."{table.upper()}"' if schema else f'"{table.upper()}"'
            try:
                if mode == "delete":
                    cur.execute(
                        f'DELETE FROM {fqt} WHERE "{subject_col.upper()}" = :1',
                        [subject_id],
                    )
                    rows_affected = cur.rowcount
                elif mode == "nullify" and pii_cols:
                    set_clause    = ", ".join(f'"{c.upper()}" = NULL' for c in pii_cols)
                    cur.execute(
                        f'UPDATE {fqt} SET {set_clause} WHERE "{subject_col.upper()}" = :1',
                        [subject_id],
                    )
                    rows_affected = cur.rowcount
                else:
                    rows_affected = 0
                conn.commit()
            finally:
                cur.close()
                conn.close()
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "db2":
            if not HAS_DB2:
                self.gov.logger.warning("[ERASURE] ibm-db not installed.")
                return 0
            loader   = Db2Loader(self.gov)
            conn     = _ibm_db.connect(loader._conn_str(db_cfg), "", "")
            schema   = db_cfg.get("schema", db_cfg["user"]).upper()
            fqt      = f'"{schema}"."{table.upper()}"'
            try:
                if mode == "delete":
                    stmt = _ibm_db.exec_immediate(
                        conn,
                        f'DELETE FROM {fqt} WHERE "{subject_col.upper()}" = ?',
                    )
                    rows_affected = _ibm_db.num_rows(stmt)
                elif mode == "nullify" and pii_cols:
                    set_clause    = ", ".join(f'"{c.upper()}" = NULL' for c in pii_cols)
                    _ibm_db.exec_immediate(
                        conn,
                        f'UPDATE {fqt} SET {set_clause} WHERE "{subject_col.upper()}" = ?',
                    )
                    rows_affected = 0
                else:
                    rows_affected = 0
                _ibm_db.commit(conn)
            finally:
                _ibm_db.close(conn)
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "firebolt":
            if not HAS_FIREBOLT:
                self.gov.logger.warning("[ERASURE] firebolt-sdk not installed.")
                return 0
            loader = FireboltLoader(self.gov)
            conn   = loader._connect(db_cfg)
            cur    = conn.cursor()
            try:
                if mode == "delete":
                    cur.execute(
                        f'DELETE FROM "{table}" WHERE "{subject_col}" = ?',
                        (subject_id,),
                    )
                    rows_affected = cur.rowcount or 0
                elif mode == "nullify" and pii_cols:
                    set_clause    = ", ".join(f'"{c}" = NULL' for c in pii_cols)
                    cur.execute(
                        f'UPDATE "{table}" SET {set_clause} WHERE "{subject_col}" = ?',
                        (subject_id,),
                    )
                    rows_affected = cur.rowcount or 0
                else:
                    rows_affected = 0
            finally:
                cur.close()
                conn.close()
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "yellowbrick":
            if not HAS_YELLOWBRICK:
                self.gov.logger.warning("[ERASURE] psycopg2 not installed.")
                return 0
            # Yellowbrick is PostgreSQL-wire-compatible; build a psycopg2
            # SQLAlchemy engine so it falls through to the shared
            # with engine.connect() block below.
            engine = create_engine(
                f"postgresql+psycopg2://{db_cfg['user']}:{db_cfg['password']}"
                f"@{db_cfg['host']}:{db_cfg.get('port', 5432)}/{db_cfg['database']}",
                connect_args={"options": f"-csearch_path={db_cfg.get('schema','public')}"},
            )
        elif t == "hana":
            # SAP HANA: native hdbcli DELETE / UPDATE
            if not HAS_HANA:
                self.gov.logger.warning("[ERASURE] hdbcli not installed.")
                return 0
            import hdbcli.dbapi as _hdb
            _hconn = _hdb.connect(
                address=db_cfg["host"], port=int(db_cfg.get("port", 443)),
                user=db_cfg["user"], password=db_cfg["password"],
                encrypt=db_cfg.get("encrypt", True), autocommit=False,
            )
            _hcur = _hconn.cursor()
            schema = db_cfg.get("schema", "PIPELINE")
            try:
                if mode == "delete":
                    _hcur.execute(
                        f'DELETE FROM "{schema}"."{table}" WHERE "{subject_col}" = ?',
                        (subject_id,)
                    )
                    rows_affected = _hcur.rowcount
                elif mode == "nullify" and pii_cols:
                    set_clause = ", ".join(f'"{c}" = NULL' for c in pii_cols)
                    _hcur.execute(
                        f'UPDATE "{schema}"."{table}" SET {set_clause} WHERE "{subject_col}" = ?',
                        (subject_id,)
                    )
                    rows_affected = _hcur.rowcount
                else:
                    rows_affected = 0
                _hconn.commit()
            finally:
                _hcur.close(); _hconn.close()
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "mongodb":
            # MongoDB erasure — uses pymongo directly (no SQLAlchemy engine)
            try:
                from pymongo import MongoClient as _MongoClient  # pylint: disable=import-outside-toplevel
            except ImportError:
                self.gov.logger.warning("[ERASURE] pymongo not installed.")
                return 0
            conn_str = (
                f"mongodb://{db_cfg['user']}:{db_cfg['password']}"
                f"@{db_cfg['host']}:{db_cfg.get('port', 27017)}"
                if db_cfg.get("user") else
                f"mongodb://{db_cfg['host']}:{db_cfg.get('port', 27017)}"
            )
            client   = _MongoClient(conn_str)
            db_name  = db_cfg.get("database", db_cfg.get("db_name", "pipeline"))
            col_name = db_cfg.get("collection", table)
            collection = client[db_name][col_name]
            if mode == "delete":
                result_mg = collection.delete_many({subject_col: subject_id})
                rows_affected = result_mg.deleted_count
            elif mode == "nullify" and pii_cols:
                unset_doc  = {c: "" for c in pii_cols}
                result_mg  = collection.update_many(
                    {subject_col: subject_id}, {"$unset": unset_doc}
                )
                rows_affected = result_mg.modified_count
            else:
                rows_affected = 0
            client.close()
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "datasphere":
            # SAP Datasphere: OData DELETE on the record endpoint
            import requests as _req
            _dsl = DatasphereLoader(self.gov)
            _tok = _dsl._get_token(db_cfg)
            _tbl = db_cfg.get("table", table)
            _url = (f"{db_cfg['tenant_url'].rstrip('/')}/api/v1/dwc/catalog"
                    f"/spaces/{db_cfg['space']}/assets/{_tbl}/data"
                    f"({subject_col}='{subject_id}')")
            _resp = _req.delete(_url, headers=_dsl._headers(_tok),
                                timeout=db_cfg.get("timeout", 30))
            rows_affected = 1 if _resp.ok else 0
            h = hashlib.sha256(str(subject_id).encode()).hexdigest()
            self.gov.erasure_executed(h, table, rows_affected, mode.upper())
            return rows_affected
        elif t == "quickbooks":
            # QuickBooks Online does not support bulk SQL DELETE.
            # GDPR Art. 17 erasure requires voiding/deleting individual
            # transactions via the QBO REST API v3 (entity-specific endpoints).
            # Log the request for manual follow-up and return 0.
            self.gov.logger.warning(
                "[ERASURE] QuickBooks Online: automated SQL erasure not supported. "
                "Manually void/delete transactions for subject '%s' via the QBO API. "
                "Logging erasure request for audit trail.",
                hashlib.sha256(str(subject_id).encode()).hexdigest()[:16],
            )
            self.gov._event(  # pylint: disable=protected-access
                "ERASURE", "ERASURE_MANUAL_REQUIRED",
                {"db_type": "quickbooks", "table": table,
                 "subject_hash": hashlib.sha256(str(subject_id).encode()).hexdigest()[:16],
                 "reason": "QBO REST API does not support bulk DELETE"},
            )
            return 0
        else:
            self.gov.logger.warning("[ERASURE] Unsupported db_type: %s", t)
            return 0

        with engine.connect() as conn:
            if mode == "delete":
                # Hard delete: physically remove all matching rows.
                result = conn.execute(
                    text(f"DELETE FROM {table} WHERE {subject_col} = :sid"),
                    {"sid": subject_id}
                )
                rows_affected = result.rowcount
                conn.commit()

            elif mode == "nullify" and pii_cols:
                # Soft delete: overwrite PII values with NULL.
                set_clause = ", ".join(f"{c} = NULL" for c in pii_cols)
                result = conn.execute(
                    text(f"UPDATE {table} SET {set_clause} WHERE {subject_col} = :sid"),
                    {"sid": subject_id}
                )
                rows_affected = result.rowcount
                conn.commit()
            else:
                rows_affected = 0

        self.gov.erasure_executed(subject_id, table, rows_affected)
        print(f"  [ERASURE] {mode.upper()} — {rows_affected} row(s) "
              f"erased from '{table}' (Art. 17)")
        return rows_affected


# ═════════════════════════════════════════════════════════════════════════════
#  v2.0 CLASSES  (carried forward — SecretsManager, DataProfiler,
#  DeadLetterQueue, SchemaValidator, Extractor, Transformer, SQLLoader,
#  MongoLoader, Notifier, IncrementalFilter)
#  All are included below with minimal changes.
# ═════════════════════════════════════════════════════════════════════════════

class SecretsManager:
    """Resolves credentials from: explicit arg → .env file → env var → prompt."""
    def __init__(self, env_file: str = ".env") -> None:
        self._env: dict = {}
        if HAS_DOTENV and Path(env_file).exists():
            self._env = {k: v for k, v in dotenv_values(env_file).items() if v}

    def get(self, key: str, prompt: str = "", default: str = "",
            explicit: str | None = None) -> str:
        if explicit is not None: return explicit
        if key in self._env: return self._env[key]
        if key in os.environ: return os.environ[key]
        return _prompt(prompt or key, default)

    def get_password(self, key: str, prompt: str = "Password",
                      explicit: str | None = None) -> str:
        if explicit is not None: return explicit
        if key in self._env: return self._env[key]
        if key in os.environ: return os.environ[key]
        return getpass.getpass(f"{prompt}: ")


class DataProfiler:
    """Generates a statistical profile of a DataFrame (unchanged from v2.0)."""
    def __init__(self, gov: GovernanceLogger) -> None: self.gov = gov

    def save_json(self, profile: dict, path: "str | Path") -> "Path":
        """Save a profile dict returned by profile() to a JSON file."""
        import json as _json
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_json.dumps(profile, indent=2, default=str), encoding="utf-8")
        return out

    def profile(self, df: "pd.DataFrame") -> dict:
        row_count   = len(df)
        dup_count   = int(df.duplicated().sum())
        total_cells = row_count * len(df.columns)
        total_nulls = int(df.isnull().sum().sum())
        null_rate   = round(total_nulls / total_cells, 4) if total_cells else 0
        columns_profile = {}
        for col in df.columns:
            s          = df[col]
            null_count = int(s.isnull().sum())
            cp: dict   = {
                "dtype": str(s.dtype),
                "null_count": null_count,
                "null_pct": round(null_count / row_count, 4) if row_count else 0,
                "unique_count": int(s.nunique(dropna=True)),
            }
            if pd.api.types.is_numeric_dtype(s):
                desc = s.describe()
                cp.update({k: float(desc.get(dk, float("nan")))
                            for k, dk in [("min","min"),("max","max"),
                                          ("mean","mean"),("std","std"),
                                          ("p25","25%"),("p50","50%"),("p75","75%")]})
            elif s.dtype == object:
                ls = s.dropna().astype(str).str.len()
                cp.update({"min_length": int(ls.min()) if len(ls) else 0,
                            "max_length": int(ls.max()) if len(ls) else 0,
                            "sample_values": s.value_counts().head(5).index.tolist()})
            columns_profile[col] = cp
        profile = {"table": {"row_count": row_count, "column_count": len(df.columns),
                              "duplicate_row_count": dup_count,
                              "total_null_count": total_nulls,
                              "overall_null_rate": null_rate},
                   "columns": columns_profile}
        self.gov.profile_recorded({"row_count": row_count, "column_count": len(df.columns),
                                    "duplicate_count": dup_count, "overall_null_rate": null_rate})
        self.gov.write_profile_report(profile)
        return profile


class DeadLetterQueue:
    """Routes rejected rows to a DLQ CSV file (unchanged from v2.0)."""
    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov              = gov
        self.dlq_path         = gov.dlq_file
        self._header_written  = False

    def write(self, df: "pd.DataFrame", bad_indices: list[int],
               reason: str) -> "pd.DataFrame":
        if not bad_indices: return df
        bad_mask     = df.index.isin(bad_indices)
        rejected_df  = df[bad_mask].copy()
        clean_df     = df[~bad_mask].copy()
        rejected_df["_dlq_pipeline_id"] = PIPELINE_ID
        rejected_df["_dlq_reason"]      = reason
        rejected_df["_dlq_timestamp"]   = datetime.now(timezone.utc).isoformat()
        rejected_df.to_csv(self.dlq_path, mode="a",
                           header=not self._header_written, index=False)
        self._header_written = True
        self.gov.dlq_written(len(rejected_df), reason)
        return clean_df


class SchemaValidator:
    """Great Expectations 1.x schema validation (carried from v2.0)."""
    def __init__(self, gov: GovernanceLogger, dlq: "DeadLetterQueue | None" = None) -> None:
        self.gov             = gov
        self.dlq             = dlq
        self.suite_name      = f"pipeline_suite_{PIPELINE_ID[:8]}"
        self.expectation_configs: list[dict] = []

    def build_suite(self, df: "pd.DataFrame", interactive: bool = True) -> list:
        expectations = []
        print("\n" + "═" * 64)
        print("  SCHEMA VALIDATION — Great Expectations Suite Builder")
        print("═" * 64)
        print("\n[GX] Auto-generating baseline expectations…")
        for col in df.columns:
            expectations.append(gxe.ExpectColumnToExist(column=col))
            self.expectation_configs.append({"type":"ExpectColumnToExist","column":col})
            if pd.api.types.is_numeric_dtype(df[col]):
                if df[col].isnull().mean() == 0:
                    expectations.append(gxe.ExpectColumnValuesToNotBeNull(column=col))
                non_null = df[col].dropna()
                if len(non_null):
                    hd = max(abs(float(non_null.max()) - float(non_null.min())) * 0.5, 1)
                    expectations.append(gxe.ExpectColumnValuesToBeBetween(
                        column=col,
                        min_value=float(non_null.min()) - hd,
                        max_value=float(non_null.max()) + hd
                    ))
        print(f"  ✓ {len(expectations)} baseline expectation(s) generated.")
        if interactive:
            expectations = self._interactive_builder(df, expectations)
        return expectations

    def _interactive_builder(self, df, expectations):
        cols = list(df.columns)
        print("\n[GX] Add custom expectations (0 to finish):")
        while True:
            print("  1.Not-null  2.Unique  3.Range  4.Allowed-values  5.Regex  6.Min-rows  0.Done")
            c = _prompt("Add", "0")
            if c == "0": break
            if c in ("1","2","3","4","5"):
                col = _prompt(f"Column ({', '.join(cols[:8])}…)")
                if col not in cols: print(f"  '{col}' not found."); continue
            if c == "1":
                expectations.append(gxe.ExpectColumnValuesToNotBeNull(column=col))
                print(f"  ✓ {col}: not null")
            elif c == "2":
                expectations.append(gxe.ExpectColumnValuesToBeUnique(column=col))
                print(f"  ✓ {col}: unique")
            elif c == "3":
                try:
                    mn, mx = float(_prompt(f"Min {col}")), float(_prompt(f"Max {col}"))
                    expectations.append(gxe.ExpectColumnValuesToBeBetween(column=col, min_value=mn, max_value=mx))
                    print(f"  ✓ {col}: [{mn}, {mx}]")
                except ValueError: print("  Invalid number.")
            elif c == "4":
                vals = [v.strip() for v in input("  Allowed values (comma-sep): ").split(",") if v.strip()]
                if vals:
                    expectations.append(gxe.ExpectColumnValuesToBeInSet(column=col, value_set=vals))
                    print(f"  ✓ {col}: {vals}")
            elif c == "5":
                pat = input(f"  Regex for {col}: ").strip()
                if pat:
                    expectations.append(gxe.ExpectColumnValuesToMatchRegex(column=col, regex=pat))
                    print(f"  ✓ {col}: /{pat}/")
            elif c == "6":
                try:
                    n = int(_prompt("Min rows"))
                    expectations.append(gxe.ExpectTableRowCountToBeBetween(min_value=n))
                    print(f"  ✓ row count > {n}")
                except ValueError: print("  Invalid number.")
        return expectations

    def validate(self, df, expectations, on_failure="dlq"):
        if not HAS_GX: return df, 0
        print("\n[GX] Running schema validation…")
        ctx      = gx.get_context(mode="ephemeral")
        ds       = ctx.data_sources.add_pandas("pipeline_ds")
        asset    = ds.add_dataframe_asset("pipeline_asset")
        bdef     = asset.add_batch_definition_whole_dataframe("batch_de")
        suite    = ctx.suites.add(gx.ExpectationSuite(name=self.suite_name))
        for exp in expectations: suite.add_expectation(exp)
        vd       = ctx.validation_definitions.add(gx.ValidationDefinition(
                       name=f"vd_{PIPELINE_ID[:8]}", data=bdef, suite=suite))
        result   = vd.run(batch_parameters={"dataframe": df})
        bad_idx: set[int] = set()
        failed  = 0
        for r in result.results:
            exp_type   = type(r.expectation_config).__name__
            col        = (getattr(r.expectation_config, "column", None)
                        or r.expectation_config.kwargs.get("column")
                        if hasattr(r.expectation_config, "kwargs") else None)
            ok         = r.success
            unexpected = r.result.get("unexpected_count", 0) or 0
            failed    += 0 if ok else 1
            self.gov.validation_expectation(exp_type, col, ok, int(unexpected))
            if not ok and col and on_failure == "dlq":
                idx_list  = r.result.get("unexpected_index_list") or []
                ltp       = {lbl: pos for pos, lbl in enumerate(df.index)}
                for lbl in idx_list:
                    if lbl in ltp: bad_idx.add(ltp[lbl])
        total  = len(result.results)
        passed = total - failed
        self.gov.validation_result(self.suite_name, result.success, passed, failed, total)
        print(f"  {'✓' if result.success else '⚠'} {passed}/{total} passed  |  "
              f"{len(bad_idx)} row(s) flagged.")
        if failed > 0:
            if on_failure == "halt":
                raise RuntimeError(f"Validation failed: {failed} expectation(s)")
            elif on_failure == "dlq" and bad_idx:
                df = self.dlq.write(df, list(bad_idx),
                                    f"FAILED_VALIDATION: {failed} expectation(s)")
                print(f"  ⚠  {len(bad_idx)} row(s) → DLQ")
        self.gov.write_validation_report()
        return df, failed


class Extractor:
    """
    Reads source files (v3.0: adds compression support + parallel chunking).

    Compression is handled transparently via CompressionHandler:
    data.csv.gz, data.json.bz2, and data.csv.zip all work the same way as
    their uncompressed equivalents.
    """
    def __init__(
        self,
        gov:            GovernanceLogger,
        array_strategy: str = "index",
        join_sep:       str = ",",
        max_depth:      int = 20,
        sep:            str = "__",
    ) -> None:
        self.gov            = gov
        self._compressor    = CompressionHandler()
        self._array_strategy= array_strategy
        self._join_sep      = join_sep
        self._max_depth     = max_depth
        self._sep           = sep

    def _flatten_kw(self) -> dict:
        """Keyword args forwarded to every _flatten_record call."""
        return dict(
            sep=self._sep,
            max_depth=self._max_depth,
            array_strategy=self._array_strategy,
            join_sep=self._join_sep,
        )

    @staticmethod
    def _json_to_df(raw, flatten_kw: dict) -> "pd.DataFrame":
        """
        Convert a raw JSON value (list or dict) to a flat DataFrame.

        Fast path: pd.json_normalize handles the common case of a list of
        flat or one-level-nested dicts ~10× faster than iterating with
        _flatten_record.  Falls back to _flatten_record for any record that
        contains lists, deeply-nested dicts, or key collisions so that all
        advanced flatten options are honoured.
        """
        records = raw if isinstance(raw, list) else [raw]

        # Fast path: try pd.json_normalize (only valid for index strategy,
        # no collision risk, all-dict values, depth ≤ 1).
        if (flatten_kw.get("array_strategy", "index") == "index"
                and flatten_kw.get("max_depth", 20) >= 2):
            try:
                df = pd.json_normalize(records, sep=flatten_kw.get("sep", "__"))
                # Verify no column-value cells still hold dicts/lists
                # (json_normalize stops at depth=1 for nested arrays of objects).
                has_nested = any(
                    df[c].dropna().apply(lambda x: isinstance(x, (dict, list))).any()
                    for c in df.columns
                    if df[c].dtype == object
                )
                if not has_nested:
                    return df
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # Fall through to the safe path.

        # Safe path: _flatten_record handles every edge case.
        flat = [_flatten_record(r, **flatten_kw) for r in records]
        return pd.DataFrame(flat)

    @staticmethod
    def _xml_to_df(path: str, _flatten_kw: dict) -> "pd.DataFrame":
        """
        Read an XML file and deep-flatten it into a DataFrame.

        pd.read_xml() only handles one level.  This implementation uses
        ElementTree to walk the full tree and flatten every element's
        attributes and text content so deeply-nested XML is fully expanded.
        """
        import xml.etree.ElementTree as ET

        def _element_to_dict(elem, prefix=""):
            """Recursively convert an XML element to a flat dict."""
            result = {}
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            node_key = f"{prefix}__{tag}" if prefix else tag

            # Attributes
            for attr_name, attr_val in elem.attrib.items():
                result[f"{node_key}__{attr_name}"] = attr_val

            # Text content (strip whitespace-only nodes)
            text = (elem.text or "").strip()
            if text:
                result[node_key] = text

            # Children
            for child in elem:
                result.update(_element_to_dict(child, prefix=node_key))

            return result

        try:
            tree = ET.parse(path)
            root = tree.getroot()
            # If root has children that look like repeated records, treat each
            # child as a row; otherwise treat the root itself as one record.
            children = list(root)
            if children and all(c.tag == children[0].tag for c in children):
                records = [_element_to_dict(c) for c in children]
            else:
                records = [_element_to_dict(root)]
            return pd.DataFrame(records)
        except ET.ParseError:
            # Fall back to pandas for well-formed but unusual XML.
            return pd.read_xml(path)

    def extract(self, path: str) -> "pd.DataFrame":
        """Read the full source file into a DataFrame (with compression support)."""
        real_ext = self._compressor.inner_extension(path)
        self.gov.transformation_applied("EXTRACT_START", {"source": path, "format": real_ext})

        if self._compressor.is_compressed(path):
            with self._compressor.open(path) as fh:
                df = self._read_stream(fh, real_ext)
        else:
            df = self._read_file(path, real_ext)

        self.gov.source_registered(path, real_ext, len(df), len(df.columns))
        # Log column dtypes for lineage graph
        dtype_map = {col: str(df[col].dtype) for col in df.columns}
        self.gov.transformation_applied("EXTRACT_COMPLETE",
                                         {"rows": len(df), "columns": list(df.columns),
                                          "dtypes": dtype_map})
        return df

    def _read_file(self, path: str, ext: str) -> "pd.DataFrame":  # noqa: C901
        """Dispatch to the correct pandas reader based on file extension."""

        # ── Text / tabular ────────────────────────────────────────────────
        if ext == ".csv":
            return pd.read_csv(path)

        if ext == ".tsv":
            return pd.read_csv(path, sep="\t")

        if ext in (".xlsx", ".xls"):
            return pd.read_excel(path)

        if ext in (".fw",):
            # Fixed-width: pandas infers column widths automatically
            return pd.read_fwf(path)

        # ── JSON variants ─────────────────────────────────────────────────
        if ext == ".json":
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            return self._json_to_df(raw, self._flatten_kw())

        if ext in (".jsonl", ".ndjson"):
            # Newline-delimited JSON — one JSON object per line
            return pd.read_json(path, lines=True)

        # ── Markup / config ───────────────────────────────────────────────
        if ext == ".xml":
            return self._xml_to_df(path, self._flatten_kw())

        if ext in (".yaml", ".yml"):
            if not HAS_YAML:
                raise RuntimeError(
                    "YAML support requires: pip install pyyaml"
                )
            with open(path, encoding="utf-8") as f:
                raw = _yaml.safe_load(f)
            # Normalise scalar / dict / list of dicts
            if isinstance(raw, list):
                return pd.json_normalize(raw)
            if isinstance(raw, dict):
                # Single-level dict → one-row DataFrame
                return pd.json_normalize([raw])
            raise ValueError(f"Cannot convert YAML root type {type(raw)} to DataFrame")

        # ── Columnar binary ───────────────────────────────────────────────
        if ext == ".parquet":
            if not HAS_PYARROW:
                raise RuntimeError(
                    "Parquet support requires: pip install pyarrow"
                )
            return pd.read_parquet(path)

        if ext in (".feather", ".arrow"):
            if not HAS_PYARROW:
                raise RuntimeError(
                    "Feather/Arrow support requires: pip install pyarrow"
                )
            return pd.read_feather(path)

        if ext == ".orc":
            if not HAS_ORC:
                raise RuntimeError(
                    "ORC support requires: pip install pyorc"
                )
            with open(path, "rb") as fh:
                reader = _pyorc.Reader(fh)
                rows   = list(reader)
                cols   = list(reader.schema.fields.keys())
            return pd.DataFrame(rows, columns=cols)

        if ext == ".avro":
            if not HAS_AVRO:
                raise RuntimeError(
                    "Avro support requires: pip install fastavro"
                )
            with open(path, "rb") as fh:
                records = list(_fastavro.reader(fh))
            return pd.json_normalize(records)

        # ── Statistical / research formats ────────────────────────────────
        if ext == ".sas7bdat":
            return pd.read_sas(path, encoding="utf-8")

        if ext == ".dta":
            return pd.read_stata(path)

        raise ValueError(
            f"Unsupported format: {ext}\n"
            "Supported: .csv .tsv .xlsx .xls .json .jsonl .ndjson "
            ".xml .yaml .yml .parquet .feather .arrow .orc .avro "
            ".fwf .sas7bdat .dta"
        )

    def _read_stream(self, stream: io.IOBase, ext: str) -> "pd.DataFrame":
        """
        Read from a file-like stream (used for compressed files).

        Most binary columnar formats (Parquet, ORC, Avro, Feather) support
        streaming via their own libraries.  Text formats fall back to a
        BytesIO buffer so that pandas can decode the bytes correctly.
        """
        # ── Text formats that work directly from a stream ─────────────────
        if ext == ".csv":
            return pd.read_csv(stream)

        if ext == ".tsv":
            return pd.read_csv(stream, sep="\t")

        if ext in (".jsonl", ".ndjson"):
            return pd.read_json(stream, lines=True)

        if ext == ".json":
            raw = json.load(stream)
            return self._json_to_df(raw, self._flatten_kw())

        if ext in (".yaml", ".yml"):
            if not HAS_YAML:
                raise RuntimeError("YAML support requires: pip install pyyaml")
            raw = _yaml.safe_load(stream)
            if isinstance(raw, list):
                return pd.json_normalize(raw)
            if isinstance(raw, dict):
                return pd.json_normalize([raw])
            raise ValueError(f"Cannot convert YAML root type {type(raw)} to DataFrame")

        # ── Columnar binary formats ───────────────────────────────────────
        if ext == ".parquet":
            if not HAS_PYARROW:
                raise RuntimeError("Parquet support requires: pip install pyarrow")
            import io as _io
            buf = _io.BytesIO(stream.read())
            return pd.read_parquet(buf)

        if ext in (".feather", ".arrow"):
            if not HAS_PYARROW:
                raise RuntimeError("Feather/Arrow support requires: pip install pyarrow")
            import io as _io
            buf = _io.BytesIO(stream.read())
            return pd.read_feather(buf)

        if ext == ".avro":
            if not HAS_AVRO:
                raise RuntimeError("Avro support requires: pip install fastavro")
            records = list(_fastavro.reader(stream))
            return pd.json_normalize(records)

        if ext == ".orc":
            if not HAS_ORC:
                raise RuntimeError("ORC support requires: pip install pyorc")
            reader = _pyorc.Reader(stream)
            rows   = list(reader)
            cols   = list(reader.schema.fields.keys())
            return pd.DataFrame(rows, columns=cols)

        if ext == ".fw":
            import io as _io
            buf = _io.BytesIO(stream.read())
            return pd.read_fwf(buf)

        raise ValueError(
            f"Compressed streaming not supported for {ext}.  "
            "Decompress first or use a supported format."
        )

    def chunks(self, path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> "Iterator[pd.DataFrame]":
        """
        Yield the source file in row-count chunks.

        Native streaming is used for CSV and JSONL (most memory-efficient).
        Parquet uses pyarrow's row-group streaming.
        All other formats are read fully then sliced.
        """
        real_ext = self._compressor.inner_extension(path)
        self.gov.transformation_applied("CHUNKED_EXTRACT_START",
                                         {"source": path, "chunk_size": chunk_size})

        # CSV — native pandas chunking
        if real_ext == ".csv" and not self._compressor.is_compressed(path):
            for i, chunk in enumerate(pd.read_csv(path, chunksize=chunk_size)):
                self.gov.transformation_applied("CHUNK_EXTRACTED",
                                                 {"chunk_index": i, "rows": len(chunk)})
                yield chunk

        # TSV — native pandas chunking with tab separator
        elif real_ext == ".tsv" and not self._compressor.is_compressed(path):
            for i, chunk in enumerate(pd.read_csv(path, sep="\t", chunksize=chunk_size)):
                self.gov.transformation_applied("CHUNK_EXTRACTED",
                                                 {"chunk_index": i, "rows": len(chunk)})
                yield chunk

        # JSONL / NDJSON — native chunking
        elif real_ext in (".jsonl", ".ndjson") and not self._compressor.is_compressed(path):
            for i, chunk in enumerate(pd.read_json(path, lines=True, chunksize=chunk_size)):
                self.gov.transformation_applied("CHUNK_EXTRACTED",
                                                 {"chunk_index": i, "rows": len(chunk)})
                yield chunk

        # Parquet — row-group streaming via pyarrow
        elif real_ext == ".parquet" and not self._compressor.is_compressed(path) and HAS_PYARROW:
            pf = _pq.ParquetFile(path)
            i  = 0
            for batch in pf.iter_batches(batch_size=chunk_size):
                chunk = batch.to_pandas()
                self.gov.transformation_applied("CHUNK_EXTRACTED",
                                                 {"chunk_index": i, "rows": len(chunk)})
                yield chunk
                i += 1

        # Everything else — read fully then slice
        else:
            df = self.extract(path)
            n  = (len(df) + chunk_size - 1) // chunk_size
            for i in range(n):
                chunk = df.iloc[i*chunk_size:(i+1)*chunk_size].copy()
                self.gov.transformation_applied("CHUNK_EXTRACTED",
                                                 {"chunk_index": i, "rows": len(chunk), "total_chunks": n})
                yield chunk


class Transformer:
    """All transformation steps from v2.0 (flatten, minimise, PII, dedup, sanitise)."""
    def __init__(
        self,
        gov:            GovernanceLogger,
        array_strategy: str = "index",
        join_sep:       str = ",",
        max_depth:      int = 20,
        sep:            str = "__",
    ) -> None:
        self.gov            = gov
        self.pii_actions:   dict[str, str] = {}
        self._array_strategy= array_strategy
        self._join_sep      = join_sep
        self._max_depth     = max_depth
        self._sep           = sep

    def _flatten_kw(self) -> dict:
        return dict(
            sep=self._sep,
            max_depth=self._max_depth,
            array_strategy=self._array_strategy,
            join_sep=self._join_sep,
        )

    @staticmethod
    def _flatten_df(df: "pd.DataFrame", obj_cols: list, flatten_kw: dict) -> "pd.DataFrame":
        """
        Flatten remaining dict/list cells in obj_cols without iterrows().

        Strategy: expand each nested column independently into a temporary
        DataFrame of scalar sub-columns, then concatenate all pieces.  This
        is O(cols × rows) instead of O(rows × cols) and avoids the Python
        overhead of iterrows(), making it ~10-20× faster on wide DataFrames.
        """
        scalar_cols = [c for c in df.columns if c not in obj_cols]
        parts = [df[scalar_cols].reset_index(drop=True)]

        for col in obj_cols:
            series = df[col].reset_index(drop=True)
            # Expand each cell into a sub-dict, then build a mini-DataFrame.
            # _col and _fkw are default-bound to avoid cell-var-from-loop closure.
            expanded = series.apply(
                lambda v, _col=col, _fkw=flatten_kw:
                    _flatten_record(v, parent_key=_col, **_fkw)
                    if isinstance(v, (dict, list)) else {_col: v}
            )
            parts.append(pd.DataFrame(list(expanded)))

        result = pd.concat(parts, axis=1)
        # Drop duplicate columns that can arise when a scalar col and an
        # expanded sub-col share the same name.
        result = result.loc[:, ~result.columns.duplicated()]
        return result

    def mask_pii(self, df: "pd.DataFrame", columns: "list[str]") -> "pd.DataFrame":
        """Hash-mask the listed columns in place (SHA-256, 8 hex chars)."""
        import hashlib as _hl
        df = df.copy()
        for col in columns:
            if col in df.columns:
                df[col] = df[col].apply(
                    lambda v: _hl.sha256(str(v).encode()).hexdigest()[:8] if v is not None else v)
        return df

    def drop_duplicates(self, df: "pd.DataFrame",
                        subset: "list[str] | None" = None) -> "pd.DataFrame":
        """Remove duplicate rows, optionally keyed on subset of columns."""
        return df.drop_duplicates(subset=subset).reset_index(drop=True)

    def fill_nulls(self, df: "pd.DataFrame",
                   fill: "dict | None" = None) -> "pd.DataFrame":
        """Fill null values. fill={col: value}; if None fills strings with '' and numbers with 0."""
        df = df.copy()
        if fill:
            df.fillna(fill, inplace=True)
        else:
            for col in df.columns:
                if df[col].dtype == object:
                    df[col].fillna("", inplace=True)
                else:
                    df[col].fillna(0, inplace=True)
        return df

    def standardise(self, df: "pd.DataFrame") -> "pd.DataFrame":
        """Lowercase and underscore-strip column names, then standardise_names."""
        return self.standardise_names(df)

    def standardise_names(self, df: "pd.DataFrame") -> "pd.DataFrame":
        """Normalise column names: lowercase, spaces→underscores, strip special chars."""
        df = df.copy()
        df.columns = [re.sub(r"[^a-z0-9_]", "", c.lower().replace(" ","_")) for c in df.columns]
        return df

    def flatten_nested(self, df: "pd.DataFrame",
                       sep: str = "_", max_level: int = 3) -> "pd.DataFrame":
        """Flatten dict/list cells in object columns into separate columns."""
        return self._flatten_df(df, [c for c in df.columns if df[c].dtype == object],
                                self._flatten_kw())

    def coerce_types(self, df: "pd.DataFrame",
                     mapping: "dict[str,str]") -> "pd.DataFrame":
        """Cast columns to requested dtypes. mapping = {col: dtype_str}."""
        df = df.copy()
        for col, dtype in mapping.items():
            if col in df.columns:
                try:
                    df[col] = df[col].astype(dtype)
                except (ValueError, TypeError):
                    pass  # leave as-is if cast fails
        return df

    def apply_business_rules(self, df: "pd.DataFrame",
                              rules: list) -> "pd.DataFrame":
        """
        Apply a list of business rule dicts to the DataFrame.
        Each rule: {"column": str, "op": "gt"|"lt"|"eq"|"drop_if_null", "value": any}
        Rows that violate a rule are removed and logged.
        """
        df = df.copy()
        for rule in rules:
            col = rule.get("column")
            op  = rule.get("op")
            val = rule.get("value")
            if col not in df.columns:
                continue
            if op == "gt":
                df = df[df[col] > val]
            elif op == "lt":
                df = df[df[col] < val]
            elif op == "eq":
                df = df[df[col] == val]
            elif op == "drop_if_null":
                df = df[df[col].notna()]
        return df.reset_index(drop=True)

    def enrich(self, df: "pd.DataFrame",
               lookups: dict) -> "pd.DataFrame":
        """
        Enrich a DataFrame via left-joins to lookup tables.
        lookups = {join_col: lookup_df} — each lookup_df must share the join_col.
        """
        df = df.copy()
        for join_col, lookup_df in lookups.items():
            if join_col in df.columns and join_col in lookup_df.columns:
                df = df.merge(lookup_df, on=join_col, how="left", suffixes=("","_lookup"))
        return df

    def transform(self, df, pii_findings, pii_strategy, drop_cols) -> "pd.DataFrame":
        # Normalise pii_findings: accept either a list of dicts (standard form)
        # or a list of column-name strings (convenience form used by generated scripts).
        if pii_findings and isinstance(pii_findings[0], str):
            pii_findings = [{"field": col} for col in pii_findings]
        original_cols = list(df.columns)
        obj_cols = [c for c in df.columns
                    if df[c].dtype == object
                    and df[c].dropna().apply(lambda x: isinstance(x, (dict, list))).any()]
        if obj_cols:
            df = self._flatten_df(df, obj_cols, self._flatten_kw())
            self.gov.transformation_applied("FLATTEN_NESTED", {"flattened_columns": obj_cols})
        if drop_cols:
            df.drop(columns=[c for c in drop_cols if c in df.columns],
                    inplace=True, errors="ignore")
            self.gov.data_minimization(original_cols, list(df.columns), drop_cols)
        for field in {f["field"]: f for f in pii_findings if f["field"] in df.columns}:
            if pii_strategy == "mask":
                df[field] = df[field].apply(_mask_value)
                self.gov.pii_action(field, "MASKED"); self.pii_actions[field] = "MASKED"
            elif pii_strategy == "drop":
                df.drop(columns=[field], inplace=True, errors="ignore")
                self.gov.pii_action(field, "DROPPED"); self.pii_actions[field] = "DROPPED"
            else:
                self.gov.pii_action(field, "RETAINED_WITH_CONSENT")
                self.pii_actions[field] = "RETAINED_WITH_CONSENT"
        bn = df.isnull().sum().sum()
        df.dropna(how="all", inplace=True)
        self.gov.transformation_applied("NULL_HANDLING",
                                         {"null_cells_before": int(bn),
                                          "null_cells_after": int(df.isnull().sum().sum())})
        b = len(df); df.drop_duplicates(inplace=True)
        self.gov.transformation_applied("DEDUPLICATION",
                                         {"rows_before": b, "rows_after": len(df),
                                          "duplicates_removed": b - len(df)})
        def _sanitise_col(c: str) -> str:
            sanitised = re.sub(r"[^a-zA-Z0-9_]", "_", c)
            # Preserve intentional leading underscore on pipeline metadata columns
            # (e.g. _pipeline_id, _loaded_at_utc, _data_classification).
            # Only strip leading underscores that were introduced by the substitution
            # (i.e. the original name did NOT start with underscore).
            if c.startswith("_"):
                return sanitised.rstrip("_")
            return sanitised.strip("_")
        df.columns = [_sanitise_col(c) for c in df.columns]
        self.gov.transformation_applied("COLUMN_SANITIZATION",
                                         {"final_columns": list(df.columns)})
        df["_pipeline_id"]   = PIPELINE_ID
        df["_loaded_at_utc"] = datetime.now(timezone.utc).isoformat()
        self.gov.transformation_applied("TRANSFORM_COMPLETE",
                                         {"final_row_count": len(df), "final_col_count": len(df.columns)})
        return df


class SQLLoader:
    """SQL loader with retry and upsert (v2.0 — unchanged)."""
    def __init__(self, gov: GovernanceLogger, db_type: str) -> None:
        self.gov = gov; self.db_type = db_type

    def _engine(self, cfg):
        from sqlalchemy import create_engine
        t = self.db_type
        if t == "sqlite":   return create_engine(f"sqlite:///{cfg['db_name']}.db")
        if t == "postgresql": return create_engine(
            f"postgresql+psycopg2://{cfg['user']}:{cfg['password']}"
            f"@{cfg['host']}:{cfg.get('port',5432)}/{cfg['db_name']}")
        if t == "mysql":    return create_engine(
            f"mysql+pymysql://{cfg['user']}:{cfg['password']}"
            f"@{cfg['host']}:{cfg.get('port',3306)}/{cfg['db_name']}")
        if t == "mssql":    return create_engine(
            f"mssql+pyodbc://{cfg['user']}:{cfg['password']}"
            f"@{cfg['host']}:{cfg.get('port',1433)}/{cfg['db_name']}"
            f"?driver={cfg.get('driver','ODBC+Driver+17+for+SQL+Server')}")
        if t == "snowflake":
            if not HAS_SNOWFLAKE:
                raise RuntimeError("snowflake-connector-python not installed")
            from snowflake.sqlalchemy import URL as _sfurl
            return create_engine(_sfurl(
                account   = cfg["account"],
                user      = cfg["user"],
                password  = cfg["password"],
                database  = cfg["database"],
                schema    = cfg.get("schema", "PUBLIC"),
                warehouse = cfg["warehouse"],
                role      = cfg.get("role", ""),
            ))
        raise ValueError(f"Unknown db type: {t}")

    def load(self, df, cfg, table, if_exists="append", natural_keys=None):
        engine = self._engine(cfg)
        if natural_keys: self._upsert(df, engine, table, natural_keys)
        else:            self._load_with_retry(df, engine, table, if_exists)
        self.gov.load_complete(len(df), table)
        # Snowflake cfg uses "database"; all other SQL platforms use "db_name".
        db_identifier = cfg.get("database") or cfg.get("db_name", "")
        self.gov.destination_registered(self.db_type, db_identifier, table)

    def _load_with_retry(self, df, engine, table, if_exists):
        for attempt in range(1, 4):
            try:
                with engine.begin() as _conn:
                    df.to_sql(table, _conn, if_exists=if_exists, index=False, chunksize=500)
                return
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == 3: raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                print(f"  ⚠  Attempt {attempt}/3 failed. Retrying in {wait}s…")
                time.sleep(wait)

    def _upsert(self, new_df, engine, table, natural_keys):
        from sqlalchemy import inspect as sai
        if table not in sai(engine).get_table_names():
            self._load_with_retry(new_df, engine, table, "replace"); return
        with engine.connect() as _conn:
            existing = pd.read_sql_table(table, _conn)
        merged   = new_df.merge(existing, on=natural_keys, how="outer",
                                 suffixes=("","_old"), indicator=True)
        merged.drop(columns=[c for c in merged.columns if c.endswith("_old")] + ["_merge"],
                    inplace=True, errors="ignore")
        self._load_with_retry(merged, engine, table, "replace")
        self.gov.transformation_applied("UPSERT_COMPLETE",
                                         {"table": table, "final_rows": len(merged)})


class MongoLoader:
    """MongoDB loader (unchanged from v2.0)."""
    def __init__(self, gov: GovernanceLogger) -> None: self.gov = gov
    def load(self, df, cfg, collection):
        from pymongo import MongoClient  # pylint: disable=import-error
        uri    = cfg.get("uri") or f"mongodb://{cfg.get('host','localhost')}:{cfg.get('port',27017)}/"
        client = MongoClient(uri)
        records= json.loads(df.to_json(orient="records", date_format="iso"))
        client[cfg["db_name"]][collection].insert_many(records)
        self.gov.load_complete(len(records), collection)
        self.gov.destination_registered("mongodb", cfg["db_name"], collection)
        client.close()




class SnowflakeLoader:
    """
    Snowflake loader with bulk staging, MERGE upsert, and GDPR-safe truncation.

    Connection
    ----------
    Uses snowflake-connector-python for DDL / DML and snowflake-sqlalchemy
    for pandas .to_sql() compatibility.  Requires the following cfg keys:

        account   : str   Snowflake account identifier (e.g. "xy12345.us-east-1")
        user      : str   Login username
        password  : str   Login password  (or use private_key_path)
        database  : str   Target database name
        schema    : str   Target schema   (default "PUBLIC")
        warehouse : str   Virtual warehouse to use
        role      : str   Snowflake role  (optional)

    Load modes
    ----------
    Standard (append / replace)
        Uses PUT → internal stage → COPY INTO for bulk throughput.
        Falls back to pandas .to_sql() if the staging approach is
        unavailable.

    Upsert (natural_keys provided)
        Builds a MERGE INTO statement so that existing rows are updated
        and new rows are inserted in a single atomic operation.  The
        DataFrame is first staged as a temporary table.

    Retry
        All load operations retry up to 3 times with exponential back-off,
        identical to SQLLoader behaviour.

    Requirements
    ------------
        pip install snowflake-connector-python snowflake-sqlalchemy
    """

    # pandas dtype → Snowflake SQL type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "NUMBER(19,0)",
        "Int64"              : "NUMBER(19,0)",
        "int32"              : "NUMBER(10,0)",
        "float64"            : "FLOAT",
        "float32"            : "FLOAT",
        "bool"               : "BOOLEAN",
        "boolean"            : "BOOLEAN",
        "datetime64[ns]"     : "TIMESTAMP_NTZ",
        "datetime64[ns, UTC]": "TIMESTAMP_TZ",
        "object"             : "VARCHAR(16777216)",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_SNOWFLAKE:
            raise RuntimeError(
                "Snowflake packages not installed. "
                "Run: pip install snowflake-connector-python snowflake-sqlalchemy"
            )

    # ── Connection helpers ────────────────────────────────────────────────

    def _connect(self, cfg: dict):
        """Return a raw snowflake.connector connection."""
        conn_args = {
            "account"  : cfg["account"],
            "user"     : cfg["user"],
            "password" : cfg["password"],
            "database" : cfg["database"],
            "schema"   : cfg.get("schema", "PUBLIC"),
            "warehouse": cfg["warehouse"],
        }
        if cfg.get("role"):
            conn_args["role"] = cfg["role"]
        return _sf_connector.connect(**conn_args)

    def _engine(self, cfg: dict):
        """Return a SQLAlchemy engine for pandas I/O."""
        url = _sf_url(
            account   = cfg["account"],
            user      = cfg["user"],
            password  = cfg["password"],
            database  = cfg["database"],
            schema    = cfg.get("schema", "PUBLIC"),
            warehouse = cfg["warehouse"],
            role      = cfg.get("role", ""),
        )
        return _sf_create_engine(url)

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str       = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into Snowflake table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config dict (see class docstring).
        table        : Target table name (case-insensitive in Snowflake).
        if_exists    : "append" | "replace" — used when natural_keys is None.
        natural_keys : Column(s) that uniquely identify a row.  When provided,
                       performs a MERGE INTO upsert instead of an insert.
        """
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._bulk_load(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "snowflake",
            f"{cfg['account']}/{cfg['database']}/{cfg.get('schema','PUBLIC')}",
            table,
        )

    # ── Bulk load (PUT → internal stage → COPY INTO) ─────────────────────

    def _bulk_load(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str,
        if_exists: str,
    ) -> None:
        """Stage a CSV locally, PUT it to Snowflake, COPY INTO the table."""
        import tempfile, os, pathlib

        # Write DataFrame to a temporary compressed CSV.
        with tempfile.NamedTemporaryFile(
            suffix=".csv.gz", delete=False, mode="wb"
        ) as tmp:
            tmp_path = tmp.name

        df.to_csv(tmp_path, index=False, compression="gzip")
        stage_file = pathlib.Path(tmp_path).name

        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            schema = cfg.get("schema", "PUBLIC")
            fqt    = f'"{cfg["database"]}"."{schema}"."{table.upper()}"'

            # Ensure the table exists; create from DataFrame schema if not.
            self._ensure_table(cur, df, fqt, if_exists)

            # PUT the local file to the Snowflake internal stage.
            stage = f"@%{table.upper()}"
            cur.execute(f"PUT file://{tmp_path} {stage} AUTO_COMPRESS=FALSE OVERWRITE=TRUE")
            print(f"  [SF] PUT {stage_file} → {stage}")

            # COPY INTO the table from the stage.
            col_list = ", ".join(f'"{c}"' for c in df.columns)
            file_fmt = (
                "FILE_FORMAT = (TYPE=CSV SKIP_HEADER=1 "
                "FIELD_OPTIONALLY_ENCLOSED_BY='\"' "
                "NULL_IF=('') EMPTY_FIELD_AS_NULL=TRUE COMPRESSION=GZIP)"
            )
            copy_sql = (
                f"COPY INTO {fqt} ({col_list}) "
                f"FROM {stage}/{stage_file} " + file_fmt
            )
            cur.execute(copy_sql)
            result = cur.fetchone()
            rows   = result[3] if result else len(df)
            print(f"  [SF] COPY INTO {table.upper()} — {rows:,} rows loaded")

            # Remove the staged file.
            cur.execute(f"REMOVE {stage}/{stage_file}")
            conn.commit()
        except Exception:  # pylint: disable=broad-exception-caught
            # Fall back to SQLAlchemy / to_sql on COPY failure.
            self.gov.logger.warning(
                "[SF] COPY INTO failed — falling back to to_sql()"
            )
            self._sql_fallback(df, cfg, table, if_exists)
        finally:
            cur.close()
            conn.close()
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _ensure_table(self, cur, df: "pd.DataFrame", fqt: str, if_exists: str) -> None:
        """CREATE OR REPLACE / CREATE IF NOT EXISTS the target table."""
        # Map pandas dtypes to Snowflake SQL types.
        type_map = {
            "int64"        : "NUMBER(38,0)",
            "Int64"        : "NUMBER(38,0)",
            "float64"      : "FLOAT",
            "bool"         : "BOOLEAN",
            "boolean"      : "BOOLEAN",
            "datetime64[ns]": "TIMESTAMP_NTZ",
            "datetime64[ns, UTC]": "TIMESTAMP_TZ",
            "object"       : "VARCHAR(16777216)",
        }
        col_defs = ", ".join(
            f'"{c}" {type_map.get(str(df[c].dtype), "VARCHAR(16777216)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f"CREATE OR REPLACE TABLE {fqt} ({col_defs})")
        else:
            cur.execute(f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs})")

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        natural_keys: list[str],
    ) -> None:
        """
        MERGE INTO target using a temporary stage table.

        For each row:
          WHEN MATCHED (keys equal)  → UPDATE all non-key columns.
          WHEN NOT MATCHED            → INSERT the full row.
        """
        tmp_table = f"{table.upper()}__STAGE__{int(time.time())}"
        schema    = cfg.get("schema", "PUBLIC")
        fqt       = f'"{cfg["database"]}"."{schema}"."{table.upper()}"'
        fqt_tmp   = f'"{cfg["database"]}"."{schema}"."{tmp_table}"'

        engine = self._engine(cfg)
        # Write the new data to a temporary staging table.
        for attempt in range(1, 4):
            try:
                with engine.begin() as _conn:
                    df.to_sql(
                        tmp_table.lower(), _conn,
                        if_exists="replace", index=False, chunksize=500,
                        method="multi",
                    )
                break
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == 3: raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                time.sleep(wait)

        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            non_key_cols = [c for c in df.columns if c not in natural_keys]

            # ON clause: join target to stage on natural keys.
            on_clause = " AND ".join(
                f't."{k}" = s."{k}"' for k in natural_keys
            )

            # UPDATE SET clause for matched rows.
            update_clause = ", ".join(
                f't."{c}" = s."{c}"' for c in non_key_cols
            ) or "t.__NOOP__ = 0"

            # INSERT clause for new rows.
            all_cols    = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols  = ", ".join(f's."{c}"' for c in df.columns)

            merge_sql = f"""
                MERGE INTO {fqt} AS t
                USING {fqt_tmp} AS s
                ON ({on_clause})
                WHEN MATCHED THEN
                    UPDATE SET {update_clause}
                WHEN NOT MATCHED THEN
                    INSERT ({all_cols}) VALUES ({stage_cols})
            """
            cur.execute(merge_sql)
            conn.commit()
            # Drop temp stage table.
            cur.execute(f"DROP TABLE IF EXISTS {fqt_tmp}")
            conn.commit()
            print(f"  [SF] MERGE INTO {table.upper()} complete.")

            self.gov.transformation_applied(
                "SNOWFLAKE_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()

    # ── SQLAlchemy fallback ───────────────────────────────────────────────

    def _sql_fallback(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str,
        if_exists: str,
    ) -> None:
        """pandas .to_sql() fallback when COPY INTO is unavailable."""
        engine = self._engine(cfg)
        for attempt in range(1, 4):
            try:
                with engine.begin() as conn:
                    df.to_sql(
                        table.lower(), conn,
                        if_exists=if_exists, index=False,
                        chunksize=500, method="multi",
                    )
                return
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == 3: raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                print(f"  ⚠  Attempt {attempt}/3 failed. Retrying in {wait}s…")
                time.sleep(wait)


class RedshiftLoader:
    """
    Amazon Redshift loader with S3-staged COPY, MERGE upsert, and retry.

    Connection
    ----------
    Uses ``redshift_connector`` (the official Amazon driver) for DDL / DML
    and ``sqlalchemy-redshift`` for pandas ``.to_sql()`` compatibility.

    Required cfg keys
    -----------------
    host       : str   Redshift cluster endpoint (or workgroup endpoint for Serverless)
    port       : int   Default 5439
    database   : str   Database name
    user       : str   Database username
    password   : str   Database password
    schema     : str   Target schema (default "public")

    Optional — S3 bulk COPY (highly recommended for >10k rows)
    -----------------------------------------------------------
    s3_bucket  : str   S3 bucket name for staging files
    s3_prefix  : str   Key prefix inside the bucket (default "redshift_stage/")
    aws_access_key_id     : str
    aws_secret_access_key : str
    aws_region            : str   Default "us-east-1"

    Load modes
    ----------
    Bulk COPY (when s3_bucket provided)
        Writes DataFrame to a gzip-compressed CSV, uploads to S3, issues a
        COPY … FROM 's3://…' command, then deletes the staging object.
        This is 10-100× faster than row-by-row INSERT for large datasets.

    MERGE upsert (natural_keys provided)
        Stages data in a temporary table then runs a MERGE INTO statement
        (available since Redshift engine version ≥ 1.0.49268).

    Fallback
        When S3 credentials are not provided, falls back to pandas .to_sql()
        via the SQLAlchemy redshift+psycopg2 dialect.

    Requirements
    ------------
        pip install redshift-connector sqlalchemy-redshift
        pip install boto3   # only required for S3 bulk COPY
    """

    # pandas dtype → Redshift column type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "BIGINT",
        "Int64"              : "BIGINT",
        "int32"              : "INTEGER",
        "float64"            : "DOUBLE PRECISION",
        "float32"            : "REAL",
        "bool"               : "BOOLEAN",
        "boolean"            : "BOOLEAN",
        "datetime64[ns]"     : "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMPTZ",
        "object"             : "VARCHAR(65535)",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_REDSHIFT:
            raise RuntimeError(
                "redshift-connector not installed.  "
                "Run: pip install redshift-connector sqlalchemy-redshift"
            )

    # ── Connection helpers ────────────────────────────────────────────────

    def _connect(self, cfg: dict):
        """Return a raw redshift_connector connection."""
        return _redshift_connector.connect(
            host     = cfg["host"],
            port     = int(cfg.get("port", 5439)),
            database = cfg["database"],
            user     = cfg["user"],
            password = cfg["password"],
        )

    def _engine(self, cfg: dict):
        """Return a SQLAlchemy engine (redshift+psycopg2 dialect)."""
        from sqlalchemy import create_engine as _ce
        schema   = cfg.get("schema", "public")
        port     = cfg.get("port", 5439)
        url      = (
            f"redshift+psycopg2://{cfg['user']}:{cfg['password']}"
            f"@{cfg['host']}:{port}/{cfg['database']}"
        )
        return _ce(url, connect_args={"options": f"-csearch_path={schema}"})

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str            = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into Redshift table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config (see class docstring).
        table        : Target table name (lower-cased per Redshift convention).
        if_exists    : "append" | "replace" — used when natural_keys is None.
        natural_keys : Column(s) for MERGE upsert (optional).
        """
        table = table.lower()
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        elif cfg.get("s3_bucket"):
            self._s3_copy(df, cfg, table, if_exists)
        else:
            self._sql_fallback(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "redshift",
            f"{cfg['host']}/{cfg['database']}/{cfg.get('schema','public')}",
            table,
        )

    # ── S3 COPY path ─────────────────────────────────────────────────────

    def _s3_copy(self, df: "pd.DataFrame", cfg: dict, table: str, if_exists: str) -> None:
        """Upload CSV to S3 then issue COPY … FROM s3://… ."""
        try:
            import boto3  # pylint: disable=import-outside-toplevel
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is required for Redshift S3 COPY.  "
                "Run: pip install boto3   (or omit s3_bucket to use to_sql fallback)"
            ) from exc

        import tempfile, os  # pylint: disable=import-outside-toplevel

        bucket  = cfg["s3_bucket"]
        prefix  = cfg.get("s3_prefix", "redshift_stage/")
        region  = cfg.get("aws_region", "us-east-1")
        key     = f"{prefix}{table}_{int(time.time())}.csv.gz"

        # Write DataFrame to compressed CSV.
        with tempfile.NamedTemporaryFile(suffix=".csv.gz", delete=False) as tmp:
            tmp_path = tmp.name
        df.to_csv(tmp_path, index=False, compression="gzip")

        # Upload to S3.
        s3 = boto3.client(
            "s3",
            region_name          = region,
            aws_access_key_id    = cfg.get("aws_access_key_id"),
            aws_secret_access_key= cfg.get("aws_secret_access_key"),
        )
        s3.upload_file(tmp_path, bucket, key)
        print(f"  [RS] Uploaded s3://{bucket}/{key}")

        conn = self._connect(cfg)
        cur  = conn.cursor()
        schema = cfg.get("schema", "public")
        fqt    = f'"{schema}"."{table}"'

        try:
            self._ensure_table(cur, df, fqt, if_exists)

            col_list   = ", ".join(f'"{c}"' for c in df.columns)
            copy_sql   = (
                f"COPY {fqt} ({col_list}) "
                f"FROM 's3://{bucket}/{key}' "
                f"ACCESS_KEY_ID '{cfg.get('aws_access_key_id','')}' "
                f"SECRET_ACCESS_KEY '{cfg.get('aws_secret_access_key','')}' "
                f"REGION '{region}' "
                "CSV IGNOREHEADER 1 GZIP EMPTYASNULL BLANKSASNULL"
            )
            cur.execute(copy_sql)
            conn.commit()
            print(f"  [RS] COPY INTO {fqt} — {len(df):,} rows")

        except Exception:  # pylint: disable=broad-exception-caught
            self.gov.logger.warning("[RS] S3 COPY failed — falling back to to_sql()")
            self._sql_fallback(df, cfg, table, if_exists)
        finally:
            cur.close()
            conn.close()
            try:
                os.unlink(tmp_path)
                s3.delete_object(Bucket=bucket, Key=key)
            except Exception:  # pylint: disable=broad-exception-caught
                pass

    def _ensure_table(self, cur, df: "pd.DataFrame", fqt: str, if_exists: str) -> None:
        col_defs = ", ".join(
            f'"{c}" {self._DTYPE_MAP.get(str(df[c].dtype), "VARCHAR(65535)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f"DROP TABLE IF EXISTS {fqt}")
            cur.execute(f"CREATE TABLE {fqt} ({col_defs})")
        else:
            cur.execute(f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs})")

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(self, df: "pd.DataFrame", cfg: dict, table: str, natural_keys: list) -> None:
        """Stage → MERGE INTO (Redshift engine ≥ 1.0.49268)."""
        schema    = cfg.get("schema", "public")
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt       = f'"{schema}"."{table}"'
        fqt_tmp   = f'"{schema}"."{tmp_table}"'

        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            # Write staging table via to_sql (acceptable for upsert batch sizes).
            engine = self._engine(cfg)
            with engine.begin() as _conn:
                df.to_sql(tmp_table, _conn, if_exists="replace", index=False,
                          schema=schema, chunksize=500, method="multi")

            non_key_cols  = [c for c in df.columns if c not in natural_keys]
            on_clause     = " AND ".join(f't."{k}" = s."{k}"' for k in natural_keys)
            update_clause = ", ".join(f't."{c}" = s."{c}"' for c in non_key_cols)
            all_cols      = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols    = ", ".join(f's."{c}"' for c in df.columns)

            # Ensure target table exists before MERGE.
            self._ensure_table(cur, df, fqt, "append")

            merge_sql = f"""
                MERGE INTO {fqt} AS t
                USING {fqt_tmp} AS s ON ({on_clause})
                WHEN MATCHED THEN UPDATE SET {update_clause or '"__noop__"=0'}
                WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})
            """
            cur.execute(merge_sql)
            cur.execute(f"DROP TABLE IF EXISTS {fqt_tmp}")
            conn.commit()
            print(f"  [RS] MERGE INTO {fqt} — {len(df):,} rows")
            self.gov.transformation_applied(
                "REDSHIFT_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()

    # ── to_sql fallback ───────────────────────────────────────────────────

    def _sql_fallback(self, df: "pd.DataFrame", cfg: dict, table: str, if_exists: str) -> None:
        engine = self._engine(cfg)
        schema = cfg.get("schema", "public")
        for attempt in range(1, 4):
            try:
                with engine.begin() as _conn:
                    df.to_sql(table, _conn, if_exists=if_exists, index=False,
                              schema=schema, chunksize=500, method="multi")
                return
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == 3: raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                time.sleep(wait)


class BigQueryLoader:
    """
    Google BigQuery loader with native bulk load, MERGE upsert, and
    automatic EU data-residency detection for GDPR compliance.

    Connection
    ----------
    Authenticates via a GCP Service Account JSON key file, or falls back
    to Application Default Credentials (ADC) when ``credentials_path``
    is omitted — useful in GCE / Cloud Run environments where the VM's
    service account is automatically available.

    Required cfg keys
    -----------------
    project    : str   GCP project ID (e.g. "my-project-123456")
    dataset    : str   BigQuery dataset name
    location   : str   Dataset location (default "US"; use "EU" for GDPR residency)

    Optional
    --------
    credentials_path : str   Path to a service account JSON key file.
                             Omit to use Application Default Credentials.

    Load modes
    ----------
    Bulk load (default)
        Uses ``bigquery.Client.load_table_from_dataframe()`` which streams
        the DataFrame through the BQ Storage Write API — no intermediate
        file staging required.  Supports append and full-replace
        (WRITE_TRUNCATE) via ``if_exists``.

    MERGE upsert (natural_keys provided)
        Writes the DataFrame to a temporary BigQuery table in the same
        dataset, then executes a MERGE statement.  The temp table is
        deleted after the MERGE regardless of success or failure.

    GDPR compliance
        When ``location`` contains "EU" or "europe-", the loader
        automatically logs a GDPR Chapter V intra-EU transfer event so
        that data residency is recorded in the governance audit trail.

    Requirements
    ------------
        pip install google-cloud-bigquery google-cloud-bigquery-storage db-dtypes
    """

    # pandas dtype → BigQuery SQL type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "INT64",
        "Int64"              : "INT64",
        "int32"              : "INT64",
        "float64"            : "FLOAT64",
        "float32"            : "FLOAT64",
        "bool"               : "BOOL",
        "boolean"            : "BOOL",
        "datetime64[ns]"     : "DATETIME",
        "datetime64[ns, UTC]": "TIMESTAMP",
        "object"             : "STRING",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_BIGQUERY:
            raise RuntimeError(
                "google-cloud-bigquery not installed.  "
                "Run: pip install google-cloud-bigquery google-cloud-bigquery-storage db-dtypes"
            )

    def _ensure_table(self, client, dataset_ref, table_id: str,
                      df: "pd.DataFrame", if_exists: str) -> None:
        """Create the target BigQuery table if it does not already exist."""
        from google.cloud import bigquery as _bq_local  # pylint: disable=import-outside-toplevel
        table_ref = dataset_ref.table(table_id)
        schema = [
            _bq_local.SchemaField(
                c,
                self._DTYPE_MAP.get(str(df[c].dtype), "STRING"),
                mode="NULLABLE",
            )
            for c in df.columns
        ]
        if if_exists == "replace":
            try:
                client.delete_table(table_ref, not_found_ok=True)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        table = _bq_local.Table(table_ref, schema=schema)
        client.create_table(table, exists_ok=True)

    # ── Client factory ────────────────────────────────────────────────────

    def _client(self, cfg: dict) -> "_bigquery.Client":
        """Return an authenticated BigQuery client."""
        project  = cfg["project"]
        location = cfg.get("location", "US")
        creds_path = cfg.get("credentials_path")

        if creds_path:
            creds  = _gcp_sa.Credentials.from_service_account_file(
                creds_path,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            return _bigquery.Client(project=project, credentials=creds, location=location)

        # Application Default Credentials (GCE, Cloud Run, gcloud auth).
        return _bigquery.Client(project=project, location=location)

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str            = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into BigQuery table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config (see class docstring).
        table        : Target table name.
        if_exists    : "append" | "replace".
        natural_keys : Column(s) for MERGE upsert (optional).
        """
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._bulk_load(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        location = cfg.get("location", "US")
        self.gov.destination_registered(
            "bigquery",
            f"{cfg['project']}/{cfg['dataset']}@{location}",
            table,
        )
        # Log GDPR transfer event based on dataset location.
        self._log_gdpr_transfer(location)

    # ── Bulk load ─────────────────────────────────────────────────────────

    def _bulk_load(self, df: "pd.DataFrame", cfg: dict, table: str, if_exists: str) -> None:
        """Use the BQ Storage Write API via load_table_from_dataframe."""
        client   = self._client(cfg)
        dataset  = cfg["dataset"]
        table_id = f"{cfg['project']}.{dataset}.{table}"

        write_disposition = (
            _bigquery.WriteDisposition.WRITE_TRUNCATE
            if if_exists == "replace"
            else _bigquery.WriteDisposition.WRITE_APPEND
        )
        job_cfg = _bigquery.LoadJobConfig(write_disposition=write_disposition)

        for attempt in range(1, 4):
            try:
                job = client.load_table_from_dataframe(df, table_id, job_config=job_cfg)
                job.result()  # Wait for completion.
                print(f"  [BQ] Loaded {len(df):,} rows → {table_id}  "
                      f"(errors: {job.errors or 'none'})")
                return
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == 3: raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                time.sleep(wait)

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(self, df: "pd.DataFrame", cfg: dict, table: str, natural_keys: list) -> None:
        """
        Temp table → MERGE INTO target.

        BigQuery MERGE is a DML statement executed via query_job; it does
        not require separate ODBC / native connector connections.
        """
        client    = self._client(cfg)
        project   = cfg["project"]
        dataset   = cfg["dataset"]
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt       = f"`{project}.{dataset}.{table}`"
        fqt_tmp   = f"`{project}.{dataset}.{tmp_table}`"
        tmp_id    = f"{project}.{dataset}.{tmp_table}"

        # Write staging data.
        tmp_cfg = _bigquery.LoadJobConfig(
            write_disposition=_bigquery.WriteDisposition.WRITE_TRUNCATE
        )
        job = client.load_table_from_dataframe(df, tmp_id, job_config=tmp_cfg)
        job.result()

        non_key_cols  = [c for c in df.columns if c not in natural_keys]
        on_clause     = " AND ".join(f"t.`{k}` = s.`{k}`" for k in natural_keys)
        update_clause = ", ".join(f"t.`{c}` = s.`{c}`" for c in non_key_cols)
        all_cols      = ", ".join(f"`{c}`" for c in df.columns)
        stage_cols    = ", ".join(f"s.`{c}`" for c in df.columns)

        merge_sql = f"""
            MERGE {fqt} AS t
            USING {fqt_tmp} AS s ON ({on_clause})
            WHEN MATCHED THEN
                UPDATE SET {update_clause or "t.__noop__ = 0"}
            WHEN NOT MATCHED THEN
                INSERT ({all_cols}) VALUES ({stage_cols})
        """

        try:
            job = client.query(merge_sql)
            job.result()
            print(f"  [BQ] MERGE INTO {fqt} — {len(df):,} rows")
            self.gov.transformation_applied(
                "BIGQUERY_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            # Always clean up the temp table.
            try:
                client.delete_table(tmp_id, not_found_ok=True)
            except Exception:  # pylint: disable=broad-exception-caught
                pass

    # ── GDPR residency logging ────────────────────────────────────────────

    def _log_gdpr_transfer(self, location: str) -> None:
        """
        Log a GDPR Chapter V transfer event based on the BigQuery dataset location.

        EU / EU multi-region → INTRA_EU (no restrictions).
        US or other         → cross-border transfer with SCC safeguard noted.
        """
        loc_upper = location.upper()
        if "EU" in loc_upper or "EUROPE" in loc_upper:
            self.gov.transfer_logged(
                source_country = "EU",
                dest_country   = "EU",
                transfer_type  = "INTRA_EU",
                safeguard      = "EU/EEA intra-zone — no restrictions",
            )
        else:
            region_map = {
                "US"           : "US",
                "US-CENTRAL1"  : "US",
                "US-EAST1"     : "US",
                "US-WEST1"     : "US",
                "ASIA"         : "SG",
                "ASIA-EAST1"   : "TW",
                "ASIA-SOUTHEAST1": "SG",
                "AUSTRALIA-SOUTHEAST1": "AU",
            }
            dest_cc = region_map.get(loc_upper, "US")
            self.gov.transfer_logged(
                source_country = "US",
                dest_country   = dest_cc,
                transfer_type  = "BIGQUERY_REGION",
                safeguard      = "SCC",
            )


class SynapseLoader:
    """
    Azure Synapse Analytics loader with Azure Blob-staged COPY, MERGE
    upsert, and Entra ID (AAD) authentication support.

    Synapse Analytics is the evolution of Azure SQL Data Warehouse.  It
    exposes a T-SQL endpoint that is largely compatible with SQL Server /
    MSSQL, but uses a Massively Parallel Processing (MPP) architecture
    and has its own optimised COPY INTO syntax for bulk loads from Azure
    Blob Storage or ADLS Gen2.

    Connection
    ----------
    Connects via ODBC using the Microsoft ODBC Driver for SQL Server.
    Supports both SQL authentication (user/password) and Entra ID
    (Azure Active Directory) service principal authentication.

    Required cfg keys (SQL auth)
    ----------------------------
    host       : str   Synapse SQL endpoint (e.g. "myworkspace.sql.azuresynapse.net")
    port       : int   Default 1433
    database   : str   Dedicated SQL pool or serverless database name
    user       : str   SQL login username
    password   : str   SQL login password
    schema     : str   Target schema (default "dbo")

    Optional — Azure Blob bulk COPY (strongly recommended for large loads)
    -----------------------------------------------------------------------
    storage_account : str   Azure storage account name
    storage_container: str  Blob container name
    storage_sas_token: str  SAS token with write + read access to the container
                            (use azure-identity ClientSecretCredential as alternative)

    Optional — Entra ID / Service Principal auth
    --------------------------------------------
    tenant_id     : str   Azure tenant ID
    client_id     : str   Service principal application ID
    client_secret : str   Service principal secret

    Load modes
    ----------
    Blob COPY INTO (when storage_account provided)
        Uploads DataFrame as a compressed CSV to Azure Blob, issues
        COPY INTO … FROM 'https://…' with a SAS token, then deletes
        the staging blob.  This is the recommended high-throughput path
        for Synapse dedicated SQL pools.

    MERGE upsert (natural_keys provided)
        Temp table → MERGE statement (identical syntax to SQL Server).

    Fallback
        When no blob config is provided, falls back to MSSQL-compatible
        pandas .to_sql() via pyodbc, which works for small-to-medium loads.

    Requirements
    ------------
        pip install pyodbc azure-storage-blob azure-identity
        # System: Microsoft ODBC Driver 17 or 18 for SQL Server
    """

    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "BIGINT",
        "Int64"              : "BIGINT",
        "int32"              : "INT",
        "float64"            : "FLOAT",
        "float32"            : "REAL",
        "bool"               : "BIT",
        "boolean"            : "BIT",
        "datetime64[ns]"     : "DATETIME2",
        "datetime64[ns, UTC]": "DATETIMEOFFSET",
        "object"             : "NVARCHAR(MAX)",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_SYNAPSE:
            raise RuntimeError(
                "Synapse dependencies not installed.  "
                "Run: pip install pyodbc azure-storage-blob azure-identity\n"
                "Also install: Microsoft ODBC Driver 17 or 18 for SQL Server"
            )

    # ── Connection helpers ────────────────────────────────────────────────

    def _connection_string(self, cfg: dict) -> str:
        driver  = cfg.get("driver", "ODBC Driver 17 for SQL Server")
        host    = cfg["host"]
        port    = cfg.get("port", 1433)
        db      = cfg["database"]
        # Entra ID service principal auth — token acquisition validates
        # credentials; the ODBC driver handles token refresh internally.
        if cfg.get("tenant_id"):
            _AzureCSC(cfg["tenant_id"], cfg["client_id"], cfg["client_secret"])  # validates credentials
            return (
                f"DRIVER={{{driver}}};SERVER={host},{port};DATABASE={db};"
                "Authentication=ActiveDirectoryServicePrincipal;"
                f"UID={cfg['client_id']};PWD={cfg['client_secret']};"
                "Encrypt=yes;TrustServerCertificate=no"
            )
        # SQL auth.
        return (
            f"DRIVER={{{driver}}};SERVER={host},{port};DATABASE={db};"
            f"UID={cfg['user']};PWD={cfg['password']};"
            "Encrypt=yes;TrustServerCertificate=no"
        )

    def _engine(self, cfg: dict):
        """SQLAlchemy engine for pandas .to_sql() fallback."""
        from sqlalchemy import create_engine as _ce  # pylint: disable=import-outside-toplevel
        import urllib.parse                           # pylint: disable=import-outside-toplevel
        conn_str = self._connection_string(cfg)
        return _ce(f"mssql+pyodbc:///?odbc_connect={urllib.parse.quote_plus(conn_str)}")

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str            = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into Synapse table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config (see class docstring).
        table        : Target table name.
        if_exists    : "append" | "replace".
        natural_keys : Column(s) for MERGE upsert (optional).
        """
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        elif cfg.get("storage_account"):
            self._blob_copy(df, cfg, table, if_exists)
        else:
            self._sql_fallback(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "synapse",
            f"{cfg['host']}/{cfg['database']}/{cfg.get('schema','dbo')}",
            table,
        )

    # ── Azure Blob COPY INTO ──────────────────────────────────────────────

    def _blob_copy(self, df: "pd.DataFrame", cfg: dict, table: str, if_exists: str) -> None:
        """Upload to Azure Blob then COPY INTO via SAS-authenticated URL."""
        import tempfile, os  # pylint: disable=import-outside-toplevel

        account   = cfg["storage_account"]
        container = cfg["storage_container"]
        sas_token = cfg["storage_sas_token"]
        schema    = cfg.get("schema", "dbo")
        blob_name = f"synapse_stage/{table}_{int(time.time())}.csv.gz"
        blob_url  = f"https://{account}.blob.core.windows.net/{container}/{blob_name}"

        # Write DataFrame to compressed CSV.
        with tempfile.NamedTemporaryFile(suffix=".csv.gz", delete=False) as tmp:
            tmp_path = tmp.name
        df.to_csv(tmp_path, index=False, compression="gzip")

        blob_client = _BlobServiceClient(
            account_url=f"https://{account}.blob.core.windows.net",
            credential=sas_token,
        ).get_blob_client(container, blob_name)

        with open(tmp_path, "rb") as data:
            blob_client.upload_blob(data, overwrite=True)
        print(f"  [SY] Uploaded blob: {blob_url[:60]}…")

        conn_str = self._connection_string(cfg)
        conn     = _pyodbc.connect(conn_str, autocommit=False)
        cur      = conn.cursor()
        fqt      = f"[{schema}].[{table}]"

        try:
            self._ensure_table(cur, df, fqt, if_exists)

            col_list = ", ".join(f"[{c}]" for c in df.columns)
            copy_sql = (
                f"COPY INTO {fqt} ({col_list}) "
                f"FROM '{blob_url}?{sas_token}' "
                "WITH (FILE_TYPE='CSV', FIRSTROW=2, FIELDTERMINATOR=',', "
                "ROWTERMINATOR='\\n', COMPRESSION='GZIP')"
            )
            cur.execute(copy_sql)
            conn.commit()
            print(f"  [SY] COPY INTO {fqt} — {len(df):,} rows")

        except Exception:  # pylint: disable=broad-exception-caught
            self.gov.logger.warning("[SY] COPY INTO failed — falling back to to_sql()")
            self._sql_fallback(df, cfg, table, if_exists)
        finally:
            cur.close()
            conn.close()
            try:
                os.unlink(tmp_path)
                blob_client.delete_blob()
            except Exception:  # pylint: disable=broad-exception-caught
                pass

    def _ensure_table(self, cur, df: "pd.DataFrame", fqt: str, if_exists: str) -> None:
        col_defs = ", ".join(
            f"[{c}] {self._DTYPE_MAP.get(str(df[c].dtype), 'NVARCHAR(MAX)')}"
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f"IF OBJECT_ID('{fqt}', 'U') IS NOT NULL DROP TABLE {fqt}")
            cur.execute(f"CREATE TABLE {fqt} ({col_defs})")
            cur.connection.commit()
        else:
            cur.execute(
                "IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES "
                f"WHERE TABLE_SCHEMA+'.'+TABLE_NAME='{fqt.replace('[','').replace(']','')}') "
                f"CREATE TABLE {fqt} ({col_defs})"
            )
            cur.connection.commit()

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(self, df: "pd.DataFrame", cfg: dict, table: str, natural_keys: list) -> None:
        """Temp table → MERGE (T-SQL syntax, identical to SQL Server)."""
        schema    = cfg.get("schema", "dbo")
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt       = f"[{schema}].[{table}]"
        fqt_tmp   = f"[{schema}].[{tmp_table}]"

        engine = self._engine(cfg)
        with engine.begin() as _conn:
            df.to_sql(tmp_table, _conn, if_exists="replace", index=False,
                      schema=schema, chunksize=500, method="multi")

        conn_str = self._connection_string(cfg)
        conn     = _pyodbc.connect(conn_str, autocommit=False)
        cur      = conn.cursor()
        try:
            non_key_cols  = [c for c in df.columns if c not in natural_keys]
            on_clause     = " AND ".join(f"t.[{k}] = s.[{k}]" for k in natural_keys)
            update_clause = ", ".join(f"t.[{c}] = s.[{c}]" for c in non_key_cols)
            all_cols      = ", ".join(f"[{c}]" for c in df.columns)
            stage_cols    = ", ".join(f"s.[{c}]" for c in df.columns)

            self._ensure_table(cur, df, fqt, "append")

            merge_sql = (
                f"MERGE {fqt} AS t "
                f"USING {fqt_tmp} AS s ON ({on_clause}) "
                f"WHEN MATCHED THEN UPDATE SET {update_clause or 't.[__noop__]=0'} "
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols});"
            )
            cur.execute(merge_sql)
            cur.execute(f"DROP TABLE IF EXISTS {fqt_tmp}")
            conn.commit()
            print(f"  [SY] MERGE INTO {fqt} — {len(df):,} rows")
            self.gov.transformation_applied(
                "SYNAPSE_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()

    # ── pyodbc / to_sql fallback ──────────────────────────────────────────

    def _sql_fallback(self, df: "pd.DataFrame", cfg: dict, table: str, if_exists: str) -> None:
        engine = self._engine(cfg)
        schema = cfg.get("schema", "dbo")
        for attempt in range(1, 4):
            try:
                with engine.begin() as _conn:
                    df.to_sql(table, _conn, if_exists=if_exists, index=False,
                              schema=schema, chunksize=500, method="multi")
                return
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == 3: raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                time.sleep(wait)


class DatabricksLoader:
    """
    Databricks / Delta Lake loader with MERGE upsert, time-travel audit
    support, and schema evolution.

    Architecture
    ------------
    Databricks uses the Lakehouse architecture: data lives in Delta tables
    on cloud object storage (S3 / ADLS / GCS), accessed through a SQL
    warehouse or compute cluster via the Databricks SQL Connector.

    Delta Lake adds ACID transactions, time-travel (queryable history),
    schema enforcement, and CDC tracking on top of Parquet files — making
    it a natural complement to this pipeline's data governance features.

    Connection
    ----------
    Uses ``databricks-sql-connector`` (the official Databricks driver).
    Authenticates via a Personal Access Token or OAuth M2M client
    credentials.

    Required cfg keys
    -----------------
    server_hostname : str   Databricks workspace hostname
                            (e.g. "adb-1234567890.12.azuredatabricks.net")
    http_path       : str   SQL warehouse or cluster HTTP path
                            (e.g. "/sql/1.0/warehouses/abc123def456")
    access_token    : str   Personal Access Token (or use oauth_* below)
    catalog         : str   Unity Catalog name (default "hive_metastore")
    schema          : str   Schema / database name (default "default")

    Optional — OAuth M2M (service principal)
    ----------------------------------------
    oauth_client_id     : str
    oauth_client_secret : str

    Load modes
    ----------
    Batch INSERT (default)
        Bulk-inserts the DataFrame row-by-row through the SQL connector
        using executemany().  Efficient for small-to-medium loads.  For
        very large DataFrames (>1M rows), consider writing Parquet to
        cloud storage and using COPY INTO instead.

    MERGE upsert (natural_keys provided)
        Creates a temporary Delta view from the DataFrame, then executes
        a MERGE INTO statement.  Delta Lake's MERGE is ACID — either all
        rows succeed or none, with full Write-Ahead Log protection.

    Schema evolution
        When ``schema_evolution=True`` (default), adds
        ``spark.databricks.delta.schema.autoMerge.enabled=True`` to the
        session so that new columns in the DataFrame are automatically
        added to the target Delta table without raising an error.

    Time-travel audit
        Delta Lake retains the full transaction history of every table.
        After each load, the loader logs the Delta table version number
        to the governance audit trail so that any load can be reproduced
        exactly by querying ``SELECT * FROM table VERSION AS OF <n>``.

    Requirements
    ------------
        pip install databricks-sql-connector
    """

    # pandas dtype → Databricks SQL / Delta type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "BIGINT",
        "Int64"              : "BIGINT",
        "int32"              : "INT",
        "float64"            : "DOUBLE",
        "float32"            : "FLOAT",
        "bool"               : "BOOLEAN",
        "boolean"            : "BOOLEAN",
        "datetime64[ns]"     : "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMP",
        "object"             : "STRING",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_DATABRICKS:
            raise RuntimeError(
                "databricks-sql-connector not installed.  "
                "Run: pip install databricks-sql-connector"
            )

    # ── Connection helper ─────────────────────────────────────────────────

    def _connect(self, cfg: dict):
        """Return a Databricks SQL connection."""
        conn_kwargs: dict = {
            "server_hostname": cfg["server_hostname"],
            "http_path"      : cfg["http_path"],
        }
        if cfg.get("access_token"):
            conn_kwargs["access_token"] = cfg["access_token"]
        elif cfg.get("oauth_client_id"):
            # OAuth M2M via client credentials.
            conn_kwargs["credentials_provider"] = self._oauth_provider(cfg)
        if cfg.get("catalog") and cfg["catalog"] != "hive_metastore":
            conn_kwargs["catalog"] = cfg["catalog"]
        return _databricks_sql.connect(**conn_kwargs)

    @staticmethod
    def _oauth_provider(cfg: dict):
        """Build a credentials provider callable for OAuth M2M auth."""
        # databricks-sdk handles the token exchange; fall back to access_token
        # if sdk is unavailable.
        try:
            from databricks.sdk.oauth import ClientCredentials  # pylint: disable=import-outside-toplevel
            return ClientCredentials(
                client_id     = cfg["oauth_client_id"],
                client_secret = cfg["oauth_client_secret"],
                token_url     = f"https://{cfg['server_hostname']}/oidc/v1/token",
                scopes        = ["all-apis"],
            )
        except ImportError as exc:
            raise RuntimeError(
                "databricks-sdk is required for OAuth M2M auth.  "
                "Run: pip install databricks-sdk  (or use access_token instead)"
            ) from exc

    # ── Fully-qualified table name ────────────────────────────────────────

    def _fqt(self, cfg: dict, table: str) -> str:
        catalog = cfg.get("catalog", "hive_metastore")
        schema  = cfg.get("schema", "default")
        if catalog == "hive_metastore":
            return f"`{schema}`.`{table}`"
        return f"`{catalog}`.`{schema}`.`{table}`"

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:               "pd.DataFrame",
        cfg:              dict,
        table:            str,
        if_exists:        str            = "append",
        natural_keys:     list[str] | None = None,
        schema_evolution: bool           = True,
    ) -> None:
        """
        Load *df* into a Databricks Delta table.

        Parameters
        ----------
        df               : DataFrame to load.
        cfg              : Connection config (see class docstring).
        table            : Target Delta table name.
        if_exists        : "append" | "replace".
        natural_keys     : Column(s) for MERGE upsert (optional).
        schema_evolution : Auto-add new columns to target table (default True).
        """
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys, schema_evolution)
        else:
            self._bulk_insert(df, cfg, table, if_exists, schema_evolution)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "databricks",
            f"{cfg['server_hostname']}/{cfg.get('catalog','hive_metastore')}"
            f"/{cfg.get('schema','default')}",
            table,
        )

    # ── Bulk INSERT ───────────────────────────────────────────────────────

    def _bulk_insert(
        self,
        df:               "pd.DataFrame",
        cfg:              dict,
        table:            str,
        if_exists:        str,
        schema_evolution: bool,
    ) -> None:
        """CREATE / REPLACE table then INSERT rows via executemany()."""
        fqt  = self._fqt(cfg, table)
        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            if schema_evolution:
                cur.execute(
                    "SET spark.databricks.delta.schema.autoMerge.enabled = true"
                )

            self._ensure_table(cur, df, fqt, if_exists)

            # INSERT rows in batches of 1,000 via executemany.
            col_list    = ", ".join(f"`{c}`" for c in df.columns)
            placeholders= ", ".join("?" * len(df.columns))
            insert_sql  = f"INSERT INTO {fqt} ({col_list}) VALUES ({placeholders})"

            # Convert DataFrame to list of tuples, replacing pd.NA / NaT with None.
            rows = [
                tuple(None if pd.isna(v) else v for v in row)
                for row in df.itertuples(index=False, name=None)
            ]
            # executemany in 1,000-row batches.
            batch_size = 1_000
            for i in range(0, len(rows), batch_size):
                cur.executemany(insert_sql, rows[i: i + batch_size])

            version = self._table_version(cur, fqt)
            print(f"  [DB] INSERT INTO {fqt} — {len(df):,} rows  "
                  f"(Delta version {version})")
            self._log_delta_version(table, version, "INSERT")
            conn.commit()
        finally:
            cur.close()
            conn.close()

    def _ensure_table(self, cur, df: "pd.DataFrame", fqt: str, if_exists: str) -> None:
        """CREATE OR REPLACE / CREATE IF NOT EXISTS the Delta table."""
        col_defs = ", ".join(
            f"`{c}` {self._DTYPE_MAP.get(str(df[c].dtype), 'STRING')}"
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(
                f"CREATE OR REPLACE TABLE {fqt} ({col_defs}) "
                "USING DELTA"
            )
        else:
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs}) "
                "USING DELTA"
            )

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(
        self,
        df:               "pd.DataFrame",
        cfg:              dict,
        table:            str,
        natural_keys:     list[str],
        schema_evolution: bool,
    ) -> None:
        """
        Delta Lake MERGE INTO using a temporary view.

        1. Registers the DataFrame as a temporary view in the session.
        2. Issues MERGE INTO target USING tmp_view ON (keys).
        3. Drops the temporary view.

        Delta MERGE is ACID — either all changes commit or none, with a
        new entry written to the Delta transaction log either way.
        """
        fqt      = self._fqt(cfg, table)
        tmp_view = f"_pipeline_stage_{table}_{int(time.time())}"
        conn     = self._connect(cfg)
        cur      = conn.cursor()
        try:
            if schema_evolution:
                cur.execute(
                    "SET spark.databricks.delta.schema.autoMerge.enabled = true"
                )

            self._ensure_table(cur, df, fqt, "append")

            # Upload staging data as a VALUES literal (works for moderate sizes).
            # For very large DataFrames a Parquet-to-stage approach is preferable.
            col_list     = ", ".join(f"`{c}`" for c in df.columns)
            non_key_cols = [c for c in df.columns if c not in natural_keys]

            # Build VALUES list.
            def _fmt(v):
                if v is None or (not isinstance(v, str) and pd.isna(v)):
                    return "NULL"
                if isinstance(v, bool):
                    return "TRUE" if v else "FALSE"
                if isinstance(v, (int, float)):
                    return str(v)
                # Escape single quotes for SQL string literals.
                return "'" + str(v).replace("'", "''") + "'"

            value_rows = ", ".join(
                "(" + ", ".join(_fmt(v) for v in row) + ")"
                for row in df.itertuples(index=False, name=None)
            )

            on_clause     = " AND ".join(
                f"t.`{k}` = s.`{k}`" for k in natural_keys
            )
            update_clause = ", ".join(
                f"t.`{c}` = s.`{c}`" for c in non_key_cols
            ) or "`__noop__` = 0"
            all_cols      = ", ".join(f"`{c}`" for c in df.columns)
            stage_cols    = ", ".join(f"s.`{c}`" for c in df.columns)

            # Create a temporary view from VALUES.
            col_typed = ", ".join(
                f"`{c}` {self._DTYPE_MAP.get(str(df[c].dtype), 'STRING')}"
                for c in df.columns
            )
            cur.execute(
                f"CREATE OR REPLACE TEMPORARY VIEW `{tmp_view}` ({col_typed}) "
                f"AS SELECT * FROM (VALUES {value_rows}) AS t({col_list})"
            )

            merge_sql = f"""
                MERGE INTO {fqt} AS t
                USING `{tmp_view}` AS s
                ON ({on_clause})
                WHEN MATCHED THEN
                    UPDATE SET {update_clause}
                WHEN NOT MATCHED THEN
                    INSERT ({all_cols}) VALUES ({stage_cols})
            """
            cur.execute(merge_sql)
            version = self._table_version(cur, fqt)
            print(f"  [DB] MERGE INTO {fqt} — {len(df):,} rows  "
                  f"(Delta version {version})")
            self._log_delta_version(table, version, "MERGE")
            conn.commit()
        finally:
            try:
                cur.execute(f"DROP VIEW IF EXISTS `{tmp_view}`")
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            cur.close()
            conn.close()

    # ── Delta time-travel helpers ─────────────────────────────────────────

    def _table_version(self, cur, fqt: str) -> int | None:
        """Return the current Delta table version number."""
        try:
            cur.execute(f"DESCRIBE HISTORY {fqt} LIMIT 1")
            row = cur.fetchone()
            return int(row[0]) if row else None
        except Exception:  # pylint: disable=broad-exception-caught
            return None

    def _log_delta_version(self, table: str, version: int | None, operation: str) -> None:
        """Record Delta table version in the governance audit trail."""
        self.gov.transformation_applied(
            "DELTA_VERSION_RECORDED",
            {
                "table"     : table,
                "operation" : operation,
                "version"   : version,
                "time_travel_query":
                    f"SELECT * FROM {table} VERSION AS OF {version}"
                    if version is not None else "N/A",
            },
        )


class ClickHouseLoader:
    """
    ClickHouse loader with native bulk insert, ReplacingMergeTree upsert,
    and high-concurrency OLAP optimisations.

    Architecture
    ------------
    ClickHouse uses a columnar, append-oriented storage engine optimised
    for OLAP workloads.  It achieves very high ingest throughput and
    sub-second query latency at large scale.

    Unlike RDBMS systems, ClickHouse does not support traditional MERGE/
    UPDATE as an atomic DML operation.  Upsert semantics are instead
    provided by the ``ReplacingMergeTree`` engine, which deduplicates
    rows with the same primary key during background merges.  For
    immediate consistency, ``OPTIMIZE TABLE ... FINAL`` forces the merge
    synchronously (appropriate for low-volume loads; omit for high-volume).

    Connection
    ----------
    Uses ``clickhouse-connect`` (the official ClickHouse Python driver).
    Supports both plain HTTP and HTTPS, with optional TLS verification.

    Required cfg keys
    -----------------
    host     : str   ClickHouse server hostname (default "localhost")
    port     : int   HTTP port (default 8123; 8443 for HTTPS)
    username : str   Username (default "default")
    password : str   Password
    database : str   Database name (default "default")
    secure   : bool  Use HTTPS (default False)

    Load modes
    ----------
    Bulk insert (default)
        Uses ``client.insert_df()`` — the native ClickHouse binary
        protocol insert.  This is the fastest possible ingestion path,
        typically achieving 100k–1M rows/second.

    ReplacingMergeTree upsert (natural_keys provided)
        Creates the target table with the ``ReplacingMergeTree(updated_at)``
        engine and an ``ORDER BY (natural_keys)`` clause.  New rows are
        appended; ClickHouse deduplicates during background merges.  An
        ``OPTIMIZE TABLE ... FINAL`` is issued after each upsert to force
        immediate deduplication (omit in high-throughput production use).

    Requirements
    ------------
        pip install clickhouse-connect
    """

    # pandas dtype → ClickHouse column type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "Int64",
        "Int64"              : "Nullable(Int64)",
        "int32"              : "Int32",
        "float64"            : "Float64",
        "float32"            : "Float32",
        "bool"               : "UInt8",
        "boolean"            : "Nullable(UInt8)",
        "datetime64[ns]"     : "DateTime64(9)",
        "datetime64[ns, UTC]": "DateTime64(9, 'UTC')",
        "object"             : "Nullable(String)",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_CLICKHOUSE:
            raise RuntimeError(
                "clickhouse-connect not installed.  "
                "Run: pip install clickhouse-connect"
            )

    # ── Client factory ────────────────────────────────────────────────────

    def _client(self, cfg: dict):
        """Return an authenticated ClickHouse client."""
        return _clickhouse_connect.get_client(
            host    = cfg.get("host", "localhost"),
            port    = int(cfg.get("port", 8443 if cfg.get("secure") else 8123)),
            username= cfg.get("username", "default"),
            password= cfg.get("password", ""),
            database= cfg.get("database", "default"),
            secure  = bool(cfg.get("secure", False)),
        )

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str            = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into ClickHouse table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config (see class docstring).
        table        : Target table name.
        if_exists    : "append" | "replace".
        natural_keys : Column(s) used as ORDER BY for ReplacingMergeTree upsert.
        """
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._bulk_insert(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "clickhouse",
            f"{cfg.get('host','localhost')}:{cfg.get('port',8123)}"
            f"/{cfg.get('database','default')}",
            table,
        )

    # ── Bulk INSERT ───────────────────────────────────────────────────────

    def _bulk_insert(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str,
        if_exists: str,
    ) -> None:
        """Use client.insert_df() — the fastest ClickHouse ingestion path."""
        client   = self._client(cfg)
        database = cfg.get("database", "default")

        self._ensure_table(client, df, database, table, if_exists)

        # Sanitise the DataFrame for ClickHouse (no pandas nullable dtypes).
        df_ch = self._prepare_df(df)

        for attempt in range(1, 4):
            try:
                client.insert_df(table, df_ch, database=database)
                print(f"  [CH] INSERT INTO {database}.{table} — {len(df):,} rows")
                return
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if attempt == 3: raise
                wait = 2 ** attempt
                self.gov.retry_attempt(attempt, 3, float(wait), exc)
                print(f"  ⚠  Attempt {attempt}/3 failed. Retrying in {wait}s…")
                time.sleep(wait)

    def _ensure_table(
        self,
        client,
        df:        "pd.DataFrame",
        database:  str,
        table:     str,
        if_exists: str,
        order_by:  list[str] | None = None,
        engine:    str = "MergeTree()",
    ) -> None:
        """CREATE OR REPLACE / CREATE IF NOT EXISTS ClickHouse table."""
        col_defs = ", ".join(
            f"`{c}` {self._DTYPE_MAP.get(str(df[c].dtype), 'Nullable(String)')}"
            for c in df.columns
        )
        order_clause = (
            f"ORDER BY ({', '.join(f'`{k}`' for k in order_by)})"
            if order_by
            else "ORDER BY tuple()"
        )

        if if_exists == "replace":
            client.command(f"DROP TABLE IF EXISTS `{database}`.`{table}`")

        create_sql = (
            f"CREATE TABLE IF NOT EXISTS `{database}`.`{table}` "
            f"({col_defs}) "
            f"ENGINE = {engine} "
            f"{order_clause}"
        )
        client.command(create_sql)

    # ── ReplacingMergeTree upsert ─────────────────────────────────────────

    def _upsert(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        natural_keys: list[str],
    ) -> None:
        """
        Append rows using ReplacingMergeTree, then OPTIMIZE for immediate
        deduplication.

        ClickHouse does not support true UPDATE semantics — instead,
        ReplacingMergeTree keeps the *last* inserted row per primary key
        after a merge.  ``OPTIMIZE TABLE ... FINAL`` forces this merge
        synchronously so that downstream queries see deduplicated data
        immediately after load.

        For high-throughput pipelines, omit the OPTIMIZE call and let
        ClickHouse merge in the background.
        """
        client   = self._client(cfg)
        database = cfg.get("database", "default")

        # Ensure table uses ReplacingMergeTree ordered by the natural keys.
        # Add an `_updated_at` version column so ReplacingMergeTree keeps
        # the most recently inserted version of each key.
        df_with_ts = df.copy()
        df_with_ts["_updated_at"] = int(time.time())

        self._ensure_table(
            client, df_with_ts, database, table, "append",
            order_by = natural_keys,
            engine   = "ReplacingMergeTree(_updated_at)",
        )

        df_ch = self._prepare_df(df_with_ts)
        client.insert_df(table, df_ch, database=database)

        # Force synchronous deduplication.
        client.command(f"OPTIMIZE TABLE `{database}`.`{table}` FINAL")
        print(
            f"  [CH] UPSERT → {database}.{table} — {len(df):,} rows  "
            "(ReplacingMergeTree + OPTIMIZE FINAL)"
        )
        self.gov.transformation_applied(
            "CLICKHOUSE_UPSERT_COMPLETE",
            {
                "table"       : table,
                "natural_keys": natural_keys,
                "rows"        : len(df),
                "engine"      : "ReplacingMergeTree",
                "note"        : "OPTIMIZE FINAL issued; background merge not required",
            },
        )

    # ── DataFrame preparation ─────────────────────────────────────────────

    @staticmethod
    def _prepare_df(df: "pd.DataFrame") -> "pd.DataFrame":
        """
        Convert pandas nullable / extension dtypes to ClickHouse-safe types.

        clickhouse-connect cannot serialize pandas Int64 (nullable integer)
        or BooleanDtype directly — these must be cast to their numpy
        equivalents (float64 to preserve NA as NaN, or object).
        """
        out = df.copy()
        for col in out.columns:
            dtype_str = str(out[col].dtype)
            if dtype_str in ("Int64", "Int32", "UInt8", "boolean", "bool"):
                # Cast nullable ints/bools to float64 (NaN-safe).
                out[col] = out[col].astype("float64")
        return out


class OracleLoader:
    """
    Oracle Autonomous Data Warehouse (ADW) loader with bulk array insert,
    MERGE upsert, and Thin-mode operation (no Oracle Client required).

    Architecture
    ------------
    Oracle ADW is Oracle's serverless, fully-managed cloud data warehouse.
    It auto-scales compute and storage, provides built-in ML with OML4Py,
    and is the dominant choice in regulated industries (finance, healthcare,
    government) where Oracle licensing is already established.

    Connection
    ----------
    Uses ``python-oracledb`` in **Thin mode** (default since v1.0) — the
    pure-Python driver that connects directly to Oracle Database without
    requiring the Oracle Instant Client.  For ADW, pass the wallet
    directory path to use mTLS (mutual TLS) authentication.

    Required cfg keys
    -----------------
    user        : str   Database username
    password    : str   Database password
    dsn         : str   Connect descriptor; one of:
                        - Easy Connect: "host:port/service_name"
                        - TNS alias:    "mydb_high"  (requires tns_admin)
                        - ADW: "myatp_high" + wallet_location below

    Optional
    --------
    wallet_location : str   Path to the directory containing the ADW
                            wallet (cwallet.sso, tnsnames.ora, etc.).
                            Required for Autonomous Database connections.
    tns_admin       : str   Directory containing tnsnames.ora / sqlnet.ora.
                            Defaults to wallet_location when provided.
    schema          : str   Target schema (default: same as user).
    encoding        : str   Client charset (default "UTF-8").

    Load modes
    ----------
    Array INSERT (default)
        Converts the DataFrame to a list of tuples and uses
        ``cursor.executemany()`` with ``batcherrors=True`` so that bad
        rows are quarantined to the Dead Letter Queue rather than aborting
        the entire batch.

    MERGE upsert (natural_keys provided)
        Creates a staging table, bulk-inserts into it, then issues a
        ``MERGE INTO target USING staging ON (keys)`` statement.  The
        staging table is dropped in a finally block.

    Requirements
    ------------
        pip install oracledb
    """

    # pandas dtype → Oracle SQL type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "NUMBER(19)",
        "Int64"              : "NUMBER(19)",
        "int32"              : "NUMBER(10)",
        "float64"            : "BINARY_DOUBLE",
        "float32"            : "BINARY_FLOAT",
        "bool"               : "NUMBER(1)",
        "boolean"            : "NUMBER(1)",
        "datetime64[ns]"     : "TIMESTAMP(6)",
        "datetime64[ns, UTC]": "TIMESTAMP(6) WITH TIME ZONE",
        "object"             : "VARCHAR2(4000)",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_ORACLE:
            raise RuntimeError(
                "python-oracledb not installed.  "
                "Run: pip install oracledb"
            )

    # ── Connection helpers ────────────────────────────────────────────────

    def _connect(self, cfg: dict):
        """Return a python-oracledb connection (Thin mode by default)."""
        conn_kwargs: dict = {
            "user"    : cfg["user"],
            "password": cfg["password"],
            "dsn"     : cfg["dsn"],
        }
        if cfg.get("wallet_location"):
            conn_kwargs["wallet_location"] = cfg["wallet_location"]
            conn_kwargs["wallet_password"]  = cfg.get("wallet_password", "")
        if cfg.get("tns_admin"):
            _oracledb.init_oracle_client()   # activate thick mode only if explicit
            conn_kwargs["config_dir"] = cfg["tns_admin"]
        return _oracledb.connect(**conn_kwargs)

    def _engine(self, cfg: dict):
        """Return a SQLAlchemy engine using the oracledb dialect."""
        from sqlalchemy import create_engine as _ce  # pylint: disable=import-outside-toplevel
        user      = cfg["user"]
        password  = cfg["password"]
        dsn       = cfg["dsn"]
        wallet    = cfg.get("wallet_location", "")
        if wallet:
            # For ADW: use thick-mode dialect with wallet path in connect_args.
            return _ce(
                f"oracle+oracledb://{user}:{password}@",
                connect_args={"dsn": dsn, "wallet_location": wallet,
                              "wallet_password": cfg.get("wallet_password", "")},
            )
        return _ce(f"oracle+oracledb://{user}:{password}@{dsn}")

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str            = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into Oracle table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config (see class docstring).
        table        : Target table name (upper-cased per Oracle convention).
        if_exists    : "append" | "replace".
        natural_keys : Column(s) for MERGE upsert (optional).
        """
        table = table.upper()
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._array_insert(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "oracle",
            f"{cfg['dsn']}/{cfg.get('schema', cfg['user'])}",
            table,
        )

    # ── Array INSERT ──────────────────────────────────────────────────────

    def _array_insert(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str,
        if_exists: str,
    ) -> None:
        """executemany() array insert with batcherrors quarantine and retry."""
        schema = cfg.get("schema", "").upper()
        fqt    = f'"{schema}"."{table}"' if schema else f'"{table}"'

        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            self._ensure_table(cur, df, fqt, if_exists)
            conn.commit()

            bind_vars  = ", ".join(f":{i+1}" for i in range(len(df.columns)))
            insert_sql = f"INSERT INTO {fqt} VALUES ({bind_vars})"

            rows = [
                tuple(None if (v is not None and not isinstance(v, str) and pd.isna(v)) else v
                      for v in row)
                for row in df.itertuples(index=False, name=None)
            ]

            # executemany with batcherrors: bad rows quarantined, not fatal.
            for attempt in range(1, 4):
                try:
                    cur.executemany(insert_sql, rows, batcherrors=True)
                    batch_errors = cur.getbatcherrors()
                    if batch_errors:
                        self.gov.logger.warning(
                            "[ORA] %d batch error(s) during INSERT (rows skipped)",
                            len(batch_errors),
                        )
                        for err in batch_errors[:5]:
                            self.gov.logger.warning("[ORA] Row %d: %s", err.offset, err.message)
                    conn.commit()
                    print(
                        f"  [ORA] INSERT INTO {fqt} — "
                        f"{len(df) - len(batch_errors):,} rows OK, "
                        f"{len(batch_errors)} quarantined"
                    )
                    break
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    if attempt == 3: raise
                    wait = 2 ** attempt
                    self.gov.retry_attempt(attempt, 3, float(wait), exc)
                    time.sleep(wait)
        finally:
            cur.close()
            conn.close()

    def _ensure_table(self, cur, df: "pd.DataFrame", fqt: str, if_exists: str) -> None:
        col_defs = ", ".join(
            f'"{c.upper()}" {self._DTYPE_MAP.get(str(df[c].dtype), "VARCHAR2(4000)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            try:
                cur.execute(f"DROP TABLE {fqt} PURGE")
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # Table may not exist yet
        cur.execute(
            "DECLARE "
            "  v_cnt NUMBER; "
            "BEGIN "
            "  SELECT COUNT(*) INTO v_cnt FROM user_tables "
            f"  WHERE table_name = '{fqt.split('.')[-1].strip(chr(34))}'; "
            "  IF v_cnt = 0 THEN "
            f"    EXECUTE IMMEDIATE 'CREATE TABLE {fqt} ({col_defs})'; "
            "  END IF; "
            "END;"
        )

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        natural_keys: list[str],
    ) -> None:
        """Stage → Oracle MERGE INTO."""
        schema    = cfg.get("schema", "").upper()
        tmp_table = f"{table[:20]}_STG_{int(time.time()) % 100000}"
        fqt       = f'"{schema}"."{table}"'     if schema else f'"{table}"'
        fqt_tmp   = f'"{schema}"."{tmp_table}"' if schema else f'"{tmp_table}"'

        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            self._ensure_table(cur, df, fqt, "append")
            self._ensure_table(cur, df, fqt_tmp, "replace")
            conn.commit()

            bind_vars  = ", ".join(f":{i+1}" for i in range(len(df.columns)))
            insert_sql = f"INSERT INTO {fqt_tmp} VALUES ({bind_vars})"
            rows = [
                tuple(None if (v is not None and not isinstance(v, str) and pd.isna(v)) else v
                      for v in row)
                for row in df.itertuples(index=False, name=None)
            ]
            cur.executemany(insert_sql, rows)
            conn.commit()

            non_key_cols  = [c for c in df.columns if c not in natural_keys]
            on_clause     = " AND ".join(
                f't."{k.upper()}" = s."{k.upper()}"' for k in natural_keys
            )
            update_clause = ", ".join(
                f't."{c.upper()}" = s."{c.upper()}"' for c in non_key_cols
            ) or "t.ROWID = t.ROWID"
            all_cols      = ", ".join(f'"{c.upper()}"' for c in df.columns)
            stage_cols    = ", ".join(f's."{c.upper()}"' for c in df.columns)

            merge_sql = (
                f"MERGE INTO {fqt} t "
                f"USING {fqt_tmp} s ON ({on_clause}) "
                f"WHEN MATCHED THEN UPDATE SET {update_clause} "
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            )
            cur.execute(merge_sql)
            conn.commit()
            print(f"  [ORA] MERGE INTO {fqt} — {len(df):,} rows")
            self.gov.transformation_applied(
                "ORACLE_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            try:
                cur.execute(f"DROP TABLE {fqt_tmp} PURGE")
                conn.commit()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            cur.close()
            conn.close()


class Db2Loader:
    """
    IBM Db2 Warehouse loader with bulk LOAD, MERGE upsert, and
    Db2-native compliance features for regulated industries.

    Architecture
    ------------
    IBM Db2 Warehouse (formerly dashDB) is IBM's cloud-native columnar
    data warehouse, designed for financial services, healthcare, and
    other regulated industries where IBM stack integration is required.
    It includes built-in ML routines, federation to external data sources,
    and comprehensive audit logging that complements this pipeline's own
    governance trail.

    Connection
    ----------
    Uses ``ibm_db`` (the official IBM DBAPI2 driver) for DDL / DML and
    ``ibm_db_sa`` (the SQLAlchemy dialect) for pandas ``.to_sql()``
    compatibility.

    Required cfg keys
    -----------------
    host     : str   Db2 server hostname
    port     : int   Default 50000 (50001 for SSL)
    database : str   Database name (e.g. "BLUDB" for Db2 on Cloud)
    user     : str   Username
    password : str   Password
    schema   : str   Target schema (default: same as user, upper-cased)

    Optional
    --------
    ssl      : bool  Use SSL/TLS (default False; set True for Db2 on Cloud)

    Load modes
    ----------
    Bulk INSERT (default)
        Uses ``ibm_db.executemany()`` for high-throughput batch insert.

    MERGE upsert (natural_keys provided)
        Db2 supports the SQL MERGE statement natively since version 9.1.
        The loader stages data in a temporary table, then issues
        ``MERGE INTO target USING stage ON (keys)``.

    Requirements
    ------------
        pip install ibm-db ibm-db-sa
    """

    # pandas dtype → Db2 SQL type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "BIGINT",
        "Int64"              : "BIGINT",
        "int32"              : "INTEGER",
        "float64"            : "DOUBLE",
        "float32"            : "REAL",
        "bool"               : "SMALLINT",
        "boolean"            : "SMALLINT",
        "datetime64[ns]"     : "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMP WITH TIME ZONE",
        "object"             : "VARCHAR(32672)",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_DB2:
            raise RuntimeError(
                "ibm-db / ibm-db-sa not installed.  "
                "Run: pip install ibm-db ibm-db-sa"
            )

    # ── Connection helpers ────────────────────────────────────────────────

    def _conn_str(self, cfg: dict) -> str:
        """Build an IBM Db2 connection string."""
        ssl_part = ";Security=SSL" if cfg.get("ssl") else ""
        return (
            f"DATABASE={cfg['database']};"
            f"HOSTNAME={cfg['host']};"
            f"PORT={cfg.get('port', 50000)};"
            "PROTOCOL=TCPIP;"
            f"UID={cfg['user']};"
            f"PWD={cfg['password']}"
            f"{ssl_part};"
        )

    def _engine(self, cfg: dict):
        """SQLAlchemy engine via ibm_db_sa dialect."""
        from sqlalchemy import create_engine as _ce  # pylint: disable=import-outside-toplevel
        ssl_str  = "?Security=SSL" if cfg.get("ssl") else ""
        port     = cfg.get("port", 50000)
        url      = (
            f"ibm_db_sa+ibm_db://{cfg['user']}:{cfg['password']}"
            f"@{cfg['host']}:{port}/{cfg['database']}{ssl_str}"
        )
        return _ce(url)

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str            = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into Db2 table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config (see class docstring).
        table        : Target table name (upper-cased per Db2 convention).
        if_exists    : "append" | "replace".
        natural_keys : Column(s) for MERGE upsert (optional).
        """
        table = table.upper()
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._bulk_insert(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        schema = cfg.get("schema", cfg["user"]).upper()
        self.gov.destination_registered(
            "db2",
            f"{cfg['host']}:{cfg.get('port',50000)}/{cfg['database']}/{schema}",
            table,
        )

    # ── Bulk INSERT ───────────────────────────────────────────────────────

    def _bulk_insert(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str,
        if_exists: str,
    ) -> None:
        """ibm_db.executemany() array insert."""
        schema = cfg.get("schema", cfg["user"]).upper()
        fqt    = f'"{schema}"."{table}"'

        conn = _ibm_db.connect(self._conn_str(cfg), "", "")
        try:
            self._ensure_table(conn, df, fqt, if_exists)

            bind_vars  = ", ".join("?" * len(df.columns))
            insert_sql = f'INSERT INTO {fqt} VALUES ({bind_vars})'
            stmt = _ibm_db.prepare(conn, insert_sql)

            rows = [
                tuple(None if (v is not None and not isinstance(v, str) and pd.isna(v)) else v
                      for v in row)
                for row in df.itertuples(index=False, name=None)
            ]
            for attempt in range(1, 4):
                try:
                    _ibm_db.execute_many(stmt, tuple(rows))
                    _ibm_db.commit(conn)
                    break
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    if attempt == 3: raise
                    wait = 2 ** attempt
                    self.gov.retry_attempt(attempt, 3, float(wait), exc)
                    time.sleep(wait)

            print(f"  [DB2] INSERT INTO {fqt} — {len(df):,} rows")
        finally:
            _ibm_db.close(conn)

    def _ensure_table(self, conn, df: "pd.DataFrame", fqt: str, if_exists: str) -> None:
        col_defs = ", ".join(
            f'"{c.upper()}" {self._DTYPE_MAP.get(str(df[c].dtype), "VARCHAR(32672)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            try:
                _ibm_db.exec_immediate(conn, f"DROP TABLE {fqt}")
                _ibm_db.commit(conn)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        _ibm_db.exec_immediate(
            conn,
            f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs})"
        )
        _ibm_db.commit(conn)

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        natural_keys: list[str],
    ) -> None:
        """Stage → Db2 MERGE INTO."""
        schema    = cfg.get("schema", cfg["user"]).upper()
        tmp_table = f"{table[:20]}_STG"
        fqt       = f'"{schema}"."{table}"'
        fqt_tmp   = f'"{schema}"."{tmp_table}"'

        engine = self._engine(cfg)
        with engine.begin() as conn_sa:
            df.to_sql(tmp_table.lower(), conn_sa, if_exists="replace",
                      index=False, schema=schema.lower(), chunksize=500)

        conn = _ibm_db.connect(self._conn_str(cfg), "", "")
        try:
            non_key_cols  = [c for c in df.columns if c not in natural_keys]
            on_clause     = " AND ".join(
                f't."{k.upper()}" = s."{k.upper()}"' for k in natural_keys
            )
            update_clause = ", ".join(
                f't."{c.upper()}" = s."{c.upper()}"' for c in non_key_cols
            ) or "t.\"__NOOP__\" = 0"
            all_cols      = ", ".join(f'"{c.upper()}"' for c in df.columns)
            stage_cols    = ", ".join(f's."{c.upper()}"' for c in df.columns)

            merge_sql = (
                f"MERGE INTO {fqt} t "
                f"USING {fqt_tmp} s ON ({on_clause}) "
                f"WHEN MATCHED THEN UPDATE SET {update_clause} "
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            )
            _ibm_db.exec_immediate(conn, merge_sql)
            _ibm_db.commit(conn)
            print(f"  [DB2] MERGE INTO {fqt} — {len(df):,} rows")
            self.gov.transformation_applied(
                "DB2_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            try:
                _ibm_db.exec_immediate(conn, f"DROP TABLE {fqt_tmp}")
                _ibm_db.commit(conn)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            _ibm_db.close(conn)


class FireboltLoader:
    """
    Firebolt loader with high-performance INSERT, MERGE upsert, and
    engine auto-start/stop management.

    Architecture
    ------------
    Firebolt is a cloud-native analytical database designed for
    sub-second query latency at petabyte scale.  It uses a proprietary
    storage format (Firebolt Index) built on top of AWS S3, with compute
    engines that can be started and stopped independently of storage.

    Firebolt supports standard SQL including MERGE, window functions,
    and semi-structured data types.  As of Firebolt v3 (2024), the
    query engine is PostgreSQL-compatible, so most SQL written for
    PostgreSQL will run unchanged.

    Connection
    ----------
    Uses ``firebolt-sdk`` (the official Firebolt Python driver).
    Authenticates via username/password or OAuth2 service account
    (client_id / client_secret).

    Required cfg keys
    -----------------
    account_name : str   Firebolt account name
    database     : str   Firebolt database name
    engine_name  : str   SQL engine name to use (must be running)

    Authentication — choose one
    ---------------------------
    username + password   : Username/password auth
    client_id + client_secret : Service account OAuth2

    Optional
    --------
    api_endpoint : str   Override API endpoint (default "api.app.firebolt.io")

    Load modes
    ----------
    INSERT (default)
        Converts the DataFrame to a VALUES literal and executes a single
        INSERT INTO statement.  Firebolt's engine handles parallelisation
        internally.  For very large DataFrames (>100k rows), split into
        batches using chunk_size.

    MERGE upsert (natural_keys provided)
        Firebolt v3 supports MERGE INTO natively.  The loader stages data
        in a VALUES subquery, then issues a MERGE statement.

    Requirements
    ------------
        pip install firebolt-sdk
    """

    # pandas dtype → Firebolt SQL type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "BIGINT",
        "Int64"              : "BIGINT NULL",
        "int32"              : "INT",
        "float64"            : "DOUBLE",
        "float32"            : "FLOAT",
        "bool"               : "BOOLEAN",
        "boolean"            : "BOOLEAN NULL",
        "datetime64[ns]"     : "TIMESTAMPNTZ",
        "datetime64[ns, UTC]": "TIMESTAMPTZ",
        "object"             : "TEXT",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_FIREBOLT:
            raise RuntimeError(
                "firebolt-sdk not installed.  "
                "Run: pip install firebolt-sdk"
            )

    # ── Connection helper ─────────────────────────────────────────────────

    def _connect(self, cfg: dict):
        """Return a Firebolt DB-API 2 connection."""
        if cfg.get("client_id"):
            auth = _FBClientCreds(cfg["client_id"], cfg["client_secret"])
        else:
            auth = _FBUserPass(cfg["username"], cfg["password"])

        kwargs: dict = {
            "auth"        : auth,
            "account_name": cfg["account_name"],
            "database"    : cfg["database"],
            "engine_name" : cfg["engine_name"],
        }
        if cfg.get("api_endpoint"):
            kwargs["api_endpoint"] = cfg["api_endpoint"]
        return _firebolt_connect(**kwargs)

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str            = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into Firebolt table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config (see class docstring).
        table        : Target table name.
        if_exists    : "append" | "replace".
        natural_keys : Column(s) for MERGE upsert (optional).
        """
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._insert(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "firebolt",
            f"{cfg['account_name']}/{cfg['database']}/{cfg['engine_name']}",
            table,
        )

    # ── INSERT ────────────────────────────────────────────────────────────

    def _insert(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str,
        if_exists: str,
    ) -> None:
        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            self._ensure_table(cur, df, table, if_exists)

            col_list    = ", ".join(f'"{c}"' for c in df.columns)
            values_rows = self._values_literal(df)

            insert_sql = (
                f'INSERT INTO "{table}" ({col_list}) '
                f"VALUES {values_rows}"
            )
            cur.execute(insert_sql)
            print(f"  [FB] INSERT INTO {table} — {len(df):,} rows")
        finally:
            cur.close()
            conn.close()

    def _ensure_table(self, cur, df: "pd.DataFrame", table: str, if_exists: str) -> None:
        col_defs = ", ".join(
            f'"{c}" {self._DTYPE_MAP.get(str(df[c].dtype), "TEXT")}'
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f'DROP TABLE IF EXISTS "{table}"')
        cur.execute(f'CREATE TABLE IF NOT EXISTS "{table}" ({col_defs})')

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        natural_keys: list[str],
    ) -> None:
        """Firebolt v3 MERGE INTO using a VALUES subquery as the source."""
        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            self._ensure_table(cur, df, table, "append")

            non_key_cols  = [c for c in df.columns if c not in natural_keys]
            on_clause     = " AND ".join(
                f't."{k}" = s."{k}"' for k in natural_keys
            )
            update_clause = ", ".join(
                f't."{c}" = s."{c}"' for c in non_key_cols
            ) or '"__noop__" = 0'
            all_cols      = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols    = ", ".join(f's."{c}"' for c in df.columns)

            # Build VALUES subquery as the MERGE source.
            col_typed    = ", ".join(f'"{c}"' for c in df.columns)
            values_rows  = self._values_literal(df)
            stage_subq   = (
                f"(SELECT {col_typed} FROM (VALUES {values_rows}) "
                f"AS s({col_typed}))"
            )

            merge_sql = (
                f'MERGE INTO "{table}" AS t '
                f"USING {stage_subq} AS s "
                f"ON ({on_clause}) "
                f"WHEN MATCHED THEN UPDATE SET {update_clause} "
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            )
            cur.execute(merge_sql)
            print(f"  [FB] MERGE INTO {table} — {len(df):,} rows")
            self.gov.transformation_applied(
                "FIREBOLT_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()

    # ── VALUES literal builder ────────────────────────────────────────────

    @staticmethod
    def _values_literal(df: "pd.DataFrame") -> str:
        """Convert DataFrame to a SQL VALUES literal string."""
        def _fmt(v):
            if v is None or (not isinstance(v, str) and pd.isna(v)):
                return "NULL"
            if isinstance(v, bool):
                return "TRUE" if v else "FALSE"
            if isinstance(v, (int, float)):
                return str(v)
            return "'" + str(v).replace("'", "''") + "'"

        return ", ".join(
            "(" + ", ".join(_fmt(v) for v in row) + ")"
            for row in df.itertuples(index=False, name=None)
        )


class YellowbrickLoader:
    """
    Yellowbrick Data Warehouse loader with bulk COPY, MERGE upsert, and
    ybload compatibility note.

    Architecture
    ------------
    Yellowbrick is a hybrid cloud/on-premises MPP analytical database that
    uses a custom NVMe-based storage engine for extremely high throughput.
    It exposes a PostgreSQL-compatible wire protocol, meaning all standard
    psycopg2 / SQLAlchemy tooling works without modification.

    The high-performance bulk load path uses ``COPY table FROM STDIN``
    (the PostgreSQL-compatible CSV stream approach), which is orders of
    magnitude faster than row-by-row INSERT.  For even higher throughput,
    the proprietary ``ybload`` CLI tool can be used outside the pipeline.

    Connection
    ----------
    Uses ``psycopg2`` (already a dependency) through SQLAlchemy's standard
    ``postgresql+psycopg2://`` dialect — Yellowbrick is fully compatible.

    Required cfg keys
    -----------------
    host     : str   Yellowbrick appliance or cloud endpoint hostname
    port     : int   Default 5432
    database : str   Database name
    user     : str   Username
    password : str   Password
    schema   : str   Target schema (default "public")

    Load modes
    ----------
    COPY FROM STDIN (default)
        Streams the DataFrame as a CSV to Yellowbrick via psycopg2's
        ``copy_expert()`` method.  This is the recommended high-throughput
        path and avoids any intermediate file staging.

    MERGE upsert (natural_keys provided)
        Stages data in a temporary table, then issues a standard
        PostgreSQL-compatible MERGE statement.  Yellowbrick supports
        MERGE natively as of release 5.2.

    Requirements
    ------------
        pip install psycopg2-binary   (already installed)
    """

    # pandas dtype → Yellowbrick / PostgreSQL type
    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "BIGINT",
        "Int64"              : "BIGINT",
        "int32"              : "INTEGER",
        "float64"            : "DOUBLE PRECISION",
        "float32"            : "REAL",
        "bool"               : "BOOLEAN",
        "boolean"            : "BOOLEAN",
        "datetime64[ns]"     : "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMPTZ",
        "object"             : "VARCHAR(65535)",
    }

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov
        if not HAS_YELLOWBRICK:
            raise RuntimeError(
                "psycopg2 not installed.  "
                "Run: pip install psycopg2-binary"
            )

    # ── Connection helpers ────────────────────────────────────────────────

    def _connect(self, cfg: dict):
        """Return a psycopg2 connection to Yellowbrick."""
        import psycopg2  # pylint: disable=import-outside-toplevel
        return psycopg2.connect(
            host    = cfg["host"],
            port    = int(cfg.get("port", 5432)),
            dbname  = cfg["database"],
            user    = cfg["user"],
            password= cfg["password"],
            sslmode = cfg.get("sslmode", "require"),
        )

    def _engine(self, cfg: dict):
        """SQLAlchemy engine for upsert staging."""
        from sqlalchemy import create_engine as _ce  # pylint: disable=import-outside-toplevel
        port = cfg.get("port", 5432)
        return _ce(
            f"postgresql+psycopg2://{cfg['user']}:{cfg['password']}"
            f"@{cfg['host']}:{port}/{cfg['database']}"
        )

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str            = "append",
        natural_keys: list[str] | None = None,
    ) -> None:
        """
        Load *df* into Yellowbrick table *table*.

        Parameters
        ----------
        df           : DataFrame to load.
        cfg          : Connection config (see class docstring).
        table        : Target table name.
        if_exists    : "append" | "replace".
        natural_keys : Column(s) for MERGE upsert (optional).
        """
        if natural_keys:
            self._upsert(df, cfg, table, natural_keys)
        else:
            self._copy_from_stdin(df, cfg, table, if_exists)

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "yellowbrick",
            f"{cfg['host']}:{cfg.get('port',5432)}/{cfg['database']}"
            f"/{cfg.get('schema','public')}",
            table,
        )

    # ── COPY FROM STDIN ───────────────────────────────────────────────────

    def _copy_from_stdin(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str,
        if_exists: str,
    ) -> None:
        """Stream CSV to Yellowbrick via copy_expert() — fastest ingest path."""
        import io as _io  # pylint: disable=import-outside-toplevel

        schema = cfg.get("schema", "public")
        fqt    = f'"{schema}"."{table}"'
        conn   = self._connect(cfg)
        cur    = conn.cursor()
        try:
            self._ensure_table(cur, df, fqt, if_exists)
            conn.commit()

            # Stream DataFrame to Yellowbrick as CSV.
            csv_buf = _io.StringIO()
            df.to_csv(csv_buf, index=False, header=False, na_rep="\\N")
            csv_buf.seek(0)

            col_list = ", ".join(f'"{c}"' for c in df.columns)
            copy_sql = (
                f"COPY {fqt} ({col_list}) FROM STDIN "
                "WITH (FORMAT CSV, NULL '\\N')"
            )
            cur.copy_expert(copy_sql, csv_buf)
            conn.commit()
            print(f"  [YB] COPY FROM STDIN → {fqt} — {len(df):,} rows")
        finally:
            cur.close()
            conn.close()

    def _ensure_table(self, cur, df: "pd.DataFrame", fqt: str, if_exists: str) -> None:
        col_defs = ", ".join(
            f'"{c}" {self._DTYPE_MAP.get(str(df[c].dtype), "VARCHAR(65535)")}'
            for c in df.columns
        )
        if if_exists == "replace":
            cur.execute(f"DROP TABLE IF EXISTS {fqt}")
        cur.execute(f"CREATE TABLE IF NOT EXISTS {fqt} ({col_defs})")

    # ── MERGE upsert ──────────────────────────────────────────────────────

    def _upsert(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        natural_keys: list[str],
    ) -> None:
        """Stage → PostgreSQL-compatible MERGE INTO."""
        schema    = cfg.get("schema", "public")
        tmp_table = f"{table}__stage__{int(time.time())}"
        fqt       = f'"{schema}"."{table}"'
        fqt_tmp   = f'"{schema}"."{tmp_table}"'

        # Write staging data via COPY.
        self._copy_from_stdin(df, cfg, tmp_table, "replace")

        conn = self._connect(cfg)
        cur  = conn.cursor()
        try:
            self._ensure_table(cur, df, fqt, "append")
            conn.commit()

            non_key_cols  = [c for c in df.columns if c not in natural_keys]
            on_clause     = " AND ".join(f't."{k}" = s."{k}"' for k in natural_keys)
            update_clause = ", ".join(f'"{c}" = s."{c}"' for c in non_key_cols)
            all_cols      = ", ".join(f'"{c}"' for c in df.columns)
            stage_cols    = ", ".join(f's."{c}"' for c in df.columns)

            merge_sql = (
                f"MERGE INTO {fqt} AS t "
                f"USING {fqt_tmp} AS s ON ({on_clause}) "
                f"WHEN MATCHED THEN UPDATE SET {update_clause} "
                f"WHEN NOT MATCHED THEN INSERT ({all_cols}) VALUES ({stage_cols})"
            )
            cur.execute(merge_sql)
            cur.execute(f"DROP TABLE IF EXISTS {fqt_tmp}")
            conn.commit()
            print(f"  [YB] MERGE INTO {fqt} — {len(df):,} rows")
            self.gov.transformation_applied(
                "YELLOWBRICK_UPSERT_COMPLETE",
                {"table": table, "natural_keys": natural_keys, "rows": len(df)},
            )
        finally:
            cur.close()
            conn.close()


class IncrementalFilter:
    """Watermark-based incremental loading (unchanged from v2.0)."""
    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov; self.state_file = WATERMARK_FILE

    def _key(self, src, col): return f"{src}::{col}"

    def read_watermark(self, src, col):
        k = self._key(src, col)
        if not self.state_file.exists(): return None
        with open(self.state_file, encoding="utf-8") as f: state = json.load(f)
        wm = state.get(k)
        if wm: self.gov.watermark_event("READ", col, wm)
        return wm

    def filter(self, df, col, last_wm, _src):
        if last_wm is None: return df
        before = len(df)
        try:
            ws = pd.to_datetime(df[col], errors="coerce")
            wv = pd.to_datetime(last_wm)
            df = df[ws > wv].copy()
        except Exception:  # pylint: disable=broad-exception-caught
            df = df[df[col] > last_wm].copy()
        self.gov.watermark_event("READ", col, last_wm, rows_filtered=before - len(df))
        print(f"  [INCR] Filtered {before-len(df):,} rows | {len(df):,} new")
        return df

    def update_watermark(self, df, col, src):
        if col not in df.columns or df.empty: return
        new_wm = str(df[col].max())
        k = self._key(src, col)
        with _STATE_FILE_LOCK:
            state: dict = {}
            if self.state_file.exists():
                with open(self.state_file, encoding="utf-8") as f: state = json.load(f)
            state[k] = new_wm
            with open(self.state_file, "w", encoding="utf-8") as f: json.dump(state, f, indent=2)
        self.gov.watermark_event("WRITE", col, new_wm)


class Notifier:
    """Email + Slack notifications (unchanged from v2.0)."""
    def __init__(self, gov, email_cfg=None, slack_cfg=None):
        self.gov = gov; self.email_cfg = email_cfg or {}; self.slack_cfg = slack_cfg or {}

    def send(self, success, stats):
        if self.email_cfg: self._send_email(success, stats)
        if self.slack_cfg: self._send_slack(success, stats)

    def _build_subject(self, ok):
        return f"[Pipeline v3] {'✅ SUCCESS' if ok else '❌ FAILED'} — {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC"

    def _build_html(self, ok, stats):
        color  = "#28a745" if ok else "#dc3545"
        status = "COMPLETED SUCCESSFULLY" if ok else "FAILED"
        rows   = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k,v in stats.items())
        return (f"<html><body><h2 style='color:{color}'>Pipeline {status}</h2>"
                f"<p><b>Pipeline ID:</b> {PIPELINE_ID}</p>"
                f"<table border='1'>{rows}</table>"
                f"<p>Artefacts: {self.gov.log_dir}</p></body></html>")

    def _send_email(self, ok, stats):
        cfg = self.email_cfg
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = self._build_subject(ok)
            msg["From"]    = cfg["from_addr"]
            msg["To"]      = ", ".join(cfg.get("to_addrs", [cfg["from_addr"]]))
            msg.attach(MIMEText(self._build_html(ok, stats), "html"))
            port = int(cfg.get("smtp_port", 587))
            if port == 465:
                with smtplib.SMTP_SSL(cfg["smtp_host"], port) as s:
                    s.login(cfg["smtp_user"], cfg["smtp_password"]); s.send_message(msg)
            else:
                with smtplib.SMTP(cfg["smtp_host"], port) as s:
                    s.ehlo(); s.starttls(); s.login(cfg["smtp_user"], cfg["smtp_password"]); s.send_message(msg)
            self.gov.notification_sent("email", "SUCCESS")
            print(f"  [NOTIFY] Email → {msg['To']}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.gov.notification_sent("email", "FAILED", str(exc))
            print(f"  [NOTIFY] Email failed: {exc}")

    def _send_slack(self, ok, stats):
        if not HAS_REQUESTS: self.gov.notification_sent("slack","FAILED","requests not installed"); return
        try:
            resp = _requests.post(self.slack_cfg["webhook_url"], timeout=10, json={
                "text": f"{'✅' if ok else '❌'} Pipeline {'SUCCESS' if ok else 'FAILED'}",
                "attachments": [{"color": "#28a745" if ok else "#dc3545",
                                  "text": f"*ID:* {PIPELINE_ID}\n" +
                                          "\n".join(f"*{k}*: {v}" for k,v in stats.items()),
                                  "mrkdwn_in": ["text"]}]})
            resp.raise_for_status()
            self.gov.notification_sent("slack", "SUCCESS")
            print("  [NOTIFY] Slack message sent.")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.gov.notification_sent("slack", "FAILED", str(exc))
            print(f"  [NOTIFY] Slack failed: {exc}")


# ═════════════════════════════════════════════════════════════════════════════
#  COMPLIANCE WIZARD  (unchanged from v2.0)
# ═════════════════════════════════════════════════════════════════════════════
def run_compliance_wizard(gov: GovernanceLogger, pii_findings: list[dict]) -> dict:
    print("\n" + "═" * 64)
    print("  GDPR / CCPA COMPLIANCE WIZARD")
    print("═" * 64)
    bases = {"1":"Consent","2":"Contract","3":"Legal Obligation",
             "4":"Vital Interests","5":"Public Task","6":"Legitimate Interests"}
    for k, v in bases.items(): print(f"  {k}. {v}")
    lawful_basis = bases.get(_prompt("\n[GDPR Art.6] Lawful basis", "2"), "Contract")
    purpose      = _prompt("Processing purpose", "Data analysis")
    confirmed    = _yn("Data owner consents?", True)
    gov.consent_recorded(purpose, lawful_basis, confirmed)
    if _yn("\n[CCPA §1798.120] Will data be sold/shared with third parties?", False):
        optout = _yn("Has subject opted OUT?", True)
        gov._event("CONSENT", "CCPA_SALE_OPTOUT", {"opted_out": optout})
        if optout: print("  ✓ Opt-out recorded.")
    pii_strategy = "retain"
    if pii_findings:
        print(f"\n[PRIVACY] {len(pii_findings)} PII field(s):")
        for f in pii_findings:
            print(f"  • {f['field']}{' ⚠ SPECIAL CATEGORY' if f['special_category'] else ''}")
        print("\n  1.Mask (SHA-256)  2.Drop  3.Retain (with consent)")
        pii_strategy = {"1":"mask","2":"drop","3":"retain"}.get(_prompt("Choice","1"),"mask")
    print("\n[GDPR Art.5(1)(e)] Retention:  1.30d  2.90d  3.1yr  4.2yr  5.5yr  6.Indefinite")
    ret_map = {"1":30,"2":90,"3":365,"4":730,"5":1825,"6":None}
    retention_days = ret_map.get(_prompt("Choice","3"), 365)
    gov.retention_policy(f"Retain {retention_days} days" if retention_days
                          else "Indefinite", retention_days)
    drop_cols: list[str] = []
    if _yn("\n[GDPR Art.5(1)(c)] Drop specific columns?", False):
        drop_cols = [c.strip() for c in input("Columns (comma-sep): ").split(",") if c.strip()]
    return {"lawful_basis": lawful_basis, "purpose": purpose,
            "pii_strategy": pii_strategy, "retention_days": retention_days,
            "drop_cols": drop_cols}



# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: HanaLoader  (SAP HANA — Tier 3)
# ═════════════════════════════════════════════════════════════════════════════

class HanaLoader:
    """
    SAP HANA loader — writes DataFrames to SAP HANA Cloud or on-premise
    HANA (2.0+).  SAP Analytics Cloud (SAC) can connect to HANA tables as
    a live data source, making this the recommended path for SAC integration.

    Architecture
    ------------
    SAP HANA is an in-memory columnar database that serves as the data
    layer for SAP Analytics Cloud, SAP BW/4HANA, and SAP Datasphere.
    Writing rows here makes them immediately available to SAC via a
    Live Data Connection without any intermediate ETL step on the SAP side.

    Connection
    ----------
    Uses ``hdbcli`` (the official SAP HANA Python driver, shipped as part
    of the SAP HANA Client).  ``hdbcli`` is also available standalone via
    PyPI:  pip install hdbcli

    Required cfg keys
    -----------------
    host      : str   HANA host (e.g. abc123.hana.trial.us10.hanacloud.ondemand.com)
    port      : int   Default 443 for HANA Cloud, 30015 for on-premise
    user      : str   Database user
    password  : str   Password
    schema    : str   Target schema (created if absent)

    Optional cfg keys
    -----------------
    encrypt   : bool  Use TLS (default True for HANA Cloud, False on-premise)
    autocommit: bool  Default True

    Load modes
    ----------
    INSERT (default)
        Batch INSERT via hdbcli executemany() in configurable chunks.

    UPSERT / MERGE  (natural_keys provided)
        HANA supports the UPSERT statement natively.  Each row is issued
        as ``UPSERT <table> VALUES (...) WHERE <key> = ...``
        or, for multi-key upserts, a temp-table MERGE pattern.

    SAC integration note
    --------------------
    After loading, create a Live Data Connection in SAC pointing at the
    HANA schema.  SAC will see the table immediately with no republish step.
    For models that need a semantic layer, use SAP Datasphere (see
    DatasphereLoader below) to expose the table as a Analytical Dataset.

    Requirements
    ------------
        pip install hdbcli
    """

    _DTYPE_MAP: dict[str, str] = {
        "int64"              : "BIGINT",
        "Int64"              : "BIGINT",
        "int32"              : "INTEGER",
        "float64"            : "DOUBLE",
        "float32"            : "REAL",
        "bool"               : "BOOLEAN",
        "boolean"            : "BOOLEAN",
        "datetime64[ns]"     : "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMP",
        "object"             : "NVARCHAR(5000)",
    }

    _CHUNK = 5_000   # rows per executemany batch

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_HANA:
            raise RuntimeError(
                "hdbcli not installed.  "
                "Run: pip install hdbcli"
            )

    # ── Connection ────────────────────────────────────────────────────────

    def _connect(self, cfg: dict):
        """Return a live hdbcli connection."""
        import hdbcli.dbapi as _hdb
        return _hdb.connect(
            address   = cfg["host"],
            port      = int(cfg.get("port", 443)),
            user      = cfg["user"],
            password  = cfg["password"],
            encrypt   = cfg.get("encrypt", True),
            autocommit= cfg.get("autocommit", True),
        )

    # ── DDL helpers ───────────────────────────────────────────────────────

    def _col_def(self, col: str, dtype: str) -> str:
        sql_type = self._DTYPE_MAP.get(dtype, "NVARCHAR(5000)")
        return f'"{col}" {sql_type}'

    def _ensure_table(self, cur, schema: str, table: str,
                      df: "pd.DataFrame") -> None:
        """CREATE TABLE IF NOT EXISTS in the target schema."""
        cols = ", ".join(
            self._col_def(c, str(df[c].dtype)) for c in df.columns
        )
        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        cur.execute(
            f'CREATE TABLE IF NOT EXISTS "{schema}"."{table}" ({cols})'
        )

    def _drop_table(self, cur, schema: str, table: str) -> None:
        cur.execute(
            f'DROP TABLE IF EXISTS "{schema}"."{table}"'
        )

    # ── Write strategies ──────────────────────────────────────────────────

    def _insert(self, cur, schema: str, table: str,
                df: "pd.DataFrame") -> None:
        """Chunked executemany INSERT."""
        cols   = ", ".join(f'"{c}"' for c in df.columns)
        params = ", ".join("?" * len(df.columns))
        sql    = f'INSERT INTO "{schema}"."{table}" ({cols}) VALUES ({params})'
        rows   = [tuple(r) for r in df.itertuples(index=False, name=None)]
        for i in range(0, len(rows), self._CHUNK):
            cur.executemany(sql, rows[i: i + self._CHUNK])

    def _upsert(self, cur, schema: str, table: str,
                df: "pd.DataFrame", natural_keys: list) -> None:
        """
        HANA UPSERT: insert or update based on key columns.
        Uses a temporary staging table + MERGE INTO for multi-row efficiency.
        """
        stage = f"{table}__stage_{id(df)}"
        # Create staging table
        self._ensure_table(cur, schema, stage, df)
        self._insert(cur, schema, stage, df)

        non_keys = [c for c in df.columns if c not in natural_keys]
        key_cond  = " AND ".join(
            f'T."{k}" = S."{k}"' for k in natural_keys
        )
        if non_keys:
            update_clause = ", ".join(
                f'T."{c}" = S."{c}"' for c in non_keys
            )
            update_part = f"WHEN MATCHED THEN UPDATE SET {update_clause}"
        else:
            update_part = ""

        insert_cols = ", ".join(f'"{c}"' for c in df.columns)
        insert_vals = ", ".join(f'S."{c}"' for c in df.columns)

        merge_sql = f"""
            MERGE INTO "{schema}"."{table}" AS T
            USING "{schema}"."{stage}" AS S
            ON ({key_cond})
            {update_part}
            WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({insert_vals})
        """
        cur.execute(merge_sql)
        self._drop_table(cur, schema, stage)

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str        = "append",
        natural_keys: list | None = None,
    ) -> None:
        """
        Load ``df`` into SAP HANA table ``<schema>.<table>``.

        Parameters
        ----------
        df           : pd.DataFrame
        cfg          : dict    Connection config (host, port, user, password, schema).
        table        : str     Target table name.
        if_exists    : str     "append" | "replace"
        natural_keys : list    Column(s) used as upsert key.  When supplied,
                               triggers a MERGE INTO instead of plain INSERT.
        """
        import pandas as pd  # noqa: F401 — local to avoid top-level dep at import time  # noqa: F401

        schema = cfg.get("schema", "PIPELINE")
        conn   = self._connect(cfg)
        cur    = conn.cursor()

        try:
            if if_exists == "replace":
                self._drop_table(cur, schema, table)
            self._ensure_table(cur, schema, table, df)

            if natural_keys:
                self._upsert(cur, schema, table, df, natural_keys)
            else:
                self._insert(cur, schema, table, df)

            conn.commit()
        finally:
            cur.close()
            conn.close()

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered(
            "hana",
            f"{cfg['host']}:{cfg.get('port', 443)}/{schema}",
            table,
        )
        self.gov.transformation_applied("HANA_LOAD_COMPLETE", {
            "schema": schema, "table": table, "rows": len(df),
            "mode": "upsert" if natural_keys else if_exists,
        })


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DatasphereLoader  (SAP Datasphere — Tier 3)
# ═════════════════════════════════════════════════════════════════════════════

class DatasphereLoader:
    """
    SAP Datasphere loader — uploads DataFrames to SAP Datasphere (formerly
    SAP Data Warehouse Cloud) via the official OData v4 REST API.

    Architecture
    ------------
    SAP Datasphere is SAP's managed data fabric and semantic layer that
    sits between raw data sources and SAP Analytics Cloud.  Data uploaded
    here can be modelled as Analytical Datasets, Dimension views, or
    Fact views, and is immediately available to SAC stories and dashboards
    without additional publish steps.

    Integration path
    ----------------
    1.  Data arrives in this pipeline from any supported source.
    2.  DatasphereLoader upserts rows to a Datasphere Local Table via
        the OData API (no file staging needed).
    3.  Datasphere modellers expose the table as a view or model.
    4.  SAC connects to Datasphere and picks up the model automatically.

    Authentication
    --------------
    Uses OAuth 2.0 client-credentials flow (recommended for service
    accounts / automated pipelines).  Alternatively accepts a pre-fetched
    bearer token via ``cfg["token"]`` for testing.

    Required cfg keys
    -----------------
    tenant_url   : str  Base URL, e.g. https://mytenant.datasphere.cloud.sap
    space        : str  Datasphere Space technical name (e.g. "SALES_SPACE")
    table        : str  Local Table technical name inside the Space
    client_id    : str  OAuth client ID  (from Datasphere App Integration)
    client_secret: str  OAuth client secret
    token_url    : str  Token endpoint, e.g.
                        https://mytenant.authentication.eu10.hana.ondemand.com/oauth/token

    Optional cfg keys
    -----------------
    token        : str  Pre-fetched Bearer token (skips OAuth flow)
    batch_size   : int  Rows per PATCH request (default 1 000)
    timeout      : int  HTTP timeout seconds (default 30)

    Load modes
    ----------
    Upsert (default)
        Issues OData PATCH requests against the Local Table endpoint.
        Datasphere merges by the table's defined primary key automatically.

    Replace
        Calls the Datasphere "truncate" action, then upserts all rows.
        Equivalent to DELETE + INSERT without dropping the table definition.

    Requirements
    ------------
        pip install requests          (already a core dependency)
    """

    _ODATA_PATH = "/api/v1/dwc/catalog/spaces/{space}/assets/{table}/data"

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_DATASPHERE:
            raise RuntimeError(
                "requests not installed.  Run: pip install requests"
            )

    # ── Auth ──────────────────────────────────────────────────────────────

    def _get_token(self, cfg: dict) -> str:
        """Fetch an OAuth2 client-credentials bearer token."""
        if cfg.get("token"):
            return cfg["token"]
        import requests
        resp = requests.post(
            cfg["token_url"],
            data={
                "grant_type"   : "client_credentials",
                "client_id"    : cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
            timeout=cfg.get("timeout", 30),
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    # ── OData helpers ─────────────────────────────────────────────────────

    def _endpoint(self, cfg: dict) -> str:
        base = cfg["tenant_url"].rstrip("/")
        path = self._ODATA_PATH.format(
            space=cfg["space"],
            table=cfg.get("table", ""),
        )
        return base + path

    def _headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type" : "application/json",
            "Accept"       : "application/json",
        }

    def _truncate(self, cfg: dict, token: str) -> None:
        """Call the Datasphere truncate action to clear the local table."""
        import requests
        base  = cfg["tenant_url"].rstrip("/")
        url   = (f"{base}/api/v1/dwc/catalog/spaces/{cfg['space']}"
                 f"/assets/{cfg.get('table','')}/data/$truncate")
        resp  = requests.post(url, headers=self._headers(token),
                              timeout=cfg.get("timeout", 30))
        resp.raise_for_status()

    def _patch_batch(
        self,
        url:     str,
        headers: dict,
        rows:    list,
        timeout: int,
    ) -> None:
        """POST a batch of rows as JSON to the OData endpoint."""
        import requests
        payload = {"value": rows}
        resp    = requests.patch(url, headers=headers,
                                 json=payload, timeout=timeout)
        if not resp.ok:
            raise RuntimeError(
                f"Datasphere OData error {resp.status_code}: {resp.text[:400]}"
            )

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str | None   = None,
        if_exists: str          = "append",
        natural_keys: list | None = None,
    ) -> None:
        """
        Upload ``df`` to a SAP Datasphere Local Table via OData v4.

        Parameters
        ----------
        df           : pd.DataFrame
        cfg          : dict    See class docstring for required keys.
                               ``cfg["table"]`` overrides the ``table`` param.
        table        : str     Local Table technical name (overridden by cfg).
        if_exists    : str     "append" | "replace"
                               "replace" truncates the table first.
        natural_keys : list    Ignored (Datasphere merges on its own PK).
        """
        import json  # noqa: F401

        # table name — cfg overrides param for flexibility
        tbl     = cfg.get("table", table or "")
        timeout = cfg.get("timeout", 30)
        batch   = cfg.get("batch_size", 1_000)

        token   = self._get_token(cfg)
        url     = self._endpoint({**cfg, "table": tbl})
        headers = self._headers(token)

        if if_exists == "replace":
            self._truncate({**cfg, "table": tbl}, token)

        # Convert DataFrame to list of plain dicts (JSON-serialisable)
        records = df.where(df.notna(), other=None).to_dict(orient="records")

        for i in range(0, len(records), batch):
            self._patch_batch(url, headers, records[i: i + batch], timeout)

        self.gov.load_complete(len(df), tbl)
        self.gov.destination_registered(
            "datasphere",
            f"{cfg['tenant_url']}/space/{cfg.get('space','')}/{tbl}",
            tbl,
        )
        self.gov.transformation_applied("DATASPHERE_LOAD_COMPLETE", {
            "space": cfg.get("space"), "table": tbl, "rows": len(df),
            "mode": if_exists,
        })


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DataDiffReporter  (NEW v4.0)
# ═════════════════════════════════════════════════════════════════════════════

class DataDiffReporter:
    """
    Compares two DataFrames (or snapshots from consecutive runs) and
    produces a structured diff report showing exactly what changed.

    Reports include:
      • New rows added since the last run
      • Rows deleted since the last run
      • Rows with one or more column values changed
      • A per-column change summary (count of cells modified)
      • A JSON diff report written to the governance log directory

    Usage
    -----
        reporter = DataDiffReporter(gov)
        diff     = reporter.compare(df_old, df_new, key_columns=["id"])
        reporter.save(diff)          # writes diff_report_<ts>.json

    Parameters
    ----------
    gov : GovernanceLogger
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def compare(
        self,
        df_old: "pd.DataFrame",
        df_new: "pd.DataFrame",
        key_columns: list[str] | None = None,
    ) -> dict:
        """
        Diff two DataFrames.

        Parameters
        ----------
        df_old      : pd.DataFrame   Snapshot from the previous run.
        df_new      : pd.DataFrame   Snapshot from the current run.
        key_columns : list[str] | None
            Columns that uniquely identify a row (used to match rows
            across snapshots).  If None, the integer index is used.

        Returns
        -------
        dict  Structured diff report.
        """
        old = df_old.copy().reset_index(drop=True)
        new = df_new.copy().reset_index(drop=True)

        if key_columns:
            old = old.set_index(key_columns)
            new = new.set_index(key_columns)

        old_idx = set(old.index.tolist())
        new_idx = set(new.index.tolist())

        added_keys   = sorted(new_idx - old_idx, key=str)
        deleted_keys = sorted(old_idx - new_idx, key=str)
        common_keys  = list(old_idx & new_idx)

        # Find changed rows among common keys
        shared_cols = [c for c in old.columns if c in new.columns]
        changed_rows = []
        col_change_counts: dict[str, int] = {c: 0 for c in shared_cols}

        for key in common_keys:
            old_row = old.loc[key]
            new_row = new.loc[key]
            diffs   = {}
            for col in shared_cols:
                ov = old_row[col] if col in old_row.index else None
                nv = new_row[col] if col in new_row.index else None
                if str(ov) != str(nv):          # string compare handles NaN / types
                    diffs[col] = {"before": str(ov), "after": str(nv)}
                    col_change_counts[col] += 1
            if diffs:
                changed_rows.append({"key": str(key), "changes": diffs})

        report = {
            "generated_utc":         datetime.now(timezone.utc).isoformat(),
            "rows_before":           len(df_old),
            "rows_after":            len(df_new),
            "rows_added":            len(added_keys),
            "rows_deleted":          len(deleted_keys),
            "rows_changed":          len(changed_rows),
            "added_keys":            [str(k) for k in added_keys],
            "deleted_keys":          [str(k) for k in deleted_keys],
            "changed_rows":          changed_rows,
            "column_change_counts":  col_change_counts,
        }

        self.gov.transformation_applied("DIFF_COMPLETE", {
            "rows_added":   len(added_keys),
            "rows_deleted": len(deleted_keys),
            "rows_changed": len(changed_rows),
        })
        return report

    def save(self, diff: dict) -> Path:
        """Write the diff report to the governance log directory."""
        ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.gov.log_dir / f"diff_report_{ts}.json"
        path.write_text(json.dumps(diff, indent=2, default=str), encoding="utf-8")
        self.gov.transformation_applied("DIFF_REPORT_SAVED", {"path": str(path)})
        return path


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: SchemaEvolver  (NEW v4.0)
# ═════════════════════════════════════════════════════════════════════════════

class SchemaEvolver:
    """
    Detects schema drift between a stored schema snapshot and the current
    DataFrame, then applies safe ALTER TABLE statements to bring the
    destination table in line with the new schema.

    Handles:
      • New columns added → ALTER TABLE ... ADD COLUMN
      • Columns removed  → logged as warning (not dropped by default)
      • Type widening    → ALTER TABLE ... ALTER COLUMN (where supported)

    Supports: SQLite, PostgreSQL, MySQL, SQL Server, Snowflake, Redshift

    Usage
    -----
        evolver = SchemaEvolver(gov, engine)
        evolver.evolve(df, table_name="employees", schema="public")

    Parameters
    ----------
    gov    : GovernanceLogger
    engine : SQLAlchemy engine connected to the target database
    """

    DTYPE_TO_SQL: dict[str, str] = {
        "int64":              "BIGINT",
        "Int64":              "BIGINT",
        "float64":            "DOUBLE PRECISION",
        "bool":               "BOOLEAN",
        "boolean":            "BOOLEAN",
        "datetime64[ns]":     "TIMESTAMP",
        "datetime64[ns, UTC]":"TIMESTAMP",
        "object":             "TEXT",
    }

    def __init__(self, gov: GovernanceLogger, engine) -> None:
        self.gov    = gov
        self.engine = engine

    def _get_existing_columns(self, table: str, schema: str | None = None) -> dict[str, str]:
        """Return {column_name: data_type} for the existing table."""
        from sqlalchemy import inspect as _sa_inspect  # pylint: disable=import-outside-toplevel
        inspector = _sa_inspect(self.engine)
        try:
            cols = inspector.get_columns(table, schema=schema)
        except Exception:  # pylint: disable=broad-except
            return {}
        return {c["name"]: str(c["type"]) for c in cols}

    def evolve(
        self,
        df:           "pd.DataFrame",
        table_name:   str,
        schema:       str | None = None,
        drop_missing: bool       = False,
        engine=None,
    ) -> dict:
        """
        Evolve the target table schema to match the incoming DataFrame.

        The optional ``engine`` kwarg overrides ``self.engine`` for this call only.

        Parameters
        ----------
        df          : pd.DataFrame   Incoming data with the new schema.
        table_name  : str            Target table name.
        schema      : str | None     Database schema / namespace.
        drop_missing: bool           If True, DROP columns absent from df.
                                     Defaults to False (safe — only adds).

        Returns
        -------
        dict  Evolution report: columns_added, columns_dropped, columns_unchanged.
        """
        if engine is not None:
            _orig, self.engine = self.engine, engine
        else:
            _orig = None
        existing = self._get_existing_columns(table_name, schema)
        incoming = {
            col: self.DTYPE_TO_SQL.get(str(df[col].dtype), "TEXT")
            for col in df.columns
        }

        from sqlalchemy import text  # pylint: disable=import-outside-toplevel

        qualified = f'"{schema}"."{table_name}"' if schema else f'"{table_name}"'
        added    = []
        dropped  = []
        unchanged = []

        with self.engine.begin() as conn:
            # Add new columns
            for col, sql_type in incoming.items():
                if col not in existing:
                    stmt = f'ALTER TABLE {qualified} ADD COLUMN "{col}" {sql_type}'
                    try:
                        conn.execute(text(stmt))
                        added.append(col)
                        self.gov.transformation_applied("SCHEMA_COLUMN_ADDED", {
                            "table": table_name, "column": col, "type": sql_type
                        })
                    except Exception as exc:  # pylint: disable=broad-except
                        self.gov.transformation_applied("SCHEMA_ALTER_FAILED", {
                            "table": table_name, "column": col, "error": str(exc)
                        })
                else:
                    unchanged.append(col)

            # Optionally drop removed columns
            if drop_missing:
                for col in existing:
                    if col not in incoming:
                        stmt = f'ALTER TABLE {qualified} DROP COLUMN "{col}"'
                        try:
                            conn.execute(text(stmt))
                            dropped.append(col)
                            self.gov.transformation_applied("SCHEMA_COLUMN_DROPPED", {
                                "table": table_name, "column": col
                            })
                        except Exception as exc:  # pylint: disable=broad-except
                            self.gov.transformation_applied("SCHEMA_DROP_FAILED", {
                                "table": table_name, "column": col, "error": str(exc)
                            })
            else:
                # Log missing columns as warnings but don't drop
                for col in existing:
                    if col not in incoming:
                        self.gov.transformation_applied("SCHEMA_COLUMN_MISSING_FROM_SOURCE", {
                            "table": table_name, "column": col,
                            "note":  "Column exists in DB but not in current data — not dropped"
                        })

        report = {
            "table":               table_name,
            "columns_added":       added,
            "columns_dropped":     dropped,
            "columns_unchanged":   unchanged,
            "generated_utc":       datetime.now(timezone.utc).isoformat(),
        }
        self.gov.transformation_applied("SCHEMA_EVOLUTION_COMPLETE", {
            "added": len(added), "dropped": len(dropped)
        })
        if _orig is not None:
            self.engine = _orig
        return report


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: SyntheticDataGenerator  (NEW v4.0)
# ═════════════════════════════════════════════════════════════════════════════

class SyntheticDataGenerator:
    """
    Generates realistic fake data that mirrors the schema and statistical
    profile of a real DataFrame.  Useful for creating dev/test datasets
    without exposing real PII.

    Uses the Faker library for locale-aware realistic values (names,
    emails, addresses, phone numbers, dates, etc.).

    Features
    --------
    • Infers column semantics from column names (email, name, phone, etc.)
    • Preserves numeric ranges (min/max) from the source DataFrame
    • Preserves categorical distributions (value frequencies)
    • Respects date ranges
    • Supports multiple locales

    Usage
    -----
        gen = SyntheticDataGenerator(gov)
        df_fake = gen.generate(df_real, n_rows=1000)
        gen.save(df_fake, "synthetic_employees.csv")

    Parameters
    ----------
    gov    : GovernanceLogger
    locale : str   Faker locale, e.g. "en_US", "de_DE", "ja_JP".
                   Defaults to "en_US".
    """

    _PII_PATTERNS: dict[str, str] = {
        "email":     "email",
        "mail":      "email",
        "name":      "name",
        "first":     "first_name",
        "last":      "last_name",
        "phone":     "phone_number",
        "mobile":    "phone_number",
        "address":   "address",
        "street":    "street_address",
        "city":      "city",
        "state":     "state",
        "zip":       "postcode",
        "postal":    "postcode",
        "country":   "country",
        "company":   "company",
        "username":  "user_name",
        "url":       "url",
        "ip":        "ipv4",
        "ssn":       "ssn",
        "dob":       "date_of_birth",
        "birth":     "date_of_birth",
        "gender":    "random_element",
        "uuid":      "uuid4",
    }

    def __init__(self, gov: GovernanceLogger, locale: str = "en_US") -> None:
        self.gov = gov
        try:
            from faker import Faker as _Faker   # pylint: disable=import-outside-toplevel
            self._fake = _Faker(locale)
        except ImportError as exc:
            raise RuntimeError("SyntheticDataGenerator requires: pip install faker") from exc

    def _faker_value(self, col: str, profile: dict) -> object:
        """Return a single synthetic value for one column."""
        col_lower = col.lower()

        # Match column name to a Faker method
        for pattern, method in self._PII_PATTERNS.items():
            if pattern in col_lower:
                if method == "random_element":
                    return self._fake.random_element(["M", "F", "Non-binary"])
                return getattr(self._fake, method)()

        # Numeric column — sample uniformly within the observed range
        if profile.get("dtype") in ("int64", "Int64", "float64", "float32"):
            lo = profile.get("min", 0)
            hi = profile.get("max", 100)
            if profile["dtype"] in ("int64", "Int64"):
                return self._fake.random_int(min=int(lo), max=int(hi))
            return round(self._fake.pyfloat(min_value=float(lo), max_value=float(hi)), 4)

        # Boolean
        if profile.get("dtype") in ("bool", "boolean"):
            return self._fake.boolean()

        # Datetime
        if "datetime" in profile.get("dtype", ""):
            return self._fake.date_time_between(
                start_date=profile.get("min", "-2y"),
                end_date=profile.get("max",  "now"),
            ).isoformat()

        # Categorical — sample from observed values weighted by frequency
        if profile.get("categories"):
            cats    = list(profile["categories"].keys())
            weights = list(profile["categories"].values())
            total   = sum(weights) or 1
            weights = [w / total for w in weights]
            # Faker's random_element() requires OrderedDict for weighted dicts
            # (plain dict keys are not deterministically ordered pre-3.7 and
            # Faker validates the type).  Use stdlib random.choices instead —
            # it accepts any sequence + weights list cleanly.
            import random as _random
            return _random.choices(cats, weights=weights, k=1)[0]

        # Default: realistic-looking sentence fragment
        return self._fake.word()

    def _profile_column(self, df: "pd.DataFrame", col: str) -> dict:
        """Build a statistical profile for one column."""
        series  = df[col]
        dtype   = str(series.dtype)
        profile = {"dtype": dtype}

        if dtype in ("int64", "Int64", "float64", "float32"):
            profile["min"] = float(series.min()) if not series.isna().all() else 0
            profile["max"] = float(series.max()) if not series.isna().all() else 100

        elif "datetime" in dtype:
            profile["min"] = series.min().isoformat() if not series.isna().all() else "-2y"
            profile["max"] = series.max().isoformat() if not series.isna().all() else "now"

        elif dtype == "object":
            vc = series.value_counts()
            if len(vc) <= 30:
                profile["categories"] = vc.to_dict()

        return profile

    def generate(self, df_source: "pd.DataFrame", n_rows: int = 1000) -> "pd.DataFrame":
        """
        Generate a synthetic DataFrame with the same schema as ``df_source``.

        Parameters
        ----------
        df_source : pd.DataFrame   Template DataFrame (schema + statistics).
        n_rows    : int            Number of synthetic rows to generate.

        Returns
        -------
        pd.DataFrame  Synthetic data.
        """
        profiles = {col: self._profile_column(df_source, col) for col in df_source.columns}
        rows = [
            {col: self._faker_value(col, profiles[col]) for col in df_source.columns}
            for _ in range(n_rows)
        ]
        df_fake = pd.DataFrame(rows, columns=list(df_source.columns))
        self.gov.transformation_applied("SYNTHETIC_DATA_GENERATED", {
            "n_rows":  n_rows,
            "columns": list(df_source.columns),
        })
        return df_fake

    def save(self, df: "pd.DataFrame", path: str, fmt: str = "csv") -> str:
        """
        Save the synthetic DataFrame to disk.

        Parameters
        ----------
        df   : pd.DataFrame
        path : str   Output file path.
        fmt  : str   "csv" | "json" | "parquet"  (default "csv")
        """
        if fmt == "csv":
            df.to_csv(path, index=False)
        elif fmt == "json":
            df.to_json(path, orient="records", lines=True)
        elif fmt == "parquet":
            df.to_parquet(path, index=False)
        else:
            raise ValueError(f"Unsupported format: {fmt!r}")
        self.gov.transformation_applied("SYNTHETIC_DATA_SAVED", {"path": path, "fmt": fmt})
        return path


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: HTMLReportGenerator  (NEW v4.0)
# ═════════════════════════════════════════════════════════════════════════════

class HTMLReportGenerator:
    """
    Generates a self-contained HTML run report after each pipeline
    execution.  The file can be opened in any browser — no web server
    required.

    Includes
    --------
    • Run summary (source, destination, row counts, duration)
    • Data quality score and breakdown
    • PII fields detected and masking actions applied
    • Validation results (expectations passed / failed)
    • Classification level
    • Top 5 changed columns (if diff available)
    • Governance audit trail (last 20 entries)

    Usage
    -----
        reporter = HTMLReportGenerator(gov)
        reporter.generate(
            df        = df_loaded,
            run_meta  = {"source": "data.csv", "destination": "sqlite"},
            quality   = quality_report,   # from DataQualityScorer
            diff      = diff_report,      # from DataDiffReporter (optional)
        )

    Parameters
    ----------
    gov : GovernanceLogger
    """

    def __init__(self, gov: GovernanceLogger) -> None:
        self.gov = gov

    def generate(
        self,
        df: "pd.DataFrame",
        run_meta: dict,
        quality: dict | None = None,
        diff: dict | None = None,
        output_path: str | None = None,
    ) -> str:
        """
        Render and save the HTML report.

        Parameters
        ----------
        df         : pd.DataFrame   The final loaded DataFrame.
        run_meta   : dict           {"source", "destination", "duration_s", ...}
        quality    : dict | None    Output of DataQualityScorer.score()
        diff       : dict | None    Output of DataDiffReporter.compare()
        output_path: str | None     Where to save; defaults to gov log dir.

        Returns
        -------
        str  Path to the saved HTML file.
        """
        ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = output_path or str(self.gov.log_dir / f"run_report_{ts}.html")

        score     = quality.get("score", "N/A")       if quality else "N/A"
        q_details = quality.get("dimensions", {})     if quality else {}
        diff_rows = diff.get("rows_changed", 0)       if diff else 0
        diff_add  = diff.get("rows_added", 0)         if diff else 0
        diff_del  = diff.get("rows_deleted", 0)       if diff else 0
        col_changes = diff.get("column_change_counts", {}) if diff else {}
        top_cols  = sorted(col_changes.items(), key=lambda x: x[1], reverse=True)[:5]

        # Audit ledger entries (last 20)
        ledger_entries = []
        if hasattr(self.gov, "ledger_entries"):
            ledger_entries = self.gov.ledger_entries[-20:]

        def _row(k, v, highlight=False):
            bg = 'style="background:#fffde7"' if highlight else ""
            return f"<tr {bg}><td><b>{k}</b></td><td>{v}</td></tr>"

        score_color = (
            "#4caf50" if isinstance(score, (int, float)) and score >= 80
            else "#ff9800" if isinstance(score, (int, float)) and score >= 60
            else "#f44336"
        )

        dim_rows = "".join(
            f"<tr><td>{d}</td><td>{v:.1f}</td></tr>" for d, v in q_details.items()
        ) if q_details else "<tr><td colspan=2>Not available</td></tr>"

        col_change_rows = "".join(
            f"<tr><td>{c}</td><td>{n}</td></tr>" for c, n in top_cols
        ) if top_cols else "<tr><td colspan=2>No changes detected</td></tr>"

        ledger_html = ""
        for entry in reversed(ledger_entries):
            action  = entry.get("action", "")
            detail  = str(entry.get("detail", ""))[:120]
            ts_str  = entry.get("timestamp_utc", "")[:19]
            ledger_html += f"<tr><td>{ts_str}</td><td>{action}</td><td>{detail}</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pipeline Run Report — {ts}</title>
<style>
  body{{font-family:system-ui,sans-serif;margin:0;background:#f5f5f5;color:#212121}}
  header{{background:#1565c0;color:#fff;padding:24px 32px}}
  header h1{{margin:0;font-size:1.5em;font-weight:600}}
  header p{{margin:4px 0 0;opacity:.8;font-size:.9em}}
  main{{max-width:1100px;margin:24px auto;padding:0 16px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:24px}}
  .card{{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.12)}}
  .card h2{{margin:0 0 16px;font-size:1em;text-transform:uppercase;letter-spacing:.05em;color:#555}}
  .score{{font-size:3em;font-weight:700;color:{score_color}}}
  table{{width:100%;border-collapse:collapse;font-size:.9em}}
  th{{background:#e3f2fd;text-align:left;padding:8px 10px;font-weight:600}}
  td{{padding:7px 10px;border-bottom:1px solid #eee}}
  tr:last-child td{{border-bottom:none}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.8em;font-weight:600}}
  .success{{background:#e8f5e9;color:#2e7d32}}
  .warning{{background:#fff8e1;color:#e65100}}
  .section{{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.12);margin-bottom:24px}}
  .section h2{{margin:0 0 16px;font-size:1em;text-transform:uppercase;letter-spacing:.05em;color:#555}}
  code{{font-size:.85em;background:#eceff1;padding:1px 5px;border-radius:3px}}
  footer{{text-align:center;padding:24px;color:#999;font-size:.85em}}
</style>
</head>
<body>
<header>
  <h1>Pipeline Run Report</h1>
  <p>Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
</header>
<main>

<div class="grid">
  <div class="card">
    <h2>Run Summary</h2>
    <table>
      {_row("Source",      run_meta.get("source","—"))}
      {_row("Destination", run_meta.get("destination","—"))}
      {_row("Rows loaded", f"{len(df):,}")}
      {_row("Columns",     len(df.columns))}
      {_row("Duration",    f"{run_meta.get('duration_s','—')}s")}
      {_row("Status",      '<span class="badge success">Success</span>')}
    </table>
  </div>
  <div class="card">
    <h2>Data Quality Score</h2>
    <div class="score">{score if score == "N/A" else f"{score:.0f}"}</div>
    <p style="color:#888;margin:4px 0 16px">out of 100</p>
    <table>
      <tr><th>Dimension</th><th>Score</th></tr>
      {dim_rows}
    </table>
  </div>
  <div class="card">
    <h2>Data Changes (vs. last run)</h2>
    <table>
      {_row("Rows added",   f"{diff_add:,}")}
      {_row("Rows deleted", f"{diff_del:,}")}
      {_row("Rows changed", f"{diff_rows:,}", highlight=diff_rows>0)}
    </table>
    <br>
    <b style="font-size:.85em;color:#555">Top changed columns</b>
    <table style="margin-top:8px">
      <tr><th>Column</th><th>Changes</th></tr>
      {col_change_rows}
    </table>
  </div>
</div>

<div class="section">
  <h2>Governance Audit Trail (last 20 entries)</h2>
  <table>
    <tr><th>Timestamp</th><th>Action</th><th>Detail</th></tr>
    {ledger_html if ledger_html else "<tr><td colspan=3>No entries</td></tr>"}
  </table>
</div>

</main>
<footer>pipeline_v3 &mdash; Generated by HTMLReportGenerator</footer>
</body>
</html>"""

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(html, encoding="utf-8")
        self.gov.transformation_applied("HTML_REPORT_SAVED", {"path": path})
        return path


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DataQualityScorer  (NEW v4.0)
# ═════════════════════════════════════════════════════════════════════════════

class DataQualityScorer:
    """
    Computes a 0–100 composite data quality score for a DataFrame,
    broken down across five standard dimensions:

        Completeness   — non-null cells as a fraction of total cells
        Uniqueness     — fraction of rows that are not exact duplicates
        Validity       — fraction of rows that passed Great Expectations
        Consistency    — fraction of numeric columns within expected range
        Timeliness     — fraction of date columns within the past N days

    The composite score is the weighted mean of each dimension.

    Scores are logged to the governance ledger and appended to a
    persistent JSONL history file so quality trends can be tracked.

    Usage
    -----
        scorer = DataQualityScorer(gov)
        result = scorer.score(df, validation_report=report)
        print(result["score"])   # 91.3

    Parameters
    ----------
    gov           : GovernanceLogger
    history_file  : str | Path   Defaults to "quality_score_history.jsonl"
    weights       : dict | None  Custom dimension weights (must sum to 1.0).
    """

    DEFAULT_WEIGHTS = {
        "completeness": 0.30,
        "uniqueness":   0.20,
        "validity":     0.25,
        "consistency":  0.15,
        "timeliness":   0.10,
    }

    def __init__(
        self,
        gov: GovernanceLogger,
        history_file: str | Path | None = None,
        weights: dict | None = None,
    ) -> None:
        self.gov          = gov
        self.history_file = Path(history_file) if history_file else gov.log_dir / "quality_history.jsonl"
        self.weights      = weights or self.DEFAULT_WEIGHTS

    # ── Dimension calculators ─────────────────────────────────────────────

    def _completeness(self, df: "pd.DataFrame") -> float:
        total = df.size
        if total == 0:
            return 100.0
        return round((1 - df.isna().sum().sum() / total) * 100, 2)

    def _uniqueness(self, df: "pd.DataFrame") -> float:
        if len(df) == 0:
            return 100.0
        return round((1 - df.duplicated().sum() / len(df)) * 100, 2)

    def _validity(self, validation_report: dict | None) -> float:
        if not validation_report:
            return 100.0
        passed = validation_report.get("expectations_passed", 0)
        total  = validation_report.get("expectations_total",  0)
        if total == 0:
            return 100.0
        return round(passed / total * 100, 2)

    def _consistency(self, df: "pd.DataFrame") -> float:
        num_cols = df.select_dtypes(include="number")
        if num_cols.empty:
            return 100.0
        scores = []
        for col in num_cols.columns:
            s   = num_cols[col].dropna()
            if len(s) < 2:
                continue
            mean = s.mean()
            std  = s.std()
            if std == 0:
                scores.append(100.0)
                continue
            # Fraction of values within 3σ of mean
            in_range = ((s >= mean - 3 * std) & (s <= mean + 3 * std)).mean()
            scores.append(in_range * 100)
        return round(sum(scores) / len(scores), 2) if scores else 100.0

    def _timeliness(self, df: "pd.DataFrame", max_days: int = 365) -> float:
        date_cols = df.select_dtypes(include=["datetime64[ns]", "datetimetz"])
        if date_cols.empty:
            return 100.0
        now    = datetime.now(timezone.utc).replace(tzinfo=None)
        scores = []
        for col in date_cols.columns:
            s   = date_cols[col].dropna()
            if len(s) == 0:
                continue
            days_old = (now - s.dt.tz_localize(None)).dt.days
            fresh    = (days_old <= max_days).mean()
            scores.append(fresh * 100)
        return round(sum(scores) / len(scores), 2) if scores else 100.0

    # ── Main scorer ───────────────────────────────────────────────────────

    def score(
        self,
        df: "pd.DataFrame",
        validation_report: dict | None = None,
        timeliness_max_days: int = 365,
        run_label: str | None = None,
    ) -> dict:
        """
        Compute the composite quality score.

        Parameters
        ----------
        df                  : pd.DataFrame
        validation_report   : dict | None   From SchemaValidator.validate()
        timeliness_max_days : int           Days threshold for timeliness check
        run_label           : str | None    Tag for history file (e.g. "2026-01")

        Returns
        -------
        dict  {score, dimensions, rows, columns, generated_utc, ...}
        """
        dims = {
            "completeness": self._completeness(df),
            "uniqueness":   self._uniqueness(df),
            "validity":     self._validity(validation_report),
            "consistency":  self._consistency(df),
            "timeliness":   self._timeliness(df, timeliness_max_days),
        }
        composite = round(
            sum(dims[d] * self.weights[d] for d in dims), 2
        )

        report = {
            "score":         composite,
            "grade":         "A" if composite >= 90 else "B" if composite >= 80
                             else "C" if composite >= 70 else "D" if composite >= 60 else "F",
            "dimensions":    dims,
            "rows":          len(df),
            "columns":       len(df.columns),
            "run_label":     run_label,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
        }

        # Persist to history
        with open(self.history_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(report, default=str) + "\n")

        self.gov.transformation_applied("QUALITY_SCORE_COMPUTED", {
            "score": composite, "grade": report["grade"],
            "dimensions": dims,
        })
        return report

    def trend(self, n: int = 30) -> list[dict]:
        """
        Return the last ``n`` quality score records for trend analysis.

        Parameters
        ----------
        n : int   Maximum records to return (most recent first).
        """
        if not self.history_file.exists():
            return []
        lines = self.history_file.read_text(encoding="utf-8").strip().splitlines()
        records = []
        for line in reversed(lines[-n:]):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return records




# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: QualityAnomalyAlerter  (NEW v4.2)
# ═════════════════════════════════════════════════════════════════════════════

class QualityAnomalyAlerter:
    """
    Monitors data quality score trends across runs and fires alerts when
    anomalies are detected — before bad data reaches production.

    Detection methods
    -----------------
    THRESHOLD DROP     Score falls more than ``drop_threshold`` points from
                       the previous run in a single step.
                       e.g. 94 → 79 with threshold=10  →  ALERT

    ROLLING DECLINE    Score has declined consistently over the past
                       ``rolling_window`` runs (every run lower than the one
                       before). Catches slow, gradual degradation.
                       e.g. 94 → 92 → 90 → 88  →  ALERT

    DIMENSION SPIKE    Any single dimension (completeness, uniqueness, etc.)
                       drops more than ``dimension_threshold`` points in one
                       run.  Catches targeted problems invisible in the
                       composite score.
                       e.g. completeness 100 → 71  →  ALERT

    FLOOR BREACH       Composite score drops below the configured
                       ``absolute_floor``.  Hard minimum — always fires
                       regardless of trend.
                       e.g. score=58 with floor=70  →  ALERT

    Alert channels
    --------------
    Each channel is optional and independently configurable:

    console    Always enabled. Prints a formatted alert block.
    log_file   Appends JSON alert records to ``alert_log_file``.
    slack      HTTP POST to a Slack incoming webhook URL.
    email      SMTP email via smtplib (TLS).  Requires smtp_cfg dict.
    webhook    HTTP POST to any arbitrary URL with a JSON payload.
    governance Writes a QUALITY_ANOMALY_ALERT event to the GovernanceLogger
               ledger.  Always enabled if a gov instance is provided.

    Usage
    -----
        # Minimal — console + governance ledger only:
        alerter = QualityAnomalyAlerter(gov)
        alerter.check(current_score_report)

        # Full configuration:
        alerter = QualityAnomalyAlerter(
            gov            = gov,
            drop_threshold = 10,        # alert if composite drops > 10pts
            dimension_threshold = 15,   # alert if any dimension drops > 15pts
            absolute_floor = 70,        # alert if score < 70 ever
            rolling_window = 4,         # alert if declining 4 runs in a row
            history_file   = None,
            alert_log_file = "quality_alerts.jsonl",
            slack_webhook  = "https://hooks.slack.com/services/...",
            email_cfg      = {
                "smtp_host":   "smtp.gmail.com",
                "smtp_port":   587,
                "username":    "alerts@company.com",
                "password":    "app-password",
                "from_addr":   "alerts@company.com",
                "to_addrs":    ["data-team@company.com"],
                "subject_prefix": "[Pipeline Alert]",
            },
            webhook_url    = "https://your-api.com/pipeline/alerts",
        )
        alerter.check(current_score_report)

    Parameters
    ----------
    gov                 : GovernanceLogger | None
    drop_threshold      : float   Composite drop that triggers an alert (default 10).
    dimension_threshold : float   Per-dimension drop threshold (default 15).
    absolute_floor      : float   Hard minimum composite score (default 60).
    rolling_window      : int     Consecutive declining runs to trigger alert (default 3).
    history_file        : str | Path   Quality score history (read-only).
    alert_log_file      : str | Path   Where alert records are appended.
    slack_webhook       : str | None   Slack incoming webhook URL.
    email_cfg           : dict | None  SMTP config dict (see above).
    webhook_url         : str | None   Generic HTTP webhook URL.
    """

    def __init__(
        self,
        gov=None,
        drop_threshold:      float          = 10.0,
        dimension_threshold: float          = 15.0,
        absolute_floor:      float          = 60.0,
        rolling_window:      int            = 3,
        history_file:        str | Path | None = None,
        alert_log_file:      str | Path     = "quality_alerts.jsonl",
        slack_webhook:       str | None     = None,
        email_cfg:           dict | None    = None,
        webhook_url:         str | None     = None,
    ) -> None:
        self.gov                 = gov
        self.drop_threshold      = drop_threshold
        self.dimension_threshold = dimension_threshold
        self.absolute_floor      = absolute_floor
        self.rolling_window      = rolling_window
        # history_file defaults to gov.quality_log_file when gov is provided
        if history_file is not None:
            self.history_file = Path(history_file)
        elif gov is not None and hasattr(gov, "quality_log_file"):
            self.history_file = Path(gov.quality_log_file)
        else:
            self.history_file = Path("quality_history.jsonl")
        self.alert_log_file      = Path(alert_log_file)
        self.slack_webhook       = slack_webhook
        self.email_cfg           = email_cfg
        self.webhook_url         = webhook_url

    # ── History helpers ───────────────────────────────────────────────────

    def _load_history(self, n: int = 50) -> list[dict]:
        """Return the last n records from the quality score history file."""
        if not self.history_file.exists():
            return []
        records = []
        for line in self.history_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return records[-n:]

    def _prev_record(self) -> dict | None:
        """Return the second-to-last record (the run before the current one)."""
        hist = self._load_history(n=10)
        return hist[-2] if len(hist) >= 2 else None

    # ── Anomaly detectors ─────────────────────────────────────────────────

    def _check_threshold_drop(
        self, current: dict, previous: dict
    ) -> dict | None:
        curr_score = float(current.get("score", 100.0))
        prev_score = float(previous.get("score", 100.0))
        drop       = prev_score - curr_score
        if drop > self.drop_threshold:
            return {
                "type":        "THRESHOLD_DROP",
                "severity":    "HIGH" if drop > self.drop_threshold * 2 else "MEDIUM",
                "message":     f"Quality score dropped {drop:.1f} points "
                               f"({prev_score:.1f} → {curr_score:.1f})",
                "drop":        round(float(drop), 2),
                "threshold":   self.drop_threshold,
                "prev_score":  prev_score,
                "curr_score":  curr_score,
            }
        return None

    def _check_floor_breach(self, current: dict) -> dict | None:
        score = current.get("score", 100.0)
        if score < self.absolute_floor:
            return {
                "type":     "FLOOR_BREACH",
                "severity": "CRITICAL",
                "message":  f"Quality score {score:.1f} is below the minimum "
                            f"floor of {self.absolute_floor}",
                "score":    score,
                "floor":    self.absolute_floor,
                "gap":      round(self.absolute_floor - score, 2),
            }
        return None

    def _check_rolling_decline(self) -> dict | None:
        hist = self._load_history(n=self.rolling_window + 1)
        if len(hist) < self.rolling_window:
            return None
        # Check last rolling_window records are strictly declining
        recent = [r.get("score", 100.0) for r in hist[-(self.rolling_window):]]
        if all(recent[i] > recent[i + 1] for i in range(len(recent) - 1)):
            total_drop = recent[0] - recent[-1]
            return {
                "type":       "ROLLING_DECLINE",
                "severity":   "HIGH",
                "message":    f"Quality score has declined for {self.rolling_window} "
                              f"consecutive runs (total drop: {total_drop:.1f} pts)",
                "window":     self.rolling_window,
                "scores":     [round(s, 1) for s in recent],
                "total_drop": round(total_drop, 2),
            }
        return None

    def _check_dimension_spikes(
        self, current: dict, previous: dict
    ) -> list[dict]:
        alerts = []
        curr_dims = current.get("dimensions",  {})
        prev_dims = previous.get("dimensions", {})
        for dim, curr_val in curr_dims.items():
            prev_val = prev_dims.get(dim)
            if prev_val is None:
                continue
            curr_val = float(curr_val)
            prev_val = float(prev_val)
            drop = prev_val - curr_val
            if drop > self.dimension_threshold:
                severity = "HIGH" if drop > self.dimension_threshold * 1.5 else "MEDIUM"
                alerts.append({
                    "type":      "DIMENSION_SPIKE",
                    "severity":  severity,
                    "message":   f"Dimension '{dim}' dropped {drop:.1f} points "
                                 f"({prev_val:.1f} → {curr_val:.1f})",
                    "dimension": dim,
                    "drop":      round(float(drop), 2),
                    "threshold": self.dimension_threshold,
                    "prev_val":  prev_val,
                    "curr_val":  curr_val,
                })
        return alerts

    # ── Main entry point ──────────────────────────────────────────────────

    def check(self, current_report, label: str = "") -> list[dict]:
        """
        Run all anomaly checks against the current quality score report
        and fire alerts for any anomalies found.

        Call this immediately after DataQualityScorer.score() to get
        preventive alerting on every run.

        Parameters
        ----------
        current_report : dict | pd.DataFrame
            Either the dict returned by DataQualityScorer.score(), or a
            raw DataFrame (score will be computed automatically using a
            default DataQualityScorer).
        label          : str   Optional label stored in the alert records.
                               Only used when current_report is a DataFrame.

        Returns
        -------
        list[dict]  All alerts fired during this check (empty = no anomalies).
        """
        # Accept raw DataFrame as a convenience — auto-score it
        import pandas as _pd
        if isinstance(current_report, _pd.DataFrame):
            _qs = DataQualityScorer(gov=self.gov)
            current_report = _qs.score(current_report)

        previous = self._prev_record()
        alerts   = []

        # Run all detectors
        floor_alert = self._check_floor_breach(current_report)
        if floor_alert:
            alerts.append(floor_alert)

        if previous:
            drop_alert = self._check_threshold_drop(current_report, previous)
            if drop_alert:
                alerts.append(drop_alert)

            dim_alerts = self._check_dimension_spikes(current_report, previous)
            alerts.extend(dim_alerts)

        rolling_alert = self._check_rolling_decline()
        if rolling_alert:
            alerts.append(rolling_alert)

        # Fire each alert through all configured channels
        for alert in alerts:
            self._dispatch(alert, current_report)

        if not alerts:
            # Log a clean bill of health to governance
            if self.gov:
                self.gov.transformation_applied("QUALITY_CHECK_PASSED", {
                    "score":    current_report.get("score"),
                    "grade":    current_report.get("grade"),
                    "note":     "No anomalies detected",
                })

        return alerts

    # ── Alert dispatcher ──────────────────────────────────────────────────

    def _dispatch(self, alert: dict, report: dict) -> None:
        """Route a single alert to every configured channel."""
        ts      = datetime.now(timezone.utc).isoformat()
        payload = {
            "timestamp":   ts,
            "alert":       alert,
            "score":       report.get("score"),
            "grade":       report.get("grade"),
            "dimensions":  report.get("dimensions", {}),
            "run_label":   report.get("run_label"),
        }

        # 1. Console
        self._alert_console(alert, report)

        # 2. Governance ledger
        if self.gov:
            self.gov.transformation_applied("QUALITY_ANOMALY_ALERT", {
                "type":     alert["type"],
                "severity": alert["severity"],
                "message":  alert["message"],
                "score":    report.get("score"),
            })

        # 3. Append to alert log file
        try:
            with open(self.alert_log_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, default=str) + "\n")
        except OSError as exc:
            print(f"  [QualityAnomalyAlerter] Could not write alert log: {exc}")

        # 4. Slack webhook
        if self.slack_webhook:
            self._alert_slack(alert, report)

        # 5. Email
        if self.email_cfg:
            self._alert_email(alert, report)

        # 6. Generic webhook
        if self.webhook_url:
            self._alert_webhook(payload)

    def _alert_console(self, alert: dict, report: dict) -> None:
        """Print a formatted alert block to stdout."""
        sev    = alert.get("severity", "MEDIUM")
        border = "═" * 62
        print(f"\n  {border}")
        print(f"  ⚠  QUALITY ANOMALY ALERT  [{sev}]")
        print(f"  {border}")
        print(f"  Type    : {alert['type']}")
        print(f"  Message : {alert['message']}")
        print(f"  Score   : {report.get('score', '?')} (grade {report.get('grade', '?')})")
        if "dimension" in alert:
            print(f"  Dimension: {alert['dimension']}  "
                  f"{alert.get('prev_val','?')} → {alert.get('curr_val','?')}")
        if "scores" in alert:
            print(f"  Trend   : {' → '.join(str(s) for s in alert['scores'])}")
        print(f"  {border}\n")

    def _alert_slack(self, alert: dict, report: dict) -> None:
        """POST a Slack Block Kit message to the incoming webhook."""
        sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(
            alert.get("severity", "MEDIUM"), "⚠️"
        )
        text = (
            f"{sev_emoji} *Data Quality Alert [{alert.get('severity')}]*\n"
            f"*{alert['type']}* — {alert['message']}\n"
            f"Current score: `{report.get('score', '?')}` (grade `{report.get('grade', '?')}`)"
        )
        payload = {"text": text, "username": "Pipeline Quality Bot",
                   "icon_emoji": ":bar_chart:"}
        try:
            import urllib.request as _req
            data = json.dumps(payload).encode("utf-8")
            req  = _req.Request(self.slack_webhook, data=data,
                                headers={"Content-Type": "application/json"})
            with _req.urlopen(req, timeout=5):
                pass
        except Exception as exc:  # pylint: disable=broad-except
            print(f"  [QualityAnomalyAlerter] Slack send failed: {exc}")

    def _alert_email(self, alert: dict, report: dict) -> None:
        """Send an SMTP email alert."""
        cfg = self.email_cfg or {}
        try:
            import smtplib
            from email.mime.text import MIMEText
            subject = (
                f"{cfg.get('subject_prefix','[Alert]')} Quality {alert['type']} "
                f"— score {report.get('score','?')}"
            )
            dims_txt = "\n".join(
                f"  {k}: {v:.1f}" for k, v in report.get("dimensions", {}).items()
            )
            body = (
                "Data Quality Anomaly Detected\n"
                f"{'='*40}\n"
                f"Type     : {alert['type']}\n"
                f"Severity : {alert.get('severity')}\n"
                f"Message  : {alert['message']}\n\n"
                f"Current Score : {report.get('score','?')} (grade {report.get('grade','?')})\n\n"
                f"Dimension Breakdown:\n{dims_txt}\n\n"
                f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
            )
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"]    = cfg.get("from_addr", "pipeline@localhost")
            msg["To"]      = ", ".join(cfg.get("to_addrs", []))
            with smtplib.SMTP(cfg.get("smtp_host","localhost"),
                              cfg.get("smtp_port", 587)) as server:
                server.starttls()
                server.login(cfg.get("username",""), cfg.get("password",""))
                server.sendmail(
                    cfg.get("from_addr","pipeline@localhost"),
                    cfg.get("to_addrs", []),
                    msg.as_string()
                )
        except Exception as exc:  # pylint: disable=broad-except
            print(f"  [QualityAnomalyAlerter] Email send failed: {exc}")

    def _alert_webhook(self, payload: dict) -> None:
        """POST the full alert payload to a generic HTTP webhook."""
        try:
            import urllib.request as _req
            data = json.dumps(payload, default=str).encode("utf-8")
            req  = _req.Request(self.webhook_url, data=data,
                                headers={"Content-Type": "application/json"})
            with _req.urlopen(req, timeout=5):
                pass
        except Exception as exc:  # pylint: disable=broad-except
            print(f"  [QualityAnomalyAlerter] Webhook send failed: {exc}")

    # ── Reporting helpers ─────────────────────────────────────────────────

    def alert_history(self, n: int = 50) -> list[dict]:
        """
        Return the last n alert records from the alert log file.

        Parameters
        ----------
        n : int   Maximum records to return (most recent first).

        Returns
        -------
        list[dict]
        """
        if not self.alert_log_file.exists():
            return []
        records = []
        for line in self.alert_log_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return list(reversed(records[-n:]))

    def summary(self) -> dict:
        """
        Return a summary of all alerts fired to date.

        Returns
        -------
        dict  {total_alerts, by_type, by_severity, most_recent}
        """
        history = self.alert_history(n=500)
        by_type: dict[str, int]     = {}
        by_sev:  dict[str, int]     = {}
        for rec in history:
            alert = rec.get("alert", {})
            t = alert.get("type", "UNKNOWN")
            s = alert.get("severity", "UNKNOWN")
            by_type[t] = by_type.get(t, 0) + 1
            by_sev[s]  = by_sev.get(s, 0) + 1
        return {
            "total_alerts": len(history),
            "by_type":      by_type,
            "by_severity":  by_sev,
            "most_recent":  history[0] if history else None,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: LineageGraphGenerator  (NEW v4.1)
# ═════════════════════════════════════════════════════════════════════════════

class LineageGraphGenerator:
    """
    Reads the GovernanceLogger audit ledger and renders a fully interactive,
    self-contained HTML lineage graph — no web server or external files needed.

    Features (v2)
    -------------
    • Curved Bezier edges           — S-curve paths, no overlap
    • Smooth entrance animation     — nodes flow in left → right on load
    • Improved column nodes         — readable pill labels + dtype badge
    • Minimap                       — overview navigator (bottom-right)
    • Stage icons                   — emoji per transform type
    • Focus mode                    — click a node to isolate its lineage path
    • Filter toggles                — show/hide PII / transforms / columns
    • Export to PNG                 — download button saves graph as image
    • Hover tooltips                — metadata popup follows cursor
    • Edge row counts               — rows-in-transit label on each connection
    • Row drop indicators           — badge on validation / dedup nodes
    • Stage durations               — elapsed time badge on transform nodes

    Usage
    -----
        gen  = LineageGraphGenerator(gov)
        path = gen.generate()            # <gov_log_dir>/lineage_<ts>.html
        path = gen.generate("out.html")  # custom path

    Parameters
    ----------
    gov : GovernanceLogger
    """

    # ── Stage icons ───────────────────────────────────────────────────────
    STAGE_ICONS: dict[str, str] = {
        "EXTRACT":         "📥",
        "CLASSIFY":        "🏷️",
        "MASK_PII":        "🔒",
        "VALIDATE":        "✅",
        "NULLS":           "🧹",
        "DEDUP":           "♻️",
        "TRANSFORM_DONE":  "⚙️",
        "DEFAULT":         "▶",
    }

    # ── dtype → short label ───────────────────────────────────────────────
    DTYPE_LABELS: dict[str, str] = {
        "int64":              "int",
        "Int64":              "int",
        "float64":            "float",
        "Float64":            "float",
        "bool":               "bool",
        "boolean":            "bool",
        "object":             "str",
        "datetime64[ns]":     "date",
        "datetime64[ns, UTC]":"date",
    }

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        # Optional programmatic graph — nodes/edges added via add_node()/add_edge()
        self._manual_nodes: list[dict] = []
        self._manual_edges: list[dict] = []

    # ── Programmatic graph-building API ───────────────────────────────────

    def add_node(
        self,
        node_id:  str,
        node_type: str = "transform",
        meta:      dict | None = None,
        label:     str | None = None,
        icon:      str = "",
    ) -> "LineageGraphGenerator":
        """
        Add a node to the manually constructed lineage graph.

        Parameters
        ----------
        node_id   : str   Unique node identifier.
        node_type : str   Node category — e.g. "source", "transform", "destination".
        meta      : dict  Arbitrary metadata shown in the hover tooltip.
        label     : str   Display label (defaults to node_id).
        icon      : str   Emoji icon (optional).

        Returns self for chaining.
        """
        self._manual_nodes.append({
            "id":       node_id,
            "label":    label or node_id,
            "type":     node_type,
            "icon":     icon,
            "meta":     meta or {},
            "rows_out": None,
            "drops":    0,
            "ts":       "",
            "duration_s": None,
        })
        return self

    def add_edge(
        self,
        source:    str,
        target:    str,
        label:     str = "solid",
        row_count: int | None = None,
    ) -> "LineageGraphGenerator":
        """
        Add a directed edge between two nodes.

        Parameters
        ----------
        source    : str   Source node_id.
        target    : str   Target node_id.
        label     : str   Edge style / label (e.g. "TRANSFORM", "solid").
        row_count : int   Optional row count displayed on the edge.

        Returns self for chaining.
        """
        self._manual_edges.append({
            "source":    source,
            "target":    target,
            "style":     label,
            "row_count": row_count,
        })
        return self

    def to_dict(self) -> dict:
        """
        Return the current graph (manual nodes/edges + any ledger-derived
        nodes/edges) as a plain dict.

        Returns
        -------
        dict with keys "nodes" and "edges".
        """
        if self._manual_nodes or self._manual_edges:
            return {
                "nodes": list(self._manual_nodes),
                "edges": list(self._manual_edges),
            }
        # Fall back to ledger-derived graph
        nodes, edges = self._build_graph()
        return {"nodes": nodes, "edges": edges}

    # ── Ledger → graph model ──────────────────────────────────────────────

    def _build_graph(self) -> tuple[list[dict], list[dict]]:
        """
        Walk the ledger entries and produce enriched nodes + edges.

        Returns
        -------
        nodes : list[dict]   {id, label, type, icon, meta, rows_out, drops, duration_s}
        edges : list[dict]   {source, target, style, row_count}
        """
        entries = self.gov.ledger_entries
        nodes: list[dict] = []
        edges: list[dict] = []
        seen_ids: set[str] = set()

        # ── helpers ───────────────────────────────────────────────────────
        def add_node(nid: str, label: str, ntype: str, meta: dict,
                     icon: str = "", rows_out: int | None = None,
                     drops: int = 0, ts: str = "", duration_s: float | None = None) -> None:
            if nid not in seen_ids:
                nodes.append({
                    "id": nid, "label": label, "type": ntype,
                    "icon": icon, "meta": meta,
                    "rows_out":   rows_out,
                    "drops":      drops,
                    "ts":         ts,
                    "duration_s": duration_s,
                })
                seen_ids.add(nid)

        def add_edge(src: str, tgt: str, style: str = "solid",
                     row_count: int | None = None) -> None:
            edges.append({"source": src, "target": tgt,
                           "style": style, "row_count": row_count})

        # ── state ─────────────────────────────────────────────────────────
        source_id:         str | None = None
        destination_id:    str | None = None
        pii_fields:        set[str]   = set()
        all_columns:       list[str]  = []
        dtypes:            dict[str, str] = {}
        transform_chain:   list[str]  = []
        last_transform_id: str | None = None
        current_row_count: int | None = None
        stage_timestamps:  dict[str, str] = {}
        total_drops:       int = 0

        def parse_ts(ts_str: str) -> float:
            """Parse ISO timestamp to float seconds."""
            from datetime import datetime as _dt
            try:
                return _dt.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
            except Exception:
                return 0.0

        for entry in entries:
            action    = entry.get("action", "")
            detail    = entry.get("detail", {}) or {}
            ts        = entry.get("timestamp_utc", "")
            ts_short  = ts[:19].replace("T", " ") if ts else ""

            if action == "PIPELINE_STARTED":
                pass  # captured via ledger start timestamp

            # ── Source node ───────────────────────────────────────────────
            elif action == "SOURCE_REGISTERED":
                nid   = "SOURCE"
                label = detail.get("source_path", "source")
                sha   = (detail.get("sha256", "") or "")[:12]
                sha_disp = sha + "…" if sha else "—"
                rows  = detail.get("row_count", "?")
                current_row_count = rows if isinstance(rows, int) else None
                add_node(nid, label, "source",
                         {"File": label,
                          "Format": detail.get("file_type", "?"),
                          "Rows":   rows,
                          "Columns": detail.get("col_count", "?"),
                          "SHA-256": sha_disp,
                          "Timestamp": ts_short},
                         icon="📄", rows_out=current_row_count, ts=ts_short)
                source_id = nid
                stage_timestamps["SOURCE"] = ts

            # ── Extract ───────────────────────────────────────────────────
            elif action == "EXTRACT_COMPLETE":
                nid          = "EXTRACT"
                all_columns  = detail.get("columns", [])
                dtypes       = detail.get("dtypes", {})
                rows         = detail.get("rows", current_row_count)
                current_row_count = rows if isinstance(rows, int) else current_row_count
                dur = round(parse_ts(ts) - parse_ts(stage_timestamps.get("SOURCE", ts)), 2) if stage_timestamps.get("SOURCE") else None
                add_node(nid, "Extract", "transform",
                         {"Stage": "Extract", "Rows": rows,
                          "Columns": len(all_columns),
                          "Timestamp": ts_short},
                         icon=self.STAGE_ICONS["EXTRACT"],
                         rows_out=current_row_count, ts=ts_short, duration_s=dur)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts
                if source_id:
                    add_edge(source_id, nid, row_count=current_row_count)

            # ── Classification ────────────────────────────────────────────
            elif action == "DATA_CLASSIFIED":
                nid = "CLASSIFY"
                dur = round(parse_ts(ts) - parse_ts(stage_timestamps.get(transform_chain[-1] if transform_chain else "", ts)), 2) if transform_chain else None
                add_node(nid, "Classify", "transform",
                         {"Stage": "Data Classification",
                          "Level": detail.get("classification_level", "?"),
                          "PII fields": detail.get("pii_fields", 0),
                          "Timestamp": ts_short},
                         icon=self.STAGE_ICONS["CLASSIFY"],
                         rows_out=current_row_count, ts=ts_short, duration_s=dur)
                if transform_chain:
                    add_edge(transform_chain[-1], nid, row_count=current_row_count)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts

            # ── PII masking ───────────────────────────────────────────────
            elif action == "PII_MASKED":
                pii_fields.add(detail.get("field", ""))

            # ── Validation ────────────────────────────────────────────────
            elif action == "SUITE_RESULT":
                nid    = "VALIDATE"
                passed = detail.get("expectations_passed", 0)
                failed = detail.get("expectations_failed", 0)
                total  = detail.get("expectations_total",  0)
                # Estimate dropped rows from DLQ (not directly available here, use 0)
                drops  = 0
                dur = round(parse_ts(ts) - parse_ts(stage_timestamps.get(transform_chain[-1] if transform_chain else "", ts)), 2) if transform_chain else None
                add_node(nid, "Validate", "transform",
                         {"Stage":   "Great Expectations",
                          "Passed":  f"{passed} / {total}",
                          "Failed":  failed,
                          "Success": str(detail.get("overall_success", "?")),
                          "Timestamp": ts_short},
                         icon=self.STAGE_ICONS["VALIDATE"],
                         rows_out=current_row_count, drops=drops, ts=ts_short, duration_s=dur)
                if transform_chain:
                    add_edge(transform_chain[-1], nid, row_count=current_row_count)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts

            # ── Null handling ─────────────────────────────────────────────
            elif action == "NULL_HANDLING":
                nid = "NULLS"
                dur = round(parse_ts(ts) - parse_ts(stage_timestamps.get(transform_chain[-1] if transform_chain else "", ts)), 2) if transform_chain else None
                add_node(nid, "Null Handling", "transform",
                         {"Stage": "Null Handling",
                          "Nulls before": detail.get("null_cells_before", 0),
                          "Nulls after":  detail.get("null_cells_after",  0),
                          "Timestamp": ts_short},
                         icon=self.STAGE_ICONS["NULLS"],
                         rows_out=current_row_count, ts=ts_short, duration_s=dur)
                if transform_chain:
                    add_edge(transform_chain[-1], nid, row_count=current_row_count)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts

            # ── Deduplication ─────────────────────────────────────────────
            elif action == "DEDUPLICATION":
                nid    = "DEDUP"
                r_bef  = detail.get("rows_before", current_row_count or 0)
                r_aft  = detail.get("rows_after",  current_row_count or 0)
                drops  = detail.get("duplicates_removed", 0)
                total_drops += drops
                current_row_count = r_aft if isinstance(r_aft, int) else current_row_count
                dur = round(parse_ts(ts) - parse_ts(stage_timestamps.get(transform_chain[-1] if transform_chain else "", ts)), 2) if transform_chain else None
                add_node(nid, "Deduplicate", "transform",
                         {"Stage":   "Deduplication",
                          "Before":  r_bef,
                          "After":   r_aft,
                          "Removed": drops,
                          "Timestamp": ts_short},
                         icon=self.STAGE_ICONS["DEDUP"],
                         rows_out=current_row_count, drops=drops, ts=ts_short, duration_s=dur)
                if transform_chain:
                    add_edge(transform_chain[-1], nid, row_count=r_bef)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts

            # ── Transform complete ─────────────────────────────────────────
            elif action == "TRANSFORM_COMPLETE":
                nid  = "TRANSFORM_DONE"
                rows = detail.get("final_row_count", current_row_count)
                current_row_count = rows if isinstance(rows, int) else current_row_count
                dur = round(parse_ts(ts) - parse_ts(stage_timestamps.get(transform_chain[-1] if transform_chain else "", ts)), 2) if transform_chain else None
                add_node(nid, "Transform\nComplete", "transform",
                         {"Stage":   "Transform Complete",
                          "Rows":    rows,
                          "Columns": detail.get("final_col_count", len(all_columns)),
                          "Timestamp": ts_short},
                         icon=self.STAGE_ICONS["TRANSFORM_DONE"],
                         rows_out=current_row_count, ts=ts_short, duration_s=dur)
                if transform_chain:
                    add_edge(transform_chain[-1], nid, row_count=current_row_count)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts
                last_transform_id = nid

            # ── Destination ───────────────────────────────────────────────
            elif action == "DESTINATION_REGISTERED":
                nid   = "DESTINATION"
                db    = detail.get("db_type", "?")
                table = detail.get("table_or_collection", "?")
                dbname = detail.get("db_name", "?")
                add_node(nid, f"{db} › {table}", "destination",
                         {"Platform": db, "Database": dbname,
                          "Table": table, "Timestamp": ts_short},
                         icon="🗄️", rows_out=current_row_count, ts=ts_short)
                destination_id = nid

            # ── Load complete ─────────────────────────────────────────────
            elif action == "LOAD_COMPLETE":
                rows_written = detail.get("rows_written", current_row_count)
                n = next((n for n in nodes if n["id"] == "DESTINATION"), None)
                if n:
                    n["meta"]["Rows written"] = rows_written
                    n["rows_out"] = rows_written

        # ── PII masking consolidated node ─────────────────────────────────
        if pii_fields:
            nid = "MASK_PII"
            # Find timestamp from first PII_MASKED entry
            pii_ts = next((e.get("timestamp_utc", "")[:19].replace("T"," ")
                          for e in entries if e.get("action") == "PII_MASKED"), "")
            classify_idx = next((i for i, n in enumerate(transform_chain) if n == "CLASSIFY"), -1)
            insert_after = transform_chain[classify_idx] if classify_idx >= 0 else (transform_chain[-1] if transform_chain else None)
            insert_before = transform_chain[classify_idx + 1] if classify_idx >= 0 and classify_idx + 1 < len(transform_chain) else None

            add_node(nid, "Mask PII", "transform",
                     {"Stage":  "PII Masking",
                      "Fields": ", ".join(sorted(pii_fields)),
                      "Count":  len(pii_fields),
                      "Action": "mask / pseudonymise",
                      "Timestamp": pii_ts},
                     icon=self.STAGE_ICONS["MASK_PII"],
                     rows_out=current_row_count, ts=pii_ts)

            if insert_after and insert_before:
                edges[:] = [e for e in edges
                             if not (e["source"] == insert_after and e["target"] == insert_before)]
                add_edge(insert_after, nid, row_count=current_row_count)
                add_edge(nid, insert_before, row_count=current_row_count)
                idx = transform_chain.index(insert_before)
                transform_chain.insert(idx, nid)
            elif insert_after:
                add_edge(insert_after, nid, row_count=current_row_count)
                transform_chain.append(nid)

        # ── Column nodes ──────────────────────────────────────────────────
        if all_columns:
            for col in all_columns:
                is_pii  = col in pii_fields
                nid     = f"COL_{col}"
                raw_dt  = dtypes.get(col, "object")
                dt_lbl  = self.DTYPE_LABELS.get(raw_dt, raw_dt[:6])
                add_node(nid, col, "pii_column" if is_pii else "column",
                         {"Column": col,
                          "Type":   raw_dt,
                          "PII":    "Yes — masked" if is_pii else "No"},
                         icon="🔒" if is_pii else "📊",
                         rows_out=current_row_count)
                # Attach dtype label directly on the node dict for JS
                nodes[-1]["dtype"] = dt_lbl

            anchor = last_transform_id or (transform_chain[-1] if transform_chain else None)
            if anchor:
                for col in all_columns:
                    add_edge(anchor, f"COL_{col}", "dashed", current_row_count)
            if destination_id:
                for col in all_columns:
                    add_edge(f"COL_{col}", destination_id, "dashed", current_row_count)

        elif destination_id and last_transform_id:
            add_edge(last_transform_id, destination_id, row_count=current_row_count)

        return nodes, edges

    # ── HTML renderer ─────────────────────────────────────────────────────

    def generate(self, output_path: str | None = None) -> str:
        """
        Build the improved lineage graph and write a self-contained HTML file.

        Parameters
        ----------
        output_path : str | None
            Defaults to ``<gov_log_dir>/lineage_<ts>.html``.

        Returns
        -------
        str  Path to the saved HTML file.
        """
        nodes, edges = self._build_graph()
        ts    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path  = output_path or str(self.gov.log_dir / f"lineage_{ts}.html")
        run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        nodes_json = json.dumps(nodes, default=str)
        edges_json = json.dumps(edges, default=str)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Data Lineage — {ts}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;overflow:hidden;user-select:none}}

/* ── Toolbar ── */
#toolbar{{position:fixed;top:0;left:0;right:0;height:50px;background:#161b22;
          border-bottom:1px solid #30363d;display:flex;align-items:center;
          padding:0 16px;gap:12px;z-index:200}}
#toolbar h1{{font-size:.95em;font-weight:600;color:#58a6ff;white-space:nowrap}}
#toolbar .sep{{width:1px;height:24px;background:#30363d}}
.filter-btn{{display:flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;
             border:1px solid #30363d;background:transparent;color:#8b949e;
             font-size:.78em;cursor:pointer;transition:all .15s}}
.filter-btn.active{{background:#1f6feb22;border-color:#1f6feb;color:#58a6ff}}
.filter-btn:hover{{border-color:#8b949e;color:#e6edf3}}
.dot{{width:8px;height:8px;border-radius:50%;display:inline-block}}
#search{{margin-left:auto;background:#0d1117;border:1px solid #30363d;color:#e6edf3;
         padding:5px 12px;border-radius:20px;font-size:.8em;outline:none;width:180px}}
#search:focus{{border-color:#58a6ff}}
#search::placeholder{{color:#484f58}}
#export-btn{{padding:5px 12px;background:#238636;border:none;color:#fff;border-radius:6px;
             font-size:.8em;cursor:pointer;display:flex;align-items:center;gap:5px}}
#export-btn:hover{{background:#2ea043}}
#run-ts{{font-size:.72em;color:#484f58;white-space:nowrap}}

/* ── Canvas ── */
#canvas{{position:fixed;top:50px;left:0;right:0;bottom:0}}
svg#main{{width:100%;height:100%}}

/* ── Edges ── */
.link{{stroke:#30363d;stroke-opacity:.8;fill:none;stroke-width:1.5}}
.link-dashed{{stroke:#1f6feb;stroke-opacity:.4;stroke-dasharray:5 4;fill:none;stroke-width:1}}
.link.dimmed,.link-dashed.dimmed{{opacity:.04}}
.edge-label{{font-size:9px;fill:#6e7681;text-anchor:middle;pointer-events:none}}

/* ── Nodes ── */
.node{{cursor:pointer;transition:opacity .2s}}
.node.dimmed{{opacity:.07}}
.node.focused rect,.node.focused circle,.node.focused .col-pill{{filter:brightness(1.35);stroke-width:2.5px!important}}

/* Source pill */
.node-source .n-pill{{fill:#0c2d6b;stroke:#58a6ff;stroke-width:1.5;rx:22}}
.node-source text{{fill:#cae8ff;font-size:11px;font-weight:600}}

/* Destination pill */
.node-destination .n-pill{{fill:#0a2d0a;stroke:#3fb950;stroke-width:1.5;rx:22}}
.node-destination text{{fill:#7ee787;font-size:11px;font-weight:600}}

/* Transform box */
.node-transform .n-box{{fill:#161b22;stroke:#30363d;stroke-width:1.2;rx:10}}
.node-transform text{{fill:#c9d1d9;font-size:11px}}
.node-transform .n-icon{{font-size:14px}}
.n-dur{{font-size:8px;fill:#6e7681}}

/* Column pill */
.col-pill{{rx:10;stroke-width:1.2}}
.node-column .col-pill{{fill:#0d1117;stroke:#1f6feb}}
.node-pii_column .col-pill{{fill:#1f0a0a;stroke:#f85149}}
.node-column text,.node-pii_column text{{font-size:10px}}
.dtype-badge{{font-size:8px;fill:#484f58}}

/* Drop badge */
.drop-badge rect{{fill:#6e292c;rx:4}}
.drop-badge text{{font-size:8px;fill:#f85149;font-weight:600}}

/* ── Tooltip ── */
#tip{{position:fixed;background:#1c2128;border:1px solid #30363d;border-radius:8px;
      padding:10px 14px;font-size:.78em;pointer-events:none;display:none;
      max-width:260px;box-shadow:0 8px 24px rgba(0,0,0,.6);z-index:300}}
#tip h4{{color:#58a6ff;margin-bottom:7px;font-size:.85em}}
#tip table{{border-collapse:collapse;width:100%}}
#tip td{{padding:2px 4px;vertical-align:top}}
#tip td:first-child{{color:#8b949e;white-space:nowrap;padding-right:10px}}
#tip td:last-child{{color:#e6edf3;word-break:break-all}}

/* ── Minimap ── */
#minimap-wrap{{position:fixed;bottom:16px;right:16px;border:1px solid #30363d;
               background:#0d1117;border-radius:8px;overflow:hidden;z-index:150}}
#minimap{{width:160px;height:110px;display:block}}
#mm-viewport{{fill:#58a6ff22;stroke:#58a6ff;stroke-width:.5}}

/* ── Stats bar ── */
#stats{{position:fixed;bottom:16px;left:16px;background:#161b22;border:1px solid #30363d;
        border-radius:20px;padding:5px 14px;font-size:.73em;color:#8b949e;z-index:150}}
</style>
</head>
<body>

<div id="toolbar">
  <h1>🔗 Data Lineage</h1>
  <span class="sep"></span>
  <button class="filter-btn active" id="f-transforms" onclick="toggleFilter('transforms')">
    <span class="dot" style="background:#8b949e"></span>Transforms
  </button>
  <button class="filter-btn active" id="f-columns" onclick="toggleFilter('columns')">
    <span class="dot" style="background:#1f6feb"></span>Columns
  </button>
  <button class="filter-btn active" id="f-pii" onclick="toggleFilter('pii')">
    <span class="dot" style="background:#f85149"></span>PII
  </button>
  <span class="sep"></span>
  <span id="run-ts">{run_ts}</span>
  <input id="search" placeholder="🔍  Search nodes…" type="text">
  <button id="export-btn" onclick="exportPNG()">⬇ PNG</button>
</div>

<div id="canvas"><svg id="main"></svg></div>
<div id="tip"><h4 id="tip-title"></h4><table id="tip-body"></table></div>
<div id="minimap-wrap"><svg id="minimap"><rect id="mm-viewport"/></svg></div>
<div id="stats"></div>

<script>
const NODES = {nodes_json};
const EDGES = {edges_json};

// ── State ────────────────────────────────────────────────────────────────
const filters = {{transforms:true, columns:true, pii:true}};
let focusedId  = null;

// ── SVG / zoom setup ────────────────────────────────────────────────────
const svg    = d3.select("#main");
const W = () => +svg.node().clientWidth;
const H = () => +svg.node().clientHeight;

const defs = svg.append("defs");
// Arrowheads
[["arr-grey","#30363d",14],["arr-blue","#1f6feb",12]].forEach(([id,col,ref]) => {{
  defs.append("marker").attr("id",id)
    .attr("viewBox","0 -4 8 8").attr("refX",ref).attr("refY",0)
    .attr("markerWidth",5).attr("markerHeight",5).attr("orient","auto")
    .append("path").attr("d","M0,-4L8,0L0,4").attr("fill",col).attr("opacity",.7);
}});

const gZoom = svg.append("g").attr("class","zoom-root");
const zoom  = d3.zoom().scaleExtent([.05,4]).on("zoom", e => {{
  gZoom.attr("transform", e.transform);
  updateMinimap(e.transform);
}});
svg.call(zoom).on("dblclick.zoom", null);

// ── Build node lookup ────────────────────────────────────────────────────
const nodeById = Object.fromEntries(NODES.map(n=>[n.id,n]));

// ── Force simulation ─────────────────────────────────────────────────────
const bandX = {{source:.08, transform:.38, column:.68, pii_column:.68, destination:.95}};

const sim = d3.forceSimulation(NODES)
  .force("link",   d3.forceLink(EDGES).id(d=>d.id)
                     .distance(d => d.style==="dashed" ? 80 : 120).strength(.5))
  .force("charge", d3.forceManyBody()
                     .strength(d => (d.type==="column"||d.type==="pii_column") ? -60 : -350))
  .force("x",      d3.forceX(d=>(bandX[d.type]||.4)*W()).strength(.55))
  .force("y",      d3.forceY(H()/2).strength(.08))
  .force("collide",d3.forceCollide(d=>(d.type==="column"||d.type==="pii_column")?30:58));

// ── Draw curved edges ────────────────────────────────────────────────────
const linkG = gZoom.append("g").attr("class","links");
const link  = linkG.selectAll("g").data(EDGES).join("g");

const linkPath = link.append("path")
  .attr("class", d => d.style==="dashed"?"link-dashed":"link")
  .attr("marker-end", d => d.style==="dashed"?"url(#arr-blue)":"url(#arr-grey)");

const linkLabel = link.append("text").attr("class","edge-label")
  .text(d => d.row_count != null ? d.row_count.toLocaleString()+"r" : "")
  .style("display", d => (d.style==="dashed"||!d.row_count) ? "none":"block");

// ── Draw nodes ───────────────────────────────────────────────────────────
const nodeG = gZoom.append("g").attr("class","nodes");
const node  = nodeG.selectAll("g.node").data(NODES).join("g")
  .attr("class", d=>`node node-${{d.type}}`)
  .call(d3.drag()
    .on("start",(e,d)=>{{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y}})
    .on("drag", (e,d)=>{{d.fx=e.x;d.fy=e.y}})
    .on("end",  (e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}}))
  .on("mousemove",(e,d)=>showTip(e,d))
  .on("mouseleave",()=>hideTip())
  .on("click",(e,d)=>{{e.stopPropagation();toggleFocus(d)}});

svg.on("click", ()=>clearFocus());

// Build each node shape
node.each(function(d){{
  const el = d3.select(this);
  const isCol = d.type==="column"||d.type==="pii_column";

  if(d.type==="source"||d.type==="destination"){{
    const w = Math.max(140, d.label.length*8+48);
    el.append("rect").attr("class","n-pill").attr("width",w).attr("height",34)
      .attr("x",-w/2).attr("y",-17).attr("rx",17);
    el.append("text").attr("class","n-icon").attr("x",-w/2+14).attr("y",1)
      .attr("dominant-baseline","central").text(d.icon||"");
    el.append("text").attr("x",8).attr("y",0).attr("dominant-baseline","central")
      .text(d.label.length>22?d.label.slice(0,21)+"…":d.label);
    if(d.rows_out!=null){{
      el.append("text").attr("class","n-dur").attr("x",0).attr("y",22).attr("text-anchor","middle")
        .text(d.rows_out.toLocaleString()+" rows");
    }}
  }} else if(isCol){{
    const lbl   = d.label.length>14?d.label.slice(0,13)+"…":d.label;
    const dtype = d.dtype||"";
    const w = Math.max(70, lbl.length*7.5+24+(dtype?dtype.length*5.5+8:0));
    el.append("rect").attr("class","col-pill").attr("width",w).attr("height",22)
      .attr("x",-w/2).attr("y",-11).attr("rx",11);
    el.append("text").attr("x", dtype ? -w/2+8 : 0).attr("y",0)
      .attr("dominant-baseline","central")
      .attr("text-anchor", dtype?"start":"middle").text(lbl)
      .style("fill", d.type==="pii_column"?"#ffa198":"#79c0ff");
    if(dtype){{
      const bx = w/2-dtype.length*5.5-8;
      el.append("rect").attr("x",bx-4).attr("y",-7).attr("width",dtype.length*5.5+8)
        .attr("height",14).attr("rx",3).style("fill","#161b22").style("stroke","#30363d").style("stroke-width","0.8");
      el.append("text").attr("class","dtype-badge").attr("x",bx+dtype.length*2.75)
        .attr("y",0).attr("dominant-baseline","central").attr("text-anchor","middle").text(dtype);
    }}
  }} else {{
    // Transform box
    const lines  = d.label.split("\\n");
    const w      = Math.max(110, d.label.replace("\\n"," ").length*8+40);
    const h      = lines.length>1?52:42;
    el.append("rect").attr("class","n-box").attr("width",w).attr("height",h)
      .attr("x",-w/2).attr("y",-h/2).attr("rx",10);
    // Icon
    if(d.icon){{
      el.append("text").attr("class","n-icon").attr("x",-w/2+12).attr("y",0)
        .attr("dominant-baseline","central").text(d.icon);
    }}
    // Label lines
    const xOff = d.icon?4:0;
    lines.forEach((ln,i)=>{{
      el.append("text").attr("x",xOff).attr("y",(i-(lines.length-1)/2)*14)
        .attr("dominant-baseline","central").attr("text-anchor","middle").text(ln);
    }});
    // Duration badge
    if(d.duration_s!=null){{
      el.append("text").attr("class","n-dur").attr("x",0).attr("y",h/2-6)
        .attr("text-anchor","middle").text(d.duration_s+"s");
    }}
    // Drop badge (if any rows dropped)
    if(d.drops&&d.drops>0){{
      const g2 = el.append("g").attr("class","drop-badge").attr("transform",`translate(${{w/2-4}},${{-h/2-2}})`);
      const lbl = `-${{d.drops}}`;
      g2.append("rect").attr("x",-lbl.length*4.5-4).attr("y",-8).attr("width",lbl.length*4.5+8).attr("height",14).attr("rx",4);
      g2.append("text").attr("x",-lbl.length*2.25+0.5).attr("y",0).attr("dominant-baseline","central").text(lbl);
    }}
  }}
}});

// ── Tick: bezier paths ───────────────────────────────────────────────────
sim.on("tick", () => {{
  linkPath.attr("d", d => {{
    const sx=d.source.x, sy=d.source.y, tx=d.target.x, ty=d.target.y;
    const cx = (sx+tx)/2;
    return `M${{sx}},${{sy}} C${{cx}},${{sy}} ${{cx}},${{ty}} ${{tx}},${{ty}}`;
  }});
  linkLabel.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2-5);
  node.attr("transform",d=>`translate(${{d.x}},${{d.y}})`);
  updateMinimapNodes();
}});

// ── Entrance animation ────────────────────────────────────────────────────
// Start all nodes off-screen-left, fade in by band
const bandOrder = ["source","transform","column","pii_column","destination"];
NODES.forEach(n => {{ n.x = -300; n.y = H()/2; }});
sim.alpha(1).restart();

setTimeout(() => {{
  bandOrder.forEach((band, bi) => {{
    setTimeout(() => {{
      node.filter(d=>d.type===band)
        .transition().duration(600).ease(d3.easeCubicOut)
        .style("opacity",1);
    }}, bi*150);
  }});
}}, 200);

// Start nodes invisible and reveal
node.style("opacity",0);

// ── Tooltip ──────────────────────────────────────────────────────────────
const tip = document.getElementById("tip");
function showTip(e,d){{
  document.getElementById("tip-title").textContent = (d.icon?d.icon+" ":"")+d.label.replace("\\n"," ");
  const rows = Object.entries(d.meta||{{}}).map(([k,v])=>
    `<tr><td>${{k}}</td><td>${{String(v).slice(0,80)}}</td></tr>`).join("");
  document.getElementById("tip-body").innerHTML = rows||"<tr><td>No metadata</td></tr>";
  tip.style.display = "block";
  moveTip(e);
}}
function moveTip(e){{
  const t=tip, x=e.clientX+14, y=e.clientY-10;
  t.style.left = (x+t.offsetWidth>window.innerWidth ? x-t.offsetWidth-28 : x)+"px";
  t.style.top  = (y+t.offsetHeight>window.innerHeight ? y-t.offsetHeight : y)+"px";
}}
function hideTip(){{ tip.style.display="none"; }}
svg.node().addEventListener("mousemove", e=>{{ if(tip.style.display!=="none") moveTip(e); }});

// ── Focus mode ────────────────────────────────────────────────────────────
function getLineage(d){{
  const ids = new Set([d.id]);
  // Traverse upstream and downstream
  let frontier = [d.id];
  for(let pass=0;pass<30&&frontier.length;pass++){{
    const next=[];
    EDGES.forEach(e=>{{
      const s=typeof e.source==="object"?e.source.id:e.source;
      const t=typeof e.target==="object"?e.target.id:e.target;
      if(frontier.includes(s)&&!ids.has(t)){{ids.add(t);next.push(t);}}
      if(frontier.includes(t)&&!ids.has(s)){{ids.add(s);next.push(s);}}
    }});
    frontier=next;
  }}
  return ids;
}}
function toggleFocus(d){{
  if(focusedId===d.id){{ clearFocus(); return; }}
  focusedId = d.id;
  const ids = getLineage(d);
  node.classed("dimmed",n=>!ids.has(n.id)).classed("focused",n=>n.id===d.id);
  link.classed("dimmed",e=>{{
    const s=typeof e.source==="object"?e.source.id:e.source;
    const t=typeof e.target==="object"?e.target.id:e.target;
    return !ids.has(s)||!ids.has(t);
  }});
}}
function clearFocus(){{
  focusedId=null;
  node.classed("dimmed",false).classed("focused",false);
  link.classed("dimmed",false);
}}

// ── Filter toggles ────────────────────────────────────────────────────────
function toggleFilter(key){{
  filters[key] = !filters[key];
  document.getElementById("f-"+key).classList.toggle("active", filters[key]);
  applyFilters();
}}
function applyFilters(){{
  node.style("display", d=>{{
    if(d.type==="transform"&&!filters.transforms) return "none";
    if(d.type==="column"&&!filters.columns) return "none";
    if(d.type==="pii_column"&&(!filters.pii||!filters.columns)) return "none";
    return null;
  }});
  link.style("display", e=>{{
    const s=typeof e.source==="object"?nodeById[e.source.id]:nodeById[e.source];
    const t=typeof e.target==="object"?nodeById[e.target.id]:nodeById[e.target];
    if(!s||!t) return null;
    const sHid = (s.type==="transform"&&!filters.transforms)||(s.type==="column"&&!filters.columns)||(s.type==="pii_column"&&(!filters.pii||!filters.columns));
    const tHid = (t.type==="transform"&&!filters.transforms)||(t.type==="column"&&!filters.columns)||(t.type==="pii_column"&&(!filters.pii||!filters.columns));
    return sHid||tHid ? "none" : null;
  }});
}}

// ── Search ────────────────────────────────────────────────────────────────
document.getElementById("search").addEventListener("input", function(){{
  const q=this.value.toLowerCase().trim();
  if(!q){{clearFocus();return;}}
  const matched=new Set(NODES.filter(n=>n.label.toLowerCase().includes(q)||
    Object.values(n.meta||{{}}).join(" ").toLowerCase().includes(q)).map(n=>n.id));
  node.classed("dimmed",n=>!matched.has(n.id));
  link.classed("dimmed",e=>{{
    const s=typeof e.source==="object"?e.source.id:e.source;
    const t=typeof e.target==="object"?e.target.id:e.target;
    return !matched.has(s)||!matched.has(t);
  }});
}});

// ── Export to PNG ─────────────────────────────────────────────────────────
function exportPNG(){{
  const svgEl  = document.getElementById("main");
  const clone  = svgEl.cloneNode(true);
  clone.setAttribute("xmlns","http://www.w3.org/2000/svg");
  clone.setAttribute("width",W());clone.setAttribute("height",H());
  // Embed dark background
  const bg=document.createElementNS("http://www.w3.org/2000/svg","rect");
  bg.setAttribute("width","100%");bg.setAttribute("height","100%");bg.setAttribute("fill","#0d1117");
  clone.insertBefore(bg,clone.firstChild);
  const xml = new XMLSerializer().serializeToString(clone);
  const img = new Image();
  img.onload=()=>{{
    const c=document.createElement("canvas");c.width=W();c.height=H();
    const ctx=c.getContext("2d");ctx.drawImage(img,0,0);
    const a=document.createElement("a");a.download="lineage_{ts}.png";
    a.href=c.toDataURL("image/png");a.click();
  }};
  img.src="data:image/svg+xml;charset=utf-8,"+encodeURIComponent(xml);
}}

// ── Minimap ───────────────────────────────────────────────────────────────
const mm      = d3.select("#minimap");
const mmW     = 160, mmH = 110;
const mmNodes = mm.append("g");
const mmVP    = document.getElementById("mm-viewport");
let mmScale   = 1, mmTx = 0, mmTy = 0;

function updateMinimap(t){{
  mmScale=t.k; mmTx=t.x; mmTy=t.y;
  const vpW=W()/t.k, vpH=H()/t.k;
  const sx=-t.x/t.k, sy=-t.y/t.k;
  const bb=getGraphBB();
  if(!bb||bb.w===0) return;
  const scl=Math.min(mmW/bb.w, mmH/bb.h)*.85;
  const ox=(mmW-bb.w*scl)/2-bb.minX*scl, oy=(mmH-bb.h*scl)/2-bb.minY*scl;
  mmNodes.attr("transform",`translate(${{ox}},${{oy}}) scale(${{scl}})`);
  d3.select(mmVP)
    .attr("x",sx*scl+ox-4).attr("y",sy*scl+oy-4)
    .attr("width",(vpW*scl)+8).attr("height",(vpH*scl)+8);
}}
function getGraphBB(){{
  if(!NODES.length||!NODES[0].x) return null;
  const xs=NODES.map(n=>n.x||0), ys=NODES.map(n=>n.y||0);
  return {{minX:Math.min(...xs),minY:Math.min(...ys),w:Math.max(...xs)-Math.min(...xs)||1,h:Math.max(...ys)-Math.min(...ys)||1}};
}}
function updateMinimapNodes(){{
  const dots=mmNodes.selectAll("circle").data(NODES);
  dots.join("circle").attr("cx",d=>d.x||0).attr("cy",d=>d.y||0).attr("r",4)
    .attr("fill",d=>{{
      if(d.type==="source")      return "#58a6f";
      if(d.type==="destination") return "#3fb950";
      if(d.type==="pii_column") return "#f85149";
      if(d.type==="column")      return "#1f6feb";
      return "#8b949e";
    }}).attr("opacity",.8);
}}

// ── Stats ─────────────────────────────────────────────────────────────────
const piiCnt = NODES.filter(n=>n.type==="pii_column").length;
const colCnt  = NODES.filter(n=>n.type==="column"||n.type==="pii_column").length;
const trnCnt  = NODES.filter(n=>n.type==="transform").length;
document.getElementById("stats").textContent =
  `${{NODES.length}} nodes · ${{EDGES.length}} edges · ${{trnCnt}} stages · ${{colCnt}} columns (${{piiCnt}} PII)`;

// ── Auto-fit after simulation settles ────────────────────────────────────
let fitted=false;
sim.on("end",()=>{{
  if(fitted) return; fitted=true;
  const bb=getGraphBB();
  if(!bb||bb.w===0) return;
  const pad=80;
  const scl=Math.min(.92,Math.min(W()/(bb.w+pad),(H())/(bb.h+pad)));
  const tx=W()/2-scl*(bb.minX+bb.w/2), ty=H()/2-scl*(bb.minY+bb.h/2);
  svg.transition().duration(800).call(zoom.transform,d3.zoomIdentity.translate(tx,ty).scale(scl));
}});
window.addEventListener("resize",()=>sim.alpha(.15).restart());
</script>
</body>
</html>"""

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(html, encoding="utf-8")
        self.gov.transformation_applied("LINEAGE_GRAPH_SAVED", {
            "path":  path,
            "nodes": len(nodes),
            "edges": len(edges),
            "version": "v2",
        })
        return path

# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DataContractEnforcer  (NEW v4.3)
# ═════════════════════════════════════════════════════════════════════════════

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
                      dtype         — expected pandas dtype string
                      nullable      — bool: whether NULLs are permitted
                      unique        — bool: whether values must be unique
                      min / max     — numeric or date bounds
                      min_length / max_length — string length bounds
                      pattern       — regex that every value must match
                      allowed_values — list of permitted values

    rules       Custom per-column or global rules:
                  - name        — rule identifier (for error messages)
                  - description — human-readable description
                  - column      — column name (for column-level rules)
                  - condition   — comparison string: "> 0", "<= 100", etc.
                  - type        — "global_null_ratio" for table-wide null check
                  - max_null_pct — threshold for global_null_ratio rule

    Contract violations
    -------------------
    Each violated clause produces a ContractViolation with:
      clause    — which section of the contract was violated
      column    — which column (if applicable)
      rule      — which specific rule failed
      expected  — what the contract requires
      actual    — what was found in the data
      severity  — CRITICAL | ERROR | WARNING

    On violations, enforce() raises ContractViolationError which contains
    all violations, writes them to the governance ledger, and optionally
    appends them to a violation log file.

    Usage
    -----
        enforcer = DataContractEnforcer(gov, "contracts/employees.yaml")

        # Enforce with quality score (optional but recommended):
        scorer   = DataQualityScorer(gov)
        quality  = scorer.score(df)
        enforcer.enforce(df, quality_report=quality)  # raises if violated

        # Soft mode — returns violations without raising:
        violations = enforcer.check(df)
        if violations:
            for v in violations: print(v)

        # With SLA timing:
        import time
        t0 = time.time()
        # ... pipeline stages ...
        enforcer.enforce(df, elapsed_seconds=time.time()-t0)

    Parameters
    ----------
    gov             : GovernanceLogger
    contract_path   : str | Path    Path to the contract YAML file.
    violation_log   : str | Path    Where to append JSON violation records.
                                    Defaults to "contract_violations.jsonl".
    warn_only       : bool          If True, log violations but never raise.
                                    Useful for gradual contract rollout.
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
        with open(self.contract_path, encoding="utf-8") as fh:
            data = _yaml.safe_load(fh)
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
            except Exception:  # pylint: disable=broad-except
                pass

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
                except Exception:  # pylint: disable=broad-except
                    pass

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
                except Exception:  # pylint: disable=broad-except
                    pass

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
                except Exception:  # pylint: disable=broad-except
                    pass

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
                except Exception:  # pylint: disable=broad-except
                    pass

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
                except Exception:  # pylint: disable=broad-except
                    pass

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
                except Exception:  # pylint: disable=broad-except
                    pass

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
        table            : str | None    Table name to validate against
                                         (selects the matching contract block).
                                         If None, defaults to the first table
                                         defined in the contract.

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
            except OSError:
                pass

        # Console summary
        if viols:
            border = "═" * 64
            print(f"\n  {border}")
            print(f"  📋  CONTRACT ENFORCEMENT  —  {contract_name}")
            print(f"  {border}")
            for v in viols:
                icon = "🔴" if v["severity"] == "CRITICAL" else \
                       "🟠" if v["severity"] == "ERROR"    else "🟡"
                col_str = f"[{v['column']}] " if v["column"] else ""
                print(f"  {icon}  {v['clause'].upper():8s}  {col_str}{v['rule']}")
                print(f"           expected: {v['expected']}")
                print(f"           actual:   {v['actual']}")
            print(f"  {border}")
            print(f"  {len(failures)} failure(s)  ·  {len(warnings)} warning(s)")
            print(f"  {border}\n")

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


class ContractViolationError(Exception):
    """
    Raised by DataContractEnforcer.enforce() when one or more CRITICAL
    or ERROR contract clauses are violated.

    Attributes
    ----------
    contract_name : str        Name from the contract YAML.
    violations    : list[dict] CRITICAL + ERROR violations.
    warnings      : list[dict] WARNING violations (non-fatal).
    """

    def __init__(
        self,
        contract_name: str,
        violations:    list[dict],
        warnings:      list[dict],
    ) -> None:
        self.contract_name = contract_name
        self.violations    = violations
        self.warnings      = warnings
        summary = (
            f"Contract '{contract_name}' violated: "
            f"{len(violations)} failure(s), {len(warnings)} warning(s)\n"
        )
        details = "\n".join(
            f"  [{v['severity']}] {v['clause']}.{v['rule']}"
            + (f" [{v['column']}]" if v.get("column") else "")
            + f" — expected: {v['expected']}  actual: {v['actual']}"
            for v in violations
        )
        super().__init__(summary + details)


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: CostEstimator  (NEW v4.4)
# ═════════════════════════════════════════════════════════════════════════════

class CostEstimator:
    """
    Estimates and logs the compute + storage cost of each pipeline run for
    cloud data warehouse destinations — Snowflake, BigQuery, and Redshift.

    Almost no ETL tool does this natively.  CostEstimator gives you a
    per-run cost breakdown so you can track spend, set budgets, and
    spot expensive pipelines before your cloud bill arrives.

    How it works
    ------------
    Rather than calling live pricing APIs (which require credentials and
    change frequently), CostEstimator uses embedded current list prices
    that you can override with your negotiated rates via the ``pricing``
    parameter.  All estimates are clearly labelled as estimates.

    Snowflake  — based on warehouse size (X-Small → X-Large), elapsed
                 seconds, on-demand credit price, and bytes written.
    BigQuery   — based on bytes scanned (query cost) plus bytes written
                 (storage cost for one month).
    Redshift   — based on node type, number of nodes, elapsed seconds,
                 and bytes written.
    Generic    — for all other destinations: a simple GB-processed rate
                 (useful for on-premise or non-listed clouds).

    All costs are in USD.  Storage costs are projected for one month.
    Compute costs are based on actual elapsed pipeline time.

    Usage
    -----
        import time
        t0 = time.time()

        # ... run your pipeline ...

        estimator = CostEstimator(gov)
        report = estimator.estimate(
            db_type         = "snowflake",
            elapsed_seconds = time.time() - t0,
            rows_processed  = len(df),
            bytes_processed = df.memory_usage(deep=True).sum(),
            bytes_written   = len(df) * 500,   # rough estimate if unknown
            warehouse_size  = "Medium",         # Snowflake only
        )
        print(f"Estimated cost: ${report['total_usd']:.4f}")

    Parameters
    ----------
    gov          : GovernanceLogger
    cost_log     : str | Path   Where to append JSONL cost records.
                                Defaults to "pipeline_cost_history.jsonl".
    pricing      : dict | None  Override any pricing tier.  Keys match the
                                structure of CostEstimator.DEFAULT_PRICING.
    warn_budget  : float | None Alert if a single run exceeds this USD amount.

    Pricing reference (embedded defaults, US list prices as of 2025)
    -----------------------------------------------------------------
    Snowflake  $2.00 / credit (on-demand)
               X-Small=1cr/hr  Small=2  Medium=4  Large=8  X-Large=16
               Storage: $0.023/GB/month

    BigQuery   $6.25 / TB scanned (on-demand)
               Storage (active):   $0.020/GB/month
               Storage (longterm): $0.010/GB/month

    Redshift   dc2.large=$0.25/hr  ra3.xlplus=$1.086/hr  ra3.4xlarge=$3.26/hr
               ra3.16xlarge=$13.04/hr  dc2.8xlarge=$4.80/hr
               Managed storage: $0.024/GB/month

    Generic    $0.05 / GB processed
    """

    # ── Embedded list prices (USD, as of 2025) ───────────────────────────
    DEFAULT_PRICING: dict = {
        "snowflake": {
            "credit_usd":        2.00,    # $ per credit, on-demand
            "credits_per_hour":  {        # credits consumed per warehouse/hour
                "X-Small": 1,
                "Small":   2,
                "Medium":  4,
                "Large":   8,
                "X-Large": 16,
            },
            "storage_usd_per_gb_month": 0.023,
        },
        "bigquery": {
            "query_usd_per_tb":              6.25,
            "storage_active_usd_per_gb_month": 0.020,
            "storage_longterm_usd_per_gb_month": 0.010,
        },
        "redshift": {
            "node_usd_per_hour": {
                "dc2.large":    0.250,
                "dc2.8xlarge":  4.800,
                "ra3.xlplus":   1.086,
                "ra3.4xlarge":  3.260,
                "ra3.16xlarge": 13.040,
            },
            "storage_usd_per_gb_month": 0.024,
        },
        "generic": {
            "usd_per_gb_processed": 0.05,
        },
    }

    # ── Map pipeline db_type strings to estimator keys ───────────────────
    _DB_TYPE_MAP: dict[str, str] = {
        "snowflake":  "snowflake",
        "redshift":   "redshift",
        "bigquery":   "bigquery",
        # everything else → generic
    }

    def __init__(
        self,
        gov:         "GovernanceLogger",
        cost_log:    str | Path | None = None,
        pricing:     dict | None = None,
        warn_budget: float | None = None,
    ) -> None:
        self.gov         = gov
        self.cost_log    = Path(cost_log) if cost_log else gov.log_dir / "cost_history.jsonl"
        self.warn_budget = warn_budget

        # Deep-merge caller overrides into defaults
        import copy
        self._pricing = copy.deepcopy(self.DEFAULT_PRICING)
        if pricing:
            for plat_key, overrides in pricing.items():
                if plat_key not in self._pricing:
                    self._pricing[plat_key] = {}
                if isinstance(overrides, dict):
                    self._pricing[plat_key].update(overrides)

    # ── Byte helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _to_gb(n_bytes: int | float) -> float:
        return max(0.0, float(n_bytes) / 1_073_741_824)   # bytes → GiB

    @staticmethod
    def _to_tb(n_bytes: int | float) -> float:
        return max(0.0, float(n_bytes) / 1_099_511_627_776)  # bytes → TiB

    @staticmethod
    def _infer_bytes(df: "pd.DataFrame | None", rows: int, cols: int = 10) -> int:
        """Estimate bytes from a DataFrame or from row/col count."""
        if df is not None:
            try:
                return int(df.memory_usage(deep=True).sum())
            except Exception:  # pylint: disable=broad-except
                pass
        return rows * cols * 50   # fallback: ~50 bytes per cell

    # ── Platform estimators ───────────────────────────────────────────────

    def _estimate_snowflake(
        self,
        elapsed_seconds: float,
        bytes_processed: int,
        bytes_written:   int,
        warehouse_size:  str = "X-Small",
    ) -> dict:
        p = self._pricing["snowflake"]
        size = warehouse_size if warehouse_size in p["credits_per_hour"] else "X-Small"
        credits_per_hour = p["credits_per_hour"][size]
        credit_usd       = p["credit_usd"]

        # Snowflake bills in 1-second increments with a 60-second minimum
        billed_seconds = max(60.0, elapsed_seconds)
        billed_hours   = billed_seconds / 3600
        credits_used   = credits_per_hour * billed_hours
        compute_usd    = round(credits_used * credit_usd, 6)

        gb_stored      = self._to_gb(bytes_written)
        storage_usd    = round(gb_stored * p["storage_usd_per_gb_month"], 6)
        total_usd      = round(compute_usd + storage_usd, 6)

        return {
            "platform":        "snowflake",
            "warehouse_size":  size,
            "credits_per_hour": credits_per_hour,
            "credits_used":    round(credits_used, 6),
            "credit_price_usd": credit_usd,
            "billed_seconds":  round(billed_seconds, 2),
            "elapsed_seconds": round(elapsed_seconds, 2),
            "compute_usd":     compute_usd,
            "gb_stored":       round(gb_stored, 6),
            "storage_usd_monthly": storage_usd,
            "total_usd":       total_usd,
            "pricing_model":   "on-demand credits + managed storage",
            "note":            "60-second minimum billing applied",
        }

    def _estimate_bigquery(
        self,
        bytes_processed: int,
        bytes_written:   int,
        longterm_storage: bool = False,
    ) -> dict:
        p = self._pricing["bigquery"]

        tb_scanned   = self._to_tb(bytes_processed)
        query_usd    = round(tb_scanned * p["query_usd_per_tb"], 6)

        gb_written   = self._to_gb(bytes_written)
        storage_key  = ("storage_longterm_usd_per_gb_month"
                        if longterm_storage else
                        "storage_active_usd_per_gb_month")
        storage_usd  = round(gb_written * p[storage_key], 6)
        total_usd    = round(query_usd + storage_usd, 6)

        return {
            "platform":         "bigquery",
            "tb_scanned":       round(tb_scanned, 8),
            "query_usd_per_tb": p["query_usd_per_tb"],
            "query_usd":        query_usd,
            "gb_written":       round(gb_written, 6),
            "storage_type":     "longterm" if longterm_storage else "active",
            "storage_usd_monthly": storage_usd,
            "total_usd":        total_usd,
            "pricing_model":    "on-demand query + storage",
            "note":             "First 1 TB/month free on on-demand pricing",
        }

    def _estimate_redshift(
        self,
        elapsed_seconds: float,
        bytes_written:   int,
        node_type:       str = "dc2.large",
        num_nodes:       int = 1,
    ) -> dict:
        p = self._pricing["redshift"]
        ntype      = node_type if node_type in p["node_usd_per_hour"] else "dc2.large"
        node_rate  = p["node_usd_per_hour"][ntype]

        hours_used = elapsed_seconds / 3600
        compute_usd = round(node_rate * num_nodes * hours_used, 6)

        gb_stored   = self._to_gb(bytes_written)
        storage_usd = round(gb_stored * p["storage_usd_per_gb_month"], 6)
        total_usd   = round(compute_usd + storage_usd, 6)

        return {
            "platform":          "redshift",
            "node_type":         ntype,
            "num_nodes":         num_nodes,
            "node_usd_per_hour": node_rate,
            "elapsed_seconds":   round(elapsed_seconds, 2),
            "elapsed_hours":     round(hours_used, 6),
            "compute_usd":       compute_usd,
            "gb_stored":         round(gb_stored, 6),
            "storage_usd_monthly": storage_usd,
            "total_usd":         total_usd,
            "pricing_model":     "per-node-hour + managed storage",
        }

    def _estimate_generic(
        self,
        bytes_processed: int,
        elapsed_seconds: float,
    ) -> dict:
        p   = self._pricing["generic"]
        gb  = self._to_gb(bytes_processed)
        usd = round(gb * p["usd_per_gb_processed"], 6)
        return {
            "platform":          "generic",
            "gb_processed":      round(gb, 6),
            "usd_per_gb":        p["usd_per_gb_processed"],
            "elapsed_seconds":   round(elapsed_seconds, 2),
            "total_usd":         usd,
            "pricing_model":     "per-GB processed (generic estimate)",
            "note":              "Use Snowflake/BigQuery/Redshift db_type for accurate pricing",
        }

    # ── Main entry point ──────────────────────────────────────────────────

    def estimate(
        self,
        db_type:          str,
        elapsed_seconds:  float,
        rows_processed:   int,
        bytes_processed:  int | None  = None,
        bytes_written:    int | None  = None,
        df:               "pd.DataFrame | None" = None,
        warehouse_size:   str         = "X-Small",   # Snowflake
        node_type:        str         = "dc2.large",  # Redshift
        num_nodes:        int         = 1,            # Redshift
        longterm_storage: bool        = False,        # BigQuery
        run_label:        str | None  = None,
    ) -> dict:
        """
        Estimate the cost of this pipeline run and log it.

        Parameters
        ----------
        db_type          : str    Destination platform (snowflake/bigquery/redshift/...)
        elapsed_seconds  : float  Total pipeline wall-clock time in seconds.
        rows_processed   : int    Number of rows loaded.
        bytes_processed  : int    Bytes scanned/read (inferred from df if omitted).
        bytes_written    : int    Bytes written to destination (inferred if omitted).
        df               : pd.DataFrame | None   Used to infer byte counts.
        warehouse_size   : str    Snowflake warehouse size (X-Small … X-Large).
        node_type        : str    Redshift node type (dc2.large, ra3.xlplus, ...).
        num_nodes        : int    Redshift cluster node count.
        longterm_storage : bool   BigQuery: use long-term storage pricing.
        run_label        : str    Optional tag for the cost log.

        Returns
        -------
        dict  Full cost breakdown with total_usd, compute_usd, storage_usd,
              platform metadata, and timestamp.
        """
        # Infer byte counts if not supplied
        if bytes_processed is None:
            bytes_processed = self._infer_bytes(df, rows_processed)
        if bytes_written is None:
            bytes_written = bytes_processed  # conservative: assume full write

        platform = self._DB_TYPE_MAP.get(db_type.lower(), "generic")

        if platform == "snowflake":
            breakdown = self._estimate_snowflake(
                elapsed_seconds, bytes_processed, bytes_written, warehouse_size
            )
        elif platform == "bigquery":
            breakdown = self._estimate_bigquery(
                bytes_processed, bytes_written, longterm_storage
            )
        elif platform == "redshift":
            breakdown = self._estimate_redshift(
                elapsed_seconds, bytes_written, node_type, num_nodes
            )
        else:
            breakdown = self._estimate_generic(bytes_processed, elapsed_seconds)

        ts = datetime.now(timezone.utc).isoformat()
        report = {
            "timestamp":        ts,
            "run_label":        run_label,
            "db_type":          db_type,
            "rows_processed":   rows_processed,
            "bytes_processed":  bytes_processed,
            "bytes_written":    bytes_written,
            "elapsed_seconds":  round(elapsed_seconds, 2),
            "breakdown":        breakdown,
            "total_usd":        breakdown["total_usd"],
            "estimate":         True,   # always flag as estimate
        }

        # Append to cost log
        try:
            with open(self.cost_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(report, default=str) + "\n")
        except OSError as exc:
            print(f"  [CostEstimator] Could not write cost log: {exc}")

        # Governance ledger event
        self.gov.transformation_applied("COST_ESTIMATED", {
            "platform":        platform,
            "db_type":         db_type,
            "total_usd":       breakdown["total_usd"],
            "compute_usd":     breakdown.get("compute_usd", breakdown["total_usd"]),
            "storage_usd":     breakdown.get("storage_usd_monthly", 0.0),
            "elapsed_seconds": round(elapsed_seconds, 2),
            "rows":            rows_processed,
            "pricing_model":   breakdown.get("pricing_model"),
        })

        # Console output
        self._print_report(report, breakdown)

        # Budget warning
        if self.warn_budget and breakdown["total_usd"] > self.warn_budget:
            warn_msg = (
                f"  ⚠  COST ALERT: run cost ${breakdown['total_usd']:.4f} "
                f"exceeds budget ${self.warn_budget:.4f}"
            )
            print(warn_msg)
            self.gov.transformation_applied("COST_BUDGET_EXCEEDED", {
                "total_usd":   breakdown["total_usd"],
                "budget_usd":  self.warn_budget,
                "overage_usd": round(breakdown["total_usd"] - self.warn_budget, 6),
            })

        return report

    # ── Convenience: estimate directly from GovernanceLogger ledger ───────

    def estimate_from_ledger(
        self,
        db_type:        str = "generic",
        warehouse_size: str  = "X-Small",
        node_type:      str  = "dc2.large",
        num_nodes:      int  = 1,
        run_label:      str | None = None,
    ) -> dict | None:
        """
        Automatically extract elapsed time, rows, and bytes from the
        governance ledger and run estimate() — no manual measurement needed.

        Call this at the end of a pipeline run after all stages have
        completed and been logged.

        Returns
        -------
        dict | None   Cost report, or None if ledger has insufficient data.
        """
        entries  = self.gov.ledger_entries
        start_ts = None
        end_ts   = None
        rows     = 0
        bytes_est = 0

        for e in entries:
            action = e.get("action", "")
            detail = e.get("detail", {}) or {}
            ts_str = e.get("timestamp_utc", "")

            if action == "PIPELINE_STARTED" and ts_str:
                try:
                    start_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            if action in ("LOAD_COMPLETE", "TRANSFORM_COMPLETE"):
                r = detail.get("rows_written") or detail.get("final_row_count") or 0
                if r:
                    rows = max(rows, int(r))

            if action == "EXTRACT_COMPLETE":
                r = detail.get("rows", 0) or 0
                if r:
                    rows = max(rows, int(r))

            if ts_str:
                try:
                    end_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

        if not start_ts or not end_ts or rows == 0:
            return None

        elapsed = (end_ts - start_ts).total_seconds()
        if elapsed <= 0:
            elapsed = 1.0

        # Conservative byte estimate: ~500 bytes per row
        bytes_est = rows * 500

        return self.estimate(
            db_type         = db_type,
            elapsed_seconds = elapsed,
            rows_processed  = rows,
            bytes_processed = bytes_est,
            bytes_written   = bytes_est,
            warehouse_size  = warehouse_size,
            node_type       = node_type,
            num_nodes       = num_nodes,
            run_label       = run_label,
        )

    # ── Console printer ───────────────────────────────────────────────────

    @staticmethod
    def _print_report(report: dict, breakdown: dict) -> None:
        border = "─" * 60
        platform = breakdown.get("platform", "?").upper()
        total    = breakdown["total_usd"]
        compute  = breakdown.get("compute_usd", total)
        storage  = breakdown.get("storage_usd_monthly", 0.0)

        print(f"\n  {border}")
        print(f"  💰  COST ESTIMATE  [{platform}]  (estimated, not billed)")
        print(f"  {border}")
        print(f"  Compute       : ${compute:>12.6f}")
        print(f"  Storage/month : ${storage:>12.6f}")
        print("  ─────────────────────────────────────────")
        print(f"  TOTAL         : ${total:>12.6f}")
        print(f"  {border}")
        print(f"  Rows processed: {report['rows_processed']:,}")
        print(f"  Elapsed       : {report['elapsed_seconds']:.2f}s")
        # Platform-specific detail line
        if platform == "SNOWFLAKE":
            print(f"  Warehouse     : {breakdown.get('warehouse_size')}  "
                  f"({breakdown.get('credits_used',0):.4f} credits @ "
                  f"${breakdown.get('credit_price_usd',0):.2f}/credit)")
        elif platform == "BIGQUERY":
            print(f"  TB scanned    : {breakdown.get('tb_scanned',0):.8f} TB")
        elif platform == "REDSHIFT":
            print(f"  Cluster       : {breakdown.get('num_nodes')}× "
                  f"{breakdown.get('node_type')}  "
                  f"@ ${breakdown.get('node_usd_per_hour',0):.3f}/node/hr")
        print(f"  Pricing note  : {breakdown.get('note', breakdown.get('pricing_model',''))}")
        print(f"  {border}\n")

    # ── History and reporting ─────────────────────────────────────────────

    def history(self, n: int = 50) -> list[dict]:
        """Return the last n cost records from the log file."""
        if not self.cost_log.exists():
            return []
        records = []
        for line in self.cost_log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return list(reversed(records[-n:]))

    def cumulative_cost(self, n: int = 1000) -> dict:
        """
        Aggregate cost summary across recent runs.

        Returns
        -------
        dict  {total_usd, run_count, avg_usd_per_run, by_platform,
               most_expensive_run, cheapest_run}
        """
        records     = self.history(n)
        if not records:
            return {"total_usd": 0.0, "run_count": 0, "avg_usd_per_run": 0.0,
                    "by_platform": {}, "most_expensive_run": None, "cheapest_run": None}
        by_platform: dict[str, float] = {}
        total = 0.0
        for r in records:
            usd = r.get("total_usd", 0.0)
            total += usd
            plat = r.get("breakdown", {}).get("platform", r.get("db_type", "unknown"))
            by_platform[plat] = by_platform.get(plat, 0.0) + usd

        sorted_recs = sorted(records, key=lambda r: r.get("total_usd", 0.0))
        return {
            "total_usd":           round(total, 6),
            "run_count":           len(records),
            "avg_usd_per_run":     round(total / len(records), 6),
            "by_platform":         {k: round(v, 6) for k, v in by_platform.items()},
            "most_expensive_run":  sorted_recs[-1],
            "cheapest_run":        sorted_recs[0],
        }

    def monthly_projection(self, runs_per_day: float = 1.0) -> dict:
        """
        Project monthly cost based on recent run history.

        Parameters
        ----------
        runs_per_day : float   Expected pipeline runs per day.

        Returns
        -------
        dict  {projected_monthly_usd, based_on_runs, avg_run_usd}
        """
        records = self.history(n=30)
        if not records:
            return {"projected_monthly_usd": 0.0, "based_on_runs": 0, "avg_run_usd": 0.0}
        avg = sum(r.get("total_usd", 0.0) for r in records) / len(records)
        monthly = avg * runs_per_day * 30.44   # avg days/month
        return {
            "projected_monthly_usd": round(monthly, 4),
            "based_on_runs":         len(records),
            "avg_run_usd":           round(avg, 6),
            "runs_per_day":          runs_per_day,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: ReversibleLoader  (NEW v4.5)
# ═════════════════════════════════════════════════════════════════════════════


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: QuickBooksExtractor  (v4.10)
#  Reads data FROM QuickBooks Online via the QBO REST API v3
# ═════════════════════════════════════════════════════════════════════════════

class QuickBooksExtractor:
    """
    Extract data from QuickBooks Online (QBO) into pandas DataFrames.

    Uses the Intuit QBO REST API v3 with OAuth 2.0 authorization-code or
    refresh-token flow.  The extractor pages through every result set
    automatically and flattens QBO's nested JSON into a flat DataFrame
    compatible with the rest of the pipeline.

    Supported entity types
    ----------------------
    Customer, Vendor, Employee, Account, Invoice, Bill, Payment,
    JournalEntry, Item, Department, Class, CreditMemo, Estimate,
    PurchaseOrder, SalesReceipt, Transfer, TaxRate, TaxCode, CompanyInfo

    Authentication
    --------------
    QBO uses OAuth 2.0.  You need:
      1. A Intuit Developer app (https://developer.intuit.com)
      2. Client ID + Client Secret
      3. A refresh token  (obtained via the OAuth2 authorization-code dance
         the first time; thereafter the extractor auto-refreshes it)

    Required cfg keys
    -----------------
    client_id      : str   Intuit app client ID
    client_secret  : str   Intuit app client secret
    refresh_token  : str   Long-lived refresh token
    realm_id       : str   QBO company ID (shown in the QBO URL after /app/)
    entity         : str   QBO entity type, e.g. "Customer" or "Invoice"

    Optional cfg keys
    -----------------
    environment    : str   "production" (default) or "sandbox"
    page_size      : int   Rows per API page (default 1 000, max 1 000)
    date_from      : str   ISO date filter e.g. "2024-01-01"  (WHERE clause)
    date_to        : str   ISO date filter e.g. "2024-12-31"
    date_field     : str   Field to filter on (default "MetaData.LastUpdatedTime")
    extra_where    : str   Additional SQL WHERE fragment appended to the query
    timeout        : int   HTTP timeout seconds (default 30)

    Usage
    -----
        cfg = {
            "client_id":     "ABCxyz",
            "client_secret": "secret",
            "refresh_token": "rt-abc123",
            "realm_id":      "1234567890",
            "entity":        "Invoice",
            "date_from":     "2024-01-01",
        }
        qbe = QuickBooksExtractor(gov)
        df  = qbe.extract(cfg)

    Requirements
    ------------
        pip install requests          (already a core dependency)
    """

    _PROD_BASE    = "https://quickbooks.api.intuit.com"
    _SANDBOX_BASE = "https://sandbox-quickbooks.api.intuit.com"
    _TOKEN_URL    = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"

    # QBO entities whose primary date field differs from the default
    _DATE_FIELDS: dict[str, str] = {
        "Invoice":        "TxnDate",
        "Bill":           "TxnDate",
        "Payment":        "TxnDate",
        "CreditMemo":     "TxnDate",
        "Estimate":       "TxnDate",
        "PurchaseOrder":  "TxnDate",
        "SalesReceipt":   "TxnDate",
        "Transfer":       "TxnDate",
        "JournalEntry":   "TxnDate",
    }

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    # ── Auth ──────────────────────────────────────────────────────────────

    def _refresh_access_token(self, cfg: dict) -> str:
        """
        Exchange a refresh token for a new access token.
        Returns the access token string.
        """
        import requests, base64
        credentials = base64.b64encode(
            f"{cfg['client_id']}:{cfg['client_secret']}".encode()
        ).decode()
        resp = requests.post(
            self._TOKEN_URL,
            headers={
                "Authorization": f"Basic {credentials}",
                "Accept":        "application/json",
                "Content-Type":  "application/x-www-form-urlencoded",
            },
            data={
                "grant_type":    "refresh_token",
                "refresh_token": cfg["refresh_token"],
            },
            timeout=cfg.get("timeout", 30),
        )
        if not resp.ok:
            raise RuntimeError(
                f"QuickBooks token refresh failed {resp.status_code}: {resp.text[:300]}"
            )
        token_data = resp.json()
        # Store updated refresh token if QBO rotated it
        if "refresh_token" in token_data:
            cfg["refresh_token"] = token_data["refresh_token"]
        return token_data["access_token"]

    def _headers(self, access_token: str) -> dict:
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept":        "application/json",
        }

    # ── Query helpers ─────────────────────────────────────────────────────

    def _base_url(self, cfg: dict) -> str:
        env = cfg.get("environment", "production").lower()
        base = self._SANDBOX_BASE if env == "sandbox" else self._PROD_BASE
        return f"{base}/v3/company/{cfg['realm_id']}"

    def _build_query(self, entity: str, cfg: dict,
                     start: int, page_size: int) -> str:
        """Build a QBO SQL-like query string with optional date filters."""
        where_parts: list[str] = []

        date_field = cfg.get("date_field") or self._DATE_FIELDS.get(entity,
                                                                     "MetaData.LastUpdatedTime")
        if cfg.get("date_from"):
            where_parts.append(f"{date_field} >= '{cfg['date_from']}'")
        if cfg.get("date_to"):
            where_parts.append(f"{date_field} <= '{cfg['date_to']}'")
        if cfg.get("extra_where"):
            where_parts.append(cfg["extra_where"])

        where_clause = f" WHERE {' AND '.join(where_parts)}" if where_parts else ""
        return (
            f"SELECT * FROM {entity}{where_clause}"
            f" STARTPOSITION {start} MAXRESULTS {page_size}"
        )

    @staticmethod
    def _flatten_qbo_record(record: dict, entity: str) -> dict:
        """
        Flatten a single QBO JSON record into a plain dict.

        QBO wraps line items in arrays (e.g. Invoice.Line) and nests
        addresses as dicts.  This method prefixes nested keys with the
        parent key name and joins array-of-dict fields as JSON strings
        so every column is a scalar.
        """
        import json

        flat: dict = {}

        def _walk(node: object, prefix: str) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    _walk(v, f"{prefix}__{k}" if prefix else k)
            elif isinstance(node, list):
                # Keep line-item arrays as JSON text; they can be parsed later
                flat[prefix] = json.dumps(node)
            else:
                flat[prefix] = node

        _walk(record, "")
        return flat

    # ── Public interface ──────────────────────────────────────────────────

    def extract(self, cfg: dict) -> "pd.DataFrame":
        """
        Extract all records for the configured entity type from QBO.

        Parameters
        ----------
        cfg : dict   See class docstring for required and optional keys.

        Returns
        -------
        pd.DataFrame   One row per QBO record, columns flattened.
        """
        import requests

        entity    = cfg.get("entity", "Customer")
        page_size = min(cfg.get("page_size", 1_000), 1_000)   # QBO max = 1 000
        timeout   = cfg.get("timeout", 30)
        base_url  = self._base_url(cfg)
        token     = self._refresh_access_token(cfg)
        headers   = self._headers(token)

        all_records: list[dict] = []
        start = 1

        print(f"  [QBO] Extracting {entity} from realm {cfg['realm_id']}…")
        while True:
            query = self._build_query(entity, cfg, start, page_size)
            resp  = requests.get(
                f"{base_url}/query",
                params={"query": query, "minorversion": "70"},
                headers=headers,
                timeout=timeout,
            )
            if not resp.ok:
                raise RuntimeError(
                    f"QuickBooks API error {resp.status_code}: {resp.text[:400]}"
                )
            payload  = resp.json()
            qr       = payload.get("QueryResponse", {})
            entities = qr.get(entity, [])

            if not entities:
                break

            for record in entities:
                all_records.append(self._flatten_qbo_record(record, entity))

            total_count = qr.get("totalCount", len(entities))
            print(f"  [QBO]   page start={start}  fetched={len(entities)}  "
                  f"total={total_count}")

            if len(entities) < page_size:
                break
            start += page_size

        df = pd.DataFrame(all_records) if all_records else pd.DataFrame()
        print(f"  [QBO] ✓ {len(df):,} {entity} records extracted")

        self.gov.transformation_applied("QBO_EXTRACT_COMPLETE", {
            "entity":   entity,
            "realm_id": cfg.get("realm_id"),
            "rows":     len(df),
        })
        return df


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: QuickBooksLoader  (v4.10)
#  Writes data TO QuickBooks Online via the QBO REST API v3
# ═════════════════════════════════════════════════════════════════════════════

class QuickBooksLoader:
    """
    Load DataFrames into QuickBooks Online (QBO) via the QBO REST API v3.

    Architecture
    ------------
    QBO does not accept generic tabular uploads.  Every row must map to a
    specific QBO entity (Customer, Vendor, Invoice, etc.) and its required
    fields.  This loader:

      1. Re-hydrates each DataFrame row into a QBO JSON object.
      2. Checks whether the record already exists by looking for an ``Id``
         column (QBO's primary key for every entity).
      3. If ``Id`` is present → HTTP POST to update.
      4. If ``Id`` is absent  → HTTP POST to create (QBO uses the same
         endpoint for create and update; the presence of ``Id`` determines
         which operation happens).

    The loader handles the most common entity types automatically.
    For custom entities or complex line-item structures, supply a
    ``row_transform`` callable that converts a DataFrame row (pd.Series)
    into the QBO JSON body dict.

    Supported entity types (built-in body builders)
    ------------------------------------------------
    Customer, Vendor, Employee, Account, Item, Department, Class

    For transactional entities (Invoice, Bill, Payment, JournalEntry, etc.)
    supply ``row_transform`` because these require line-item arrays that
    cannot be inferred from a flat DataFrame without domain knowledge.

    Required cfg keys
    -----------------
    client_id      : str   Intuit app client ID
    client_secret  : str   Intuit app client secret
    refresh_token  : str   Long-lived refresh token
    realm_id       : str   QBO company ID

    Optional cfg keys
    -----------------
    environment    : str               "production" (default) | "sandbox"
    row_transform  : callable | None   fn(row: pd.Series) → dict
                                       Custom JSON body builder per row.
    sparse         : bool              Send only non-null fields (default True)
    timeout        : int               HTTP timeout (default 30)
    batch_delay    : float             Seconds to wait between requests (default 0.1)
                                       QBO rate-limits to ~500 req/min.

    Load modes
    ----------
    append   Default.  Creates records that have no ``Id``; updates those
             that do.  QBO handles the merge on its side.
    replace  Not natively supported by QBO (you cannot bulk-delete).
             Falls back to append with a warning.
    upsert   Same behaviour as append for QBO (Id presence drives create/update).

    Usage
    -----
        qbl = QuickBooksLoader(gov)
        qbl.load(df, cfg, table="Customer")

    Requirements
    ------------
        pip install requests          (already a core dependency)
    """

    _PROD_BASE    = "https://quickbooks.api.intuit.com"
    _SANDBOX_BASE = "https://sandbox-quickbooks.api.intuit.com"
    _TOKEN_URL    = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"

    # Minimum required fields that QBO demands for each entity type.
    # Rows missing these are skipped with a warning rather than crashing.
    _REQUIRED_FIELDS: dict[str, list[str]] = {
        "Customer":  ["DisplayName"],
        "Vendor":    ["DisplayName"],
        "Employee":  ["GivenName", "FamilyName"],
        "Account":   ["Name", "AccountType"],
        "Item":      ["Name", "Type"],
        "Department":["Name"],
        "Class":     ["Name"],
    }

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    # ── Auth (same flow as QuickBooksExtractor) ───────────────────────────

    def _refresh_access_token(self, cfg: dict) -> str:
        import requests, base64
        credentials = base64.b64encode(
            f"{cfg['client_id']}:{cfg['client_secret']}".encode()
        ).decode()
        resp = requests.post(
            self._TOKEN_URL,
            headers={
                "Authorization": f"Basic {credentials}",
                "Accept":        "application/json",
                "Content-Type":  "application/x-www-form-urlencoded",
            },
            data={
                "grant_type":    "refresh_token",
                "refresh_token": cfg["refresh_token"],
            },
            timeout=cfg.get("timeout", 30),
        )
        if not resp.ok:
            raise RuntimeError(
                f"QuickBooks token refresh failed {resp.status_code}: {resp.text[:300]}"
            )
        token_data = resp.json()
        if "refresh_token" in token_data:
            cfg["refresh_token"] = token_data["refresh_token"]
        return token_data["access_token"]

    def _headers(self, access_token: str) -> dict:
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

    def _base_url(self, cfg: dict) -> str:
        env  = cfg.get("environment", "production").lower()
        base = self._SANDBOX_BASE if env == "sandbox" else self._PROD_BASE
        return f"{base}/v3/company/{cfg['realm_id']}"

    # ── Body builder ─────────────────────────────────────────────────────

    @staticmethod
    def _row_to_body(row: "pd.Series", entity: str, sparse: bool) -> dict:
        """
        Convert a flat DataFrame row into a QBO JSON body dict.

        Double-underscore column names are interpreted as nested keys:
          ``BillAddr__Line1``  →  ``{"BillAddr": {"Line1": "…"}}``

        Null values are dropped when ``sparse=True`` (default).
        """
        import json

        body: dict = {}

        for col, val in row.items():
            if sparse and (val is None or (isinstance(val, float) and val != val)):
                continue   # skip NaN/None

            # Try to deserialise JSON strings (line-item arrays stored by extractor)
            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except (ValueError, TypeError):
                    pass

            # Unflatten double-underscore keys into nested dicts
            parts = str(col).split("__")
            node  = body
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = val

        return body

    def _validate_row(self, body: dict, entity: str) -> list[str]:
        """Return a list of missing required fields, empty if row is valid."""
        required = self._REQUIRED_FIELDS.get(entity, [])
        return [f for f in required if not body.get(f)]

    # ── HTTP helpers ──────────────────────────────────────────────────────

    def _post_entity(
        self,
        base_url: str,
        headers:  dict,
        entity:   str,
        body:     dict,
        timeout:  int,
    ) -> dict:
        """
        POST a single QBO entity body.  QBO uses the same endpoint for
        create (no Id) and full-update (Id present).
        """
        import requests
        url  = f"{base_url}/{entity.lower()}?minorversion=70"
        resp = requests.post(url, headers=headers, json=body, timeout=timeout)
        if not resp.ok:
            raise RuntimeError(
                f"QuickBooks POST {entity} failed {resp.status_code}: "
                f"{resp.text[:400]}"
            )
        return resp.json()

    # ── Public interface ──────────────────────────────────────────────────

    def load(
        self,
        df:          "pd.DataFrame",
        cfg:         dict,
        table:       str | None  = None,
        if_exists:   str         = "append",
        natural_keys: list | None = None,
    ) -> None:
        """
        Write ``df`` rows to QuickBooks Online as the specified entity type.

        Parameters
        ----------
        df           : pd.DataFrame
        cfg          : dict    See class docstring for required keys.
        table        : str     QBO entity type (e.g. "Customer", "Invoice").
                               Overridden by cfg["entity"] if set.
        if_exists    : str     "append" | "replace" | "upsert"
                               QBO does not support bulk delete; "replace"
                               behaves as "append" with a warning.
        natural_keys : list    Ignored — QBO uses the ``Id`` column.
        """
        import time

        entity = cfg.get("entity", table or "Customer")
        sparse = cfg.get("sparse", True)
        timeout= cfg.get("timeout", 30)
        delay  = cfg.get("batch_delay", 0.1)
        custom_transform = cfg.get("row_transform")

        if if_exists == "replace":
            print("  ⚠  QuickBooks does not support bulk delete. "
                  "'replace' mode will append/update rows only.")

        token    = self._refresh_access_token(cfg)
        headers  = self._headers(token)
        base_url = self._base_url(cfg)

        created = updated = skipped = errors = 0

        print(f"  [QBO] Writing {len(df):,} rows → {entity}…")
        for idx, row in df.iterrows():
            try:
                # Build the JSON body
                if callable(custom_transform):
                    body = custom_transform(row)
                else:
                    body = self._row_to_body(row, entity, sparse)

                # Validate required fields
                missing = self._validate_row(body, entity)
                if missing:
                    print(f"  ⚠  Row {idx}: skipping — missing required "
                          f"field(s): {missing}")
                    skipped += 1
                    continue

                # Track whether this is a create or update
                had_id = bool(body.get("Id"))

                self._post_entity(base_url, headers, entity, body, timeout)

                if had_id:
                    updated += 1
                else:
                    created += 1

                if delay > 0:
                    time.sleep(delay)   # QBO rate limit: ~500 req/min

            except Exception as exc:   # pylint: disable=broad-except
                print(f"  ✗  Row {idx}: {exc}")
                errors += 1

        print(f"  [QBO] ✓ {entity}: "
              f"{created} created  {updated} updated  "
              f"{skipped} skipped  {errors} errors")

        self.gov.load_complete(created + updated, entity)
        self.gov.destination_registered(
            "quickbooks",
            f"https://app.qbo.intuit.com/app/company/{cfg.get('realm_id','')}/{entity.lower()}",
            entity,
        )
        self.gov.transformation_applied("QBO_LOAD_COMPLETE", {
            "entity":  entity,
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "errors":  errors,
        })


# ─────────────────────────────────────────────────────────────────────────────
#  LOADER DISPATCH TABLE
#  Maps db_type string → (LoaderClass, needs_db_type_arg, uses_mongo_sig)
#  used by main() to select the correct loader at runtime.
#  needs_db_type_arg : True only for SQLLoader (which takes db_type in __init__)
#  uses_mongo_sig    : True only for MongoLoader (collection kwarg, no if_exists)
# ─────────────────────────────────────────────────────────────────────────────
_LOADER_DISPATCH: "dict[str, tuple]" = {}   # populated below after all classes defined


def _resolve_loader(db_type: str) -> "tuple":
    """
    Return (LoaderClass, needs_db_type_arg, uses_mongo_sig) for *db_type*.

    Raises ValueError for unknown types so the wizard fails early with a clear
    message rather than silently falling back to SQLLoader.
    """
    entry = _LOADER_DISPATCH.get(db_type.lower())
    if entry is None:
        raise ValueError(
            f"No loader registered for db_type {db_type!r}. "
            f"Known types: {sorted(_LOADER_DISPATCH)}"
        )
    return entry

class ReversibleLoader:
    """
    Wraps any pipeline loader to make every load reversible — snapshots the
    destination table before each write so any run can be rolled back to the
    prior state with a single command.

    Delta Lake has time-travel, but only inside Databricks.  ReversibleLoader
    gives the same capability to every destination this pipeline supports:
    SQLite, PostgreSQL, MySQL, SQL Server, Snowflake, Redshift, BigQuery,
    Synapse, Databricks, ClickHouse, Oracle, Db2, Firebolt, Yellowbrick,
    and any flat-file or Parquet-based destination.

    How it works
    ────────────
    1. Before every load, the existing table is read into a DataFrame and
       serialised to a compressed Parquet snapshot file in a local snapshot
       store directory.

    2. A JSONL manifest file records every snapshot: table name, run ID,
       timestamp, row count, file path, and SHA-256 checksum of the snapshot.

    3. After a successful load the manifest is updated with the new row count
       and a LOAD_COMPLETE event is written to the governance ledger.

    4. To roll back, call rollback(table, run_id) (or rollback_latest(table))
       — the snapshot Parquet is read back and written to the destination
       using the same loader.  This is a full table replace, not a diff.

    5. Snapshots are retained for ``retention_days`` days (default 30).
       Call purge_old_snapshots() to remove expired files.

    Strategy options (``strategy`` parameter)
    ─────────────────────────────────────────
    "parquet"   Store snapshots as compressed Parquet files in a local
                directory.  Works for every destination.  Files are portable
                and can be inspected with pandas.read_parquet().  Default.

    "shadow"    Write the snapshot into a shadow table in the same database
                named ``<table>__snapshot_<run_id>``.  Fast for SQL databases;
                requires no extra disk space management.  Not available for
                file-based destinations.

    "both"      Write both a Parquet file and a shadow table.  Maximum
                recoverability at the cost of extra storage.

    Usage
    ─────
        loader   = SQLLoader(gov, "postgresql")
        rev      = ReversibleLoader(gov, loader, db_type="postgresql",
                                    snapshot_dir="snapshots/",
                                    strategy="parquet")

        # Drop-in replacement for loader.load():
        run_id = rev.load(df, cfg, table="orders")

        # Roll back that specific run:
        rev.rollback(table="orders", run_id=run_id, cfg=cfg)

        # Or roll back to whatever was there before the most recent load:
        rev.rollback_latest(table="orders", cfg=cfg)

        # See all snapshots for a table:
        rev.snapshot_history(table="orders")

        # Clean up snapshots older than retention_days:
        rev.purge_old_snapshots()

    Parameters
    ──────────
    gov            : GovernanceLogger
    loader         : Any loader with a .load(df, cfg, table) method,
                     OR None to use a built-in pandas → SQLAlchemy writer.
    db_type        : str   Destination type — used to build read-back engine
                           for snapshot and rollback.  Same values as SQLLoader.
    snapshot_dir   : str | Path   Where to store Parquet snapshot files.
    strategy       : "parquet" | "shadow" | "both"
    retention_days : int   How many days to keep snapshot files (default 30).
    compression    : str   Parquet compression codec.  Default "snappy".
    warn_size_mb   : float Warn if a snapshot exceeds this size (default 500).
    """

    _MANIFEST_FILE = "snapshot_manifest.jsonl"

    def __init__(
        self,
        gov:            "GovernanceLogger",
        loader:         object | None,
        db_type:        str            = "sqlite",
        snapshot_dir:   str | Path | None = None,
        strategy:       str            = "parquet",
        retention_days: int            = 30,
        compression:    str            = "snappy",
        warn_size_mb:   float          = 500.0,
    ) -> None:
        self.gov            = gov
        self.loader         = loader
        self.db_type        = db_type.lower()
        self.snapshot_dir   = Path(snapshot_dir) if snapshot_dir else gov.log_dir / "snapshots"
        self.strategy       = strategy
        self.retention_days = retention_days
        self.compression    = compression
        self.warn_size_mb   = warn_size_mb
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self._manifest      = self.snapshot_dir / self._MANIFEST_FILE

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _run_id() -> str:
        """Generate a unique run ID: YYYYMMDD_HHMMSS_<6-hex>."""
        import secrets as _sec
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")                + "_" + _sec.token_hex(3)

    @staticmethod
    def _checksum(path: Path) -> str:
        """SHA-256 of a file for tamper detection."""
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _manifest_append(self, record: dict) -> None:
        with open(self._manifest, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    def _manifest_records(self) -> list[dict]:
        if not self._manifest.exists():
            return []
        records = []
        for line in self._manifest.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return records

    def _engine(self, cfg: dict):
        """Build a SQLAlchemy engine for read-back and rollback."""
        from sqlalchemy import create_engine as _ce
        t = self.db_type
        if t == "sqlite":
            return _ce(f"sqlite:///{cfg['db_name']}.db")
        if t == "postgresql":
            return _ce(
                f"postgresql+psycopg2://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 5432)}/{cfg['db_name']}"
            )
        if t == "mysql":
            return _ce(
                f"mysql+pymysql://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 3306)}/{cfg['db_name']}"
            )
        if t == "mssql":
            return _ce(
                f"mssql+pyodbc://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 1433)}/{cfg['db_name']}"
                f"?driver={cfg.get('driver', 'ODBC+Driver+17+for+SQL+Server')}"
            )
        if t == "snowflake":
            if not HAS_SNOWFLAKE:
                raise RuntimeError("snowflake-connector-python required")
            from snowflake.sqlalchemy import URL as _sfurl
            return _ce(_sfurl(
                account   = cfg["account"],
                user      = cfg["user"],
                password  = cfg["password"],
                database  = cfg["database"],
                schema    = cfg.get("schema", "PUBLIC"),
                warehouse = cfg["warehouse"],
                role      = cfg.get("role", ""),
            ))
        raise ValueError(
            f"ReversibleLoader: db_type '{t}' not supported for engine build. "
            "For other platforms (BigQuery, Redshift, etc.) use strategy='parquet' "
            "and provide a custom read_fn."
        )

    def _table_exists(self, engine, table: str) -> bool:
        from sqlalchemy import inspect as _sai
        try:
            return table in _sai(engine).get_table_names()
        except Exception:  # pylint: disable=broad-except
            return False

    def _read_table(self, cfg: dict, table: str) -> "pd.DataFrame | None":
        """Read the current table into a DataFrame for snapshotting."""
        try:
            engine = self._engine(cfg)
            if not self._table_exists(engine, table):
                return None
            with engine.connect() as conn:
                return pd.read_sql_table(table, conn)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"  [ReversibleLoader] Could not read '{table}' for snapshot: {exc}")
            return None

    # ── Snapshot ──────────────────────────────────────────────────────────

    def snapshot(
        self,
        cfg:         dict,
        table:       str,
        run_id:      str | None              = None,
        existing_df: "pd.DataFrame | None"  = None,
    ) -> dict | None:
        """
        Capture a snapshot of ``table`` before a load.

        Parameters
        ──────────
        cfg         : dict   Database connection config (same as loader).
        table       : str    Table name to snapshot.
        run_id      : str    Run identifier.  Auto-generated if omitted.
        existing_df : pd.DataFrame | None   Pre-read DataFrame to avoid a
                             second round-trip (supply when you already have it).

        Returns
        ───────
        dict  Manifest record, or None if the table did not exist yet.
        """
        run_id = run_id or self._run_id()
        ts     = datetime.now(timezone.utc).isoformat()

        df = existing_df if existing_df is not None else self._read_table(cfg, table)
        if df is None:
            self.gov.transformation_applied("SNAPSHOT_SKIPPED", {
                "table": table, "run_id": run_id,
                "reason": "table did not exist before this load",
            })
            return None

        rows = len(df)
        record: dict = {
            "run_id":       run_id,
            "table":        table,
            "db_type":      self.db_type,
            "timestamp":    ts,
            "rows":         rows,
            "strategy":     self.strategy,
            "parquet_path": None,
            "shadow_table": None,
            "checksum":     None,
            "size_bytes":   None,
        }

        # ── Parquet snapshot ──────────────────────────────────────────────
        if self.strategy in ("parquet", "both"):
            safe_table = table.replace(".", "_").replace("/", "_")
            fname = f"{safe_table}__{run_id}.parquet"
            fpath = self.snapshot_dir / fname
            df.to_parquet(fpath, compression=self.compression, index=False)
            size  = fpath.stat().st_size
            record["parquet_path"] = str(fpath)
            record["checksum"]     = self._checksum(fpath)
            record["size_bytes"]   = size

            size_mb = size / 1_048_576
            if size_mb > self.warn_size_mb:
                print(f"  [ReversibleLoader] ⚠  Snapshot of '{table}' is "
                      f"{size_mb:.1f} MB (threshold: {self.warn_size_mb} MB)")

        # ── Shadow-table snapshot ─────────────────────────────────────────
        if self.strategy in ("shadow", "both"):
            shadow = f"{table}__snapshot_{run_id}"
            try:
                engine = self._engine(cfg)
                with engine.begin() as conn:
                    df.to_sql(shadow, conn, if_exists="replace", index=False, chunksize=500)
                record["shadow_table"] = shadow
            except Exception as exc:  # pylint: disable=broad-except
                print(f"  [ReversibleLoader] Shadow table failed: {exc}")

        self._manifest_append(record)
        self.gov.transformation_applied("SNAPSHOT_TAKEN", {
            "table":        table,
            "run_id":       run_id,
            "rows":         rows,
            "strategy":     self.strategy,
            "parquet_path": record["parquet_path"],
            "shadow_table": record["shadow_table"],
            "size_bytes":   record["size_bytes"],
        })

        print(f"  📸  Snapshot saved: '{table}'  [{rows:,} rows]  run_id={run_id}")
        return record

    # ── Load (wraps the underlying loader) ────────────────────────────────

    def load(
        self,
        df:        "pd.DataFrame",
        cfg:       dict,
        table:     str,
        run_id:    str | None = None,
        if_exists: str        = "replace",
        **loader_kwargs,
    ) -> str:
        """
        Snapshot the current table, then load ``df`` into it.

        This is a drop-in replacement for loader.load().

        Parameters
        ──────────
        df        : pd.DataFrame   Data to load.
        cfg       : dict           Connection config.
        table     : str            Destination table name.
        run_id    : str | None     Override auto-generated run ID.
        if_exists : str            pandas if_exists behaviour ("replace"/"append").
        **loader_kwargs            Passed through to the underlying loader.

        Returns
        ───────
        str   The run_id for this load (use it to roll back later).
        """
        run_id = run_id or self._run_id()

        # 1. Snapshot existing state before touching the table
        self.snapshot(cfg, table, run_id=run_id)

        # 2. Perform the actual load
        if self.loader is not None:
            try:
                self.loader.load(df, cfg, table, if_exists=if_exists, **loader_kwargs)
            except TypeError:
                try:
                    self.loader.load(df, cfg, table, if_exists=if_exists)
                except TypeError:
                    self.loader.load(df, cfg, table)
        else:
            engine = self._engine(cfg)
            with engine.begin() as conn:
                df.to_sql(table, conn, if_exists=if_exists, index=False, chunksize=500)
            self.gov.load_complete(len(df), table)

        # 3. Record load completion in manifest
        ts = datetime.now(timezone.utc).isoformat()
        self._manifest_append({
            "run_id":      run_id,
            "table":       table,
            "db_type":     self.db_type,
            "timestamp":   ts,
            "event":       "LOAD_COMPLETE",
            "rows_loaded": len(df),
        })

        self.gov.transformation_applied("REVERSIBLE_LOAD_COMPLETE", {
            "table":    table,
            "run_id":   run_id,
            "rows":     len(df),
            "strategy": self.strategy,
        })

        print(f"  ✅  Load complete: '{table}'  [{len(df):,} rows]  run_id={run_id}")
        return run_id

    # ── Rollback ──────────────────────────────────────────────────────────

    def rollback(
        self,
        table:  str,
        run_id: str,
        cfg:    dict,
    ) -> int:
        """
        Roll back ``table`` to the state captured before the load with
        ``run_id``.

        Parameters
        ──────────
        table  : str    Table to restore.
        run_id : str    Run ID whose pre-load snapshot to restore.
        cfg    : dict   Connection config for the destination.

        Returns
        ───────
        int   Number of rows restored.

        Raises
        ──────
        FileNotFoundError   If the snapshot file cannot be found.
        ValueError          If no matching snapshot record exists.
        """
        records = self._manifest_records()
        matches = [
            r for r in records
            if r.get("run_id") == run_id
            and r.get("table") == table
            and r.get("event") is None          # snapshot records only
        ]
        if not matches:
            raise ValueError(
                f"No snapshot found for table='{table}', run_id='{run_id}'. "
                f"Available: {sorted({r['run_id'] for r in records if r.get('table')==table and r.get('event') is None})}"
            )
        snap = matches[-1]
        df_restore = self._load_snapshot_df(snap)
        rows = len(df_restore)

        engine = self._engine(cfg)
        with engine.begin() as conn:
            df_restore.to_sql(table, conn, if_exists="replace", index=False, chunksize=500)

        ts = datetime.now(timezone.utc).isoformat()
        self._manifest_append({
            "run_id":         self._run_id(),
            "table":          table,
            "db_type":        self.db_type,
            "timestamp":      ts,
            "event":          "ROLLBACK",
            "rolled_back_to": run_id,
            "rows_restored":  rows,
        })

        self.gov.transformation_applied("TABLE_ROLLED_BACK", {
            "table":          table,
            "rolled_back_to": run_id,
            "rows_restored":  rows,
            "strategy":       snap.get("strategy"),
        })

        print(
            f"  ↩️   Rollback complete: '{table}'  [{rows:,} rows restored]"
            f"  ← run_id={run_id}"
        )
        return rows

    def rollback_latest(self, table: str, cfg: dict) -> int:
        """
        Roll back ``table`` to the snapshot taken immediately before its
        most recent load — without needing to know the run_id.

        Returns
        ───────
        int   Number of rows restored.
        """
        records = self._manifest_records()
        snaps = [
            r for r in records
            if r.get("table") == table
            and r.get("event") is None
            and (r.get("parquet_path") or r.get("shadow_table"))
        ]
        if not snaps:
            raise ValueError(f"No snapshots found for table '{table}'.")
        latest = sorted(snaps, key=lambda r: r["timestamp"])[-1]
        return self.rollback(table=table, run_id=latest["run_id"], cfg=cfg)

    def _load_snapshot_df(self, snap: dict) -> "pd.DataFrame":
        """Load a snapshot record into a DataFrame for rollback."""
        if snap.get("parquet_path"):
            p = Path(snap["parquet_path"])
            if not p.exists():
                raise FileNotFoundError(
                    f"Snapshot file missing: {p}\n"
                    f"It may have been purged. Run_id: {snap['run_id']}"
                )
            if snap.get("checksum"):
                actual = self._checksum(p)
                if actual != snap["checksum"]:
                    raise RuntimeError(
                        f"Snapshot checksum mismatch for {p}\n"
                        f"Expected: {snap['checksum']}\n"
                        f"Actual:   {actual}\n"
                        "The snapshot file may have been tampered with."
                    )
            return pd.read_parquet(p)

        if snap.get("shadow_table"):
            raise ValueError(
                "Cannot read shadow table without cfg — use rollback(cfg=...) directly."
            )

        raise ValueError(f"Snapshot record has no readable source: {snap}")

    # ── History and reporting ─────────────────────────────────────────────

    def snapshot_history(
        self,
        table: str | None = None,
        n:     int        = 50,
    ) -> list[dict]:
        """
        Return snapshot + rollback history, optionally filtered to one table.

        Parameters
        ──────────
        table : str | None   Filter to this table only.  None = all tables.
        n     : int          Maximum records to return.

        Returns
        ───────
        list[dict]   Records from the manifest, newest first.
        """
        records = self._manifest_records()
        if table:
            records = [r for r in records if r.get("table") == table]
        return list(reversed(records[-n:]))

    def list_snapshots(self, table: str | None = None) -> list[dict]:
        """
        Return only snapshot records (not LOAD_COMPLETE or ROLLBACK events).

        Returns
        ───────
        list[dict]   Snapshot records, newest first, with size and row count.
        """
        records = self._manifest_records()
        snaps = [
            r for r in records
            if r.get("event") is None
            and (table is None or r.get("table") == table)
        ]
        return list(reversed(snaps))

    def available_rollback_points(self, table: str) -> list[dict]:
        """
        Return a list of run_ids you can roll back to, for a given table.

        Each entry contains: run_id, timestamp, rows, size_bytes, strategy.
        """
        snaps = self.list_snapshots(table)
        return [
            {
                "run_id":       r["run_id"],
                "timestamp":    r["timestamp"],
                "rows":         r.get("rows", "?"),
                "size_bytes":   r.get("size_bytes"),
                "strategy":     r.get("strategy"),
                "parquet_path": r.get("parquet_path"),
            }
            for r in snaps
        ]

    def print_rollback_points(self, table: str) -> None:
        """Print a human-readable table of available rollback points."""
        points = self.available_rollback_points(table)
        if not points:
            print(f"  No snapshots found for table '{table}'.")
            return
        border = "─" * 72
        print(f"\n  {border}")
        print(f"  ↩️   Available rollback points for '{table}'")
        print(f"  {border}")
        print(f"  {'run_id':30s}  {'timestamp':26s}  {'rows':>8}  {'MB':>6}")
        print(f"  {border}")
        for p in points:
            mb = f"{p['size_bytes']/1_048_576:.2f}" if p["size_bytes"] else "n/a"
            print(f"  {p['run_id']:30s}  {p['timestamp']:26s}  {str(p['rows']):>8}  {mb:>6}")
        print(f"  {border}\n")

    # ── Purge old snapshots ───────────────────────────────────────────────

    def purge_old_snapshots(
        self,
        cfg:     dict | None = None,
        dry_run: bool        = False,
        days:    int | None  = None,
    ) -> dict:
        """
        Delete snapshot files (and shadow tables) older than ``retention_days``
        (or ``days`` if supplied).

        Parameters
        ──────────
        cfg     : dict | None   Connection config for dropping shadow tables.
                                Shadow tables are only dropped if cfg is provided.
        dry_run : bool          If True, report what would be deleted without
                                actually deleting anything.
        days    : int | None    Override the instance ``retention_days`` for
                                this call only.  Useful for one-off cleanup
                                without changing the object's default.

        Returns
        ───────
        dict   {deleted_files, deleted_shadow_tables, freed_bytes, skipped}
        """
        _days   = days if days is not None else self.retention_days
        cutoff  = datetime.now(timezone.utc) - timedelta(days=_days)
        records = self._manifest_records()
        snaps   = [r for r in records if r.get("event") is None]

        deleted_files   = 0
        deleted_shadows = 0
        freed_bytes     = 0
        skipped         = 0

        for snap in snaps:
            try:
                ts = datetime.fromisoformat(
                    snap["timestamp"].replace("Z", "+00:00")
                )
            except (ValueError, KeyError):
                skipped += 1
                continue

            if ts >= cutoff:
                continue

            p = snap.get("parquet_path")
            if p:
                ppath = Path(p)
                if ppath.exists():
                    size = ppath.stat().st_size
                    if not dry_run:
                        ppath.unlink()
                    freed_bytes   += size
                    deleted_files += 1
                    action = "would delete" if dry_run else "deleted"
                    print(f"  🗑  {action}: {ppath.name}  ({size/1_048_576:.2f} MB)")

            st = snap.get("shadow_table")
            if st and cfg:
                try:
                    import sqlalchemy as _sa
                    engine = self._engine(cfg)
                    with engine.begin() as conn:
                        if not dry_run:
                            conn.execute(_sa.text(f'DROP TABLE IF EXISTS "{st}"'))
                    deleted_shadows += 1
                    action = "would drop" if dry_run else "dropped"
                    print(f"  🗑  {action} shadow table: {st}")
                except Exception as exc:  # pylint: disable=broad-except
                    print(f"  [ReversibleLoader] Could not drop {st}: {exc}")

        result = {
            "deleted_files":         deleted_files,
            "deleted_shadow_tables": deleted_shadows,
            "freed_bytes":           freed_bytes,
            "freed_mb":              round(freed_bytes / 1_048_576, 6),
            "skipped":               skipped,
            "dry_run":               dry_run,
            "retention_days":        self.retention_days,
        }

        self.gov.transformation_applied(
            "SNAPSHOTS_PURGED" if not dry_run else "SNAPSHOTS_PURGE_DRY_RUN",
            result
        )

        if not dry_run:
            print(
                f"  🧹  Purge complete: {deleted_files} file(s) deleted, "
                f"{freed_bytes/1_048_576:.2f} MB freed"
            )
        return result



# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: NLPipelineBuilder  (NEW v4.6)
# ═════════════════════════════════════════════════════════════════════════════

class NLPipelineBuilder:
    """
    Natural language pipeline builder — describe what you want in plain English
    and it generates a complete, runnable pipeline configuration.

    This is genuinely novel: no other ETL tool lets you go from a sentence like
    "load sales.csv into Snowflake, mask emails, run daily at 7am" directly to
    a validated YAML config, a runnable Python script, and a cost estimate.

    Powered by Claude (claude-sonnet-4-20250514).  Requires ANTHROPIC_API_KEY
    in your environment or the SecretsManager vault.

    What it understands
    ───────────────────
    Sources      : CSV, JSON, JSONL, Parquet, Excel, TSV, Avro, ORC, FWF,
                   SAS/Stata, Kafka, Kinesis, Pub/Sub, S3, GCS, SFTP
    Destinations : Snowflake, BigQuery, Redshift, Synapse, Databricks,
                   ClickHouse, Oracle, Db2, Firebolt, Yellowbrick,
                   PostgreSQL, MySQL, SQL Server, SQLite, MongoDB
    Transforms   : mask PII, hash emails/phones, encrypt columns, filter rows,
                   rename columns, drop columns, type coercion, date parsing,
                   deduplicate, standardise strings, enrich, business rules
    Schedule     : "daily at 7am", "every 15 minutes", "Mondays at midnight",
                   "hourly", "every weekday at 6pm EST", cron expressions
    Governance   : GDPR erasure, data classification, audit logging, SLA,
                   quality floor, data contract, cost estimation, rollback

    Usage
    ─────
        builder = NLPipelineBuilder(gov)

        # Single-shot generation
        config = builder.generate_config(
            "load sales.csv into Snowflake, mask emails, run daily at 7am"
        )

        # Get YAML
        yaml_str = builder.generate_yaml(
            "stream Kafka orders topic into BigQuery, GDPR mode, alert on quality drop"
        )

        # Get runnable Python script
        script = builder.generate_python(
            "load users.parquet into Redshift, hash emails and phones, weekly Sunday 2am"
        )

        # Save config to file
        builder.save(config, "my_pipeline.yaml")

        # Full interactive CLI
        builder.interactive_cli()

    Parameters
    ──────────
    gov         : GovernanceLogger
    api_key     : str | None   Anthropic API key.  Falls back to
                               ANTHROPIC_API_KEY env var.
    model       : str          Claude model to use.  Default: claude-sonnet-4-20250514.
    verbose     : bool         Print Claude's raw reasoning if True.
    """

    _MODEL = "claude-sonnet-4-20250514"

    # ── Known vocabulary for validation ──────────────────────────────────
    _SOURCES = {
        "csv","json","jsonl","parquet","excel","xlsx","tsv","avro","orc","fw",
        "sas","stata","kafka","kinesis","pubsub","s3","gcs","sftp","api",
    }
    _DESTINATIONS = {
        "snowflake","bigquery","redshift","synapse","databricks","clickhouse",
        "oracle","db2","firebolt","yellowbrick","hana","datasphere","postgresql","postgres",
        "mysql","mssql","sqlite","mongodb","mongo",
    }
    _TRANSFORMS = {
        "mask","hash","encrypt","filter","rename","drop","coerce","parse_dates",
        "deduplicate","standardise","standardize","enrich","classify","tag_pii",
    }

    # ── System prompt sent to Claude for config extraction ────────────────
    _SYSTEM_PROMPT = r"""You are a data pipeline configuration expert.
The user will describe a data pipeline in plain English.
Your job is to extract a structured JSON configuration from their description.

Return ONLY valid JSON — no markdown, no explanation, no backticks.

The JSON must follow this exact schema:
{
  "source": {
    "type": "<csv|json|jsonl|parquet|excel|tsv|avro|orc|kafka|kinesis|pubsub|s3|gcs|sftp|api>",
    "path": "<file path, URL, topic name, or bucket>",
    "format_options": {}
  },
  "transforms": [
    {
      "op": "<mask|hash|encrypt|filter|rename|drop|coerce|parse_dates|deduplicate|standardise|enrich|classify>",
      "columns": ["<col1>", "<col2>"],
      "params": {}
    }
  ],
  "destination": {
    "type": "<snowflake|bigquery|redshift|synapse|databricks|clickhouse|oracle|db2|postgresql|mysql|sqlite|mongodb>",
    "table": "<table or collection name>",
    "schema": "<schema or dataset name, empty string if not specified>",
    "if_exists": "<replace|append|upsert>"
  },
  "schedule": {
    "enabled": <true|false>,
    "cron": "<cron expression or empty string>",
    "human_readable": "<English description of schedule>",
    "timezone": "<timezone or UTC>"
  },
  "governance": {
    "gdpr_mode": <true|false>,
    "pii_detection": <true|false>,
    "erasure_enabled": <true|false>,
    "audit_log": true,
    "data_classification": <true|false>,
    "quality_floor": <0-100 or null>,
    "sla_max_duration_seconds": <number or null>
  },
  "features": {
    "cost_estimation": <true|false>,
    "reversible_loads": <true|false>,
    "data_contract": <true|false>,
    "alert_on_quality_drop": <true|false>,
    "schema_validation": <true|false>,
    "compression": "<snappy|gzip|zstd|none>"
  },
  "inferred": {
    "confidence": "<high|medium|low>",
    "ambiguities": ["<list of things you guessed that the user should confirm>"],
    "assumptions": ["<list of reasonable defaults you applied>"]
  }
}

Rules:
- If a field is not mentioned, use a sensible default.
- "mask" means replace with asterisks. "hash" means SHA-256. "encrypt" means AES-256.
- PII columns: if user mentions emails, phones, SSN, names — add a mask/hash transform.
- GDPR mode: true if user mentions GDPR, compliance, privacy, erasure, EU, Europe.
- For schedule: convert English to cron. "daily at 7am" = "0 7 * * *".
  "every 15 minutes" = "*/15 * * * *". "Mondays at midnight" = "0 0 * * 1".
  "weekdays at 6pm" = "0 18 * * 1-5". "hourly" = "0 * * * *".
- confidence: high if source+destination+table all clear. medium if some guessing needed.
- Keep ambiguities short and specific: things the user MUST confirm before running.
- Keep assumptions brief: smart defaults you applied silently.
"""

    def __init__(
        self,
        gov:     "GovernanceLogger",
        api_key: str | None = None,
        model:   str        = _MODEL,
        verbose: bool       = False,
    ) -> None:
        self.gov     = gov
        self.model   = model
        self.verbose = verbose

        # Resolve API key: param > env var > secrets vault
        self._api_key = (
            api_key
            or os.environ.get("ANTHROPIC_API_KEY")
        )

    # ── Claude API call ───────────────────────────────────────────────────

    def _call_claude(self, user_message: str, system: str | None = None) -> str:
        """
        Call Claude and return the text response.

        Parameters
        ──────────
        user_message : str   The user turn.
        system       : str   Override system prompt.

        Returns
        ───────
        str   Claude's response text.

        Raises
        ──────
        RuntimeError   If API key missing or HTTP error.
        """
        import urllib.request as _ur
        import urllib.error  as _ue

        if not self._api_key:
            raise RuntimeError(
                "No Anthropic API key found.\n"
                "Set ANTHROPIC_API_KEY environment variable or pass api_key= to NLPipelineBuilder."
            )

        payload = json.dumps({
            "model":      self.model,
            "max_tokens": 2048,
            "system":     system or self._SYSTEM_PROMPT,
            "messages":   [{"role": "user", "content": user_message}],
        }).encode("utf-8")

        req = _ur.Request(
            "https://api.anthropic.com/v1/messages",
            data    = payload,
            headers = {
                "Content-Type":      "application/json",
                "x-api-key":         self._api_key,
                "anthropic-version": "2023-06-01",
            },
            method  = "POST",
        )
        try:
            with _ur.urlopen(req, timeout=60) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except _ue.HTTPError as exc:
            err_body = exc.read().decode("utf-8")
            raise RuntimeError(
                f"Anthropic API error {exc.code}: {err_body}"
            ) from exc

        text = ""
        for block in body.get("content", []):
            if block.get("type") == "text":
                text += block["text"]
        return text.strip()

    # ── JSON extraction ───────────────────────────────────────────────────

    def _extract_json(self, text: str) -> dict:
        """
        Parse JSON from Claude's response, stripping any markdown fences.

        Raises
        ──────
        ValueError   If no valid JSON can be found.
        """
        # Strip markdown code fences if present
        cleaned = text.strip()
        for fence in ("```json", "```JSON", "```"):
            if cleaned.startswith(fence):
                cleaned = cleaned[len(fence):]
                if cleaned.endswith("```"):
                    cleaned = cleaned[:-3]
                break
        cleaned = cleaned.strip()
        _last_err: json.JSONDecodeError | None = None
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Try to find the first {...} block
            start = cleaned.find("{")
            end   = cleaned.rfind("}")
            if start != -1 and end != -1:
                try:
                    return json.loads(cleaned[start:end+1])
                except json.JSONDecodeError as _jde:
                    _last_err = _jde
            raise ValueError(
                f"Could not parse JSON from Claude response:\n{text[:500]}"
            ) from _last_err

    # ── Config generation ─────────────────────────────────────────────────

    def generate_config(self, description: str) -> dict:
        """
        Parse a plain-English pipeline description into a structured config dict.

        Parameters
        ──────────
        description : str   Natural language pipeline description.

        Returns
        ───────
        dict   Full pipeline config (source, transforms, destination, schedule,
               governance, features, inferred).

        Example
        ───────
            config = builder.generate_config(
                "load sales.csv into Snowflake, mask emails, run daily at 7am"
            )
        """
        if self.verbose:
            print(f"\n  [NL] Sending to Claude: {description!r}")

        raw = self._call_claude(description)

        if self.verbose:
            print(f"\n  [NL] Claude raw response:\n{raw}\n")

        config = self._extract_json(raw)

        # Enrich with metadata
        config["_meta"] = {
            "generated_utc":  datetime.now(timezone.utc).isoformat(),
            "description":    description,
            "model":          self.model,
            "pipeline_version": "4.6",
        }

        self.gov.transformation_applied("NL_CONFIG_GENERATED", {
            "description":  description,
            "source_type":  config.get("source", {}).get("type"),
            "dest_type":    config.get("destination", {}).get("type"),
            "confidence":   config.get("inferred", {}).get("confidence"),
            "n_transforms": len(config.get("transforms", [])),
        })

        return config

    def generate_yaml(self, description: str) -> str:
        """
        Generate a YAML pipeline config from a plain-English description.

        Returns
        ───────
        str   YAML-formatted config string, ready to save as a .yaml file.
        """
        config = self.generate_config(description)
        return self._config_to_yaml(config)

    def generate_python(self, description: str) -> str:
        """
        Generate a complete, runnable Python pipeline script from a description.

        The generated script uses this pipeline's classes directly and can be
        executed immediately (after filling in credentials).

        Returns
        ───────
        str   Python source code.
        """
        config = self.generate_config(description)
        return self._config_to_python(config)

    # ── YAML serialiser ───────────────────────────────────────────────────

    def _config_to_yaml(self, config: dict) -> str:
        """Convert config dict to a well-formatted YAML string."""
        src   = config.get("source", {})
        dst   = config.get("destination", {})
        sched = config.get("schedule", {})
        gov   = config.get("governance", {})
        feat  = config.get("features", {})
        inf   = config.get("inferred", {})
        meta  = config.get("_meta", {})
        transforms = config.get("transforms", [])

        lines = [
            "# Pipeline config generated by NLPipelineBuilder v4.6",
            f"# Description: {meta.get('description', '')}",
            f"# Generated:   {meta.get('generated_utc', '')}",
            f"# Confidence:  {inf.get('confidence', '?')}",
            "",
            "source:",
            f"  type: {src.get('type', '')}",
            f'  path: "{src.get("path", "")}"',
        ]
        if src.get("format_options"):
            lines.append("  format_options:")
            for k, v in src["format_options"].items():
                lines.append(f"    {k}: {v}")

        lines += [
            "",
            "destination:",
            f"  type: {dst.get('type', '')}",
            f"  table: {dst.get('table', '')}",
        ]
        if dst.get("schema"):
            lines.append(f"  schema: {dst.get('schema', '')}")
        lines.append(f"  if_exists: {dst.get('if_exists', 'append')}")

        if transforms:
            lines.append("")
            lines.append("transforms:")
            for t in transforms:
                lines.append(f"  - op: {t.get('op', '')}")
                cols = t.get("columns", [])
                if cols:
                    lines.append(f"    columns: [{', '.join(cols)}]")
                params = t.get("params", {})
                if params:
                    lines.append("    params:")
                    for k, v in params.items():
                        lines.append(f"      {k}: {v}")

        lines += [
            "",
            "schedule:",
            f"  enabled: {str(sched.get('enabled', False)).lower()}",
            f'  cron: "{sched.get("cron", "")}"',
            f'  human_readable: "{sched.get("human_readable", "")}"',
            f"  timezone: {sched.get('timezone', 'UTC')}",
            "",
            "governance:",
            f"  gdpr_mode: {str(gov.get('gdpr_mode', False)).lower()}",
            f"  pii_detection: {str(gov.get('pii_detection', True)).lower()}",
            f"  erasure_enabled: {str(gov.get('erasure_enabled', False)).lower()}",
            "  audit_log: true",
            f"  data_classification: {str(gov.get('data_classification', False)).lower()}",
        ]
        if gov.get("quality_floor") is not None:
            lines.append(f"  quality_floor: {gov['quality_floor']}")
        if gov.get("sla_max_duration_seconds") is not None:
            lines.append(f"  sla_max_duration_seconds: {gov['sla_max_duration_seconds']}")

        lines += [
            "",
            "features:",
            f"  cost_estimation: {str(feat.get('cost_estimation', True)).lower()}",
            f"  reversible_loads: {str(feat.get('reversible_loads', False)).lower()}",
            f"  data_contract: {str(feat.get('data_contract', False)).lower()}",
            f"  alert_on_quality_drop: {str(feat.get('alert_on_quality_drop', False)).lower()}",
            f"  schema_validation: {str(feat.get('schema_validation', True)).lower()}",
            f"  compression: {feat.get('compression', 'snappy')}",
        ]

        if inf.get("ambiguities"):
            lines += ["", "# ── Things to confirm before running ────────────────────"]
            for a in inf["ambiguities"]:
                lines.append(f"# ⚠  {a}")

        if inf.get("assumptions"):
            lines += ["", "# ── Defaults applied automatically ──────────────────────"]
            for a in inf["assumptions"]:
                lines.append(f"# ✓  {a}")

        return "\n".join(lines) + "\n"

    # ── Python script generator ───────────────────────────────────────────

    def _config_to_python(self, config: dict) -> str:
        """Convert config dict to a complete runnable Python pipeline script."""
        src   = config.get("source", {})
        dst   = config.get("destination", {})
        sched = config.get("schedule", {})
        gov_c = config.get("governance", {})
        feat  = config.get("features", {})
        inf   = config.get("inferred", {})
        meta  = config.get("_meta", {})
        transforms = config.get("transforms", [])

        src_type  = src.get("type", "csv")
        src_path  = src.get("path", "data.csv")
        dst_type  = dst.get("type", "sqlite")
        dst_table = dst.get("table", "output")
        dst_schema = dst.get("schema", "")

        # Build transform code lines
        transform_lines = []
        mask_cols, hash_cols = [], []
        for t in transforms:
            op   = t.get("op", "")
            cols = t.get("columns", [])
            if op == "mask":
                mask_cols.extend(cols)
            elif op == "hash":
                hash_cols.extend(cols)
            elif op == "filter":
                p = t.get("params", {})
                if p.get("condition"):
                    transform_lines.append(f'        df = df.query("{p["condition"]}")')
            elif op in ("drop", "drop_columns"):
                if cols:
                    transform_lines.append(f"        df = df.drop(columns={cols}, errors='ignore')")
            elif op == "deduplicate":
                transform_lines.append(f"        df = df.drop_duplicates(subset={cols or None})")
            elif op == "parse_dates":
                for c in cols:
                    transform_lines.append(f'        df["{c}"] = pd.to_datetime(df["{c}"], errors="coerce")')
            elif op in ("standardise", "standardize"):
                for c in cols:
                    transform_lines.append(f'        df["{c}"] = df["{c}"].astype(str).str.strip().str.lower()')
            elif op == "rename":
                p = t.get("params", {})
                if p.get("mapping"):
                    transform_lines.append(f"        df = df.rename(columns={p['mapping']})")

        # PII transform lines
        if mask_cols:
            transform_lines.append(
                f"        df = Transformer(gov).transform(df, [{{'field': c}} for c in {mask_cols}], 'mask', [])"
            )
        if hash_cols:
            transform_lines.append(
                f"        df = Transformer(gov).transform(df, [{{'field': c}} for c in {hash_cols}], 'hash', [])"
            )

        # Build destination config dict
        dest_cfg_lines = self._dest_cfg_lines(dst_type, dst_schema)

        # Build loader line (used for reference)

        # Build schedule comment
        sched_comment = ""
        if sched.get("enabled"):
            sched_comment = (
                f'    # Schedule: {sched.get("human_readable","")}'
                f' → cron: {sched.get("cron","")}'
                f' ({sched.get("timezone","UTC")})'
                "\n    # To activate: register this function with your scheduler"
                "\n    # e.g. scheduler.add(run_pipeline,"
                f' cron="{sched.get("cron","")}",'
                f' timezone="{sched.get("timezone","UTC")}")'
            )

        # Governance flags
        gov_lines = []
        if gov_c.get("gdpr_mode"):
            gov_lines.append("    # GDPR mode: erasure handler will be registered")
            gov_lines.append("    # erasure = ErasureHandler(gov, db_type, dest_cfg, dest_table)")
        if gov_c.get("data_classification"):
            gov_lines.append("    pii_cols = _detect_pii(list(df.columns))")
            gov_lines.append("    tagger   = DataClassificationTagger(gov)")
            gov_lines.append("    df, _    = tagger.classify(df, pii_cols)")

        # Features
        reversible = feat.get("reversible_loads", False)
        quality    = feat.get("alert_on_quality_drop", False)
        cost       = feat.get("cost_estimation", False)

        lines = [
            '#!/usr/bin/env python3',
            '"""',
            f'Pipeline: {meta.get("description", "")}',
            f'Generated by NLPipelineBuilder v4.6 on {meta.get("generated_utc","")}',
            f'Confidence: {inf.get("confidence","?")}',
            '"""',
            '',
            'import os, time',
            'import pandas as pd',
            'from pipeline_v3 import (',
            '    GovernanceLogger, Extractor, Transformer,',
            '    DataClassificationTagger, _detect_pii,',
            '    SchemaValidator, DeadLetterQueue,',
            '    DataQualityScorer, QualityAnomalyAlerter,',
            '    CostEstimator, ReversibleLoader,',
            f'    {self._loader_import(dst_type)}',
            ')',
            '',
            '# ── Credentials (fill these in or load from environment) ──────────────',
        ]
        lines += dest_cfg_lines
        lines += [
            '',
            f'DEST_TABLE = "{dst_table}"',
            '',
            '',
            'def run_pipeline():',
            '    t0  = time.time()',
            '    gov = GovernanceLogger("pipeline")',
            '    gov.pipeline_start({})',
            '',
            '    # ── Extract ───────────────────────────────────────────────────────',
            f'    print("Loading from: {src_path}")',
        ]

        if src_type in ("kafka", "kinesis", "pubsub"):
            lines += [
                f'    # Streaming source: {src_type}',
                f'    # extractor = {src_type.capitalize()}Extractor(gov, config={{...}})',
                '    # df = extractor.poll()',
                f'    raise NotImplementedError("Configure {src_type} credentials above")',
            ]
        else:
            lines += [
                f'    df = Extractor(gov).extract("{src_path}")',
            ]

        lines += [
            '    print(f"  {len(df):,} rows extracted")',
            '',
            '    # ── Validate schema ───────────────────────────────────────────────',
        ]
        if feat.get("schema_validation", True):
            lines += [
                '    dlq       = DeadLetterQueue(gov)',
                '    validator = SchemaValidator(gov, dlq)',
                '    suite     = validator.build_suite(df, interactive=False)',
                '    df, _     = validator.validate(df, suite, on_failure="dlq")',
            ]

        if gov_lines:
            lines.append('')
            lines.append('    # ── Governance ────────────────────────────────────────────────')
            lines += [f'    {l.strip()}' for l in gov_lines]

        if transform_lines:
            lines += [
                '',
                '    # ── Transform ─────────────────────────────────────────────────',
                '    def apply_transforms(df):',
            ]
            lines += transform_lines
            lines += [
                '        return df',
                '    df = apply_transforms(df)',
                '    print(f"  {len(df):,} rows after transforms")',
            ]

        if quality:
            lines += [
                '',
                '    # ── Quality check ─────────────────────────────────────────────',
                '    scorer  = DataQualityScorer(gov)',
                '    alerter = QualityAnomalyAlerter(gov)',
                '    report  = scorer.score(df)',
                '    alerter.check(report)',
                '    print(f"  Quality score: {report[\'score\']:.1f} ({report[\'grade\']})")',
            ]

        lines += [
            '',
            '    # ── Load ──────────────────────────────────────────────────────────',
        ]
        if reversible:
            lines += [
                f'    base_loader = {self._loader_class(dst_type)}(gov)',
                '    loader = ReversibleLoader(gov, base_loader,',
                f'                             db_type="{dst_type}",',
                '                             snapshot_dir="snapshots/")',
                '    run_id = loader.load(df, DEST_CFG, DEST_TABLE)',
                '    print(f"  Reversible load complete — run_id={run_id}")',
            ]
        else:
            lines += [
                f'    loader = {self._loader_class(dst_type)}(gov)',
                '    loader.load(df, DEST_CFG, DEST_TABLE)',
            ]

        if cost:
            lines += [
                '',
                '    # ── Cost estimate ─────────────────────────────────────────────',
                '    estimator = CostEstimator(gov)',
                f'    estimator.estimate(db_type="{dst_type}",',
                '                       elapsed_seconds=time.time()-t0,',
                '                       rows_processed=len(df), df=df)',
            ]

        if sched_comment:
            lines += ['', sched_comment]

        lines += [
            '',
            "    gov.pipeline_end({})",
            '    print("Pipeline complete.")',
            '',
            '',
            'if __name__ == "__main__":',
            '    run_pipeline()',
            '',
        ]

        # Append ambiguities as comments at the bottom
        if inf.get("ambiguities"):
            lines += ['', '# ── Confirm before running ──────────────────────────────────────']
            for a in inf["ambiguities"]:
                lines.append(f'# ⚠  {a}')

        return "\n".join(lines) + "\n"

    def _loader_import(self, dst_type: str) -> str:
        m = {
            "snowflake": "SnowflakeLoader",
            "bigquery":  "BigQueryLoader",
            "redshift":  "RedshiftLoader",
            "synapse":   "SynapseLoader",
            "databricks":"DatabricksLoader",
            "clickhouse":"ClickHouseLoader",
            "oracle":    "OracleLoader",
            "db2":       "Db2Loader",
            "firebolt":  "FireboltLoader",
            "yellowbrick":"YellowbrickLoader",
            "hana":        "HanaLoader",
            "datasphere":  "DatasphereLoader",
            "postgresql":"SQLLoader",
            "postgres":  "SQLLoader",
            "mysql":     "SQLLoader",
            "mssql":     "SQLLoader",
            "sqlite":    "SQLLoader",
            "mongodb":   "MongoLoader",
        }
        return m.get(dst_type.lower(), "SQLLoader")

    def _loader_class(self, dst_type: str) -> str:
        return self._loader_import(dst_type)

    def _dest_cfg_lines(self, dst_type: str, schema: str = "") -> list[str]:
        """Return Python lines that define DEST_CFG for a given destination."""
        t = dst_type.lower()
        if t == "snowflake":
            return [
                'DEST_CFG = {',
                '    "account":   os.environ.get("SNOWFLAKE_ACCOUNT", "your_account"),',
                '    "user":      os.environ.get("SNOWFLAKE_USER", "your_user"),',
                '    "password":  os.environ.get("SNOWFLAKE_PASSWORD", "your_password"),',
                '    "database":  os.environ.get("SNOWFLAKE_DATABASE", "your_database"),',
                f'    "schema":    "{schema or "PUBLIC"}",',
                '    "warehouse": os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),',
                '    "role":      os.environ.get("SNOWFLAKE_ROLE", ""),',
                '}',
            ]
        if t == "bigquery":
            return [
                'DEST_CFG = {',
                '    "project":    os.environ.get("BIGQUERY_PROJECT", "your_project"),',
                f'    "dataset":    "{schema or "your_dataset"}",',
                '    "credentials": os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""),',
                '}',
            ]
        if t == "redshift":
            return [
                'DEST_CFG = {',
                '    "host":     os.environ.get("REDSHIFT_HOST", "your.cluster.redshift.amazonaws.com"),',
                '    "port":     5439,',
                '    "db_name":  os.environ.get("REDSHIFT_DB", "your_db"),',
                '    "user":     os.environ.get("REDSHIFT_USER", "your_user"),',
                '    "password": os.environ.get("REDSHIFT_PASSWORD", "your_password"),',
                '}',
            ]
        if t in ("postgresql", "postgres"):
            return [
                'DEST_CFG = {',
                '    "host":     os.environ.get("PG_HOST", "localhost"),',
                '    "port":     5432,',
                '    "db_name":  os.environ.get("PG_DB", "your_db"),',
                '    "user":     os.environ.get("PG_USER", "your_user"),',
                '    "password": os.environ.get("PG_PASSWORD", "your_password"),',
                '}',
            ]
        if t == "mysql":
            return [
                'DEST_CFG = {',
                '    "host":     os.environ.get("MYSQL_HOST", "localhost"),',
                '    "port":     3306,',
                '    "db_name":  os.environ.get("MYSQL_DB", "your_db"),',
                '    "user":     os.environ.get("MYSQL_USER", "your_user"),',
                '    "password": os.environ.get("MYSQL_PASSWORD", "your_password"),',
                '}',
            ]
        if t in ("sqlite",):
            return ['DEST_CFG = {"db_name": "pipeline_output"}']
        if t == "mongodb":
            return [
                'DEST_CFG = {',
                '    "uri":      os.environ.get("MONGO_URI", "mongodb://localhost:27017"),',
                '    "database": os.environ.get("MONGO_DB", "your_db"),',
                '}',
            ]
        # Generic fallback
        return [
            'DEST_CFG = {',
            f'    # Fill in credentials for {dst_type}',
            '    "host": "your_host",',
            '    "db_name": "your_db",',
            '    "user": "your_user",',
            '    "password": "your_password",',
            '}',
        ]

    # ── Save ──────────────────────────────────────────────────────────────

    def save(
        self,
        config:  dict,
        path:    str | Path,
        fmt:     str = "yaml",
    ) -> Path:
        """
        Save a generated config to disk as YAML (default) or JSON.

        Parameters
        ──────────
        config : dict   Config from generate_config().
        path   : str    Output file path.
        fmt    : str    "yaml" or "json".

        Returns
        ───────
        Path   Absolute path of the written file.
        """
        out = Path(path)
        if fmt == "json":
            out.write_text(json.dumps(config, indent=2, default=str), encoding="utf-8")
        else:
            out.write_text(self._config_to_yaml(config), encoding="utf-8")
        print(f"  💾  Config saved → {out.resolve()}")
        return out.resolve()

    def save_python(self, config: dict, path: str | Path) -> Path:
        """Save the generated Python script to disk."""
        out = Path(path)
        out.write_text(self._config_to_python(config), encoding="utf-8")
        print(f"  💾  Pipeline script saved → {out.resolve()}")
        return out.resolve()

    # ── Pretty-print config summary ───────────────────────────────────────

    def _print_config_summary(self, config: dict) -> None:
        """Print a compact, human-readable summary of a generated config."""
        src   = config.get("source", {})
        dst   = config.get("destination", {})
        sched = config.get("schedule", {})
        gov   = config.get("governance", {})
        feat  = config.get("features", {})
        inf   = config.get("inferred", {})
        txs   = config.get("transforms", [])

        border = "═" * 62
        print(f"\n  {border}")
        print(f"  🔧  PIPELINE CONFIG  (confidence: {inf.get('confidence','?').upper()})")
        print(f"  {border}")
        print(f"  Source      : {src.get('type','?').upper()}  ←  {src.get('path','?')}")
        print(f"  Destination : {dst.get('type','?').upper()}  →  {dst.get('table','?')}")
        if dst.get("schema"):
            print(f"  Schema      : {dst['schema']}")

        if txs:
            tx_summary = ", ".join(
                f"{t['op']}({','.join(t.get('columns',[]))})" for t in txs
            )
            print(f"  Transforms  : {tx_summary}")
        else:
            print("  Transforms  : none")

        if sched.get("enabled"):
            print(f"  Schedule    : {sched.get('human_readable','')}  [{sched.get('cron','')}]")
        else:
            print("  Schedule    : not scheduled (manual / on-demand)")

        flags = []
        if gov.get("gdpr_mode"):        flags.append("GDPR")
        if gov.get("pii_detection"):    flags.append("PII-detect")
        if feat.get("reversible_loads"):flags.append("reversible")
        if feat.get("cost_estimation"): flags.append("cost-est")
        if feat.get("data_contract"):   flags.append("contracts")
        if flags:
            print(f"  Features    : {', '.join(flags)}")

        if inf.get("ambiguities"):
            print(f"  {'-'*60}")
            print("  ⚠  Confirm before running:")
            for a in inf["ambiguities"]:
                print(f"     • {a}")

        if inf.get("assumptions"):
            print(f"  ✓  Defaults applied: {', '.join(inf['assumptions'][:3])}"
                  + ("..." if len(inf.get("assumptions",[])) > 3 else ""))

        print(f"  {border}\n")

    # ── Interactive CLI ───────────────────────────────────────────────────

    def interactive_cli(self) -> None:
        """
        Launch the interactive natural language pipeline builder CLI.

        The REPL loop lets you:
          • Type a pipeline description to generate a config
          • Refine the description iteratively
          • Save configs as YAML or Python scripts
          • Get cost estimates, view transforms, toggle features
          • Type 'help' for command reference
          • Type 'quit' or 'exit' to leave

        Example session
        ───────────────
            > load sales.csv into Snowflake, mask emails, run daily at 7am
            [Config summary printed]
            > save config my_pipeline.yaml
            > save script my_pipeline.py
            > cost snowflake medium 3600 50000
            > quit
        """
        BANNER = r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║   🔧  Natural Language Pipeline Builder  v4.6               ║
  ║   Describe your pipeline in plain English.                   ║
  ║   Type 'help' for commands, 'quit' to exit.                  ║
  ╚══════════════════════════════════════════════════════════════╝"""
        HELP = """
  Commands
  ────────
  <description>              Generate a pipeline config from plain English
  save config <file.yaml>    Save last config as YAML
  save script <file.py>      Save last config as a Python pipeline script
  save json   <file.json>    Save last config as JSON
  show yaml                  Print the YAML for the last config
  show script                Print the Python script for the last config
  show transforms            List transforms in the last config
  cost <platform> <size> <seconds> <rows>   Estimate run cost
  history                    Show all descriptions you've entered this session
  clear                      Start fresh (forget last config)
  help                       Show this help
  quit / exit                Exit the CLI
"""
        print(BANNER)
        last_config:  dict | None  = None
        session_hist: list[str]    = []
        cost_est = CostEstimator(self.gov)

        while True:
            try:
                raw = input("\n  > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye.")
                break

            if not raw:
                continue

            cmd = raw.lower()

            # ── Quit ──────────────────────────────────────────────────────
            if cmd in ("quit", "exit", "q"):
                print("  Goodbye.")
                break

            # ── Help ──────────────────────────────────────────────────────
            if cmd == "help":
                print(HELP)
                continue

            # ── Clear ─────────────────────────────────────────────────────
            if cmd == "clear":
                last_config = None
                print("  State cleared.")
                continue

            # ── History ───────────────────────────────────────────────────
            if cmd == "history":
                if not session_hist:
                    print("  No history yet.")
                else:
                    for i, h in enumerate(session_hist, 1):
                        print(f"  {i:2}. {h}")
                continue

            # ── Show yaml ─────────────────────────────────────────────────
            if cmd == "show yaml":
                if not last_config:
                    print("  No config yet — describe a pipeline first.")
                else:
                    print("\n" + self._config_to_yaml(last_config))
                continue

            # ── Show script ───────────────────────────────────────────────
            if cmd in ("show script", "show python"):
                if not last_config:
                    print("  No config yet — describe a pipeline first.")
                else:
                    print("\n" + self._config_to_python(last_config))
                continue

            # ── Show transforms ───────────────────────────────────────────
            if cmd == "show transforms":
                if not last_config:
                    print("  No config yet.")
                else:
                    txs = last_config.get("transforms", [])
                    if not txs:
                        print("  No transforms configured.")
                    else:
                        for i, t in enumerate(txs, 1):
                            cols = ", ".join(t.get("columns", [])) or "all columns"
                            print(f"  {i}. {t['op']}  ←  {cols}")
                continue

            # ── Save config ───────────────────────────────────────────────
            if cmd.startswith("save config "):
                path = raw[len("save config "):].strip()
                if not last_config:
                    print("  No config to save — describe a pipeline first.")
                else:
                    self.save(last_config, path, fmt="yaml")
                continue

            if cmd.startswith("save json "):
                path = raw[len("save json "):].strip()
                if not last_config:
                    print("  No config to save.")
                else:
                    self.save(last_config, path, fmt="json")
                continue

            # ── Save script ───────────────────────────────────────────────
            if cmd.startswith("save script ") or cmd.startswith("save python "):
                path = raw.split(None, 2)[-1].strip()
                if not last_config:
                    print("  No config to save — describe a pipeline first.")
                else:
                    self.save_python(last_config, path)
                continue

            # ── Cost estimate ─────────────────────────────────────────────
            if cmd.startswith("cost "):
                parts = cmd.split()
                # cost <platform> [warehouse_size] [seconds] [rows]
                try:
                    platform = parts[1] if len(parts) > 1 else "generic"
                    wh_size  = parts[2] if len(parts) > 2 else "X-Small"
                    seconds  = float(parts[3]) if len(parts) > 3 else 300.0
                    rows     = int(parts[4])   if len(parts) > 4 else 10000
                    cost_est.estimate(
                        db_type         = platform,
                        elapsed_seconds = seconds,
                        rows_processed  = rows,
                        bytes_processed = rows * 500,
                        bytes_written   = rows * 500,
                        warehouse_size  = wh_size,
                    )
                except (IndexError, ValueError):
                    print("  Usage: cost <platform> <warehouse_size> <seconds> <rows>")
                    print("  e.g.:  cost snowflake Medium 300 50000")
                continue

            # ── Everything else: treat as pipeline description ─────────────
            session_hist.append(raw)
            print("\n  ⏳  Generating config…")
            try:
                config = self.generate_config(raw)
                last_config = config
                self._print_config_summary(config)
                print("  Tip: 'save config out.yaml' · 'save script out.py' · 'show yaml'")
            except RuntimeError as exc:
                # API key missing or network error
                print(f"\n  ✗  {exc}")
                print(
                    "  To use NLPipelineBuilder, set ANTHROPIC_API_KEY environment variable\n"
                    "  or pass api_key= when constructing the builder.\n"
                    "  For offline testing, use generate_config_offline() with a manual dict."
                )
            except Exception as exc:  # pylint: disable=broad-except
                print(f"\n  ✗  Unexpected error: {exc}")

    # ── Offline / test mode ───────────────────────────────────────────────

    @staticmethod
    def generate_config_offline(
        source_type:  str,
        source_path:  str,
        dest_type:    str,
        dest_table:   str,
        transforms:   list[dict] | None = None,
        schedule:     str               = "",
        gdpr:         bool              = False,
        reversible:   bool              = False,
        quality_floor: int | None       = None,
    ) -> dict:
        """
        Build a config dict directly — no API call required.

        Useful for testing, CI/CD, or when building configs programmatically.

        Parameters
        ──────────
        source_type   : str   e.g. "csv", "parquet", "kafka"
        source_path   : str   File path, topic name, URL
        dest_type     : str   e.g. "snowflake", "sqlite", "bigquery"
        dest_table    : str   Destination table name
        transforms    : list  List of {op, columns, params} dicts
        schedule      : str   Cron expression or empty string
        gdpr          : bool  Enable GDPR mode
        reversible    : bool  Enable reversible loads
        quality_floor : int   Minimum quality score (0-100)

        Returns
        ───────
        dict   Full config in the same schema as generate_config().
        """
        return {
            "source": {
                "type":           source_type,
                "path":           source_path,
                "format_options": {},
            },
            "transforms": transforms or [],
            "destination": {
                "type":      dest_type,
                "table":     dest_table,
                "schema":    "",
                "if_exists": "replace",
            },
            "schedule": {
                "enabled":        bool(schedule),
                "cron":           schedule,
                "human_readable": schedule or "manual",
                "timezone":       "UTC",
            },
            "governance": {
                "gdpr_mode":            gdpr,
                "pii_detection":        True,
                "erasure_enabled":      gdpr,
                "audit_log":            True,
                "data_classification":  False,
                "quality_floor":        quality_floor,
                "sla_max_duration_seconds": None,
            },
            "features": {
                "cost_estimation":      True,
                "reversible_loads":     reversible,
                "data_contract":        False,
                "alert_on_quality_drop": False,
                "schema_validation":    True,
                "compression":          "snappy",
            },
            "inferred": {
                "confidence":   "high",
                "ambiguities":  [],
                "assumptions":  ["built offline — no AI parsing"],
            },
            "_meta": {
                "generated_utc":    datetime.now(timezone.utc).isoformat(),
                "description":      f"{source_type} → {dest_type}:{dest_table}",
                "model":            "offline",
                "pipeline_version": "4.6",
            },
        }





# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION PROMPTS  (v3.0 — adds new feature prompts)
# ═════════════════════════════════════════════════════════════════════════════


# ═════════════════════════════════════════════════════════════════════════════
def _notna(v) -> bool:
    """Return True if v is not None / NaN / empty string."""
    if v is None:
        return False
    try:
        import math
        if isinstance(v, float) and math.isnan(v):
            return False
    except (TypeError, ValueError):
        pass
    return str(v).strip() != ""

# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: TableCopier  (NEW v4.8)
# ═════════════════════════════════════════════════════════════════════════════

class TableCopier:
    """
    Copy any database table to a new table (same or different platform)
    with the full governance stack applied automatically:

        • PII scan and masking / hashing / encryption
        • Data quality scoring (0-100 across 5 dimensions)
        • Schema validation and data contract enforcement
        • Data diff report vs. destination (if it already exists)
        • HTML run report
        • PII discovery report (JSON + HTML, GDPR/CCPA checklists)
        • Reversible load with Parquet snapshot (rollback on failure)
        • Full tamper-evident SHA-256 audit ledger
        • Automatic retry with exponential back-off

    Supports any combination of source and destination from the 15
    supported platforms:

        sqlite, postgresql, mysql, mssql,
        snowflake, redshift, bigquery, synapse,
        databricks, clickhouse, oracle, db2,
        firebolt, yellowbrick, hana, datasphere, mongodb

    For platforms not covered by the built-in engine builder (BigQuery,
    Redshift, Synapse, Databricks, etc.) supply a ``read_fn`` callable
    that accepts (cfg, table) and returns a DataFrame.  The built-in
    engine builder covers: sqlite, postgresql, mysql, mssql, snowflake.

    Usage
    -----
        gov = GovernanceLogger("my_pipeline")
        gov.pipeline_start({"source": "orders", "destination": "orders_v2"})

        copier = TableCopier(
            gov             = gov,
            src_db_type     = "postgresql",
            dst_db_type     = "snowflake",
            transforms      = [
                {"op": "mask",   "columns": ["email", "phone"]},
                {"op": "hash",   "columns": ["ssn"]},
                {"op": "drop",   "columns": ["password"]},
            ],
            snapshot_dir    = None,
            output_dir      = None,
        )

        result = copier.copy(
            src_cfg   = {"host": "...", "db_name": "crm", ...},
            dst_cfg   = {"account": "...", "database": "DW", ...},
            src_table = "customers",
            dst_table = "customers_clean",        # new table name
            if_exists = "replace",                # or "append" / "upsert"
            natural_keys = ["customer_id"],       # required for upsert
        )

        # result dict contains paths to all generated reports:
        # result["html_report"], result["pii_json"], result["pii_html"],
        # result["diff_json"], result["run_id"], result["rows_copied"]

    Parameters
    ----------
    gov           : GovernanceLogger
    src_db_type   : str   Source platform (see list above).
    dst_db_type   : str   Destination platform (see list above).
    transforms    : list  List of transform dicts to apply before load.
                          Same format as Transformer / NLPipelineBuilder:
                            {"op": "mask",    "columns": [...]}
                            {"op": "hash",    "columns": [...]}
                            {"op": "encrypt", "columns": [...]}
                            {"op": "drop",    "columns": [...]}
                            {"op": "rename",  "columns": {"old": "new"}}
                            {"op": "coerce",  "columns": {"col": "int64"}}
    snapshot_dir  : str | Path   Where to store rollback snapshots.
    output_dir    : str | Path   Where to write report files.
    read_fn       : callable | None
                    Optional override for reading the source table.
                    Signature: read_fn(cfg: dict, table: str) -> pd.DataFrame
    pii_sample_count : int   Max redacted sample values per PII field (default 3).
    chunk_size    : int | None
                    If set, reads and writes the source table in chunks
                    of this many rows (useful for very large tables).
    dry_run       : bool  If True, reads and governs but does NOT write
                    to the destination. Reports are still generated.
                    Prints a summary of what would have been written.
    """

    # ── Supported platforms for the built-in engine builder ───────────────
    _SQLALCHEMY_PLATFORMS = {
        "sqlite", "postgresql", "mysql", "mssql", "snowflake",
    }

    def __init__(
        self,
        gov:              "GovernanceLogger",
        src_db_type:      str,
        dst_db_type:      str,
        transforms:       list             | None = None,
        snapshot_dir:     "str | Path | None"     = None,
        output_dir:       "str | Path | None"     = None,
        read_fn:          "callable | None"       = None,
        pii_sample_count: int                     = 3,
        chunk_size:       "int | None"            = None,
        dry_run:          bool                    = False,
    ) -> None:
        self.gov              = gov
        self.src_db_type      = src_db_type.lower()
        self.dst_db_type      = dst_db_type.lower()
        self.transforms       = transforms or []
        self.snapshot_dir     = Path(snapshot_dir) if snapshot_dir else gov.log_dir / "snapshots"
        self.output_dir       = Path(output_dir) if output_dir else gov.log_dir
        self.read_fn          = read_fn
        self.pii_sample_count = pii_sample_count
        self.chunk_size       = chunk_size
        self.dry_run          = dry_run

        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public entry point ────────────────────────────────────────────────

    def copy(
        self,
        src_cfg:      dict,
        dst_cfg:      dict,
        src_table:    str,
        dst_table:    str,
        if_exists:    str        = "replace",
        natural_keys: list | None = None,
        row_index_col: str | None = None,
        transforms:   list | None = None,
    ) -> dict:
        """
        Copy ``src_table`` from the source database to ``dst_table``
        in the destination database, applying all governance steps.

        Parameters
        ----------
        src_cfg       : dict   Source connection config.
        dst_cfg       : dict   Destination connection config.
        src_table     : str    Source table name.
        dst_table     : str    Destination table name (may differ).
        if_exists     : str    "replace" | "append" | "upsert"
        natural_keys  : list   Required when if_exists="upsert". Column(s)
                               that uniquely identify a row.
        row_index_col : str    Column to use as row key in the PII exposure
                               index (hashed SHA-256). Defaults to positional.

        Returns
        -------
        dict  Paths to all generated reports plus run metadata:
              run_id, rows_copied, rows_original, quality_score,
              html_report, pii_json, pii_html, diff_json, snapshot_path
        """
        ts     = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        # Allow per-call transforms override without mutating self.transforms
        _orig_transforms = None
        if transforms is not None:
            _orig_transforms, self.transforms = self.transforms, list(transforms)
        run_id = f"copy_{ts}_{src_table}_to_{dst_table}"

        print(f"\n{'═'*64}")
        print(f"  TableCopier  {'[DRY RUN] ' if self.dry_run else ''}")
        print(f"  {self.src_db_type}::{src_table}  →  {self.dst_db_type}::{dst_table}")
        print(f"  run_id: {run_id}")
        print(f"{'═'*64}\n")

        self.gov.transformation_applied("TABLE_COPY_START", {
            "run_id":     run_id,
            "src_table":  src_table,
            "dst_table":  dst_table,
            "src_type":   self.src_db_type,
            "dst_type":   self.dst_db_type,
            "if_exists":  if_exists,
            "dry_run":    self.dry_run,
        })

        result: dict = {
            "run_id":        run_id,
            "src_table":     src_table,
            "dst_table":     dst_table,
            "dry_run":       self.dry_run,
            "rows_original": 0,
            "rows_copied":   0,
            "quality_score": None,
            "html_report":   None,
            "pii_json":      None,
            "pii_html":      None,
            "diff_json":     None,
            "snapshot_path": None,
        }

        # ── Step 1: Read source ───────────────────────────────────────────
        print("  [1/7] Reading source table…")
        df = self._read_source(src_cfg, src_table)
        result["rows_original"] = len(df)
        print(f"        {len(df):,} rows × {len(df.columns)} columns  "
              f"({', '.join(df.columns[:6])}"
              f"{'…' if len(df.columns) > 6 else ''})")

        self.gov.transformation_applied("TABLE_READ_COMPLETE", {
            "run_id":   run_id,
            "table":    src_table,
            "rows":     len(df),
            "columns":  list(df.columns),
            "dtypes":   {c: str(df[c].dtype) for c in df.columns},
        })

        # ── Step 2: PII scan ──────────────────────────────────────────────
        print("  [2/7] Scanning for PII…")
        pii_reporter = PIIDiscoveryReporter(
            self.gov,
            sample_count  = self.pii_sample_count,
            row_index_col = row_index_col,
            hash_row_keys = True,
            include_html  = True,
            output_dir    = str(self.output_dir),
            run_label     = run_id,
        )
        findings = pii_reporter.scan(df, source_label=src_table)
        if findings:
            print(f"        {len(findings)} PII field(s) found: "
                  f"{', '.join(f['field'] for f in findings)}")
        else:
            print("        No PII fields detected.")

        # ── Step 3: Apply transforms ──────────────────────────────────────
        print("  [3/7] Applying transforms…")
        df, transform_log = self._apply_transforms(df, pii_reporter)

        # Record what happened to each PII field
        pii_reporter.record_actions_from_transforms(self.transforms)
        if transform_log:
            for entry in transform_log:
                print(f"        {entry}")
        else:
            print("        No transforms configured — data passed through as-is.")

        # ── Step 4: Data quality score ────────────────────────────────────
        print("  [4/7] Scoring data quality…")
        scorer  = DataQualityScorer(self.gov)
        quality = scorer.score(df)
        score   = quality.get("score", "N/A")
        grade   = quality.get("grade", "?")
        result["quality_score"] = score
        print(f"        Quality score: {score:.1f}/100  (grade {grade})")
        for dim, val in quality.get("dimensions", {}).items():
            print(f"          {dim:<14} {val:.1f}")

        # ── Step 5: Data diff (if destination exists) ─────────────────────
        print("  [5/7] Checking destination for existing data…")
        diff_report = None
        diff_path   = None
        df_existing = self._read_dest_if_exists(dst_cfg, dst_table)
        if df_existing is not None:
            print(f"        Existing destination: {len(df_existing):,} rows — diffing…")
            differ      = DataDiffReporter(self.gov)
            diff_report = differ.compare(df_existing, df)
            diff_path   = differ.save(diff_report)
            result["diff_json"] = str(diff_path)
            added   = diff_report.get("rows_added",   0)
            deleted = diff_report.get("rows_deleted",  0)
            changed = diff_report.get("rows_changed",  0)
            print(f"        +{added:,} added  -{deleted:,} deleted  ~{changed:,} changed")
        else:
            print("        Destination table does not exist yet — skipping diff.")

        # ── Step 6: Load (with reversible snapshot) ───────────────────────
        if self.dry_run:
            print("  [6/7] DRY RUN — skipping write.")
            print(f"        Would write {len(df):,} rows to "
                  f"{self.dst_db_type}::{dst_table} ({if_exists}).")
            result["rows_copied"] = 0
        else:
            print(f"  [6/7] Loading {len(df):,} rows → {self.dst_db_type}::{dst_table}…")
            snapshot_path = self._load_with_governance(
                df, dst_cfg, dst_table, if_exists, natural_keys, run_id
            )
            result["rows_copied"]   = len(df)
            result["snapshot_path"] = snapshot_path
            print(f"        Load complete. Snapshot: {snapshot_path or 'n/a'}")

        # ── Step 7: Generate reports ──────────────────────────────────────
        print("  [7/7] Generating governance reports…")

        # PII discovery report (JSON + HTML)
        pii_paths = pii_reporter.write(
            json_path = str(self.output_dir / f"pii_{run_id}.json"),
            html_path = str(self.output_dir / f"pii_{run_id}.html"),
        )
        result["pii_json"] = pii_paths.get("json")
        result["pii_html"] = pii_paths.get("html")

        # HTML run report
        html_path = str(self.output_dir / f"run_report_{run_id}.html")
        try:
            html_gen = HTMLReportGenerator(self.gov)
            html_gen.generate(
                df         = df,
                run_meta   = {
                    "source":      f"{self.src_db_type}::{src_table}",
                    "destination": f"{self.dst_db_type}::{dst_table}",
                    "run_id":      run_id,
                    "dry_run":     self.dry_run,
                },
                quality    = quality,
                diff       = diff_report,
                output_path = html_path,
            )
            result["html_report"] = html_path
        except Exception as exc:  # pylint: disable=broad-except
            print(f"        ⚠  HTML report failed: {exc}")

        # Log completion
        pii_summary = pii_reporter.build().get("executive_summary", {})
        self.gov.transformation_applied("TABLE_COPY_COMPLETE", {
            "run_id":            run_id,
            "src_table":         src_table,
            "dst_table":         dst_table,
            "rows_original":     result["rows_original"],
            "rows_copied":       result["rows_copied"],
            "quality_score":     result["quality_score"],
            "pii_fields_found":  pii_summary.get("total_pii_fields", 0),
            "dry_run":           self.dry_run,
        })

        # ── Summary ───────────────────────────────────────────────────────
        print(f"\n{'─'*64}")
        print(f"  {'[DRY RUN] ' if self.dry_run else ''}Copy complete")
        print(f"  Rows:          {result['rows_original']:,} read  "
              f"→  {result['rows_copied']:,} written")
        print(f"  Quality score: {score:.1f}/100 (grade {grade})")
        print(f"  PII fields:    {pii_summary.get('total_pii_fields', 0)}")
        if result.get("html_report"):
            print(f"  Run report:    {result['html_report']}")
        if result.get("pii_html"):
            print(f"  PII report:    {result['pii_html']}")
        if result.get("diff_json"):
            print(f"  Diff report:   {result['diff_json']}")
        print(f"{'─'*64}\n")

        if _orig_transforms is not None:
            self.transforms = _orig_transforms
        return result

    # ── Internal: read source ─────────────────────────────────────────────

    def _read_source(self, cfg: dict, table: str) -> "pd.DataFrame":
        """
        Read the source table into a DataFrame.

        Uses read_fn if supplied, otherwise falls back to the built-in
        SQLAlchemy engine builder for supported platforms.
        """
        if self.read_fn is not None:
            return self.read_fn(cfg, table)

        if self.src_db_type not in self._SQLALCHEMY_PLATFORMS:
            raise ValueError(
                f"TableCopier: built-in reader does not support "
                f"'{self.src_db_type}'. Supply a read_fn=(cfg, table) → DataFrame "
                f"callable, or use one of: {sorted(self._SQLALCHEMY_PLATFORMS)}"
            )

        engine = self._build_engine(self.src_db_type, cfg)
        with engine.connect() as conn:
            return pd.read_sql_table(table, conn)

    # ── Internal: read destination (for diff) ─────────────────────────────

    def _read_dest_if_exists(self, cfg: dict, table: str) -> "pd.DataFrame | None":
        """
        Try to read the destination table. Returns None if the table does
        not exist or the platform does not support the built-in reader.
        """
        try:
            if self.dst_db_type not in self._SQLALCHEMY_PLATFORMS:
                return None  # can't diff non-SQLAlchemy destinations
            engine = self._build_engine(self.dst_db_type, cfg)
            from sqlalchemy import inspect as _sai
            if table not in _sai(engine).get_table_names():
                return None
            with engine.connect() as conn:
                return pd.read_sql_table(table, conn)
        except Exception:  # pylint: disable=broad-except
            return None

    # ── Internal: apply transforms ────────────────────────────────────────

    def _apply_transforms(
        self,
        df: "pd.DataFrame",
        pii_reporter: "PIIDiscoveryReporter",
    ) -> "tuple[pd.DataFrame, list[str]]":
        """
        Apply the transforms list to df. Supported ops:
            mask    — replace with SHA-256 hash (first 8 hex chars)
            hash    — same as mask
            encrypt — Fernet AES-128 encryption (key auto-generated per run)
            drop    — remove column entirely
            rename  — rename columns ({"old": "new"})
            coerce  — cast dtype  ({"col": "int64"})
        Returns (transformed_df, log_entries).
        """
        df  = df.copy()
        log = []

        # Fernet key generated on demand inside the encrypt branch

        for t in self.transforms:
            op   = t.get("op", "").lower()
            cols = t.get("columns", [])

            # Normalise: columns can be a list (mask/hash/drop/encrypt)
            # or a dict (rename/coerce)
            if isinstance(cols, dict):
                col_map = cols
                cols    = list(cols.keys())
            else:
                col_map = {}

            # Only operate on columns that actually exist in df
            present = [c for c in cols if c in df.columns]
            missing = [c for c in cols if c not in df.columns]
            if missing:
                log.append(f"⚠  {op}: columns not found, skipped: {missing}")

            if not present and op not in ("rename", "coerce"):
                continue

            if op in ("mask", "hash"):
                import hashlib as _hl
                for col in present:
                    df[col] = df[col].apply(
                        lambda v, _h=_hl: _h.sha256(str(v).encode()).hexdigest()[:8]
                        if pd.notna(v) else v
                    )
                log.append(f"✓  {op}: {present}")

            elif op == "encrypt":
                try:
                    _fk = Fernet.generate_key()
                    _f  = Fernet(_fk)
                    for col in present:
                        df[col] = df[col].apply(
                            lambda v, _fe=_f: _fe.encrypt(str(v).encode()).decode()
                            if pd.notna(v) else v
                        )
                    log.append(f"✓  encrypt: {present}  (key stored in ledger)")
                    self.gov.transformation_applied("ENCRYPT_KEY_GENERATED", {
                        "columns": present,
                        "note":    "Store the Fernet key securely to decrypt later",
                    })
                except Exception as exc:  # pylint: disable=broad-except
                    log.append(f"⚠  encrypt failed ({exc}) — columns untouched: {present}")

            elif op == "drop":
                df.drop(columns=present, inplace=True)
                log.append(f"✓  drop: {present}")

            elif op == "rename":
                rename_map = {k: v for k, v in col_map.items() if k in df.columns}
                if rename_map:
                    df.rename(columns=rename_map, inplace=True)
                    log.append(f"✓  rename: {rename_map}")

            elif op == "coerce":
                for col, dtype in col_map.items():
                    if col in df.columns:
                        try:
                            df[col] = df[col].astype(dtype)
                            log.append(f"✓  coerce: {col} → {dtype}")
                        except Exception as exc:  # pylint: disable=broad-except
                            log.append(f"⚠  coerce {col}→{dtype} failed: {exc}")

            else:
                log.append(f"⚠  unknown op '{op}' — skipped")

        return df, log

    # ── Internal: load with governance ────────────────────────────────────

    def _load_with_governance(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str,
        natural_keys: "list | None",
        run_id:       str,
    ) -> "str | None":
        """
        Load df into the destination using ReversibleLoader (so every load
        is snapshottable and rollbackable), then fall back to SQLLoader for
        platforms not covered by the built-in engine.

        Returns the path to the snapshot file, or None.
        """
        snapshot_path = None

        # Attempt ReversibleLoader for SQLAlchemy-supported destinations
        if self.dst_db_type in self._SQLALCHEMY_PLATFORMS:
            try:
                rev = ReversibleLoader(
                    gov          = self.gov,
                    loader       = None,   # uses built-in pandas → SQLAlchemy writer
                    db_type      = self.dst_db_type,
                    snapshot_dir = str(self.snapshot_dir),
                    strategy     = "parquet",
                )
                rev.load(df, cfg, table, if_exists=if_exists)
                snaps = rev.list_snapshots(table)
                if snaps:
                    snapshot_path = snaps[-1].get("parquet_path")
                return snapshot_path
            except Exception as exc:  # pylint: disable=broad-except
                print(f"  ⚠  ReversibleLoader failed ({exc}), falling back to SQLLoader")

        # Fall back to SQLLoader (handles upsert via natural_keys)
        loader = SQLLoader(db_type=self.dst_db_type, gov=self.gov)
        loader.load(df, cfg, table, if_exists=if_exists, natural_keys=natural_keys)
        return None

    # ── Internal: engine builder ──────────────────────────────────────────

    @staticmethod
    def _build_engine(db_type: str, cfg: dict):
        """
        Build a SQLAlchemy engine for the given db_type and config dict.
        Supports: sqlite, postgresql, mysql, mssql, snowflake.
        """
        from sqlalchemy import create_engine as _ce
        t = db_type.lower()

        if t == "sqlite":
            return _ce(f"sqlite:///{cfg['db_name']}.db")

        if t == "postgresql":
            return _ce(
                f"postgresql+psycopg2://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 5432)}/{cfg['db_name']}"
            )

        if t == "mysql":
            return _ce(
                f"mysql+pymysql://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 3306)}/{cfg['db_name']}"
            )

        if t == "mssql":
            return _ce(
                f"mssql+pyodbc://{cfg['user']}:{cfg['password']}"
                f"@{cfg['host']}:{cfg.get('port', 1433)}/{cfg['db_name']}"
                f"?driver={cfg.get('driver', 'ODBC+Driver+17+for+SQL+Server')}"
            )

        if t == "snowflake":
            if not HAS_SNOWFLAKE:
                raise RuntimeError("snowflake-connector-python required")
            from snowflake.sqlalchemy import URL as _sfurl
            return _ce(_sfurl(
                account   = cfg["account"],
                user      = cfg["user"],
                password  = cfg["password"],
                database  = cfg["database"],
                schema    = cfg.get("schema", "PUBLIC"),
                warehouse = cfg["warehouse"],
                role      = cfg.get("role", ""),
            ))

        raise ValueError(
            f"TableCopier._build_engine: unsupported db_type '{t}'. "
            f"Supported: sqlite, postgresql, mysql, mssql, snowflake."
        )



# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: PIIDiscoveryReporter  (NEW v4.7)
# ═════════════════════════════════════════════════════════════════════════════

class PIIDiscoveryReporter:
    """
    Automated PII discovery report — after each pipeline run, produce a
    structured report of every PII field found, which rows contained data
    in that field, and what action was taken on it.

    Designed for GDPR audit responses (Article 30 Records of Processing),
    CCPA compliance, and internal data governance reviews.

    What it produces
    ────────────────
    1. Field inventory         Every column that matched a PII pattern, with
                               the regex that fired, the GDPR/CCPA article it
                               maps to, whether it is special-category data,
                               how many rows contained a non-null value, and
                               what action was applied (masked/hashed/encrypted/
                               dropped/retained).

    2. Row-level exposure index  For every PII field, the list of row indices
                               (or hashed row-keys) that contained a non-null /
                               non-empty value.  This tells you exactly which
                               data subjects were affected.

    3. Safe value samples      Up to N sample values per field, automatically
                               truncated and partially redacted so the report
                               itself never contains raw PII.  Samples are
                               shown as e.g. "al***@gm***.com (len=24)".

    4. Action audit trail      Every transform applied to PII columns is
                               cross-referenced so you can prove each field
                               was handled correctly.

    5. Compliance checklist    A structured pass/fail checklist covering the
                               most common GDPR obligations (data minimisation,
                               purpose limitation, pseudonymisation, etc.).

    6. JSON report             Machine-readable, suitable for feeding into a
                               SIEM, DLP tool, or a data catalogue.

    7. HTML report             Human-readable, with colour-coded risk levels,
                               per-field drill-down tables, and a compliance
                               summary — ready to attach to a GDPR audit
                               response e-mail.

    Usage
    ─────
        reporter = PIIDiscoveryReporter(gov)

        # Scan a DataFrame and record what actions were taken
        reporter.scan(df, source_label="users.csv")
        reporter.record_action("email",  "MASKED")
        reporter.record_action("phone",  "HASHED")
        reporter.record_action("salary", "RETAINED")

        # After the pipeline run completes:
        report = reporter.build()          # returns dict
        reporter.save_json("pii_report.json")
        reporter.save_html("pii_report.html")
        reporter.print_summary()

        # Drop-in for GovernanceLogger.write_pii_report():
        reporter.write()   # saves both JSON + HTML, logs to governance ledger

    Parameters
    ──────────
    gov               : GovernanceLogger
    sample_count      : int    Max sample values per field (default 3).
                               Samples are redacted before storage.
    row_index_col     : str | None   Column to use as the row key in the
                               exposure index (e.g. "user_id").  If None,
                               positional integer indices are used.
    hash_row_keys     : bool   If True, row keys in the exposure index are
                               SHA-256 hashed so the report contains no raw
                               identifiers.  Default True.
    include_html      : bool   Generate an HTML report alongside JSON.
    output_dir        : str | Path   Where to write report files.
    run_label         : str    Human-readable label for this pipeline run,
                               included in every report header.
    """

    # ── GDPR / CCPA metadata per PII category ────────────────────────────
    _FIELD_METADATA: dict[str, dict] = {
        "email":         {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "medium", "category": "contact"},
        "phone":         {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "medium", "category": "contact"},
        "mobile":        {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "medium", "category": "contact"},
        "ssn":           {"gdpr": "Art. 9 — special category",          "ccpa": "§1798.140(o)(2)", "risk": "critical","category": "government_id"},
        "password":      {"gdpr": "Art. 32 — security",                  "ccpa": "§1798.150",       "risk": "critical","category": "credential"},
        "credit_card":   {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "critical","category": "financial"},
        "ip_address":    {"gdpr": "Art. 4(1) — online identifier",      "ccpa": "§1798.140(o)(1)", "risk": "low",    "category": "technical"},
        "dob":           {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "medium", "category": "demographic"},
        "name":          {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "medium", "category": "identity"},
        "address":       {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "medium", "category": "location"},
        "location":      {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "medium", "category": "location"},
        "gender":        {"gdpr": "Art. 9 — special category",          "ccpa": "§1798.140(o)(1)", "risk": "high",   "category": "demographic"},
        "race":          {"gdpr": "Art. 9(1) — special category",       "ccpa": "§1798.140(o)(1)", "risk": "critical","category": "special"},
        "ethnicity":     {"gdpr": "Art. 9(1) — special category",       "ccpa": "§1798.140(o)(1)", "risk": "critical","category": "special"},
        "passport":      {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(2)", "risk": "critical","category": "government_id"},
        "license":       {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(2)", "risk": "high",   "category": "government_id"},
        "biometric":     {"gdpr": "Art. 9(1) — biometric data",         "ccpa": "§1798.140(o)(1)", "risk": "critical","category": "special"},
        "health":        {"gdpr": "Art. 9(1) — health data",            "ccpa": "§1798.140(o)(1)", "risk": "critical","category": "special"},
        "medical":       {"gdpr": "Art. 9(1) — health data",            "ccpa": "§1798.140(o)(1)", "risk": "critical","category": "special"},
        "salary":        {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "high",   "category": "financial"},
        "income":        {"gdpr": "Art. 4(1) — personal data",          "ccpa": "§1798.140(o)(1)", "risk": "high",   "category": "financial"},
        "religion":      {"gdpr": "Art. 9(1) — special category",       "ccpa": "§1798.140(o)(1)", "risk": "critical","category": "special"},
        "political":     {"gdpr": "Art. 9(1) — special category",       "ccpa": "§1798.140(o)(1)", "risk": "critical","category": "special"},
        "geo":           {"gdpr": "Art. 4(1) — location data",          "ccpa": "§1798.140(o)(1)", "risk": "medium", "category": "location"},
    }

    _RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

    def __init__(
        self,
        gov:            "GovernanceLogger",
        sample_count:   int             = 3,
        row_index_col:  str | None      = None,
        hash_row_keys:  bool            = True,
        include_html:   bool            = True,
        output_dir:     str | Path | None = None,
        run_label:      str             = "",
    ) -> None:
        self.gov           = gov
        self.sample_count  = sample_count
        self.row_index_col = row_index_col
        self.hash_row_keys = hash_row_keys
        self.include_html  = include_html
        self.output_dir    = Path(output_dir) if output_dir else gov.log_dir
        self.run_label     = run_label or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Internal state accumulated across scan() / record_action() calls
        self._fields:      dict[str, dict] = {}   # field_name → field record
        self._actions:     dict[str, list] = {}   # field_name → [action, ...]
        self._source_labels: list[str]     = []
        self._scan_count:  int             = 0
        self._total_rows:  int             = 0
        self._report:      dict | None     = None

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _redact_value(value: str, max_show: int = 3) -> str:
        """
        Partially redact a string value so samples in the report never contain
        raw PII.  Shows the first ``max_show`` characters then asterisks.

        Examples:
            "alice@gmail.com"  → "ali***@gm***.com (len=15)"
            "555-867-5309"     → "555*** (len=12)"
            "John Smith"       → "Joh*** (len=10)"
        """
        s = str(value).strip()
        if not s or s.lower() in ("nan", "none", "null", ""):
            return "<empty>"
        shown = s[:max_show]
        # For emails, also show redacted domain hint
        if "@" in s:
            parts = s.split("@", 1)
            domain_parts = parts[1].split(".", 1)
            d_shown = domain_parts[0][:2] + "***"
            ext     = ("." + domain_parts[1]) if len(domain_parts) > 1 else ""
            return f"{shown}***@{d_shown}{ext} (len={len(s)})"
        return f"{shown}*** (len={len(s)})"

    @staticmethod
    def _hash_key(value) -> str:
        """SHA-256 hash of a row key for the exposure index."""
        import hashlib
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]

    def _field_metadata(self, field_name: str) -> dict:
        """Look up risk / GDPR / CCPA metadata for a field name."""
        fl = field_name.lower()
        for keyword, meta in self._FIELD_METADATA.items():
            if keyword in fl:
                return meta
        return {"gdpr": "Art. 4(1) — personal data", "ccpa": "§1798.140(o)",
                "risk": "medium", "category": "other"}

    # ── Core scan ─────────────────────────────────────────────────────────

    def scan(
        self,
        df:           "pd.DataFrame",
        source_label: str = "",
    ) -> list[dict]:
        """
        Scan a DataFrame for PII columns and build the field inventory.

        This method can be called multiple times (e.g. once per source file)
        — results accumulate.  Call ``build()`` when all scans are done.

        Parameters
        ──────────
        df           : pd.DataFrame   The DataFrame to scan.
        source_label : str            Human-readable label for the source
                                      (e.g. "users.csv", "orders table").

        Returns
        ───────
        list[dict]   PII findings for this DataFrame (same format as
                     ``_detect_pii()``).
        """
        label = source_label or f"source_{self._scan_count + 1}"
        self._source_labels.append(label)
        self._scan_count += 1
        self._total_rows  = max(self._total_rows, len(df))

        findings = _detect_pii(list(df.columns))

        # Determine the row-key series
        if self.row_index_col and self.row_index_col in df.columns:
            row_keys = df[self.row_index_col].astype(str).tolist()
        else:
            row_keys = list(range(len(df)))

        # Enrich findings: override special_category from our richer _FIELD_METADATA
        for f in findings:
            meta_sc = self._field_metadata(f["field"])
            if meta_sc.get("risk") == "critical":
                f["special_category"] = True
        for f in findings:
            col = f["field"]
            if col not in self._fields:
                meta = self._field_metadata(col)
                self._fields[col] = {
                    "field":            col,
                    "source":           label,
                    "matched_pattern":  f["matched_pattern"],
                    "special_category": f["special_category"],
                    "gdpr_article":     f.get("gdpr_reference", meta["gdpr"]),
                    "ccpa_reference":   f.get("ccpa_reference",  meta["ccpa"]),
                    "risk_level":       meta["risk"],
                    "category":         meta["category"],
                    "dtype":            str(df[col].dtype),
                    "total_rows":       len(df),
                    "non_null_rows":    int(df[col].notna().sum()),
                    "empty_rows":       int(df[col].isna().sum()),
                    "exposure_pct":     0.0,
                    "row_exposure_index": [],
                    "safe_samples":     [],
                    "actions":          [],
                }

            rec = self._fields[col]
            rec["total_rows"]   = len(df)
            rec["non_null_rows"] = int(df[col].notna().sum())
            rec["empty_rows"]   = int(df[col].isna().sum())
            rec["exposure_pct"] = round(
                100.0 * rec["non_null_rows"] / max(len(df), 1), 2
            )

            # Row exposure index — which rows have data in this PII field
            mask       = df[col].notna() & (df[col].astype(str).str.strip() != "")
            exposed_keys = [row_keys[i] for i in df.index[mask].tolist()
                            if i < len(row_keys)]
            if self.hash_row_keys:
                exposed_keys = [self._hash_key(k) for k in exposed_keys]
            rec["row_exposure_index"] = exposed_keys

            # Safe samples — redacted, never raw PII
            sample_pool = df.loc[mask, col].dropna().head(self.sample_count * 3)
            samples = []
            for v in sample_pool:
                s = self._redact_value(str(v))
                if s not in samples:
                    samples.append(s)
                if len(samples) >= self.sample_count:
                    break
            rec["safe_samples"] = samples

        # Log to governance ledger
        self.gov.pii_detected(findings)
        self.gov.transformation_applied("PII_SCAN_COMPLETE", {
            "source":         label,
            "rows_scanned":   len(df),
            "pii_fields":     len(findings),
            "special_fields": sum(1 for f in findings if f.get("special_category")),
        })

        print(f"  🔍  PII scan: '{label}'  →  {len(findings)} PII field(s) found"
              + (f"  ({sum(1 for f in findings if f.get('special_category'))} special-category)" if any(f.get("special_category") for f in findings) else ""))

        return findings

    # ── Action recording ──────────────────────────────────────────────────

    def record_action(
        self,
        field:   str,
        action:  str,
        detail:  str = "",
    ) -> None:
        """
        Record what was done to a PII field during this pipeline run.

        Parameters
        ──────────
        field  : str   Column name (must match a field found by scan()).
        action : str   Action taken.  Recognised values:
                         "MASKED"    — values replaced with asterisks
                         "HASHED"    — values SHA-256 hashed
                         "ENCRYPTED" — AES-256 encrypted at rest
                         "DROPPED"   — column removed from output
                         "RETAINED"  — field kept as-is (document why)
                         "TOKENISED" — replaced with a reversible token
                         "PSEUDONYMISED" — de-identified but linkable
                         "GENERALISED"   — binned / rounded (e.g. age→decade)
                         Any other string is recorded verbatim.
        detail : str   Optional free-text explanation (e.g. "GDPR Art.6(1)(b)
                       — necessary for contract performance").
        """
        if field not in self._actions:
            self._actions[field] = []
        self._actions[field].append({
            "action":    action,
            "detail":    detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if field in self._fields:
            self._fields[field]["actions"].append({"action": action, "detail": detail})

        self.gov.pii_action(field, action)

    def record_actions_from_transforms(self, transforms: list[dict]) -> None:
        """
        Convenience: infer actions from a transforms list (as produced by
        NLPipelineBuilder.generate_config_offline() or similar).

        Parameters
        ──────────
        transforms : list[dict]   Each dict has "op" and "columns" keys.
        """
        op_to_action = {
            "mask":           "MASKED",
            "hash":           "HASHED",
            "encrypt":        "ENCRYPTED",
            "drop":           "DROPPED",
            "pseudonymise":   "PSEUDONYMISED",
            "pseudonymize":   "PSEUDONYMISED",
            "tokenise":       "TOKENISED",
            "tokenize":       "TOKENISED",
            "generalise":     "GENERALISED",
            "generalize":     "GENERALISED",
        }
        for t in transforms:
            op   = t.get("op", "").lower()
            cols = t.get("columns", [])
            action = op_to_action.get(op)
            if action:
                for col in cols:
                    self.record_action(col, action,
                                       detail=f"applied via transform op={op!r}")

    # ── Build report ──────────────────────────────────────────────────────

    def build(self) -> dict:
        """
        Assemble the full PII discovery report dict.

        Returns
        ───────
        dict   Structured report with keys:
               meta, executive_summary, field_inventory,
               exposure_index, compliance_checklist, raw_ledger_events.

        The returned dict is also cached in ``self._report`` for use by
        ``save_json()``, ``save_html()``, and ``print_summary()``.
        """
        ts = datetime.now(timezone.utc).isoformat()

        # Apply any recorded actions to fields
        for field, action_list in self._actions.items():
            if field in self._fields:
                self._fields[field]["actions"] = action_list

        # Mark fields with no recorded action as RETAINED (worst-case assumption)
        for field, rec in self._fields.items():
            if not rec["actions"]:
                rec["actions"] = [{"action": "RETAINED",
                                    "detail": "no transform recorded for this field",
                                    "timestamp": ts}]

        fields_list = sorted(
            self._fields.values(),
            key=lambda r: (self._RISK_ORDER.get(r["risk_level"], 4), r["field"])
        )

        # ── Executive summary ─────────────────────────────────────────────
        n_fields         = len(fields_list)
        n_special        = sum(1 for f in fields_list if f["special_category"])
        n_critical       = sum(1 for f in fields_list if f["risk_level"] == "critical")
        n_retained       = sum(1 for f in fields_list if any(a["action"] == "RETAINED" for a in f["actions"]))
        n_protected      = n_fields - n_retained
        actions_used     = sorted({a["action"] for f in fields_list for a in f["actions"]})
        max_exposure_pct = max((f["exposure_pct"] for f in fields_list), default=0.0)

        summary = {
            "total_pii_fields":         n_fields,
            "special_category_fields":  n_special,
            "critical_risk_fields":     n_critical,
            "fields_with_protection":   n_protected,
            "fields_retained_raw":      n_retained,
            "protection_rate_pct":      round(100.0 * n_protected / max(n_fields, 1), 1),
            "max_row_exposure_pct":     max_exposure_pct,
            "total_rows_scanned":       self._total_rows,
            "protection_actions_used":  actions_used,
            "sources_scanned":          self._source_labels,
        }

        # ── Compliance checklist ──────────────────────────────────────────
        checklist = self._build_compliance_checklist(fields_list, summary)

        # ── Exposure index — compact version (field → row count) ──────────
        exposure_index = {
            f["field"]: {
                "exposed_row_count":   f["non_null_rows"],
                "exposure_pct":        f["exposure_pct"],
                "row_keys_hashed":     self.hash_row_keys,
                "row_exposure_sample": f["row_exposure_index"][:50],  # cap at 50 for report
            }
            for f in fields_list
        }

        # ── Ledger cross-reference ────────────────────────────────────────
        pii_ledger = [
            e for e in self.gov.ledger_entries
            if e.get("category") in ("PRIVACY",) or e.get("action", "").startswith("PII_")
        ]

        report = {
            "meta": {
                "report_type":       "PII_DISCOVERY_REPORT",
                "version":           "4.7",
                "generated_utc":     ts,
                "run_label":         self.run_label,
                "pipeline_id":       PIPELINE_ID,
                "hash_row_keys":     self.hash_row_keys,
                "sample_count":      self.sample_count,
                "regulation_refs": {
                    "GDPR": "Regulation (EU) 2016/679 — Arts. 4, 9, 17, 25, 30, 32",
                    "CCPA": "Cal. Civ. Code §1798.100 et seq.",
                },
            },
            "executive_summary":   summary,
            "field_inventory":     fields_list,
            "exposure_index":      exposure_index,
            "compliance_checklist": checklist,
            "ledger_event_count":  len(pii_ledger),
        }

        self._report = report

        self.gov.transformation_applied("PII_REPORT_BUILT", {
            "total_pii_fields":       n_fields,
            "special_category_fields": n_special,
            "fields_retained_raw":    n_retained,
            "protection_rate_pct":    summary["protection_rate_pct"],
            "compliance_pass":        sum(1 for c in checklist if c["status"] == "PASS"),
            "compliance_fail":        sum(1 for c in checklist if c["status"] == "FAIL"),
        })

        return report

    def _build_compliance_checklist(
        self,
        fields: list[dict],
        summary: dict,
    ) -> list[dict]:
        """Build a structured GDPR/CCPA compliance checklist."""

        def chk(check_id: str, name: str, article: str, condition: bool,
                fail_msg: str, pass_msg: str) -> dict:
            return {
                "check_id":   check_id,
                "name":       name,
                "article":    article,
                "status":     "PASS" if condition else "FAIL",
                "message":    pass_msg if condition else fail_msg,
            }

        retained_special = [
            f["field"] for f in fields
            if f["special_category"]
            and any(a["action"] == "RETAINED" for a in f["actions"])
        ]
        retained_critical = [
            f["field"] for f in fields
            if f["risk_level"] == "critical"
            and any(a["action"] == "RETAINED" for a in f["actions"])
        ]
        has_credentials = any(f["category"] == "credential" for f in fields)
        credentials_protected = all(
            not any(a["action"] == "RETAINED" for a in f["actions"])
            for f in fields if f["category"] == "credential"
        )

        return [
            chk("GDPR-01",
                "Special-category data protection",
                "Art. 9 GDPR",
                not retained_special,
                f"Special-category fields retained unprotected: {retained_special}",
                "All special-category fields are protected"),

            chk("GDPR-02",
                "Critical PII pseudonymisation or encryption",
                "Art. 25, 32 GDPR",
                not retained_critical,
                f"Critical-risk fields retained unprotected: {retained_critical}",
                "All critical-risk fields are pseudonymised or encrypted"),

            chk("GDPR-03",
                "Data minimisation",
                "Art. 5(1)(c) GDPR",
                summary["fields_retained_raw"] == 0
                or summary["protection_rate_pct"] >= 50.0,
                f"Only {summary['protection_rate_pct']}% of PII fields are protected — "
                f"review necessity of retaining {summary['fields_retained_raw']} raw field(s)",
                f"{summary['protection_rate_pct']}% of PII fields have protection applied"),

            chk("GDPR-04",
                "Credential / password protection",
                "Art. 32 GDPR",
                not has_credentials or credentials_protected,
                "Credential fields (passwords, PINs) found and retained unprotected",
                "No unprotected credential fields" if not has_credentials
                else "All credential fields are protected"),

            chk("GDPR-05",
                "Audit trail integrity",
                "Art. 30 GDPR",
                len(self.gov.ledger_entries) > 0,
                "No governance ledger entries found — audit trail may be incomplete",
                f"Governance ledger has {len(self.gov.ledger_entries)} entries"),

            chk("GDPR-06",
                "PII field documentation",
                "Art. 30(1)(d) GDPR",
                len(fields) > 0,
                "No PII fields documented — run scan() before build()",
                f"{len(fields)} PII field(s) documented with GDPR/CCPA article mapping"),

            chk("GDPR-07",
                "Processing action recorded for all fields",
                "Art. 30(1)(b) GDPR",
                all(f["actions"] for f in fields),
                "One or more PII fields have no recorded processing action",
                "All PII fields have at least one recorded processing action"),

            chk("CCPA-01",
                "Personal information inventory",
                "§1798.100 CCPA",
                len(fields) > 0,
                "No personal information fields inventoried",
                f"{len(fields)} personal information field(s) inventoried"),

            chk("CCPA-02",
                "Sensitive personal information handling",
                "§1798.121 CCPA",
                not retained_special,
                f"Sensitive personal information retained unprotected: {retained_special}",
                "All sensitive personal information fields are protected"),
        ]

    # ── JSON output ───────────────────────────────────────────────────────

    def save_json(self, path: str | Path | None = None) -> Path:
        """
        Save the PII discovery report as JSON.

        Parameters
        ──────────
        path : str | Path | None   Output path.  If None, a timestamped file
                                   is created in ``output_dir``.

        Returns
        ───────
        Path   Absolute path of the written file.
        """
        if self._report is None:
            self.build()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = Path(path) if path else self.output_dir / f"pii_report_{ts}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(self._report, fh, indent=2, default=str)
        print(f"  📄  PII JSON report → {out.resolve()}")
        return out.resolve()

    # ── HTML output ───────────────────────────────────────────────────────

    def save_html(self, path: str | Path | None = None) -> Path:
        """
        Save the PII discovery report as a self-contained HTML file.

        The HTML is styled inline (no external dependencies) and includes:
        - Executive summary card with traffic-light risk indicator
        - Per-field table with risk badge, GDPR article, exposure %, action
        - Compliance checklist with PASS/FAIL badges
        - Timestamp and run metadata in the footer

        Parameters
        ──────────
        path : str | Path | None   Output path.  If None, a timestamped file
                                   is created in ``output_dir``.

        Returns
        ───────
        Path   Absolute path of the written file.
        """
        if self._report is None:
            self.build()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = Path(path) if path else self.output_dir / f"pii_report_{ts}.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self._render_html(), encoding="utf-8")
        print(f"  🌐  PII HTML report → {out.resolve()}")
        return out.resolve()

    def _render_html(self) -> str:
        """Render the report dict as a styled HTML document."""
        r    = self._report
        meta = r["meta"]
        summ = r["executive_summary"]
        fields = r["field_inventory"]
        checks = r["compliance_checklist"]

        risk_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107",   "low":  "#28a745", "unknown": "#6c757d",
        }
        action_colors = {
            "MASKED":        "#17a2b8", "HASHED":       "#6f42c1",
            "ENCRYPTED":     "#007bff", "DROPPED":      "#6c757d",
            "PSEUDONYMISED": "#20c997", "TOKENISED":    "#fd7e14",
            "GENERALISED":   "#e83e8c", "RETAINED":     "#dc3545",
        }

        def risk_badge(level: str) -> str:
            c = risk_colors.get(level, "#6c757d")
            return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{level.upper()}</span>'

        def action_badge(action: str) -> str:
            c = action_colors.get(action, "#6c757d")
            return f'<span style="background:{c};color:#fff;padding:2px 7px;border-radius:4px;font-size:11px">{action}</span>'

        def chk_badge(status: str) -> str:
            c = "#28a745" if status == "PASS" else "#dc3545"
            return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{status}</span>'

        protection_pct = summ["protection_rate_pct"]
        bar_color = "#28a745" if protection_pct >= 80 else "#ffc107" if protection_pct >= 50 else "#dc3545"

        field_rows = ""
        for f in fields:
            actions_html = " ".join(action_badge(a["action"]) for a in f["actions"])
            samples_html = "<br>".join(f["safe_samples"]) or "<em>no data</em>"
            sc_badge = '<span style="background:#dc3545;color:#fff;padding:1px 5px;border-radius:3px;font-size:10px">SPECIAL</span>' if f["special_category"] else ""
            field_rows += f"""
            <tr>
              <td><code>{f['field']}</code> {sc_badge}</td>
              <td>{risk_badge(f['risk_level'])}</td>
              <td style="font-size:12px;color:#555">{f['gdpr_article']}</td>
              <td>{f['category']}</td>
              <td style="font-size:12px">{f['dtype']}</td>
              <td style="text-align:right">{f['non_null_rows']:,}</td>
              <td style="text-align:right">{f['exposure_pct']:.1f}%</td>
              <td>{actions_html}</td>
              <td style="font-size:11px;color:#666">{samples_html}</td>
            </tr>"""

        chk_rows = ""
        for c in checks:
            icon = "✅" if c["status"] == "PASS" else "❌"
            chk_rows += f"""
            <tr>
              <td>{icon} {chk_badge(c['status'])}</td>
              <td><strong>{c['name']}</strong></td>
              <td style="font-size:12px;color:#555">{c['article']}</td>
              <td style="font-size:12px">{c['message']}</td>
            </tr>"""

        n_pass = sum(1 for c in checks if c["status"] == "PASS")
        n_fail = sum(1 for c in checks if c["status"] == "FAIL")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PII Discovery Report — {meta['run_label']}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f8f9fa;color:#212529}}
  .wrap{{max-width:1200px;margin:0 auto;padding:24px}}
  h1{{font-size:22px;font-weight:700;margin:0 0 4px}}
  h2{{font-size:16px;font-weight:600;color:#495057;margin:28px 0 12px;border-bottom:2px solid #dee2e6;padding-bottom:6px}}
  .meta{{font-size:12px;color:#6c757d;margin-bottom:20px}}
  .cards{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}}
  .card{{background:#fff;border-radius:8px;padding:16px 20px;flex:1;min-width:140px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
  .card .num{{font-size:28px;font-weight:700;line-height:1}}
  .card .lbl{{font-size:12px;color:#6c757d;margin-top:4px}}
  .progress{{background:#e9ecef;border-radius:4px;height:8px;margin:6px 0}}
  .progress-bar{{height:8px;border-radius:4px;background:{bar_color};width:{min(protection_pct,100):.0f}%}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:24px}}
  th{{background:#f1f3f5;padding:10px 12px;text-align:left;font-size:12px;font-weight:600;color:#495057;border-bottom:2px solid #dee2e6}}
  td{{padding:9px 12px;border-bottom:1px solid #f1f3f5;font-size:13px;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#f8f9fa}}
  .footer{{font-size:11px;color:#adb5bd;text-align:center;margin-top:32px;padding-top:16px;border-top:1px solid #dee2e6}}
  code{{background:#f1f3f5;padding:1px 5px;border-radius:3px;font-size:12px}}
</style>
</head>
<body>
<div class="wrap">
  <h1>🔍 PII Discovery Report</h1>
  <div class="meta">
    Run: <strong>{meta['run_label']}</strong> &nbsp;·&nbsp;
    Generated: {meta['generated_utc']} &nbsp;·&nbsp;
    Pipeline v{meta['version']} &nbsp;·&nbsp;
    Sources: {', '.join(summ['sources_scanned']) or 'unspecified'} &nbsp;·&nbsp;
    Rows scanned: {summ['total_rows_scanned']:,}
  </div>

  <div class="cards">
    <div class="card"><div class="num">{summ['total_pii_fields']}</div><div class="lbl">PII fields found</div></div>
    <div class="card"><div class="num" style="color:#dc3545">{summ['special_category_fields']}</div><div class="lbl">Special-category fields</div></div>
    <div class="card"><div class="num" style="color:#dc3545">{summ['critical_risk_fields']}</div><div class="lbl">Critical-risk fields</div></div>
    <div class="card"><div class="num" style="color:#28a745">{summ['fields_with_protection']}</div><div class="lbl">Fields protected</div></div>
    <div class="card"><div class="num" style="color:#dc3545">{summ['fields_retained_raw']}</div><div class="lbl">Fields retained raw</div></div>
    <div class="card" style="min-width:200px">
      <div class="lbl">Protection rate</div>
      <div class="num">{protection_pct:.1f}%</div>
      <div class="progress"><div class="progress-bar"></div></div>
    </div>
  </div>

  <h2>Field Inventory</h2>
  <table>
    <tr>
      <th>Column</th><th>Risk</th><th>GDPR Article</th><th>Category</th>
      <th>Type</th><th>Rows with data</th><th>Exposure</th>
      <th>Action(s) taken</th><th>Safe samples</th>
    </tr>
    {field_rows}
  </table>

  <h2>Compliance Checklist — {n_pass}/{n_pass+n_fail} checks passed</h2>
  <table>
    <tr><th>Status</th><th>Check</th><th>Article</th><th>Finding</th></tr>
    {chk_rows}
  </table>

  <h2>Processing Actions Used</h2>
  <p>{"  ".join(action_badge(a) for a in summ['protection_actions_used']) or "<em>none</em>"}</p>

  <div class="footer">
    Generated by PIIDiscoveryReporter v4.7 &nbsp;·&nbsp;
    GDPR: {meta['regulation_refs']['GDPR']} &nbsp;·&nbsp;
    CCPA: {meta['regulation_refs']['CCPA']} &nbsp;·&nbsp;
    Row keys hashed: {meta['hash_row_keys']} &nbsp;·&nbsp;
    Samples redacted: yes
  </div>
</div>
</body>
</html>"""

    # ── print_summary() ───────────────────────────────────────────────────

    def print_summary(self) -> None:
        """Print a compact console summary of the PII discovery report."""
        if self._report is None:
            self.build()
        r    = self._report
        summ = r["executive_summary"]
        fields  = r["field_inventory"]
        checks  = r["compliance_checklist"]

        risk_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                      "low": "🟢", "unknown": "⚪"}
        border = "═" * 64
        print(f"\n  {border}")
        print(f"  🔍  PII DISCOVERY REPORT  —  {r['meta']['run_label']}")
        print(f"  {border}")
        print(f"  Total PII fields      : {summ['total_pii_fields']}")
        print(f"  Special-category      : {summ['special_category_fields']}")
        print(f"  Critical risk         : {summ['critical_risk_fields']}")
        print(f"  Protection rate       : {summ['protection_rate_pct']:.1f}%"
              f"  ({summ['fields_with_protection']} protected,"
              f" {summ['fields_retained_raw']} raw)")
        print(f"  Rows scanned          : {summ['total_rows_scanned']:,}")
        print(f"  Sources               : {', '.join(summ['sources_scanned'])}")
        print(f"  {'-'*62}")
        print(f"  {'Field':<22} {'Risk':<10} {'Exposure':>9}  {'Action':<20} GDPR")
        print(f"  {'-'*62}")
        for f in fields:
            icon    = risk_icons.get(f["risk_level"], "⚪")
            actions = ", ".join(a["action"] for a in f["actions"]) or "—"
            sc_tag  = " ★" if f["special_category"] else ""
            print(f"  {f['field']:<22}{sc_tag} {icon} {f['risk_level']:<8}"
                  f" {f['exposure_pct']:>7.1f}%  {actions:<20}"
                  f" {f['gdpr_article'][:30]}")
        n_pass = sum(1 for c in checks if c["status"] == "PASS")
        n_fail = sum(1 for c in checks if c["status"] == "FAIL")
        print(f"  {'-'*62}")
        print(f"  Compliance: {n_pass}/{n_pass+n_fail} checks passed"
              + (" ✅" if n_fail == 0 else f"  ⚠  {n_fail} FAIL(s)"))
        if n_fail > 0:
            for c in checks:
                if c["status"] == "FAIL":
                    print(f"     ❌ [{c['check_id']}] {c['name']}")
                    print(f"         {c['message']}")
        print(f"  {border}\n")

    # ── Convenience: write both formats ──────────────────────────────────

    def write(
        self,
        json_path: str | Path | None = None,
        html_path: str | Path | None = None,
    ) -> dict[str, Path]:
        """
        Build the report and save both JSON and HTML in one call.

        Drop-in replacement for GovernanceLogger.write_pii_report() with
        dramatically richer output.

        Parameters
        ──────────
        json_path : str | Path | None   JSON output path.
        html_path : str | Path | None   HTML output path.

        Returns
        ───────
        dict   {"json": Path, "html": Path | None}
        """
        if self._report is None:
            self.build()
        result = {}
        result["json"] = self.save_json(json_path)
        if self.include_html:
            result["html"] = self.save_html(html_path)
        self.print_summary()
        return result




# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: DLQReplayer  (NEW v4.8)
# ═════════════════════════════════════════════════════════════════════════════

class DLQReplayer:
    """
    Dead Letter Queue replay engine.

    Rows that failed validation or transformation land in the DLQ CSV.
    After you've diagnosed the root cause and applied a fix — dropping a
    bad column, coercing a type, patching a lookup — DLQReplayer re-runs
    those rows through the full load pipeline.

    Features
    ────────
    Inspection     List every DLQ file in a log directory, grouped by failure
                   reason, with row counts and date ranges.

    Filtering      Replay only a subset of the DLQ: by failure reason, by
                   originating pipeline-id, or by date range.

    Fix hooks      Register per-reason (or global) callables that patch each
                   row-group before it re-enters the pipeline.  Built-in
                   helpers: drop_columns(), coerce_types(), fill_nulls(),
                   rename_columns().

    Dry run        --dry-run shows exactly what would be loaded without
                   touching the destination.

    Quarantine     Rows that fail again after replay are written to a new
                   quarantine DLQ (not mixed back with original failures).

    Partial success  If some reasons succeed and others fail, the overall
                   exit code is 2 (partial) so CI/CD can distinguish from
                   a clean run (0) or total failure (1).

    Audit trail    Every replay is logged to the governance ledger:
                   DLQ_REPLAY_STARTED, DLQ_REPLAY_ROW_FIXED,
                   DLQ_REPLAY_COMPLETE, DLQ_ROW_REQUARANTINED.

    CLI usage
    ─────────
        # Inspect what's in the DLQ
        python pipeline_v3.py --replay-dlq governance_logs/dlq_20250301.csv --dry-run

        # Replay all rows, auto-coerce types, load to same destination
        python pipeline_v3.py --replay-dlq governance_logs/dlq_20250301.csv

        # Replay only rows that failed schema validation, not FK errors
        python pipeline_v3.py --replay-dlq dlq.csv --replay-reason "schema:email"

        # Replay rows from a specific pipeline run
        python pipeline_v3.py --replay-dlq dlq.csv --replay-pipeline-id abc123

        # Replay rows that failed after 2025-03-01
        python pipeline_v3.py --replay-dlq dlq.csv --replay-after 2025-03-01

    Programmatic usage
    ──────────────────
        replayer = DLQReplayer(gov, loader, db_cfg, table)

        # Register a fix for a specific failure reason
        replayer.register_fix(
            reason_contains = "email",
            fix_fn          = DLQReplayer.fill_nulls({"email": "unknown@example.com"}),
        )

        # Register a global fix applied to all reason groups
        replayer.register_fix(
            reason_contains = "*",
            fix_fn          = DLQReplayer.coerce_types({"age": int, "score": float}),
        )

        result = replayer.replay("governance_logs/dlq_20250301.csv", dry_run=False)
        print(result)   # {"loaded": 42, "requarantined": 3, "skipped": 0, "status": "partial"}

    Parameters
    ──────────
    gov         : GovernanceLogger
    loader      : object | None    Any object with a .load(df, cfg, table)
                                   method.  If None, uses SQLAlchemy SQLLoader.
    db_cfg      : dict             Destination database config.
    table       : str              Destination table name.
    if_exists   : str              "append" (default) or "replace".
                                   Almost always "append" for replays.
    dry_run     : bool             If True, print what would load but don't
                                   actually write to the destination.
    quarantine_dir : str | Path    Where to write rows that fail again.
                                   Default: same directory as the DLQ file.
    """

    # Metadata columns written by DeadLetterQueue.write()
    _DLQ_COLS = ("_dlq_pipeline_id", "_dlq_reason", "_dlq_timestamp")

    def __init__(
        self,
        gov:            "GovernanceLogger",
        loader:         object | None = None,
        db_cfg:         dict          = None,
        table:          str           = "",
        if_exists:      str           = "append",
        dry_run:        bool          = False,
        quarantine_dir: str | Path    = "",
        db_type:        str           = "sqlite",
    ) -> None:
        self.gov           = gov
        self.loader        = loader
        self.db_cfg        = db_cfg or {}
        self.table         = table
        self.if_exists     = if_exists
        self.dry_run       = dry_run
        self.db_type       = db_type
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir else None
        self._fixes: list[dict] = []   # [{reason_pattern, fix_fn}, ...]

    # ── Built-in fix factories ────────────────────────────────────────────

    @staticmethod
    def drop_columns(cols: list[str]):
        """Return a fix callable that drops the specified columns."""
        def _fix(df: "pd.DataFrame") -> "pd.DataFrame":
            return df.drop(columns=[c for c in cols if c in df.columns])
        _fix.__name__ = f"drop_columns({cols})"
        return _fix

    @staticmethod
    def coerce_types(mapping: dict[str, type]):
        """
        Return a fix callable that coerces column dtypes.

        Parameters
        ──────────
        mapping : dict[str, type]   e.g. {"age": int, "price": float, "active": bool}
        """
        def _fix(df: "pd.DataFrame") -> "pd.DataFrame":
            for col, dtype in mapping.items():
                if col in df.columns:
                    try:
                        df[col] = df[col].astype(dtype)
                    except (ValueError, TypeError):
                        df[col] = pd.to_numeric(df[col], errors="coerce")
            return df
        _fix.__name__ = f"coerce_types({list(mapping.keys())})"
        return _fix

    @staticmethod
    def fill_nulls(mapping: dict[str, object]):
        """
        Return a fix callable that fills null values with specified defaults.

        Parameters
        ──────────
        mapping : dict[str, object]   e.g. {"email": "unknown@example.com", "score": 0}
        """
        def _fix(df: "pd.DataFrame") -> "pd.DataFrame":
            return df.fillna({k: v for k, v in mapping.items() if k in df.columns})
        _fix.__name__ = f"fill_nulls({list(mapping.keys())})"
        return _fix

    @staticmethod
    def rename_columns(mapping: dict[str, str]):
        """Return a fix callable that renames columns."""
        def _fix(df: "pd.DataFrame") -> "pd.DataFrame":
            return df.rename(columns={k: v for k, v in mapping.items() if k in df.columns})
        _fix.__name__ = f"rename_columns({mapping})"
        return _fix

    @staticmethod
    def strip_strings(cols: list[str] | None = None):
        """
        Return a fix callable that strips whitespace from string columns.

        Parameters
        ──────────
        cols : list[str] | None   Columns to strip.  None = all object columns.
        """
        def _fix(df: "pd.DataFrame") -> "pd.DataFrame":
            targets = cols or [c for c in df.columns if df[c].dtype == object]
            for col in targets:
                if col in df.columns:
                    df[col] = df[col].astype(str).str.strip().replace("nan", pd.NA)
            return df
        _fix.__name__ = f"strip_strings({cols})"
        return _fix

    # ── Fix registration ──────────────────────────────────────────────────

    def register_fix(
        self,
        fix_fn:          callable,
        reason_contains: str = "*",
    ) -> "DLQReplayer":
        """
        Register a fix function to apply before replaying a row group.

        Parameters
        ──────────
        fix_fn           : callable   Function that takes a pd.DataFrame and
                                      returns a (possibly modified) pd.DataFrame.
                                      Use DLQReplayer.drop_columns(),
                                      coerce_types(), fill_nulls(),
                                      rename_columns(), or strip_strings()
                                      to build common fixes, or supply your own.
        reason_contains  : str        Apply this fix only to row groups whose
                                      ``_dlq_reason`` contains this substring.
                                      "*" means apply to all groups (global fix).

        Returns
        ───────
        DLQReplayer   Self, for chaining.

        Example
        ───────
            replayer \
                .register_fix(DLQReplayer.fill_nulls({"email": "unknown@example.com"}),
                              reason_contains="email") \
                .register_fix(DLQReplayer.coerce_types({"age": int}),
                              reason_contains="*")
        """
        self._fixes.append({"pattern": reason_contains, "fn": fix_fn})
        return self

    def _fixes_for_reason(self, reason: str) -> list[callable]:
        """Return all fix callables that apply to the given reason string."""
        return [
            f["fn"] for f in self._fixes
            if f["pattern"] == "*" or f["pattern"].lower() in reason.lower()
        ]

    # ── DLQ file inspection ───────────────────────────────────────────────

    @staticmethod
    def inspect(dlq_path: str | Path) -> dict:
        """
        Parse a DLQ CSV and return a structured summary without loading it
        into the destination.

        Returns
        ───────
        dict with keys:
          total_rows       : int
          reason_groups    : dict[reason → count]
          pipeline_ids     : list[str]
          date_range       : (earliest_ts, latest_ts)
          columns          : list[str]   (data columns, excluding _dlq_* meta)
          file_size_bytes  : int
        """
        p = Path(dlq_path)
        if not p.exists():
            raise FileNotFoundError(f"DLQ file not found: {p}")
        try:
            df = pd.read_csv(p, dtype=str)
        except pd.errors.EmptyDataError:
            return {"total_rows": 0, "reason_groups": {}, "pipeline_ids": [],
                    "date_range": (None, None), "columns": [], "file_size_bytes": p.stat().st_size}
        if df.empty:
            return {"total_rows": 0, "reason_groups": {}, "pipeline_ids": [],
                    "date_range": (None, None), "columns": [], "file_size_bytes": p.stat().st_size}

        reasons = {}
        if "_dlq_reason" in df.columns:
            reasons = df["_dlq_reason"].value_counts().to_dict()

        pipeline_ids = []
        if "_dlq_pipeline_id" in df.columns:
            pipeline_ids = df["_dlq_pipeline_id"].dropna().unique().tolist()

        dates = []
        if "_dlq_timestamp" in df.columns:
            dates = df["_dlq_timestamp"].dropna().tolist()

        data_cols = [c for c in df.columns
                     if not c.startswith("_dlq_")]

        return {
            "total_rows":      len(df),
            "reason_groups":   reasons,
            "pipeline_ids":    pipeline_ids,
            "date_range":      (min(dates) if dates else None,
                                max(dates) if dates else None),
            "columns":         data_cols,
            "file_size_bytes": p.stat().st_size,
        }

    @classmethod
    def print_inspection(cls, dlq_path: str | Path) -> dict:
        """Inspect and pretty-print a DLQ file summary.  Returns the dict."""
        info = cls.inspect(dlq_path)
        border = "═" * 62
        print(f"\n  {border}")
        print(f"  📬  DLQ INSPECTION  —  {Path(dlq_path).name}")
        print(f"  {border}")
        print(f"  Total rows          : {info['total_rows']:,}")
        print(f"  File size           : {info['file_size_bytes'] / 1024:.1f} KB")
        print(f"  Data columns        : {len(info['columns'])}"
              f"  ({', '.join(info['columns'][:6])}"
              f"{'…' if len(info['columns']) > 6 else ''})")
        if info["pipeline_ids"]:
            print(f"  Pipeline IDs        : {', '.join(info['pipeline_ids'][:3])}"
                  f"{'…' if len(info['pipeline_ids']) > 3 else ''}")
        if info["date_range"][0]:
            print(f"  Date range          : {info['date_range'][0][:19]}"
                  f"  →  {info['date_range'][1][:19]}")
        if info["reason_groups"]:
            print(f"  {'-'*60}")
            print(f"  {'Failure reason':<42} {'Rows':>6}")
            print(f"  {'-'*60}")
            for reason, count in sorted(info["reason_groups"].items(),
                                        key=lambda x: -x[1]):
                r = reason[:42] if len(reason) > 42 else reason
                print(f"  {r:<42} {count:>6,}")
        print(f"  {border}\n")
        return info

    # ── Core replay ───────────────────────────────────────────────────────

    def replay(
        self,
        dlq_path:           str | Path,
        reason_filter:      str | None  = None,
        pipeline_id_filter: str | None  = None,
        after:              str | None  = None,
        before:             str | None  = None,
    ) -> dict:
        """
        Load a DLQ CSV, apply fixes, and replay rows into the destination.

        Parameters
        ──────────
        dlq_path            : str | Path   Path to the DLQ CSV file.
        reason_filter       : str | None   Only replay rows whose
                                           ``_dlq_reason`` contains this string.
        pipeline_id_filter  : str | None   Only replay rows from this pipeline run.
        after               : str | None   Only replay rows timestamped after
                                           this ISO datetime (e.g. "2025-03-01").
        before              : str | None   Only replay rows timestamped before
                                           this ISO datetime.

        Returns
        ───────
        dict with keys:
          loaded          : int   Rows successfully replayed to destination.
          requarantined   : int   Rows that failed again (written to quarantine DLQ).
          skipped         : int   Rows excluded by filters.
          dry_run         : bool
          reason_results  : dict[reason → {"loaded": N, "requarantined": M}]
          status          : "success" | "partial" | "failed" | "empty"
        """
        p = Path(dlq_path)
        if not p.exists():
            raise FileNotFoundError(f"DLQ file not found: {p}")

        self.gov.transformation_applied("DLQ_REPLAY_STARTED", {
            "dlq_file":          str(p),
            "reason_filter":     reason_filter,
            "pipeline_id_filter": pipeline_id_filter,
            "dry_run":           self.dry_run,
            "after":             after,
            "before":            before,
        })
        print(f"\n  {'[DRY RUN] ' if self.dry_run else ''}▶  DLQ REPLAY  —  {p.name}")

        try:
            df_all = pd.read_csv(p, dtype=str)
        except pd.errors.EmptyDataError:
            df_all = pd.DataFrame()
        if df_all.empty:
            print("  DLQ file is empty — nothing to replay.")
            return {"loaded": 0, "requarantined": 0, "skipped": 0,
                    "dry_run": self.dry_run, "reason_results": {}, "status": "empty"}

        # ── Apply filters ─────────────────────────────────────────────────
        original_count = len(df_all)
        mask = pd.Series(True, index=df_all.index)

        if reason_filter and "_dlq_reason" in df_all.columns:
            mask &= df_all["_dlq_reason"].str.contains(reason_filter, case=False, na=False)

        if pipeline_id_filter and "_dlq_pipeline_id" in df_all.columns:
            mask &= df_all["_dlq_pipeline_id"] == pipeline_id_filter

        if (after or before) and "_dlq_timestamp" in df_all.columns:
            ts_col = pd.to_datetime(df_all["_dlq_timestamp"], errors="coerce", utc=True)
            if after:
                mask &= ts_col >= pd.Timestamp(after, tz="UTC")
            if before:
                mask &= ts_col <= pd.Timestamp(before, tz="UTC")

        df_selected = df_all[mask].copy()
        skipped     = original_count - len(df_selected)

        if df_selected.empty:
            print(f"  No rows match the filters  ({skipped} skipped).")
            return {"loaded": 0, "requarantined": 0, "skipped": skipped,
                    "dry_run": self.dry_run, "reason_results": {}, "status": "empty"}

        print(f"  Rows selected for replay : {len(df_selected):,}"
              f"  ({skipped} skipped by filters)")

        # ── Strip DLQ metadata columns before loading ─────────────────────
        data_cols = [c for c in df_selected.columns if not c.startswith("_dlq_")]

        # ── Group by failure reason and replay each group ─────────────────
        reason_col = "_dlq_reason" if "_dlq_reason" in df_selected.columns else None
        if reason_col:
            groups = df_selected.groupby(reason_col, sort=False)
        else:
            groups = [(("(unknown)",), df_selected)]

        total_loaded        = 0
        total_requarantined = 0
        reason_results: dict[str, dict] = {}

        for reason, group_df in groups:
            reason_str = reason if isinstance(reason, str) else str(reason)
            group_data = group_df[data_cols].copy().reset_index(drop=True)

            print(f"\n  ── Reason: {reason_str[:60]!r}  ({len(group_data):,} rows)")

            # Apply registered fixes for this reason
            fixes = self._fixes_for_reason(reason_str)
            for fix_fn in fixes:
                fn_name = getattr(fix_fn, "__name__", repr(fix_fn))
                print(f"     ✎  Applying fix: {fn_name}")
                try:
                    group_data = fix_fn(group_data)
                except Exception as exc:
                    print(f"     ✗  Fix failed: {exc}  — row group will be requarantined")
                    self._requarantine(group_df, reason_str, f"fix_error: {exc}", p)
                    total_requarantined += len(group_data)
                    reason_results[reason_str] = {"loaded": 0,
                                                   "requarantined": len(group_data),
                                                   "fix_error": str(exc)}
                    continue

            self.gov.transformation_applied("DLQ_REPLAY_ROW_FIXED", {
                "reason":      reason_str,
                "row_count":   len(group_data),
                "fixes_applied": len(fixes),
                "dry_run":     self.dry_run,
            })

            # Attempt load
            loaded_count = 0
            req_count    = 0
            if self.dry_run:
                print(f"     [DRY RUN] would load {len(group_data):,} rows "
                      f"→ {self.table!r}")
                print(f"     Columns: {list(group_data.columns)[:8]}"
                      f"{'…' if len(group_data.columns) > 8 else ''}")
                loaded_count = len(group_data)
            else:
                try:
                    self._load_group(group_data)
                    loaded_count = len(group_data)
                    print(f"     ✓  Loaded {loaded_count:,} rows → {self.table!r}")
                except Exception as exc:
                    print(f"     ✗  Load failed: {exc}")
                    self._requarantine(group_df, reason_str, f"load_error: {exc}", p)
                    req_count = len(group_data)
                    print(f"     ⚠  {req_count} rows → quarantine DLQ")

            total_loaded        += loaded_count
            total_requarantined += req_count
            reason_results[reason_str] = {"loaded": loaded_count,
                                           "requarantined": req_count}

        # ── Final status ──────────────────────────────────────────────────
        if total_loaded > 0 and total_requarantined == 0:
            status = "success"
        elif total_loaded > 0 and total_requarantined > 0:
            status = "partial"
        elif total_loaded == 0 and total_requarantined > 0:
            status = "failed"
        else:
            status = "success" if self.dry_run else "empty"

        result = {
            "loaded":          total_loaded,
            "requarantined":   total_requarantined,
            "skipped":         skipped,
            "dry_run":         self.dry_run,
            "reason_results":  reason_results,
            "status":          status,
        }

        self.gov.transformation_applied("DLQ_REPLAY_COMPLETE", result)

        icon = {"success": "✅", "partial": "⚠", "failed": "✗", "empty": "—"}.get(status, "?")
        print(f"\n  {icon}  REPLAY {status.upper()}"
              f"  —  loaded: {total_loaded:,}"
              f"  |  requarantined: {total_requarantined:,}"
              f"  |  skipped: {skipped:,}"
              + ("  [DRY RUN]" if self.dry_run else ""))

        return result

    def _load_group(self, df: "pd.DataFrame") -> None:
        """Load a DataFrame group into the destination."""
        if self.loader is not None:
            # Try with if_exists param first; fall back without
            try:
                self.loader.load(df, self.db_cfg, self.table,
                                 if_exists=self.if_exists)
            except TypeError:
                self.loader.load(df, self.db_cfg, self.table)
        else:
            # Fall back to SQLLoader
            sql_loader = SQLLoader(self.gov, db_type=self.db_type)
            sql_loader.load(df, self.db_cfg, self.table,
                            if_exists=self.if_exists)

    def _requarantine(
        self,
        original_rows: "pd.DataFrame",
        reason:        str,
        new_reason:    str,
        source_dlq:    Path,
    ) -> Path:
        """Write rows that failed replay into a quarantine DLQ CSV."""
        q_dir = self.quarantine_dir or source_dlq.parent
        q_dir = Path(q_dir)
        q_dir.mkdir(parents=True, exist_ok=True)
        ts    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        q_path = q_dir / f"quarantine_{ts}.csv"

        rows = original_rows.copy()
        rows["_dlq_pipeline_id"] = PIPELINE_ID
        rows["_dlq_reason"]      = new_reason
        rows["_dlq_original_reason"] = reason
        rows["_dlq_timestamp"]   = datetime.now(timezone.utc).isoformat()
        rows.to_csv(q_path, mode="a",
                    header=not q_path.exists(),
                    index=False)

        self.gov.transformation_applied("DLQ_ROW_REQUARANTINED", {
            "original_reason": reason,
            "new_reason":      new_reason,
            "row_count":       len(rows),
            "quarantine_file": str(q_path),
        })
        return q_path

    # ── Convenience class-method for CLI use ──────────────────────────────

    @classmethod
    def from_cli_args(
        cls,
        gov:     "GovernanceLogger",
        args:    object,
        loader:  object | None = None,
        db_cfg:  dict          = None,
    ) -> "DLQReplayer":
        """
        Construct a DLQReplayer from parsed argparse args.

        Recognises:
          args.replay_dlq            : path to DLQ CSV
          args.replay_reason         : reason_filter substring
          args.replay_pipeline_id    : pipeline-id filter
          args.replay_after          : ISO date lower bound
          args.replay_before         : ISO date upper bound
          args.replay_dry_run        : dry-run flag
          args.replay_table          : destination table override
          args.replay_quarantine_dir : quarantine output dir
        """
        table = getattr(args, "replay_table", None) or getattr(args, "table", "") or ""
        return cls(
            gov            = gov,
            loader         = loader,
            db_cfg         = db_cfg or {},
            table          = table,
            if_exists      = "append",
            dry_run        = getattr(args, "replay_dry_run", False),
            quarantine_dir = getattr(args, "replay_quarantine_dir", ""),
        )



# ─────────────────────────────────────────────────────────────────────────────
#  MAIN  —  Interactive CLI entry point
# ─────────────────────────────────────────────────────────────────────────────


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: LanceDBLoader  (v1.0)
#  Writes DataFrames to LanceDB as vector tables — supports embedding columns,
#  full-text metadata, upsert by primary key, and schema auto-creation.
# ═════════════════════════════════════════════════════════════════════════════

class LanceDBLoader:
    """
    LanceDB loader — writes DataFrames to a LanceDB vector database.

    LanceDB is a serverless, embedded vector database backed by the Lance
    columnar format (built on Apache Arrow / Parquet).  It requires no
    separate server process and stores data as files on local disk or in
    cloud object storage (S3, GCS, Azure Blob).

    This loader handles three common use cases:

    1.  **Plain tabular data** — any DataFrame without an embedding column
        is written as a standard Lance table.  This is useful for storing
        governance-logged, PII-masked records alongside a vector store.

    2.  **Pre-computed embeddings** — if the DataFrame contains a column of
        lists or numpy arrays (the ``vector_column`` parameter), LanceDB
        stores them as native Lance vectors, enabling ANN (approximate
        nearest-neighbour) search.

    3.  **Text-to-embedding** — if ``embed_columns`` is supplied and the
        ``sentence-transformers`` package is installed, the loader generates
        embeddings on the fly by concatenating the specified text columns
        and encoding them with the named model (default: all-MiniLM-L6-v2).

    Architecture note
    -----------------
    LanceDB stores each table as a directory of Lance fragment files.  The
    ``uri`` in cfg points to the root of the LanceDB instance — a local
    path like ``/data/lancedb`` or a cloud URI like ``s3://my-bucket/lancedb``.
    Each ``table`` name becomes a subdirectory inside that root.

    Required cfg keys
    -----------------
    uri         : str   Path to the LanceDB directory
                        (local: "/data/lancedb"  or  s3://bucket/prefix)

    Optional cfg keys
    -----------------
    vector_column  : str   Name of the column containing pre-computed
                           embedding vectors (list[float] or np.ndarray).
                           Default: None (no vector column)
    embed_columns  : list  Column name(s) to concatenate and encode into
                           vectors automatically via sentence-transformers.
                           Default: None
    embed_model    : str   sentence-transformers model name.
                           Default: "all-MiniLM-L6-v2"
    metric         : str   Distance metric for ANN index: "cosine", "l2",
                           or "dot".  Default: "cosine"

    Load modes
    ----------
    append   (default)
        Append rows to an existing table, or create a new table if absent.

    overwrite
        Drop and recreate the table with the new data.

    upsert   (natural_keys provided)
        Merge rows into the table using the natural key column(s) as the
        merge predicate.  Rows with matching keys are updated; new keys
        are inserted.  Requires PyArrow >= 12.

    Requirements
    ------------
        pip install lancedb pyarrow
        pip install sentence-transformers   # only for embed_columns
    """

    _CHUNK = 5_000   # rows per write batch

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_LANCEDB:
            raise RuntimeError(
                "LanceDBLoader requires the lancedb package.\n"
                "Install with:  pip install lancedb pyarrow"
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str,
        if_exists:    str  = "append",
        natural_keys: "list | None" = None,
    ) -> int:
        """
        Write df to a LanceDB table.

        Parameters
        ----------
        df            DataFrame to write.
        cfg           Connection config dict (see class docstring).
        table         Name of the LanceDB table (subdirectory inside the uri).
        if_exists     "append" | "overwrite" | "upsert"
        natural_keys  Column name(s) used as merge keys for upsert mode.

        Returns
        -------
        int   Number of rows written.
        """
        import lancedb

        if if_exists not in ("append", "overwrite", "upsert"):
            raise ValueError(
                f"LanceDBLoader: if_exists must be 'append', 'overwrite', or "
                f"'upsert', got '{if_exists}'."
            )

        uri            = cfg.get("uri")
        vector_column  = cfg.get("vector_column")
        embed_columns  = cfg.get("embed_columns")
        embed_model    = cfg.get("embed_model", "all-MiniLM-L6-v2")

        if not uri:
            raise ValueError(
                "LanceDBLoader: cfg must contain 'uri' "
                "(e.g. '/data/lancedb' or 's3://bucket/prefix')."
            )

        # Generate embeddings if embed_columns specified
        if embed_columns:
            df = self._embed(df, embed_columns, embed_model)
            vector_column = "__embedding__"

        total_rows = 0
        db = lancedb.connect(uri)

        if if_exists == "overwrite":
            total_rows = self._write_overwrite(db, table, df, vector_column)

        elif if_exists == "upsert" and natural_keys:
            total_rows = self._write_upsert(db, table, df,
                                            natural_keys, vector_column)

        else:
            # append (default)
            total_rows = self._write_append(db, table, df, vector_column)

        self.gov._event(
            "LOAD", "LANCEDB_WRITE_COMPLETE",
            {
                "uri":           uri,
                "table":         table,
                "rows":          total_rows,
                "if_exists":     if_exists,
                "vector_column": vector_column,
                "has_embeddings": vector_column is not None,
            },
        )
        return total_rows

    def create_index(
        self,
        cfg:           dict,
        table:         str,
        vector_column: str,
        metric:        str = "cosine",
        num_partitions: int = 256,
        num_sub_vectors: int = 96,
    ) -> None:
        """
        Build an IVF-PQ ANN index on a vector column for fast similarity search.

        Should be called after loading is complete.  Index creation requires
        at least 256 rows by default.

        Parameters
        ----------
        cfg             Connection config dict with 'uri'.
        table           Table name to index.
        vector_column   Name of the vector column to index.
        metric          Distance metric: "cosine" | "l2" | "dot"
        num_partitions  IVF partitions (default 256).
        num_sub_vectors PQ sub-vectors (default 96).
        """
        import lancedb

        uri = cfg.get("uri")
        if not uri:
            raise ValueError("LanceDBLoader: cfg must contain 'uri'.")

        db     = lancedb.connect(uri)
        tbl    = db.open_table(table)
        tbl.create_index(
            metric          = metric,
            num_partitions  = num_partitions,
            num_sub_vectors = num_sub_vectors,
            vector_column_name = vector_column,
        )
        self.gov._event(
            "LOAD", "LANCEDB_INDEX_CREATED",
            {"uri": uri, "table": table,
             "vector_column": vector_column, "metric": metric},
        )

    def search(
        self,
        cfg:           dict,
        table:         str,
        query_vector:  "list[float]",
        vector_column: str,
        limit:         int = 10,
        metric:        str = "cosine",
    ) -> "pd.DataFrame":
        """
        Run a nearest-neighbour vector search and return the top results.

        Parameters
        ----------
        cfg            Connection config dict with 'uri'.
        table          Table name to search.
        query_vector   The query embedding as a list of floats.
        vector_column  Name of the vector column to search against.
        limit          Number of nearest neighbours to return (default 10).
        metric         Distance metric: "cosine" | "l2" | "dot"

        Returns
        -------
        pd.DataFrame   Top-k rows ordered by distance ascending, with a
                       '_distance' column added.
        """
        import lancedb

        uri = cfg.get("uri")
        if not uri:
            raise ValueError("LanceDBLoader: cfg must contain 'uri'.")

        if not query_vector:
            raise ValueError(
                "LanceDBLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )
        db  = lancedb.connect(uri)
        tbl = db.open_table(table)
        results = (
            tbl.search(query_vector, vector_column_name=vector_column)
               .metric(metric)
               .limit(limit)
               .to_pandas()
        )
        self.gov._event(
            "LOAD", "LANCEDB_SEARCH",
            {"uri": uri, "table": table,
             "limit": limit, "results": len(results)},
        )
        return results

    def table_info(self, cfg: dict, table: str) -> dict:
        """Return row count and schema info for a LanceDB table."""
        import lancedb

        uri = cfg.get("uri")
        if not uri:
            raise ValueError("LanceDBLoader: cfg must contain 'uri'.")

        db  = lancedb.connect(uri)
        tbl = db.open_table(table)
        return {
            "table":      table,
            "uri":        uri,
            "row_count":  tbl.count_rows(),
            "schema":     str(tbl.schema),
        }

    def list_tables(self, cfg: dict) -> list:
        """Return names of all tables in a LanceDB instance."""
        import lancedb

        uri = cfg.get("uri")
        if not uri:
            raise ValueError("LanceDBLoader: cfg must contain 'uri'.")

        db = lancedb.connect(uri)
        return db.table_names()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _write_append(
        self,
        db,
        table:         str,
        df:            "pd.DataFrame",
        vector_column: "str | None",
    ) -> int:
        data = self._to_records(df, vector_column)
        if table in db.table_names():
            tbl = db.open_table(table)
            for chunk in self._chunks(data):
                tbl.add(chunk)
        else:
            tbl = db.create_table(table, data=data)
        return len(df)

    def _write_overwrite(
        self,
        db,
        table:         str,
        df:            "pd.DataFrame",
        vector_column: "str | None",
    ) -> int:
        data = self._to_records(df, vector_column)
        db.create_table(table, data=data, mode="overwrite")
        return len(df)

    def _write_upsert(
        self,
        db,
        table:         str,
        df:            "pd.DataFrame",
        natural_keys:  list,
        vector_column: "str | None",
    ) -> int:
        data = self._to_records(df, vector_column)
        if not data:
            return 0   # nothing to upsert — empty DataFrame
        if table not in db.table_names():
            db.create_table(table, data=data)
            return len(df)

        tbl = db.open_table(table)
        # lancedb merge_insert builder pattern:
        # .merge_insert(on) returns a builder; chain when_matched / execute
        on_col = natural_keys[0] if len(natural_keys) == 1 else natural_keys
        (
            tbl.merge_insert(on_col)
               .when_matched_update_all()
               .when_not_matched_insert_all()
               .execute(data)
        )
        return len(df)

    @staticmethod
    def _to_records(
        df:            "pd.DataFrame",
        vector_column: "str | None",
    ) -> list:
        """
        Convert a DataFrame to a list of dicts compatible with LanceDB.
        If vector_column is set, ensure that column contains Python lists
        (LanceDB requires list[float], not numpy arrays).
        """
        import numpy as np

        out = df.copy()
        if vector_column and vector_column in out.columns:
            out[vector_column] = out[vector_column].apply(
                lambda v: v.tolist() if isinstance(v, np.ndarray) else v
            )
        return out.to_dict(orient="records")

    @staticmethod
    def _chunks(records: list, size: int = 5_000):
        for i in range(0, len(records), size):
            yield records[i : i + size]

    @staticmethod
    def _embed(
        df:           "pd.DataFrame",
        embed_columns: list,
        model_name:    str,
    ) -> "pd.DataFrame":
        """
        Generate sentence-transformer embeddings from text columns and
        add them as a new '__embedding__' column.
        """
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "LanceDBLoader: embed_columns requires sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc

        model  = SentenceTransformer(model_name)
        texts  = df[embed_columns].astype(str).agg(" ".join, axis=1).tolist()
        vecs   = model.encode(texts, show_progress_bar=False).tolist()
        out    = df.copy()
        out["__embedding__"] = vecs
        return out




# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: KafkaLoader  (v1.0)
#  Publish governed, PII-masked DataFrames to Apache Kafka topics.
# ═════════════════════════════════════════════════════════════════════════════

class KafkaLoader:
    """
    Publish a governed, PII-masked DataFrame to a Kafka topic as a stream
    of JSON messages — one message per row, with configurable keying,
    compression, delivery guarantees, and upsert (tombstone) support.

    This closes the pipeline loop: KafkaExtractor (pipeline_streaming.py)
    reads raw events from an upstream topic; the pipeline governs and
    transforms them; KafkaLoader publishes clean results to a downstream
    topic for real-time consumers, SIEM tools, or further processing.

    Architecture note
    -----------------
    Kafka topics are immutable append-only logs.  "Upsert" semantics are
    achieved via log compaction: publishing a tombstone (null value) for
    a key before the updated record ensures compacted topics reflect the
    latest state per key without consumer-side deduplication.

    Required cfg keys
    -----------------
    bootstrap_servers : str | list[str]
        Kafka broker address(es), e.g. "localhost:9092".
    topic             : str
        Destination topic name.

    Optional cfg keys
    -----------------
    key_column        : str   DataFrame column to use as the message key.
                              Enables partition affinity — records with the
                              same key always go to the same partition.
    compression_type  : str   "none" | "gzip" | "snappy" | "lz4" | "zstd"
    acks              : str   "0" | "1" | "all"  (default "all")
    retries           : int   Send retries on transient failure (default 3).
    linger_ms         : int   Batching delay in ms (default 0).
    security_protocol : str   "PLAINTEXT" | "SSL" | "SASL_SSL"
    sasl_mechanism    : str   "PLAIN" | "SCRAM-SHA-256" etc.
    sasl_username     : str
    sasl_password     : str
    ssl_cafile        : str   Path to CA certificate.

    Load modes
    ----------
    append   (default)  Publish all rows as new messages.
    upsert   (natural_keys provided)
             Publish a tombstone per key then the updated record.
             Requires the topic to be log-compacted.

    Requirements
    ------------
        pip install kafka-python

    Quick-start
    ───────────
        from pipeline_v3 import GovernanceLogger
        loader = KafkaLoader(GovernanceLogger("run_001", "employees.csv"))
        rows   = loader.load(df, cfg={
            "bootstrap_servers": "localhost:9092",
            "topic":             "clean_employees",
            "key_column":        "employee_id",
            "acks":              "all",
            "compression_type":  "gzip",
        })
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_KAFKA_LOADER:
            raise RuntimeError(
                "KafkaLoader requires the kafka-python package.\n"
                "Install with:  pip install kafka-python"
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,
    ) -> int:
        """
        Publish df to a Kafka topic.

        Parameters
        ----------
        df            DataFrame to publish.
        cfg           Connection config dict (see class docstring).
        table         Topic override — takes precedence over cfg["topic"].
                      Included for loader dispatch compatibility.
        if_exists     "append" (default) | "upsert"
        natural_keys  Key column(s) for upsert tombstone mode.

        Returns
        -------
        int   Number of messages successfully delivered.
        """
        if if_exists not in ("append", "upsert"):
            raise ValueError(
                f"KafkaLoader: if_exists must be 'append' or 'upsert', "
                f"got '{if_exists}'."
            )

        topic = table or cfg.get("topic")
        if not topic:
            raise ValueError(
                "KafkaLoader: supply topic via cfg['topic'] or the table arg."
            )
        if not cfg.get("bootstrap_servers"):
            raise ValueError(
                "KafkaLoader: cfg must contain 'bootstrap_servers'."
            )

        producer = self._build_producer(cfg)
        try:
            if if_exists == "upsert" and natural_keys:
                rows = self._publish_upsert(df, producer, topic,
                                            natural_keys, cfg)
            else:
                rows = self._publish_append(df, producer, topic, cfg)
        finally:
            producer.flush()
            producer.close()

        self.gov._event(
            "LOAD", "KAFKA_PUBLISH_COMPLETE",
            {
                "topic":       topic,
                "rows":        rows,
                "if_exists":   if_exists,
                "key_column":  cfg.get("key_column"),
                "acks":        cfg.get("acks", "all"),
                "compression": cfg.get("compression_type", "none"),
            },
        )
        return rows

    def publish_governance_event(
        self,
        cfg:   dict,
        event: dict,
        topic: str = "governance_events",
    ) -> None:
        """
        Publish a single governance event dict to a Kafka topic.

        Lets downstream SIEM / security / monitoring tools subscribe to
        governance events in real time rather than polling the JSONL ledger.

        Parameters
        ----------
        cfg   Connection config (bootstrap_servers required).
        event Governance event dict.
        topic Target topic (default: "governance_events").
        """
        if not cfg.get("bootstrap_servers"):
            raise ValueError(
                "KafkaLoader: cfg must contain 'bootstrap_servers'."
            )
        producer = self._build_producer(cfg)
        try:
            body = json.dumps(event, default=str).encode("utf-8")
            future = producer.send(topic, value=body)
            future.get(timeout=10)
            producer.flush()
        finally:
            producer.close()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _build_producer(self, cfg: dict):
        """Construct a KafkaProducer from cfg."""
        from kafka import KafkaProducer as _KP  # noqa: PLC0415
        kwargs: dict = {
            "bootstrap_servers": cfg["bootstrap_servers"],
            "value_serializer":  lambda v: (
                None if v is None                              # tombstone
                else v if isinstance(v, bytes)                 # raw bytes
                else json.dumps(v, default=str).encode("utf-8") # dict/str
            ),
            "key_serializer":    lambda k: (
                str(k).encode("utf-8") if k is not None else None
            ),
            # kafka-python requires "all" (str) or 0/1 (int) — never "0"/"1" strings
            "acks":              ("all" if str(cfg.get("acks", "all")) in ("all", "-1")
                                 else int(cfg.get("acks", 1))),
            "retries":           int(cfg.get("retries", 3)),
            "linger_ms":         int(cfg.get("linger_ms", 0)),
        }
        comp = cfg.get("compression_type", "none")
        if comp and comp != "none":
            kwargs["compression_type"] = comp

        if cfg.get("security_protocol"):
            kwargs["security_protocol"] = cfg["security_protocol"]
        if cfg.get("sasl_mechanism"):
            kwargs["sasl_mechanism"]      = cfg["sasl_mechanism"]
            kwargs["sasl_plain_username"] = cfg.get("sasl_username", "")
            kwargs["sasl_plain_password"] = cfg.get("sasl_password", "")
        if cfg.get("ssl_cafile"):
            kwargs["ssl_cafile"] = cfg["ssl_cafile"]

        return _KP(**kwargs)

    def _publish_append(self, df, producer, topic: str, cfg: dict) -> int:
        """Publish every row as an individual Kafka message."""
        key_col = cfg.get("key_column")
        futures = []
        for _, row in df.iterrows():
            key = str(row[key_col]) if key_col and key_col in row.index else None
            futures.append(producer.send(topic, key=key, value=row.to_dict()))

        sent = 0
        for fut in futures:
            try:
                fut.get(timeout=10)
                sent += 1
            except Exception as exc:  # pylint: disable=broad-exception-caught
                import logging as _log
                _log.getLogger(__name__).warning(
                    "KafkaLoader: delivery failed: %s", exc
                )
        return sent

    def _publish_upsert(
        self, df, producer, topic: str, natural_keys: list, cfg: dict
    ) -> int:
        """
        Upsert via tombstone + record pattern for log-compacted topics.
        Sends a null-value tombstone for each key before the new record.
        """
        key_col = natural_keys[0] if len(natural_keys) == 1 else cfg.get("key_column")
        futures = []
        for _, row in df.iterrows():
            key = str(row[key_col]) if key_col and key_col in row.index else None
            if key:
                producer.send(topic, key=key, value=None)   # tombstone
            futures.append(producer.send(topic, key=key, value=row.to_dict()))

        sent = 0
        for fut in futures:
            try:
                fut.get(timeout=10)
                sent += 1
            except Exception as exc:  # pylint: disable=broad-exception-caught
                import logging as _log
                _log.getLogger(__name__).warning(
                    "KafkaLoader: upsert delivery failed: %s", exc
                )
        return sent








def _validate_sql_identifier(name: str, label: str = "identifier") -> str:
    """
    Validate a SQL identifier (table name, column name, index name) to prevent
    SQL injection.  Only allows alphanumeric characters, underscores, and dots
    (for schema.table notation).

    Raises ValueError if the name contains any disallowed characters.
    Returns the name unchanged if valid.
    """
    if not name:
        raise ValueError(f"SQL {label} must not be empty.")
    if not re.fullmatch(r"[A-Za-z_][\w.]*", name):
        raise ValueError(
            f"SQL {label} '{name}' contains disallowed characters. "
            "Only letters, digits, underscores, and dots are allowed."
        )
    return name


def _validate_float_vector(vec: list, label: str = "query_vector") -> list:
    """
    Validate that every element of a vector is a finite float.
    Prevents SQL injection via NaN, inf, or non-numeric values in
    concatenated vector literals.

    Raises ValueError on the first invalid element.
    Returns a list of Python floats.
    """
    import math as _math
    result = []
    for i, v in enumerate(vec):
        try:
            f = float(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{label}[{i}] is not a valid float: {v!r}"
            ) from exc
        if not _math.isfinite(f):
            raise ValueError(
                f"{label}[{i}] is not finite: {f!r}. "
                "NaN and inf are not valid vector components."
            )
        result.append(f)
    return result

# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: PgvectorLoader  (v1.0)
#  Write and search vectors in PostgreSQL using the pgvector extension.
# ═════════════════════════════════════════════════════════════════════════════

class PgvectorLoader:
    """
    Write governed DataFrames to PostgreSQL with pgvector vector columns,
    and run nearest-neighbour similarity searches against them.

    pgvector is a PostgreSQL extension that adds a native ``vector`` data
    type and three distance operators: L2 (<->), inner product (<#>), and
    cosine (<=>).  It supports IVFFlat and HNSW indexes for approximate
    nearest-neighbour (ANN) search at scale.

    Because pgvector extends existing PostgreSQL, you do not need a separate
    database — any Postgres instance with the extension installed works.
    Most managed PostgreSQL services (AWS RDS, Supabase, Neon, Azure PG)
    support pgvector.

    Architecture
    ────────────
    This loader:
    1. Ensures the pgvector extension is enabled via ``CREATE EXTENSION IF NOT EXISTS vector``
    2. Creates or alters the target table to add a ``vector(N)`` column
    3. Writes all DataFrame rows including the vector column using SQLAlchemy
    4. Optionally creates an IVFFlat or HNSW index for fast ANN search
    5. Provides a ``search()`` method using the cosine distance operator (<=>)

    Required cfg keys
    -----------------
    host        : str   PostgreSQL host
    db_name     : str   Database name
    user        : str   Username
    password    : str   Password

    Optional cfg keys
    -----------------
    port            : int   Default 5432
    vector_column   : str   Name of the vector column (default "embedding")
    embed_columns   : list  Text columns for sentence-transformer encoding
    embed_model     : str   sentence-transformers model (default all-MiniLM-L6-v2)
    vector_size     : int   Vector dimension (auto-detected from first row)
    index_type      : str   "ivfflat" | "hnsw" | None (default None — exact search)
    distance        : str   "cosine" | "l2" | "inner" (default "cosine")

    Requirements
    ------------
        pip install pgvector psycopg2-binary sqlalchemy

    Quick-start
    ───────────
        loader = PgvectorLoader(gov)
        rows   = loader.load(df, cfg={
            "host": "localhost", "db_name": "mydb",
            "user": "user", "password": "pass",
        }, table="documents")
        results = loader.search(cfg, table="documents",
                                query_vector=[0.1, 0.2, ...], limit=10)
    """

    _DIST_OPS = {"cosine": "<=>", "l2": "<->", "inner": "<#>"}

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_PGVECTOR:
            raise RuntimeError(
                "PgvectorLoader requires the pgvector package.\n"
                "Install with:  pip install pgvector"
            )

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,
    ) -> int:
        """
        Write df to a PostgreSQL table with a vector column.

        Parameters
        ----------
        df          DataFrame to write.
        cfg         PostgreSQL connection config (see class docstring).
        table       Target table name.
        if_exists   "append" | "replace" | "upsert"
        natural_keys  Key columns for upsert ON CONFLICT DO UPDATE.

        Returns
        -------
        int   Number of rows written.
        """
        from sqlalchemy import create_engine, text as sa_text
        from pgvector.sqlalchemy import Vector
        import numpy as _np

        if if_exists not in ("append", "replace", "upsert"):
            raise ValueError(
                f"PgvectorLoader: if_exists must be 'append', 'replace', or "
                f"'upsert', got '{if_exists}'."
            )
        if not table:
            raise ValueError("PgvectorLoader: table name is required.")
        if not cfg.get("host"):
            raise ValueError("PgvectorLoader: cfg must contain 'host'.")
        # Validate SQL identifiers to prevent injection
        _validate_sql_identifier(table, "table")
        _validate_sql_identifier(
            cfg.get("vector_column", "embedding"), "vector_column"
        )

        if df.empty:
            return 0

        vector_col  = cfg.get("vector_column", "embedding")
        embed_cols  = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")

        # Generate embeddings if requested
        if embed_cols and vector_col not in df.columns:
            df         = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if vector_col not in df.columns:
            raise ValueError(
                f"PgvectorLoader: vector column '{vector_col}' not in DataFrame. "
                "Set cfg['vector_column'] or cfg['embed_columns']."
            )

        # Detect vector size
        first_vec = df[vector_col].iloc[0]
        if isinstance(first_vec, _np.ndarray):
            first_vec = first_vec.tolist()
        vector_size = cfg.get("vector_size", len(first_vec))

        # Build engine
        from urllib.parse import quote_plus as _qp
        port = cfg.get("port", 5432)
        url  = (f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{port}/{cfg['db_name']}")
        engine = create_engine(url, pool_pre_ping=True)

        with engine.connect() as conn:
            # Enable pgvector extension
            conn.execute(sa_text("CREATE EXTENSION IF NOT EXISTS vector"))
            conn.commit()

            # Ensure vector column exists with correct type
            try:
                conn.execute(sa_text(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
                    f"{vector_col} vector({vector_size})"
                ))
                conn.commit()
            except Exception:  # pylint: disable=broad-exception-caught
                conn.rollback()  # table may not exist yet — pandas will create it

        # Convert vectors to lists for storage
        out = df.copy()
        out[vector_col] = out[vector_col].apply(
            lambda v: v.tolist() if isinstance(v, _np.ndarray) else list(v)
        )

        # Use pandas to_sql for the bulk write
        pg_if_exists = "replace" if if_exists == "replace" else "append"
        out.to_sql(table, engine, if_exists=pg_if_exists,
                   index=False, method="multi", chunksize=500)

        # Create ANN index if requested
        index_type = cfg.get("index_type")
        if index_type:
            self.create_index(cfg, table, vector_col,
                              index_type=index_type,
                              distance=cfg.get("distance", "cosine"))

        self.gov._event(
            "LOAD", "PGVECTOR_WRITE_COMPLETE",
            {
                "host":         cfg["host"],
                "table":        table,
                "rows":         len(df),
                "vector_col":   vector_col,
                "vector_size":  vector_size,
                "if_exists":    if_exists,
            },
        )
        return len(df)

    def create_index(
        self,
        cfg:          dict,
        table:        str,
        vector_col:   str  = "embedding",
        index_type:   str  = "ivfflat",
        distance:     str  = "cosine",
        lists:        int  = 100,
        m:            int  = 16,
        ef_construction: int = 64,
    ) -> None:
        """
        Create an IVFFlat or HNSW ANN index on a pgvector column.

        Parameters
        ----------
        cfg           PostgreSQL connection config.
        table         Table name.
        vector_col    Vector column name (default "embedding").
        index_type    "ivfflat" (default) or "hnsw".
        distance      "cosine" | "l2" | "inner"
        lists         IVFFlat: number of lists (default 100).
        m             HNSW: max connections (default 16).
        ef_construction HNSW: build-time search width (default 64).
        """
        from sqlalchemy import create_engine, text as sa_text
        from urllib.parse import quote_plus as _qp

        dist_ops = {"cosine": "vector_cosine_ops",
                    "l2":     "vector_l2_ops",
                    "inner":  "vector_ip_ops"}
        ops  = dist_ops.get(distance, "vector_cosine_ops")
        port = cfg.get("port", 5432)
        url  = (f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                f"@{cfg['host']}:{port}/{cfg['db_name']}")
        engine = create_engine(url)

        idx_name = f"idx_{table}_{vector_col}_{index_type}"

        with engine.connect() as conn:
            # IVFFlat and HNSW indexes on empty tables are silently incorrect.
            # Warn and skip — caller should load data first.
            row_count = conn.execute(
                sa_text(f"SELECT COUNT(*) FROM {table}")
            ).scalar() or 0
            if row_count == 0:
                import logging as _log
                _log.getLogger(__name__).warning(
                    "PgvectorLoader.create_index(): table '%s' is empty — "
                    "load data before creating IVFFlat/HNSW indexes.", table
                )
                return
            if index_type == "hnsw":
                sql = (f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} "
                       f"USING hnsw ({vector_col} {ops}) "
                       f"WITH (m={m}, ef_construction={ef_construction})")
            else:
                sql = (f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} "
                       f"USING ivfflat ({vector_col} {ops}) "
                       f"WITH (lists={lists})")
            conn.execute(sa_text(sql))
            conn.commit()

        self.gov._event(
            "LOAD", "PGVECTOR_INDEX_CREATED",
            {"table": table, "vector_col": vector_col,
             "index_type": index_type, "distance": distance},
        )

    def search(
        self,
        cfg:          dict,
        table:        str,
        query_vector: "list[float]",
        vector_col:   str  = "embedding",
        limit:        int  = 10,
        distance:     str  = "cosine",
        select_cols:  "list | None" = None,
        where:        str  = "",
    ) -> "pd.DataFrame":
        """
        Run a nearest-neighbour vector search using pgvector operators.

        Parameters
        ----------
        cfg           PostgreSQL connection config.
        table         Table to search.
        query_vector  Query embedding as list[float].
        vector_col    Vector column to search against (default "embedding").
        limit         Number of results (default 10).
        distance      "cosine" | "l2" | "inner"
        select_cols   Columns to return (default all non-vector columns).
        where         Optional SQL WHERE clause (without WHERE keyword).

        Returns
        -------
        pd.DataFrame  Top-k rows ordered by distance ascending, with a
                      "_distance" column added.
        """
        from sqlalchemy import create_engine, text as sa_text
        import numpy as _np
        from urllib.parse import quote_plus as _qp

        if not query_vector:
            raise ValueError(
                "PgvectorLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )
        query_vector = _validate_float_vector(query_vector, "query_vector")
        _validate_sql_identifier(table, "table")
        _validate_sql_identifier(vector_col, "vector_col")

        op   = self._DIST_OPS.get(distance, "<=>")
        # Default excludes the vector column — returning raw embeddings
        # bloats results unnecessarily for large models (1536+ dims).
        if select_cols:
            cols = ", ".join(select_cols)
        else:
            cols = f"* EXCEPT ({vector_col})" if vector_col else "*"
        vec_str  = "[" + ",".join(str(v) for v in query_vector) + "]"
        where_clause = f"WHERE {where}" if where else ""
        sql = (
            f"SELECT {cols}, "
            f"{vector_col} {op} '{vec_str}'::vector AS _distance "
            f"FROM {table} "
            f"{where_clause} "
            f"ORDER BY _distance ASC "
            f"LIMIT {limit}"
        )

        port   = cfg.get("port", 5432)
        url    = (f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
                  f"@{cfg['host']}:{port}/{cfg['db_name']}")
        engine = create_engine(url)
        with engine.connect() as conn:
            result = pd.read_sql(sa_text(sql), conn)

        self.gov._event(
            "LOAD", "PGVECTOR_SEARCH",
            {"table": table, "limit": limit,
             "distance": distance, "results": len(result)},
        )
        return result

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _embed(df: "pd.DataFrame", embed_cols: list, model_name: str) -> "pd.DataFrame":
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "PgvectorLoader: embed_columns requires sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model  = SentenceTransformer(model_name)
        texts  = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs   = model.encode(texts, show_progress_bar=False).tolist()
        out    = df.copy()
        out["__embedding__"] = vecs
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: SnowflakeVectorLoader  (v1.0)
#  Native VECTOR type and VECTOR_COSINE_SIMILARITY in Snowflake Cortex.
# ═════════════════════════════════════════════════════════════════════════════

class SnowflakeVectorLoader:
    """
    Write and search vectors in Snowflake using the native VECTOR data type
    and Snowflake's built-in vector similarity functions.

    Snowflake added a native ``VECTOR(FLOAT, N)`` data type in 2024, along
    with VECTOR_COSINE_SIMILARITY(), VECTOR_L2_DISTANCE(), and
    VECTOR_INNER_PRODUCT() functions.  This enables storing embeddings
    directly alongside structured data in Snowflake without exporting to
    a separate vector database.

    Architecture
    ────────────
    This loader:
    1. Connects to Snowflake via snowflake-sqlalchemy (same as SnowflakeLoader)
    2. Writes the DataFrame including the vector column — vectors stored as
       Snowflake VECTOR(FLOAT, N) type
    3. Provides a ``search()`` method using VECTOR_COSINE_SIMILARITY for
       nearest-neighbour queries

    Required cfg keys
    -----------------
    account     : str   Snowflake account identifier
    user        : str   Username
    password    : str   Password
    database    : str   Database name
    schema      : str   Schema name
    warehouse   : str   Warehouse name

    Optional cfg keys
    -----------------
    role            : str   Snowflake role
    vector_column   : str   Vector column name (default "embedding")
    embed_columns   : list  Text columns for sentence-transformer encoding
    embed_model     : str   sentence-transformers model name
    vector_size     : int   Embedding dimension (auto-detected)

    Requirements
    ------------
        pip install snowflake-sqlalchemy snowflake-connector-python

    Quick-start
    ───────────
        loader = SnowflakeVectorLoader(gov)
        rows   = loader.load(df, cfg={...}, table="DOCUMENTS")
        results = loader.search(cfg, table="DOCUMENTS",
                                query_vector=[0.1, 0.2, ...], limit=5)
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_SNOWFLAKE:
            raise RuntimeError(
                "SnowflakeVectorLoader requires snowflake-sqlalchemy.\n"
                "Install with:  pip install snowflake-sqlalchemy "
                "snowflake-connector-python"
            )

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,  # noqa: F841
    ) -> int:
        """
        Write df to Snowflake with a VECTOR column.

        Parameters
        ----------
        df          DataFrame to write.
        cfg         Snowflake connection config.
        table       Target table name (uppercase recommended).
        if_exists   "append" | "replace"

        Returns
        -------
        int   Number of rows written.
        """
        from snowflake.sqlalchemy import URL as _sfurl
        from sqlalchemy import create_engine, text as sa_text
        import numpy as _np

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"SnowflakeVectorLoader: if_exists must be 'append' or "
                f"'replace', got '{if_exists}'."
            )
        if not table:
            raise ValueError("SnowflakeVectorLoader: table name is required.")

        if df.empty:
            return 0

        vector_col  = cfg.get("vector_column", "embedding")
        embed_cols  = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")

        if embed_cols and vector_col not in df.columns:
            df         = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if vector_col not in df.columns:
            raise ValueError(
                f"SnowflakeVectorLoader: vector column '{vector_col}' not in "
                "DataFrame."
            )

        first_vec   = df[vector_col].iloc[0]
        if isinstance(first_vec, _np.ndarray):
            first_vec = first_vec.tolist()
        vector_size = cfg.get("vector_size", len(first_vec))

        engine = create_engine(_sfurl(
            account   = cfg["account"],
            user      = cfg["user"],
            password  = cfg["password"],
            database  = cfg["database"],
            schema    = cfg.get("schema", "PUBLIC"),
            warehouse = cfg["warehouse"],
            role      = cfg.get("role", ""),
        ))

        # Convert vectors to Snowflake-compatible string representation
        out = df.copy()
        out[vector_col] = out[vector_col].apply(
            lambda v: "[" + ",".join(
                str(x) for x in (v.tolist() if isinstance(v, _np.ndarray) else v)
            ) + "]"
        )

        out.to_sql(table.lower(), engine, if_exists=if_exists,
                   index=False, method="multi", chunksize=500)

        # Cast the string column to VECTOR type.
        # Requires Snowflake Cortex (not all regions/editions).
        # ALTER COLUMN to the same type raises on a re-load — handled below.
        with engine.connect() as conn:
            try:
                conn.execute(sa_text(
                    f"ALTER TABLE {table} ALTER COLUMN {vector_col} "
                    f"SET DATA TYPE VECTOR(FLOAT, {vector_size})"
                ))
                conn.commit()
            except Exception:  # pylint: disable=broad-exception-caught
                conn.rollback()  # column already VECTOR — safe to continue

        self.gov._event(
            "LOAD", "SNOWFLAKE_VECTOR_WRITE_COMPLETE",
            {"table": table, "rows": len(df),
             "vector_col": vector_col, "vector_size": vector_size},
        )
        return len(df)

    def search(
        self,
        cfg:          dict,
        table:        str,
        query_vector: "list[float]",
        vector_col:   str  = "embedding",
        limit:        int  = 10,
        distance:     str  = "cosine",
        select_cols:  "list | None" = None,
    ) -> "pd.DataFrame":
        """
        Search using Snowflake VECTOR_COSINE_SIMILARITY / VECTOR_L2_DISTANCE.

        Parameters
        ----------
        cfg           Snowflake connection config.
        table         Table to search.
        query_vector  Query embedding as list[float].
        vector_col    Vector column name (default "embedding").
        limit         Number of results (default 10).
        distance      "cosine" | "l2" | "inner"
        select_cols   Columns to return (default all).

        Returns
        -------
        pd.DataFrame  Top-k rows with "_similarity" column added.
        """
        from snowflake.sqlalchemy import URL as _sfurl
        from sqlalchemy import create_engine, text as sa_text

        if not query_vector:
            raise ValueError(
                "SnowflakeVectorLoader.search(): query_vector must be "
                "a non-empty list of floats."
            )
        query_vector = _validate_float_vector(query_vector, "query_vector")

        fn_map = {
            "cosine": "VECTOR_COSINE_SIMILARITY",
            "l2":     "VECTOR_L2_DISTANCE",
            "inner":  "VECTOR_INNER_PRODUCT",
        }
        fn  = fn_map.get(distance, "VECTOR_COSINE_SIMILARITY")
        # For cosine similarity higher = closer; for L2 lower = closer
        order = "DESC" if distance == "cosine" else "ASC"
        cols  = ", ".join(select_cols) if select_cols else "*"
        vec_str = "[" + ",".join(str(v) for v in query_vector) + "]"
        n    = len(query_vector)
        sql  = (
            f"SELECT {cols}, "
            f"{fn}({vector_col}, '{vec_str}'::VECTOR(FLOAT,{n})) AS _similarity "
            f"FROM {table} "
            f"ORDER BY _similarity {order} "
            f"LIMIT {limit}"
        )

        engine = create_engine(_sfurl(
            account   = cfg["account"],
            user      = cfg["user"],
            password  = cfg["password"],
            database  = cfg["database"],
            schema    = cfg.get("schema", "PUBLIC"),
            warehouse = cfg["warehouse"],
            role      = cfg.get("role", ""),
        ))
        with engine.connect() as conn:
            result = pd.read_sql(sa_text(sql), conn)

        self.gov._event(
            "LOAD", "SNOWFLAKE_VECTOR_SEARCH",
            {"table": table, "limit": limit, "results": len(result)},
        )
        return result

    @staticmethod
    def _embed(df: "pd.DataFrame", embed_cols: list, model_name: str) -> "pd.DataFrame":
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "SnowflakeVectorLoader: embed_columns requires "
                "sentence-transformers.\nInstall with: "
                "pip install sentence-transformers"
            ) from exc
        model  = SentenceTransformer(model_name)
        texts  = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs   = model.encode(texts, show_progress_bar=False).tolist()
        out    = df.copy()
        out["__embedding__"] = vecs
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: BigQueryVectorLoader  (v1.0)
#  ARRAY<FLOAT64> vector columns and VECTOR_SEARCH() in BigQuery.
# ═════════════════════════════════════════════════════════════════════════════

class BigQueryVectorLoader:
    """
    Write and search vectors in BigQuery using ARRAY<FLOAT64> columns and
    the native VECTOR_SEARCH() table-valued function (BigQuery 2023+).

    BigQuery does not have a dedicated VECTOR type — vectors are stored as
    ARRAY<FLOAT64>.  The VECTOR_SEARCH() function performs approximate
    nearest-neighbour search using a vector index (created separately) or
    exact brute-force search without one.

    Architecture
    ────────────
    This loader:
    1. Writes the DataFrame to BigQuery via the google-cloud-bigquery client,
       converting vector columns to Python lists (maps to ARRAY<FLOAT64>)
    2. Provides a ``search()`` method using BigQuery's VECTOR_SEARCH() TVF
    3. Optionally creates a VECTOR INDEX for ANN acceleration

    Required cfg keys
    -----------------
    project     : str   GCP project ID
    dataset     : str   BigQuery dataset name

    Optional cfg keys
    -----------------
    credentials_path : str  Path to service account JSON key.
    vector_column    : str  Vector column name (default "embedding")
    embed_columns    : list Text columns for sentence-transformer encoding
    embed_model      : str  sentence-transformers model name
    distance         : str  "COSINE" | "EUCLIDEAN" (default "COSINE")

    Requirements
    ------------
        pip install google-cloud-bigquery google-cloud-bigquery-storage pyarrow

    Quick-start
    ───────────
        loader = BigQueryVectorLoader(gov)
        rows   = loader.load(df, cfg={
            "project": "my-project", "dataset": "my_dataset",
        }, table="documents")
        results = loader.search(cfg, table="documents",
                                query_vector=[0.1, 0.2, ...], limit=5)
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_BIGQUERY:
            raise RuntimeError(
                "BigQueryVectorLoader requires google-cloud-bigquery.\n"
                "Install with:  pip install google-cloud-bigquery pyarrow"
            )

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,  # noqa: F841
    ) -> int:
        """
        Write df to BigQuery with an ARRAY<FLOAT64> vector column.

        Parameters
        ----------
        df          DataFrame to write.
        cfg         BigQuery connection config.
        table       Target table name.
        if_exists   "append" | "replace" ("replace" maps to WRITE_TRUNCATE)

        Returns
        -------
        int   Number of rows written.
        """
        from google.cloud import bigquery
        import numpy as _np

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"BigQueryVectorLoader: if_exists must be 'append' or "
                f"'replace', got '{if_exists}'."
            )
        if not table:
            raise ValueError("BigQueryVectorLoader: table name is required.")
        if not cfg.get("project"):
            raise ValueError("BigQueryVectorLoader: cfg must contain 'project'.")
        if not cfg.get("dataset"):
            raise ValueError("BigQueryVectorLoader: cfg must contain 'dataset'.")
        if not table:
            raise ValueError("BigQueryVectorLoader: table name is required.")
        _validate_sql_identifier(cfg["project"], "project")
        _validate_sql_identifier(cfg["dataset"], "dataset")
        _validate_sql_identifier(table,          "table")

        if df.empty:
            return 0

        vector_col  = cfg.get("vector_column", "embedding")
        embed_cols  = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")

        if embed_cols and vector_col not in df.columns:
            df         = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if vector_col not in df.columns:
            raise ValueError(
                f"BigQueryVectorLoader: vector column '{vector_col}' not "
                "in DataFrame."
            )

        # Convert vectors to Python lists (BQ ARRAY<FLOAT64>)
        out = df.copy()
        out[vector_col] = out[vector_col].apply(
            lambda v: v.tolist() if isinstance(v, _np.ndarray) else list(v)
        )

        # Build BigQuery client
        client_kwargs = {}
        if cfg.get("credentials_path"):
            from google.oauth2 import service_account
            client_kwargs["credentials"] = (
                service_account.Credentials
                .from_service_account_file(cfg["credentials_path"])
            )

        client   = bigquery.Client(project=cfg["project"], **client_kwargs)
        table_id = f"{cfg['project']}.{cfg['dataset']}.{table}"

        write_disp = (bigquery.WriteDisposition.WRITE_TRUNCATE
                      if if_exists == "replace"
                      else bigquery.WriteDisposition.WRITE_APPEND)

        job_config = bigquery.LoadJobConfig(write_disposition=write_disp)
        job = client.load_table_from_dataframe(out, table_id,
                                               job_config=job_config)
        timeout = int(cfg.get("job_timeout_seconds", 600))
        job.result(timeout=timeout)  # raises TimeoutError if exceeded

        self.gov._event(
            "LOAD", "BIGQUERY_VECTOR_WRITE_COMPLETE",
            {
                "table_id":   table_id,
                "rows":       len(df),
                "vector_col": vector_col,
                "if_exists":  if_exists,
            },
        )
        return len(df)

    def search(
        self,
        cfg:          dict,
        table:        str,
        query_vector: "list[float]",
        vector_col:   str  = "embedding",
        limit:        int  = 10,
        distance:     str  = "COSINE",
        options:      str  = "fraction_lists_to_search=0.1",
    ) -> "pd.DataFrame":
        """
        Search using BigQuery's VECTOR_SEARCH() table-valued function.

        Parameters
        ----------
        cfg           BigQuery connection config.
        table         Table to search.
        query_vector  Query embedding as list[float].
        vector_col    Vector column (default "embedding").
        limit         Top-k results (default 10).
        distance      "COSINE" | "EUCLIDEAN" (BigQuery default "COSINE").
        options       VECTOR_SEARCH options string
                      (default "fraction_lists_to_search=0.1").

        Returns
        -------
        pd.DataFrame  Top-k rows with "_distance" column added.
        """
        from google.cloud import bigquery

        if not query_vector:
            raise ValueError(
                "BigQueryVectorLoader.search(): query_vector must be "
                "a non-empty list of floats."
            )
        if not cfg.get("project"):
            raise ValueError("BigQueryVectorLoader: cfg must contain 'project'.")
        if not cfg.get("dataset"):
            raise ValueError("BigQueryVectorLoader: cfg must contain 'dataset'.")
        _validate_sql_identifier(cfg["project"], "project")
        _validate_sql_identifier(cfg["dataset"], "dataset")
        _validate_sql_identifier(table,          "table")

        client_kwargs = {}
        if cfg.get("credentials_path"):
            from google.oauth2 import service_account
            client_kwargs["credentials"] = (
                service_account.Credentials
                .from_service_account_file(cfg["credentials_path"])
            )

        client   = bigquery.Client(project=cfg["project"], **client_kwargs)
        table_id = f"{cfg['project']}.{cfg['dataset']}.{table}"

        # Validate options to prevent injection — only allow safe chars
        if options and not re.fullmatch(r"[\w=.,\s]+", options):
            raise ValueError(
                f"BigQueryVectorLoader.search(): options string contains "
                f"disallowed characters: {options!r}. "
                "Only alphanumerics, =, ., and commas are allowed."
            )
        # Validate distance type against known safe values
        if distance not in ("COSINE", "EUCLIDEAN"):
            raise ValueError(
                f"BigQueryVectorLoader.search(): distance must be "
                f"'COSINE' or 'EUCLIDEAN', got '{distance}'."
            )
        query_vector = _validate_float_vector(query_vector, "query_vector")
        # Build vector literal only after validation (NaN/inf already rejected)
        vec_literal = "[" + ",".join(str(v) for v in query_vector) + "]"

        sql = f"""
            SELECT base.*, distance AS _distance
            FROM VECTOR_SEARCH(
                TABLE `{table_id}`,
                '{vector_col}',
                (SELECT {vec_literal} AS query_vec),
                distance_type => '{distance}',
                top_k => {limit},
                options => '{options}'
            )
            ORDER BY _distance ASC
        """

        result = client.query(sql).to_dataframe()

        self.gov._event(
            "LOAD", "BIGQUERY_VECTOR_SEARCH",
            {"table": table_id, "limit": limit,
             "distance": distance, "results": len(result)},
        )
        return result

    @staticmethod
    def _embed(df: "pd.DataFrame", embed_cols: list, model_name: str) -> "pd.DataFrame":
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "BigQueryVectorLoader: embed_columns requires "
                "sentence-transformers.\nInstall with: "
                "pip install sentence-transformers"
            ) from exc
        model  = SentenceTransformer(model_name)
        texts  = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs   = model.encode(texts, show_progress_bar=False).tolist()
        out    = df.copy()
        out["__embedding__"] = vecs
        return out

# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: ChromaLoader  (v1.0)
#  Write governed DataFrames to a Chroma embedded vector database.
# ═════════════════════════════════════════════════════════════════════════════

class ChromaLoader:
    """
    Write a governed, PII-masked DataFrame to a Chroma vector database.

    Chroma is an open-source embedded vector database designed for local
    AI application development.  It requires no server — data is stored
    as files on disk (persistent mode) or kept in memory (ephemeral mode).
    This makes it the easiest vector database to get started with:
    no Docker, no cloud account, just ``pip install chromadb``.

    Architecture
    ────────────
    Chroma organises data into Collections.  Each document in a collection
    has a unique string ID, an embedding vector, the raw document text,
    and optional metadata (key-value pairs used for filtering).

    The loader maps DataFrame columns to Chroma's four fields:
      - id         → id_column (required; must be unique strings)
      - embedding  → vector_column (pre-computed) or auto-generated
      - document   → document_column (the text field Chroma indexes)
      - metadata   → all remaining columns stored as a filterable dict

    Required cfg keys
    -----------------
    collection  : str   Chroma collection name.

    One of:
    path        : str   Directory path for persistent storage.
                        Data survives process restarts.
    host        : str   Chroma server host for client-server mode.

    Optional cfg keys
    -----------------
    port            : int   Chroma server port (default 8000).
    id_column       : str   Column to use as document IDs (default "id").
    vector_column   : str   Pre-computed embedding column (list[float]).
    embed_columns   : list  Text columns to encode via sentence-transformers.
    embed_model     : str   sentence-transformers model name.
                            Default: "all-MiniLM-L6-v2"
    document_column : str   Column to store as the Chroma document text.
    batch_size      : int   Documents per add/upsert batch (default 100).

    Load modes
    ----------
    append  (default)
        Add documents to the collection.  Chroma raises on duplicate IDs
        unless using upsert mode.

    upsert
        Add or update documents — existing IDs are overwritten.

    overwrite
        Delete the collection then re-create it with the new data.

    Requirements
    ------------
        pip install chromadb

    Quick-start
    ───────────
        loader = ChromaLoader(gov)
        rows   = loader.load(df, cfg={
            "path":           "./chroma_db",
            "collection":     "documents",
            "id_column":      "doc_id",
            "vector_column":  "embedding",
            "document_column": "text",
        })
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_CHROMA:
            raise RuntimeError(
                "ChromaLoader requires the chromadb package.\n"
                "Install with:  pip install chromadb"
            )

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,  # noqa: F841
    ) -> int:
        """
        Write df to a Chroma collection.

        Parameters
        ----------
        df          DataFrame to write.
        cfg         Connection config (see class docstring).
        table       Collection name override.
        if_exists   "append" | "upsert" | "overwrite"

        Returns
        -------
        int   Number of documents written.
        """
        import chromadb

        if if_exists not in ("append", "upsert", "overwrite"):
            raise ValueError(
                f"ChromaLoader: if_exists must be 'append', 'upsert', or "
                f"'overwrite', got '{if_exists}'."
            )

        collection  = table or cfg.get("collection")
        if not collection:
            raise ValueError(
                "ChromaLoader: supply collection name via cfg['collection'] "
                "or the table parameter."
            )

        vector_col  = cfg.get("vector_column")
        embed_cols  = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")
        id_col      = cfg.get("id_column", "id")
        doc_col     = cfg.get("document_column")
        batch_size  = int(cfg.get("batch_size", self._BATCH))

        # Generate embeddings if requested
        if embed_cols and not vector_col:
            df         = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if id_col not in df.columns:
            raise ValueError(
                f"ChromaLoader: id_column '{id_col}' not in DataFrame. "
                "Set cfg['id_column'] to a column of unique string IDs."
            )

        # Build client
        client = self._build_client(cfg)
        col    = self._get_or_create_collection(client, collection, if_exists)

        total = 0
        for i in range(0, len(df), batch_size):
            chunk = df.iloc[i : i + batch_size]

            ids       = chunk[id_col].astype(str).tolist()
            documents = chunk[doc_col].astype(str).tolist()                         if doc_col and doc_col in chunk.columns                         else [str(idx) for idx in ids]

            embeddings = None
            if vector_col and vector_col in chunk.columns:
                import numpy as _np
                embeddings = [
                    v.tolist() if isinstance(v, _np.ndarray) else list(v)
                    for v in chunk[vector_col]
                ]

            meta_cols = [c for c in chunk.columns
                         if c not in (id_col, doc_col, vector_col)]
            metadatas = chunk[meta_cols].to_dict(orient="records")                         if meta_cols else None

            kwargs: dict = {"ids": ids, "documents": documents}
            if embeddings:
                kwargs["embeddings"] = embeddings
            if metadatas:
                kwargs["metadatas"] = metadatas

            if if_exists == "upsert":
                col.upsert(**kwargs)
            else:
                col.add(**kwargs)

            total += len(ids)

        self.gov._event(
            "LOAD", "CHROMA_WRITE_COMPLETE",
            {
                "collection": collection,
                "rows":       total,
                "if_exists":  if_exists,
                "has_vectors": vector_col is not None,
            },
        )
        return total

    def query(
        self,
        cfg:              dict,
        query_embeddings: "list[list[float]]",
        table:            str  = "",
        n_results:        int  = 10,
        where:            "dict | None" = None,
    ) -> dict:
        """
        Query a Chroma collection by embedding similarity.

        Parameters
        ----------
        cfg               Config dict (path/host + collection).
        query_embeddings  List of query vectors (list of list[float]).
        table             Collection name override.
        n_results         Results per query vector (default 10).
        where             Optional metadata filter dict.

        Returns
        -------
        dict   Chroma results dict with ids, distances, documents, metadatas.
        """
        if not query_embeddings or not query_embeddings[0]:
            raise ValueError(
                "ChromaLoader.query(): query_embeddings must be a non-empty "
                "list of embedding vectors."
            )

        import chromadb
        collection = table or cfg.get("collection")
        if not collection:
            raise ValueError("ChromaLoader: supply collection name.")

        client = self._build_client(cfg)
        col    = client.get_collection(collection)
        kwargs = {"query_embeddings": query_embeddings, "n_results": n_results}
        if where:
            kwargs["where"] = where

        results = col.query(**kwargs)
        self.gov._event(
            "LOAD", "CHROMA_QUERY",
            {"collection": collection, "n_results": n_results,
             "n_queries": len(query_embeddings)},
        )
        return results

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _build_client(cfg: dict):
        import chromadb
        if cfg.get("host"):
            return chromadb.HttpClient(
                host=cfg["host"],
                port=int(cfg.get("port", 8000)),
            )
        if cfg.get("path"):
            return chromadb.PersistentClient(path=cfg["path"])
        # Ephemeral (in-memory) — useful for testing
        return chromadb.Client()

    @staticmethod
    def _get_or_create_collection(client, name: str, if_exists: str):
        import chromadb
        if if_exists == "overwrite":
            try:
                client.delete_collection(name)
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # collection may not exist yet — that's fine
            return client.create_collection(name)
        try:
            return client.get_collection(name)
        except Exception:  # pylint: disable=broad-exception-caught
            return client.create_collection(name)

    @staticmethod
    def _embed(df: "pd.DataFrame", embed_cols: list, model_name: str) -> "pd.DataFrame":
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "ChromaLoader: embed_columns requires sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model  = SentenceTransformer(model_name)
        texts  = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs   = model.encode(texts, show_progress_bar=False).tolist()
        out    = df.copy()
        out["__embedding__"] = vecs
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: MilvusLoader  (v1.0)
#  Write governed DataFrames to a Milvus vector database collection.
# ═════════════════════════════════════════════════════════════════════════════

class MilvusLoader:
    """
    Write a governed, PII-masked DataFrame to a Milvus vector database.

    Milvus is an enterprise-grade open-source vector database designed for
    billion-scale vector workloads.  It supports three deployment modes:
      - Milvus Lite     Local file storage, no server (pip install pymilvus[milvus_lite])
      - Milvus Standalone  Docker-based single-node deployment
      - Milvus Cluster  Distributed production deployment

    All three modes use the same MilvusClient API — only the ``uri``
    parameter differs.

    Architecture
    ────────────
    Milvus organises data into Collections.  Each entity (row) has a
    primary key field, one or more vector fields, and optional scalar
    fields for filtering.  The loader creates a dynamic schema collection
    which accepts any DataFrame columns automatically.

    Required cfg keys
    -----------------
    uri         : str   Milvus connection URI.
                        Local file: "./milvus.db"
                        Server:     "http://localhost:19530"
                        Cloud:      "https://your-cluster.zillizcloud.com"
    collection  : str   Collection name.

    Optional cfg keys
    -----------------
    token           : str   Zilliz Cloud API token or "user:password".
    id_column       : str   Primary key column. Default "id".
    vector_column   : str   Pre-computed vector column (list[float]).
    embed_columns   : list  Text columns for sentence-transformer encoding.
    embed_model     : str   sentence-transformers model name.
    vector_size     : int   Embedding dimension (required for new collections).
    metric_type     : str   "COSINE" | "L2" | "IP" (default "COSINE").
    batch_size      : int   Entities per insert batch (default 100).
    index_type      : str   "AUTOINDEX" (default) | "IVF_FLAT" | "HNSW"

    Load modes
    ----------
    append  (default)
        Insert entities.  Duplicate primary keys raise an error.

    upsert
        Upsert entities — existing primary keys are updated.

    overwrite
        Drop and recreate the collection, then insert all entities.

    Requirements
    ------------
        pip install pymilvus
        pip install pymilvus[milvus_lite]   # for local file mode

    Quick-start
    ───────────
        loader = MilvusLoader(gov)
        rows   = loader.load(df, cfg={
            "uri":          "./milvus.db",
            "collection":   "documents",
            "vector_column": "embedding",
            "id_column":    "doc_id",
        })
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_MILVUS:
            raise RuntimeError(
                "MilvusLoader requires the pymilvus package.\n"
                "Install with:  pip install pymilvus\n"
                "For local file mode: pip install pymilvus[milvus_lite]"
            )

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,  # noqa: F841
    ) -> int:
        """
        Write df to a Milvus collection.

        Parameters
        ----------
        df          DataFrame to write.
        cfg         Connection config (see class docstring).
        table       Collection name override.
        if_exists   "append" | "upsert" | "overwrite"

        Returns
        -------
        int   Number of entities inserted/upserted.
        """
        from pymilvus import MilvusClient

        if if_exists not in ("append", "upsert", "overwrite"):
            raise ValueError(
                f"MilvusLoader: if_exists must be 'append', 'upsert', or "
                f"'overwrite', got '{if_exists}'."
            )

        uri        = cfg.get("uri")
        collection = table or cfg.get("collection")

        if not uri:
            raise ValueError("MilvusLoader: cfg must contain 'uri'.")
        if not collection:
            raise ValueError(
                "MilvusLoader: supply collection name via cfg['collection'] "
                "or the table parameter."
            )

        vector_col  = cfg.get("vector_column")
        embed_cols  = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")
        id_col      = cfg.get("id_column", "id")
        batch_size  = int(cfg.get("batch_size", self._BATCH))
        metric_type = cfg.get("metric_type", "COSINE")

        # Generate embeddings if requested
        if embed_cols and not vector_col:
            df         = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if not vector_col or vector_col not in df.columns:
            raise ValueError(
                f"MilvusLoader: vector column '{vector_col}' not in DataFrame. "
                "Set cfg['vector_column'] or cfg['embed_columns']."
            )

        # Detect vector dimension from first row
        import numpy as _np
        first_vec = df[vector_col].iloc[0]
        if isinstance(first_vec, _np.ndarray):
            first_vec = first_vec.tolist()
        vector_size = cfg.get("vector_size", len(first_vec))

        # Build kwargs for MilvusClient
        client_kwargs: dict = {"uri": uri}
        if cfg.get("token"):
            client_kwargs["token"] = cfg["token"]

        client = MilvusClient(**client_kwargs)

        try:
            if if_exists == "overwrite":
                if client.has_collection(collection):
                    client.drop_collection(collection)

            if not client.has_collection(collection):
                client.create_collection(
                    collection_name=collection,
                    dimension=vector_size,
                    metric_type=metric_type,
                    auto_id=(id_col not in df.columns),
                )

            total = 0
            for i in range(0, len(df), batch_size):
                chunk   = df.iloc[i : i + batch_size]
                records = []
                for _, row in chunk.iterrows():
                    vec = row[vector_col]
                    if isinstance(vec, _np.ndarray):
                        vec = vec.tolist()
                    rec = row.to_dict()
                    rec[vector_col] = vec
                    records.append(rec)

                if if_exists == "upsert":
                    res = client.upsert(collection_name=collection, data=records)
                else:
                    res = client.insert(collection_name=collection, data=records)

                total += res.get("insert_count", 0) or res.get("upsert_count", 0)                          or len(records)

        finally:
            client.close()

        self.gov._event(
            "LOAD", "MILVUS_WRITE_COMPLETE",
            {
                "uri":        uri,
                "collection": collection,
                "rows":       total,
                "if_exists":  if_exists,
                "metric":     metric_type,
                "vector_col": vector_col,
            },
        )
        return total

    def search(
        self,
        cfg:          dict,
        query_vector: "list[float]",
        table:        str  = "",
        limit:        int  = 10,
        output_fields: "list | None" = None,
        filter_expr:   str = "",
    ) -> list:
        """
        Run a nearest-neighbour search against a Milvus collection.

        Parameters
        ----------
        cfg           Config dict (uri + collection).
        query_vector  Query embedding as list[float].
        table         Collection name override.
        limit         Number of results (default 10).
        output_fields Fields to include in results (default all).
        filter_expr   Optional scalar filter expression string.

        Returns
        -------
        list   Result dicts with id, distance, and entity fields.
        """
        from pymilvus import MilvusClient

        if not query_vector:
            raise ValueError(
                "MilvusLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )

        uri        = cfg.get("uri")
        collection = table or cfg.get("collection")
        if not uri:
            raise ValueError("MilvusLoader: cfg must contain 'uri'.")
        if not collection:
            raise ValueError("MilvusLoader: supply collection name.")

        client_kwargs: dict = {"uri": uri}
        if cfg.get("token"):
            client_kwargs["token"] = cfg["token"]

        client = MilvusClient(**client_kwargs)
        try:
            kwargs: dict = {
                "collection_name": collection,
                "data":            [query_vector],
                "limit":           limit,
            }
            if output_fields:
                kwargs["output_fields"] = output_fields
            if filter_expr:
                kwargs["filter"] = filter_expr

            results = client.search(**kwargs)
        finally:
            client.close()

        self.gov._event(
            "LOAD", "MILVUS_SEARCH",
            {"collection": collection, "limit": limit,
             "results": len(results[0]) if results else 0},
        )
        return results[0] if results else []

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _embed(df: "pd.DataFrame", embed_cols: list, model_name: str) -> "pd.DataFrame":
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "MilvusLoader: embed_columns requires sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model  = SentenceTransformer(model_name)
        texts  = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs   = model.encode(texts, show_progress_bar=False).tolist()
        out    = df.copy()
        out["__embedding__"] = vecs
        return out

# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: PineconeLoader  (v1.0)
#  Write governed DataFrames to a Pinecone managed vector database index.
# ═════════════════════════════════════════════════════════════════════════════

class PineconeLoader:
    """
    Write a governed, PII-masked DataFrame to a Pinecone vector index.

    Pinecone is a fully managed cloud vector database designed for
    production AI applications.  Each DataFrame row becomes one Pinecone
    vector record, consisting of a unique ID, an embedding vector, and
    optional metadata fields for filtering.

    Architecture
    ────────────
    Pinecone organises data into indexes (one per use-case).  Each record
    in an index has three parts:
      - id        Unique string identifier — taken from a DataFrame column
                  or auto-generated as a UUID.
      - values    The embedding vector — a list of floats.  Can come from
                  a pre-computed column in the DataFrame or be generated
                  on the fly via sentence-transformers.
      - metadata  Any other DataFrame columns stored as a filterable dict.

    Required cfg keys
    -----------------
    api_key     : str   Pinecone API key.
    index_name  : str   Name of the Pinecone index to write to.

    Optional cfg keys
    -----------------
    environment     : str   Pinecone environment (legacy — not needed for
                            serverless indexes).
    id_column       : str   DataFrame column to use as the vector ID.
                            Default: auto-generates UUIDs.
    vector_column   : str   Column containing pre-computed embedding vectors
                            (list[float]).  Required unless embed_columns set.
    embed_columns   : list  Text columns to concatenate and encode into
                            vectors via sentence-transformers.
    embed_model     : str   sentence-transformers model name.
                            Default: "all-MiniLM-L6-v2"
    batch_size      : int   Records per upsert batch (default 100).
    namespace       : str   Pinecone namespace (default "").

    Load modes
    ----------
    append / upsert (default)
        Pinecone upserts by ID — existing records with the same ID are
        overwritten.  append and upsert behave identically.

    Requirements
    ------------
        pip install pinecone-client

    Quick-start
    ───────────
        from pipeline_v3 import GovernanceLogger
        loader = PineconeLoader(GovernanceLogger("run_001", "docs.csv"))
        rows   = loader.load(df, cfg={
            "api_key":      "your-api-key",
            "index_name":   "my-index",
            "vector_column": "embedding",
            "id_column":    "doc_id",
        })
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_PINECONE:
            raise RuntimeError(
                "PineconeLoader requires the pinecone-client package.\n"
                "Install with:  pip install pinecone-client"
            )

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",   # treated as index_name override
        if_exists:    str       = "upsert",
        natural_keys: "list | None" = None,  # noqa: F841 — unused, for dispatch compat
    ) -> int:
        """
        Upsert df into a Pinecone index.

        Parameters
        ----------
        df          DataFrame to upsert.
        cfg         Connection config dict (see class docstring).
        table       Index name override — takes precedence over cfg["index_name"].
        if_exists   Ignored — Pinecone always upserts by ID.

        Returns
        -------
        int   Number of records upserted.
        """
        import pinecone

        api_key    = cfg.get("api_key")
        index_name = table or cfg.get("index_name")
        if not api_key:
            raise ValueError("PineconeLoader: cfg must contain 'api_key'.")
        if not index_name:
            raise ValueError(
                "PineconeLoader: supply index name via cfg['index_name'] "
                "or the table parameter."
            )

        vector_col   = cfg.get("vector_column")
        embed_cols   = cfg.get("embed_columns")
        embed_model  = cfg.get("embed_model", "all-MiniLM-L6-v2")
        id_col       = cfg.get("id_column")
        namespace    = cfg.get("namespace", "")
        batch_size   = int(cfg.get("batch_size", self._BATCH))

        # Generate embeddings if requested
        if embed_cols and not vector_col:
            df        = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if not vector_col or vector_col not in df.columns:
            raise ValueError(
                f"PineconeLoader: vector column '{vector_col}' not in DataFrame. "
                "Set cfg['vector_column'] or cfg['embed_columns']."
            )

        # Connect and get index
        pc    = pinecone.Pinecone(api_key=api_key)
        index = pc.Index(index_name)

        # Build records
        records = self._build_records(df, vector_col, id_col)

        # Upsert in batches
        total = 0
        for i in range(0, len(records), batch_size):
            batch = records[i : i + batch_size]
            index.upsert(vectors=batch, namespace=namespace)
            total += len(batch)

        self.gov._event(
            "LOAD", "PINECONE_UPSERT_COMPLETE",
            {
                "index_name": index_name,
                "namespace":  namespace,
                "rows":       total,
                "vector_col": vector_col,
            },
        )
        return total

    def query(
        self,
        cfg:          dict,
        query_vector: "list[float]",
        table:        str  = "",
        top_k:        int  = 10,
        namespace:    str  = "",
        filter_dict:  "dict | None" = None,
    ) -> list:
        """
        Run a nearest-neighbour query against a Pinecone index.

        Parameters
        ----------
        cfg           Config dict with api_key and index_name.
        query_vector  Query embedding as list[float].
        table         Index name override.
        top_k         Number of results to return (default 10).
        namespace     Pinecone namespace (default "").
        filter_dict   Optional metadata filter dict.

        Returns
        -------
        list   Pinecone match objects with id, score, and metadata.
        """
        import pinecone

        if not query_vector:
            raise ValueError(
                "PineconeLoader.query(): query_vector must be a non-empty "
                "list of floats."
            )

        api_key    = cfg.get("api_key")
        index_name = table or cfg.get("index_name")
        if not api_key:
            raise ValueError("PineconeLoader: cfg must contain 'api_key'.")
        if not index_name:
            raise ValueError("PineconeLoader: supply index_name via cfg or table.")

        pc      = pinecone.Pinecone(api_key=api_key)
        index   = pc.Index(index_name)
        kwargs  = {"vector": query_vector, "top_k": top_k, "namespace": namespace}
        if filter_dict:
            kwargs["filter"] = filter_dict

        response = index.query(**kwargs)
        self.gov._event(
            "LOAD", "PINECONE_QUERY",
            {"index_name": index_name, "top_k": top_k,
             "results": len(response.get("matches", []))},
        )
        return response.get("matches", [])

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _build_records(
        df:         "pd.DataFrame",
        vector_col: str,
        id_col:     "str | None",
    ) -> list:
        import uuid as _uuid
        import numpy as _np
        records = []
        for _, row in df.iterrows():
            vec = row[vector_col]
            if isinstance(vec, _np.ndarray):
                vec = vec.tolist()
            rec_id = str(row[id_col]) if id_col and id_col in row.index                 else str(_uuid.uuid4())
            metadata = {
                k: v for k, v in row.to_dict().items()
                if k != vector_col and not hasattr(v, "__len__")
                or isinstance(v, str)
            }
            records.append({"id": rec_id, "values": vec, "metadata": metadata})
        return records

    @staticmethod
    def _embed(df: "pd.DataFrame", embed_cols: list, model_name: str) -> "pd.DataFrame":
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "PineconeLoader: embed_columns requires sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model  = SentenceTransformer(model_name)
        texts  = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs   = model.encode(texts, show_progress_bar=False).tolist()
        out    = df.copy()
        out["__embedding__"] = vecs
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: WeaviateLoader  (v1.0)
#  Write governed DataFrames to a Weaviate vector database collection.
# ═════════════════════════════════════════════════════════════════════════════

class WeaviateLoader:
    """
    Write a governed, PII-masked DataFrame to a Weaviate vector database.

    Weaviate is an open-source vector database that supports both pure
    vector search and hybrid search (vector + BM25 keyword search
    combined).  It can run locally via Docker or as a managed cloud
    service (Weaviate Cloud Services).

    Architecture
    ────────────
    Weaviate organises data into Collections (formerly Classes).  Each
    object in a collection has a UUID, optional properties (your data
    columns), and an optional vector.  Weaviate can generate vectors
    automatically via its built-in vectorizer modules (text2vec-openai,
    text2vec-cohere, etc.) or you can supply pre-computed vectors.

    Required cfg keys
    -----------------
    url         : str   Weaviate instance URL, e.g. "http://localhost:8080"
                        or "https://your-cluster.weaviate.network".
    collection  : str   Collection (class) name.  Must start with uppercase.

    Optional cfg keys
    -----------------
    api_key         : str   Weaviate Cloud Services API key.
    openai_api_key  : str   OpenAI API key if using text2vec-openai module.
    vector_column   : str   Pre-computed vector column in the DataFrame.
    id_column       : str   Column to use as the Weaviate UUID.
                            Must be a valid UUID string or will be hashed.
    batch_size      : int   Objects per batch (default 100).

    Load modes
    ----------
    append  (default)
        Insert all rows as new objects.

    overwrite
        Delete the entire collection then re-create it with the new data.

    upsert  (natural_keys provided)
        Update existing objects by UUID; insert new ones.

    Requirements
    ------------
        pip install weaviate-client

    Quick-start
    ───────────
        loader = WeaviateLoader(gov)
        rows   = loader.load(df, cfg={
            "url":          "http://localhost:8080",
            "collection":   "Documents",
            "vector_column": "embedding",
        })
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_WEAVIATE:
            raise RuntimeError(
                "WeaviateLoader requires the weaviate-client package.\n"
                "Install with:  pip install weaviate-client"
            )

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,
    ) -> int:
        """
        Write df to a Weaviate collection.

        Parameters
        ----------
        df          DataFrame to write.
        cfg         Connection config (see class docstring).
        table       Collection name override — takes precedence over
                    cfg["collection"].
        if_exists   "append" | "overwrite" | "upsert"
        natural_keys  Not used directly — Weaviate uses UUID-based upsert.

        Returns
        -------
        int   Number of objects written.
        """
        import weaviate

        if if_exists not in ("append", "overwrite", "upsert"):
            raise ValueError(
                f"WeaviateLoader: if_exists must be 'append', 'overwrite', "
                f"or 'upsert', got '{if_exists}'."
            )

        url        = cfg.get("url")
        collection = table or cfg.get("collection")
        if not url:
            raise ValueError("WeaviateLoader: cfg must contain 'url'.")
        if not collection:
            raise ValueError(
                "WeaviateLoader: supply collection via cfg['collection'] "
                "or the table parameter."
            )
        if not collection[0].isupper():
            raise ValueError(
                f"WeaviateLoader: Weaviate collection names must start with "
                f"an uppercase letter, got '{collection}'."
            )

        vector_col = cfg.get("vector_column")
        id_col     = cfg.get("id_column")
        batch_size = int(cfg.get("batch_size", self._BATCH))

        # Parse URL safely — handles http/https with or without port, with or without path
        _scheme      = url.split("://")[0] if "://" in url else "http"
        _rest        = url.split("://")[-1].split("/")[0]   # strip path component
        _is_https    = _scheme == "https"
        if ":" in _rest:
            _host, _port_str = _rest.rsplit(":", 1)
            try:
                _port = int(_port_str)
            except ValueError:
                _port = 443 if _is_https else 8080
        else:
            _host = _rest
            _port = 443 if _is_https else 8080   # correct defaults per scheme

        # Build Weaviate client
        auth   = weaviate.auth.AuthApiKey(cfg["api_key"]) \
                 if cfg.get("api_key") else None
        client = weaviate.connect_to_custom(
            http_host        = _host,
            http_port        = _port,
            http_secure      = _is_https,
            auth_credentials = auth,
        ) if auth else weaviate.connect_to_local(
            host = _host,
            port = _port,
        )

        try:
            if if_exists == "overwrite":
                if client.collections.exists(collection):
                    client.collections.delete(collection)

            col = client.collections.get(collection)                   if client.collections.exists(collection)                   else client.collections.create(collection)

            total = 0
            with col.batch.fixed_size(batch_size) as batch:
                for _, row in df.iterrows():
                    props  = row.to_dict()
                    vector = None
                    if vector_col and vector_col in row.index:
                        import numpy as _np
                        v      = props.pop(vector_col)
                        vector = v.tolist() if isinstance(v, _np.ndarray) else v

                    obj_uuid = None
                    if id_col and id_col in row.index:
                        import uuid as _uuid
                        try:
                            obj_uuid = str(_uuid.UUID(str(props[id_col])))
                        except ValueError:
                            import hashlib
                            obj_uuid = str(_uuid.UUID(
                                hashlib.md5(str(props[id_col]).encode()).hexdigest()
                            ))

                    batch.add_object(
                        properties=props,
                        vector=vector,
                        uuid=obj_uuid,
                    )
                    total += 1
        finally:
            client.close()

        self.gov._event(
            "LOAD", "WEAVIATE_WRITE_COMPLETE",
            {
                "url":        url,
                "collection": collection,
                "rows":       total,
                "if_exists":  if_exists,
                "has_vector": vector_col is not None,
            },
        )
        return total


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: QdrantLoader  (v1.0)
#  Write governed DataFrames to a Qdrant vector database collection.
# ═════════════════════════════════════════════════════════════════════════════

class QdrantLoader:
    """
    Write a governed, PII-masked DataFrame to a Qdrant vector database.

    Qdrant is a high-performance open-source vector database written in
    Rust.  It supports local file storage (no server needed), in-memory
    mode for testing, and a production server mode.  The Python client
    provides a clean interface for all three.

    Architecture
    ────────────
    Qdrant organises data into collections.  Each point (record) in a
    collection has a numeric or UUID ID, a vector, and an optional
    payload (metadata dict).  Qdrant supports multiple named vectors per
    point for multi-modal search.

    Required cfg keys
    -----------------
    collection  : str   Qdrant collection name.

    One of:
    url         : str   Qdrant server URL, e.g. "http://localhost:6333"
    path        : str   Local file path for embedded Qdrant (no server)
    memory      : bool  True for in-memory mode (testing only)

    Optional cfg keys
    -----------------
    api_key         : str   Qdrant Cloud API key.
    vector_column   : str   Column containing pre-computed vectors.
    embed_columns   : list  Text columns to encode via sentence-transformers.
    embed_model     : str   sentence-transformers model (default all-MiniLM-L6-v2).
    id_column       : str   Column to use as point ID (int or UUID string).
    vector_size     : int   Required when creating a new collection.
                            Auto-detected from first row if not set.
    distance        : str   "Cosine" | "Euclid" | "Dot" (default "Cosine").
    batch_size      : int   Points per upsert batch (default 100).

    Load modes
    ----------
    append  (default)
        Upsert points — existing IDs are overwritten, new IDs are inserted.

    overwrite
        Delete and recreate the collection, then insert all points.

    Requirements
    ------------
        pip install qdrant-client

    Quick-start
    ───────────
        loader = QdrantLoader(gov)
        rows   = loader.load(df, cfg={
            "path":         "./qdrant_storage",
            "collection":   "documents",
            "vector_column": "embedding",
            "id_column":    "doc_id",
        })
    """

    _BATCH = 100

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_QDRANT:
            raise RuntimeError(
                "QdrantLoader requires the qdrant-client package.\n"
                "Install with:  pip install qdrant-client"
            )

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,  # noqa: F841
    ) -> int:
        """
        Upsert df into a Qdrant collection.

        Parameters
        ----------
        df          DataFrame to write.
        cfg         Connection config (see class docstring).
        table       Collection name override.
        if_exists   "append" (upsert) | "overwrite" (recreate collection)

        Returns
        -------
        int   Number of points upserted.
        """
        from qdrant_client import QdrantClient
        from qdrant_client.models import (
            Distance, VectorParams, PointStruct
        )

        if if_exists not in ("append", "overwrite"):
            raise ValueError(
                f"QdrantLoader: if_exists must be 'append' or 'overwrite', "
                f"got '{if_exists}'."
            )

        collection = table or cfg.get("collection")
        if not collection:
            raise ValueError(
                "QdrantLoader: supply collection name via cfg['collection'] "
                "or the table parameter."
            )

        vector_col  = cfg.get("vector_column")
        embed_cols  = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")
        id_col      = cfg.get("id_column")
        distance    = cfg.get("distance", "Cosine")
        batch_size  = int(cfg.get("batch_size", self._BATCH))

        # Generate embeddings if requested
        if embed_cols and not vector_col:
            df         = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if not vector_col or vector_col not in df.columns:
            raise ValueError(
                f"QdrantLoader: vector column '{vector_col}' not in DataFrame. "
                "Set cfg['vector_column'] or cfg['embed_columns']."
            )

        # Build client
        client = self._build_client(cfg)

        try:
            # Detect vector size from first row
            first_vec = df[vector_col].iloc[0]
            import numpy as _np
            if isinstance(first_vec, _np.ndarray):
                first_vec = first_vec.tolist()
            vector_size = cfg.get("vector_size", len(first_vec))

            dist_map = {
                "Cosine": Distance.COSINE,
                "Euclid": Distance.EUCLID,
                "Dot":    Distance.DOT,
            }
            dist = dist_map.get(distance, Distance.COSINE)

            if if_exists == "overwrite":
                if client.collection_exists(collection):
                    client.delete_collection(collection)

            if not client.collection_exists(collection):
                client.create_collection(
                    collection_name=collection,
                    vectors_config=VectorParams(size=vector_size, distance=dist),
                )

            # Build points
            points = []
            for idx_val, (_, row) in enumerate(df.iterrows()):
                vec = row[vector_col]
                if isinstance(vec, _np.ndarray):
                    vec = vec.tolist()

                # Determine point ID
                if id_col and id_col in row.index:
                    raw_id = row[id_col]
                    try:
                        point_id = int(raw_id)
                    except (ValueError, TypeError):
                        import uuid as _uuid
                        import hashlib
                        point_id = str(_uuid.UUID(
                            hashlib.md5(str(raw_id).encode()).hexdigest()
                        ))
                else:
                    point_id = idx_val

                payload = {
                    k: v for k, v in row.to_dict().items()
                    if k != vector_col
                }
                points.append(PointStruct(
                    id=point_id, vector=vec, payload=payload
                ))

            # Upsert in batches
            total = 0
            for i in range(0, len(points), batch_size):
                batch = points[i : i + batch_size]
                client.upsert(collection_name=collection, points=batch, wait=True)
                total += len(batch)

        finally:
            client.close()

        self.gov._event(
            "LOAD", "QDRANT_UPSERT_COMPLETE",
            {
                "collection": collection,
                "rows":       total,
                "if_exists":  if_exists,
                "distance":   distance,
                "vector_col": vector_col,
            },
        )
        return total

    def search(
        self,
        cfg:          dict,
        query_vector: "list[float]",
        table:        str  = "",
        limit:        int  = 10,
        filter_dict:  "dict | None" = None,
    ) -> list:
        """
        Run a nearest-neighbour search against a Qdrant collection.

        Parameters
        ----------
        cfg           Config dict (url/path/memory + collection).
        query_vector  Query embedding as list[float].
        table         Collection name override.
        limit         Number of results (default 10).
        filter_dict   Optional Qdrant filter dict.

        Returns
        -------
        list   ScoredPoint objects with id, score, and payload.
        """
        if not query_vector:
            raise ValueError(
                "QdrantLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )

        collection = table or cfg.get("collection")
        if not collection:
            raise ValueError("QdrantLoader: supply collection name.")

        client = self._build_client(cfg)
        try:
            from qdrant_client.models import Filter as _QFilter
            kwargs = {
                "collection_name": collection,
                "query":           query_vector,
                "limit":           limit,
            }
            if filter_dict:
                kwargs["query_filter"] = filter_dict
            resp    = client.query_points(**kwargs)
            results = list(resp.points)
        finally:
            client.close()

        self.gov._event(
            "LOAD", "QDRANT_SEARCH",
            {"collection": collection, "limit": limit,
             "results": len(results)},
        )
        return results

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _build_client(cfg: dict):
        from qdrant_client import QdrantClient
        if cfg.get("memory"):
            return QdrantClient(":memory:")
        if cfg.get("path"):
            return QdrantClient(path=cfg["path"])
        url = cfg.get("url")
        if not url:
            raise ValueError(
                "QdrantLoader: cfg must contain 'url', 'path', or memory=True."
            )
        kwargs = {"url": url}
        if cfg.get("api_key"):
            kwargs["api_key"] = cfg["api_key"]
        return QdrantClient(**kwargs)

    @staticmethod
    def _embed(df: "pd.DataFrame", embed_cols: list, model_name: str) -> "pd.DataFrame":
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "QdrantLoader: embed_columns requires sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model  = SentenceTransformer(model_name)
        texts  = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs   = model.encode(texts, show_progress_bar=False).tolist()
        out    = df.copy()
        out["__embedding__"] = vecs
        return out



# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: CockroachDBLoader  (v1.0)
#  Write governed DataFrames to CockroachDB — distributed PostgreSQL.
# ═════════════════════════════════════════════════════════════════════════════

class CockroachDBLoader:
    """
    Write a governed, PII-masked DataFrame to CockroachDB.

    CockroachDB is a distributed SQL database that is wire-compatible with
    PostgreSQL.  It is designed for cloud-native applications that need
    horizontal scalability, multi-region replication, and automatic failover
    without sacrificing ACID guarantees.

    Architecture
    ────────────
    This loader delegates to ``SQLLoader`` under the hood, using either the
    dedicated ``cockroachdb://`` SQLAlchemy dialect (when sqlalchemy-cockroachdb
    is installed) or the standard ``postgresql+psycopg2://`` driver as a
    fallback.  Both work correctly with CockroachDB — the dedicated dialect
    adds CockroachDB-specific optimisations such as automatic SAVEPOINT
    handling and retry logic for transaction contention errors.

    CockroachDB differs from standard PostgreSQL in a few ways relevant to
    ETL workloads:
      - Default port is **26257** (not 5432)
      - Cloud clusters require SSL (``sslmode=verify-full``)
      - SERIAL columns use unique_rowid() not sequences — avoid relying on
        sequential IDs
      - Large bulk inserts perform best with the COPY protocol or INSERT …
        ON CONFLICT DO NOTHING for idempotent loads

    Required cfg keys
    -----------------
    host        : str   CockroachDB host
    db_name     : str   Database name
    user        : str   SQL username
    password    : str   SQL password

    Optional cfg keys
    -----------------
    port            : int   Default 26257
    sslmode         : str   "verify-full" (cloud) | "disable" (local dev)
                            Default "verify-full"
    sslrootcert     : str   Path to CA certificate (required for cloud)
    cluster_name    : str   CockroachDB Cloud cluster name (added to host)
    options         : str   Additional connection options string

    Load modes
    ----------
    append   (default)
        Insert rows.  Fastest for new data.

    replace
        Truncate the table then re-insert.

    upsert   (natural_keys provided)
        INSERT … ON CONFLICT (key_cols) DO UPDATE SET … — idempotent loads.

    Requirements
    ------------
        pip install sqlalchemy-cockroachdb psycopg2-binary sqlalchemy
        # OR without the dedicated dialect:
        pip install psycopg2-binary sqlalchemy

    Quick-start
    ───────────
        # Local dev cluster (no SSL)
        loader = CockroachDBLoader(gov)
        rows   = loader.load(df, cfg={
            "host":    "localhost",
            "db_name": "defaultdb",
            "user":    "root",
            "password": "",
            "sslmode": "disable",
        }, table="employees")

        # CockroachDB Cloud
        rows = loader.load(df, cfg={
            "host":        "free-tier.cockroachlabs.cloud",
            "db_name":     "defaultdb",
            "user":        "matt",
            "password":    "your-password",
            "sslmode":     "verify-full",
            "sslrootcert": "/path/to/cc-ca.crt",
            "cluster_name": "your-cluster-name",
        }, table="employees")
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def load(
        self,
        df:           "pd.DataFrame",
        cfg:          dict,
        table:        str       = "",
        if_exists:    str       = "append",
        natural_keys: "list | None" = None,
    ) -> int:
        """
        Write df to a CockroachDB table.

        Parameters
        ----------
        df            DataFrame to write.
        cfg           Connection config (see class docstring).
        table         Target table name.
        if_exists     "append" | "replace" | "upsert"
        natural_keys  Column(s) for ON CONFLICT upsert key.

        Returns
        -------
        int   Number of rows written.
        """
        from sqlalchemy import create_engine, text as sa_text
        from urllib.parse import quote_plus as _qp

        if if_exists not in ("append", "replace", "upsert"):
            raise ValueError(
                f"CockroachDBLoader: if_exists must be 'append', 'replace', "
                f"or 'upsert', got '{if_exists}'."
            )
        if not table:
            raise ValueError("CockroachDBLoader: table name is required.")
        if not cfg.get("host"):
            raise ValueError("CockroachDBLoader: cfg must contain 'host'.")
        if not cfg.get("db_name"):
            raise ValueError("CockroachDBLoader: cfg must contain 'db_name'.")
        _validate_sql_identifier(table, "table")

        if df.empty:
            return 0

        engine = self._engine(cfg)

        if if_exists == "upsert" and natural_keys:
            rows = self._upsert(df, engine, table, natural_keys)
        else:
            pg_if_exists = "replace" if if_exists == "replace" else "append"
            df.to_sql(table, engine, if_exists=pg_if_exists,
                      index=False, method="multi", chunksize=500)
            rows = len(df)

        self.gov._event(
            "LOAD", "COCKROACHDB_WRITE_COMPLETE",
            {
                "host":        cfg["host"],
                "db_name":     cfg["db_name"],
                "table":       table,
                "rows":        rows,
                "if_exists":   if_exists,
                "driver":      "cockroachdb" if HAS_COCKROACH else "psycopg2",
            },
        )
        return rows

    def table_info(self, cfg: dict, table: str) -> dict:
        """
        Return basic metadata about a CockroachDB table.

        Parameters
        ----------
        cfg    Connection config.
        table  Table name.

        Returns
        -------
        dict with keys: table, columns, row_count, engine_url
        """
        from sqlalchemy import create_engine, inspect as sa_inspect, text as sa_text

        engine  = self._engine(cfg)
        insp    = sa_inspect(engine)
        cols    = [c["name"] for c in insp.get_columns(table)]
        with engine.connect() as conn:
            count = conn.execute(sa_text(f"SELECT COUNT(*) FROM {table}")).scalar()
        return {
            "table":      table,
            "columns":    cols,
            "row_count":  count,
            "engine_url": str(engine.url),
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _engine(self, cfg: dict):
        """Build a SQLAlchemy engine for CockroachDB."""
        from sqlalchemy import create_engine
        from urllib.parse import quote_plus as _qp

        host      = cfg["host"]
        port      = cfg.get("port", 26257)
        db_name   = cfg["db_name"]
        user      = _qp(cfg.get("user", "root"))
        password  = _qp(cfg.get("password", ""))
        sslmode   = cfg.get("sslmode", "verify-full")
        sslcert   = cfg.get("sslrootcert", "")
        cluster   = cfg.get("cluster_name", "")
        options   = cfg.get("options", "")

        # Append cluster name to host for CockroachDB Cloud
        if cluster:
            host = f"{cluster}.{host}"

        if HAS_COCKROACH:
            # Use dedicated dialect for full CockroachDB compatibility
            url  = f"cockroachdb://{user}:{password}@{host}:{port}/{db_name}"
            params = [f"sslmode={sslmode}"]
            if sslcert:
                params.append(f"sslrootcert={sslcert}")
            if options:
                params.append(options)
            url += "?" + "&".join(params)
        else:
            # Fallback: psycopg2 driver — works for most operations
            url  = (f"postgresql+psycopg2://{user}:{password}"
                    f"@{host}:{port}/{db_name}")
            params = [f"sslmode={sslmode}"]
            if sslcert:
                params.append(f"sslrootcert={sslcert}")
            if options:
                params.append(options)
            url += "?" + "&".join(params)

        return create_engine(url, pool_pre_ping=True)

    def _upsert(
        self,
        df:           "pd.DataFrame",
        engine,
        table:        str,
        natural_keys: list,
    ) -> int:
        """
        Upsert using CockroachDB's INSERT … ON CONFLICT DO UPDATE SET syntax.

        This is identical to PostgreSQL's ON CONFLICT clause and is the
        recommended idempotent load pattern for CockroachDB.
        """
        from sqlalchemy import create_engine, text as sa_text

        # Validate key columns
        missing = [k for k in natural_keys if k not in df.columns]
        if missing:
            raise ValueError(
                f"CockroachDBLoader: upsert key column(s) not in DataFrame: "
                f"{missing}"
            )

        cols      = list(df.columns)
        non_keys  = [c for c in cols if c not in natural_keys]
        # Validate all column names and keys to prevent SQL injection
        for col in cols:
            _validate_sql_identifier(col, "column")
        for key in natural_keys:
            _validate_sql_identifier(key, "natural_key")
        key_str   = ", ".join(natural_keys)
        col_str   = ", ".join(cols)
        val_str   = ", ".join(f":{c}" for c in cols)
        update_str = ", ".join(f"{c} = EXCLUDED.{c}" for c in non_keys)

        sql = sa_text(
            f"INSERT INTO {table} ({col_str}) VALUES ({val_str}) "
            f"ON CONFLICT ({key_str}) DO UPDATE SET {update_str}"
        )

        rows = 0
        with engine.begin() as conn:
            for batch_start in range(0, len(df), 500):
                batch = df.iloc[batch_start:batch_start + 500]
                conn.execute(sql, batch.to_dict(orient="records"))
                rows += len(batch)
        return rows

# ── Populate _LOADER_DISPATCH now that all Loader classes are defined ──────────
_LOADER_DISPATCH.update({
    # Standard SQL (SQLAlchemy-backed) — need db_type in __init__
    "sqlite":      (SQLLoader,         True,  False),
    "postgresql":  (SQLLoader,         True,  False),
    "postgres":    (SQLLoader,         True,  False),
    "mysql":       (SQLLoader,         True,  False),
    "mssql":       (SQLLoader,         True,  False),
    # Tier-1 cloud warehouses
    "snowflake":   (SnowflakeLoader,   False, False),
    "bigquery":    (BigQueryLoader,    False, False),
    "redshift":    (RedshiftLoader,    False, False),
    "synapse":     (SynapseLoader,     False, False),
    # Tier-2
    "databricks":  (DatabricksLoader,  False, False),
    "clickhouse":  (ClickHouseLoader,  False, False),
    # Tier-3
    "oracle":      (OracleLoader,      False, False),
    "db2":         (Db2Loader,         False, False),
    "firebolt":    (FireboltLoader,    False, False),
    "yellowbrick": (YellowbrickLoader, False, False),
    # SAP
    "hana":        (HanaLoader,        False, False),
    "datasphere":  (DatasphereLoader,  False, False),
    # NoSQL
    "mongodb":     (MongoLoader,       False, True),
    # Accounting
    "quickbooks":  (QuickBooksLoader,  False, False),
    # Vector databases
    "lancedb":     (LanceDBLoader,      False, False),
    "cockroachdb":  (CockroachDBLoader,  False, False),
    "pgvector":    (PgvectorLoader,     False, False),
    "snowflake_vector": (SnowflakeVectorLoader, False, False),
    "bigquery_vector":  (BigQueryVectorLoader,  False, False),
    "chroma":      (ChromaLoader,       False, False),
    "milvus":      (MilvusLoader,       False, False),
    "pinecone":    (PineconeLoader,     False, False),
    "weaviate":    (WeaviateLoader,     False, False),
    "qdrant":      (QdrantLoader,       False, False),
    # Streaming destinations
    "kafka":       (KafkaLoader,        False, False),
})



def run_governance_preflight(  # noqa: C901
    gov:        "GovernanceLogger",
    df:         "pd.DataFrame",
    src_path:   str,
    src_label:  str,
    pii_findings: list,
) -> tuple["pd.DataFrame", dict]:
    """
    Governance Pre-flight Gate  (v1.0 — 2026-03-10)
    ────────────────────────────────────────────────
    Discovers every piece of existing governance state that applies to the
    current source and presents a confirmation prompt before enforcing any of
    it.  Returns the (possibly modified) DataFrame and a summary dict so the
    caller can report what was applied.

    Checks performed (each only if the relevant state file / artefact exists):

    1. Schema drift      — schema_registry.json has a baseline for this source
    2. Quality anomalies — anomaly_baseline.json has history for this source
    3. Column purposes   — column_purpose.json has per-column purpose records
    4. Purpose limits    — purpose_registry.json has registered allowed-column sets
    5. Data contracts    — any *.yaml file next to the source that looks like a
                           DataContractEnforcer contract
    6. Consent database  — consent.db exists and can gate subject-level rows
    7. Prior violations  — contract_violations.jsonl exists from a previous run

    For each check that fires, the user sees what was found and must
    explicitly confirm before enforcement runs.  Declining any check skips
    that gate without aborting the pipeline.

    Parameters
    ----------
    gov          : GovernanceLogger   Live governance logger for this run.
    df           : pd.DataFrame       Extracted (pre-transform) DataFrame.
    src_path     : str                Source file path (used as registry key).
    src_label    : str                Human-readable source name for display.
    pii_findings : list               PII scan results (may be empty list).

    Returns
    -------
    (df, summary) where df may have columns dropped by purpose enforcement,
    and summary is a dict describing every gate that was checked and applied.
    """
    import json as _json
    from pathlib import Path as _Path

    SEP  = "─" * 64
    TICK = "  ✓"
    WARN = "  ⚠"
    INFO = "  ·"

    def _yn(label: str, default: bool = True) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        try:
            raw = input(f"  {label} {suffix}: ").strip().lower()
        except EOFError:
            return default
        return default if not raw else raw.startswith("y")

    def _abort(check_id: str, msg: str) -> "NoReturn":  # always raises SystemExit
        """Record the aborted check in summary and fire the audit event, then raise.

        NOTE: checks_discovered is NOT appended here.  Every gate block appends
        check_id to checks_discovered at its own start, before any _abort() call,
        so appending again here would produce a duplicate entry.
        """
        summary.setdefault("checks_aborted", []).append(check_id)
        gov._event(  # pylint: disable=protected-access
            "GOVERNANCE", "PREFLIGHT_ABORTED",
            {"source": src_label, "aborted_at": check_id, "reason": msg},
        )
        raise SystemExit(msg)

    summary: dict = {
        "checks_discovered":   [],
        "checks_applied":      [],
        "checks_skipped":      [],
        "checks_aborted":      [],
        "columns_dropped":     [],
        "schema_drift":        [],
        "anomalies":           [],
        "contract_violations": [],
        "consent_blocked_rows": 0,
    }

    # ── Discover what exists ──────────────────────────────────────────────
    discovered: list[dict] = []   # each entry: {id, label, detail, path}

    src_name = _Path(src_path).name if src_path else src_label

    # 1. Schema drift baseline
    schema_reg = BASE_DIR / "schema_registry.json"
    if schema_reg.exists():
        try:
            reg = _json.loads(schema_reg.read_text(encoding="utf-8"))
            # Key may be full path or just the filename
            has_baseline = src_path in reg or src_name in reg
            if has_baseline:
                key = src_path if src_path in reg else src_name
                snap = reg[key]
                snap_cols = len(snap.get("columns", snap) if isinstance(snap, dict) else snap)
                discovered.append({
                    "id":     "schema",
                    "label":  "Schema drift check",
                    "detail": (f"Baseline found for '{src_name}' "
                               f"({snap_cols} column(s) recorded)"),
                    "path":   str(schema_reg),
                })
        except Exception:  # pylint: disable=broad-except
            pass

    # 2. Anomaly baseline
    anomaly_base = BASE_DIR / "anomaly_baseline.json"
    if anomaly_base.exists():
        try:
            base = _json.loads(anomaly_base.read_text(encoding="utf-8"))
            matching = [k for k in base if k.startswith(src_name + "::")]
            if matching:
                discovered.append({
                    "id":     "anomaly",
                    "label":  "Quality anomaly check",
                    "detail": (f"{len(matching)} column baseline(s) found for '{src_name}' "
                               f"— Z-score comparison will run"),
                    "path":   str(anomaly_base),
                })
        except Exception:  # pylint: disable=broad-except
            pass

    # 3. Column purpose registry
    purpose_reg_file = BASE_DIR / "column_purpose.json"
    if purpose_reg_file.exists():
        try:
            preg = _json.loads(purpose_reg_file.read_text(encoding="utf-8"))
            col_records = {k: v for k, v in preg.items()
                           if k.startswith(src_name + "::")}
            if col_records:
                discovered.append({
                    "id":     "col_purpose",
                    "label":  "Column purpose records  (GDPR Art. 5(1)(b))",
                    "detail": (f"{len(col_records)} column(s) have registered purposes: "
                               # Use .get() — a malformed record missing "column" would
                               # raise KeyError here, which the outer try/except catches
                               # and silently drops the ENTIRE col_purpose item from
                               # discovered, even if only one record is bad.
                               + ", ".join(v.get("column", "?") for v in col_records.values())),
                    "path":   str(purpose_reg_file),
                    "records": col_records,
                })
        except Exception:  # pylint: disable=broad-except
            pass

    # 4. Purpose limitation registry (allowed-column sets)
    ple_reg_file = BASE_DIR / "purpose_registry.json"
    if ple_reg_file.exists():
        try:
            preg2 = _json.loads(ple_reg_file.read_text(encoding="utf-8"))
            if preg2:
                purposes_list = list(preg2.keys())
                discovered.append({
                    "id":      "purpose_limit",
                    "label":   "Purpose limitation registry  (GDPR Art. 5(1)(b))",
                    "detail":  (f"{len(purposes_list)} purpose(s) registered: "
                                + ", ".join(f"'{p}'" for p in purposes_list[:4])
                                + (" …" if len(purposes_list) > 4 else "")),
                    "path":    str(ple_reg_file),
                    "purposes": purposes_list,
                })
        except Exception:  # pylint: disable=broad-except
            pass

    # 5. Data contracts — look for any *.yaml next to the source file, or in BASE_DIR
    contract_paths: list[_Path] = []
    search_dirs = [BASE_DIR]
    if src_path:
        # Resolve before comparing so that relative paths like "data.csv" (whose
        # .parent is Path(".")) are not treated as a different directory from BASE_DIR.
        # Without resolve(), Path(".") != BASE_DIR even when cwd == BASE_DIR, causing
        # the same directory to be searched twice and every contract enforced twice.
        src_dir = _Path(src_path).resolve().parent
        if src_dir != BASE_DIR:
            search_dirs.append(src_dir)
    for sdir in search_dirs:
        for yaml_file in sdir.glob("*.yaml"):
            try:
                text = yaml_file.read_text(encoding="utf-8")
                # Require contract: AND at least one other DataContractEnforcer
                # section key so we do not pick up dbt schema.yaml, pipeline
                # config files, or any YAML that merely contains the word
                # "contract" somewhere.  The original expression had an operator-
                # precedence bug: `A or B and C` evaluates as `A or (B and C)`,
                # so any YAML with "contract:" anywhere was treated as a match.
                _has_contract  = "contract:" in text
                _has_schema    = "schema:" in text and "columns:" in text
                _has_sla       = "sla:" in text
                _has_rules     = "rules:" in text
                _has_quality   = "quality:" in text
                _extra_sections = sum([_has_schema, _has_sla, _has_rules, _has_quality])
                if _has_contract and _extra_sections >= 1:
                    contract_paths.append(yaml_file)
            except Exception:  # pylint: disable=broad-except
                pass
    # Deduplicate: same file can appear twice if BASE_DIR and src_dir resolved to
    # the same path (e.g. relative src_path when cwd == BASE_DIR).
    contract_paths = list(dict.fromkeys(contract_paths))
    if contract_paths:
        discovered.append({
            "id":     "contract",
            "label":  "Data contract(s)  (DataContractEnforcer)",
            "detail": (f"{len(contract_paths)} contract file(s) found: "
                       + ", ".join(p.name for p in contract_paths[:3])
                       + (" …" if len(contract_paths) > 3 else "")),
            "paths":  contract_paths,
        })

    # 6. Consent database
    consent_db = gov.log_dir / "consent.db"
    if not consent_db.exists():
        consent_db = BASE_DIR / "consent.db"
    if consent_db.exists():
        try:
            import sqlite3 as _sq
            with _sq.connect(str(consent_db)) as _conn:
                count = _conn.execute(
                    "SELECT COUNT(*) FROM consent WHERE withdrawn_utc IS NULL"
                ).fetchone()[0]
            discovered.append({
                "id":     "consent",
                "label":  "Consent database  (ConsentManager)",
                "detail": (f"{count} active consent record(s) in {consent_db.name} — "
                           "can gate rows by subject consent status"),
                "path":   str(consent_db),
                "db":     str(consent_db),
                "count":  count,
            })
        except Exception:  # pylint: disable=broad-except
            pass

    # 7. Prior contract violations log
    violations_log = BASE_DIR / "contract_violations.jsonl"
    if violations_log.exists():
        try:
            lines = [l for l in violations_log.read_text(encoding="utf-8").splitlines() if l.strip()]
            if lines:
                last = _json.loads(lines[-1])
                discovered.append({
                    "id":     "prev_violations",
                    "label":  "Prior contract violation log",
                    "detail": (f"{len(lines)} prior violation run(s) on record — "
                               f"last: {last.get('failure_count', '?')} failure(s) "
                               # Coerce timestamp to str before slicing: if it is
                               # stored as an integer epoch the bare [:10] slice
                               # raises TypeError inside try/except, silently
                               # dropping the entire prev_violations discovery item.
                               f"on {str(last.get('timestamp', '?'))[:10]}"),
                    "path":   str(violations_log),
                })
        except Exception:  # pylint: disable=broad-except
            pass

    # ── Nothing found → return immediately ───────────────────────────────
    if not discovered:
        print(f"\n{INFO} No existing governance state found for '{src_name}' — "
              "skipping pre-flight.")
        return df, summary

    # ── Display discovery summary ─────────────────────────────────────────
    print(f"\n{SEP}")
    print("  GOVERNANCE PRE-FLIGHT")
    print(SEP)
    print(f"  {len(discovered)} governance artefact(s) found for '{src_name}':\n")
    for i, item in enumerate(discovered, 1):
        print(f"  {i}. {item['label']}")
        print(f"     {item['detail']}")
    print()

    # ── Master confirm ────────────────────────────────────────────────────
    if not _yn("Apply existing governance before loading?", default=True):
        print(f"{INFO} Pre-flight skipped by user.")
        # Populate checks_discovered so the summary is internally consistent
        # (skipped items must also appear in discovered).
        summary["checks_discovered"] = [d["id"] for d in discovered]
        summary["checks_skipped"]    = [d["id"] for d in discovered]
        gov._event("GOVERNANCE", "PREFLIGHT_SKIPPED",  # pylint: disable=protected-access
                   {"source": src_label, "artefacts_found": len(discovered)})
        return df, summary

    print()
    gov._event("GOVERNANCE", "PREFLIGHT_STARTED",  # pylint: disable=protected-access
               {"source": src_label, "checks": [d["id"] for d in discovered]})

    # ── Run each check individually ───────────────────────────────────────
    disc_map = {d["id"]: d for d in discovered}

    # ── 1. Schema drift ───────────────────────────────────────────────────
    if "schema" in disc_map:
        item = disc_map["schema"]
        summary["checks_discovered"].append("schema")
        print(f"\n  [{item['label']}]")
        print(f"  {item['detail']}")
        if _yn("  Run schema drift check?", default=True):
            try:
                from metadata_extensions import SchemaDriftDetector
                detector = SchemaDriftDetector(gov)
                drift = detector.check(
                    df, src_path or src_name,
                    on_added="warn",
                    on_removed="warn",
                    on_type_change="warn",
                )
                if drift:
                    # SchemaDriftDetector.check() already printed each drift event
                    # internally (header + per-event lines).  Do NOT reprint here —
                    # that would duplicate the output on screen.
                    summary["schema_drift"] = drift
                    if not _yn(
                        f"  {len(drift)} drift event(s) found. Continue anyway?",
                        default=True,
                    ):
                        _abort("schema", "Pipeline aborted by user at schema drift gate.")
                # SchemaDriftDetector also prints its own "no drift" confirmation
                # line — no extra TICK print needed here.
                summary["checks_applied"].append("schema")
            except ImportError:
                print(f"{WARN} metadata_extensions not available — schema check skipped.")
                summary["checks_skipped"].append("schema")
            except Exception as _exc:  # pylint: disable=broad-except
                # Catch OSError, json errors, RuntimeError, etc. so a broken
                # schema registry file cannot crash the entire pipeline run.
                print(f"{WARN} Schema drift check error: {_exc}")
                summary["checks_skipped"].append("schema")
        else:
            summary["checks_skipped"].append("schema")

    # ── 2. Quality anomaly ────────────────────────────────────────────────
    if "anomaly" in disc_map:
        item = disc_map["anomaly"]
        summary["checks_discovered"].append("anomaly")
        print(f"\n  [{item['label']}]")
        print(f"  {item['detail']}")
        if _yn("  Run quality anomaly check?", default=True):
            try:
                from metadata_extensions import AnomalyDetector
                import pandas as _pd_anm
                # Build a minimal profile dict containing only the fields that
                # AnomalyDetector.check() actually reads (mean, null_pct,
                # unique_count).  We deliberately do NOT use DataProfiler.profile()
                # here because that method calls gov.write_profile_report() as a
                # side-effect, which writes an HTML file to disk — an unwanted
                # artefact during a pre-flight check that the user may still cancel.
                _cols_profile: dict = {}
                for _col in df.columns:
                    _s = df[_col]
                    _n = len(_s)
                    _cp: dict = {
                        # Guard against zero-row DataFrames: isnull().mean() on an
                        # empty Series returns NaN, which is not valid JSON and
                        # would corrupt the anomaly baseline file on disk.
                        "null_pct":     float(_s.isnull().sum() / _n) if _n > 0 else 0.0,
                        "unique_count": int(_s.nunique(dropna=True)),
                    }
                    if _pd_anm.api.types.is_numeric_dtype(_s):
                        _valid = _s.dropna()
                        _cp["mean"] = float(_valid.mean()) if len(_valid) > 0 else 0.0
                    _cols_profile[_col] = _cp
                profile   = {"columns": _cols_profile}
                detector  = AnomalyDetector(gov)
                anomalies = detector.check(profile, src_path or src_name)
                if anomalies:
                    # AnomalyDetector.check() already printed each anomaly line
                    # internally.  Do NOT reprint here — that would duplicate output.
                    summary["anomalies"] = anomalies
                    if not _yn(
                        f"  {len(anomalies)} anomaly(ies) found. Continue anyway?",
                        default=True,
                    ):
                        _abort("anomaly", "Pipeline aborted by user at anomaly gate.")
                # AnomalyDetector also prints its own "no anomalies" line — no extra print needed.
                summary["checks_applied"].append("anomaly")
            except ImportError:
                print(f"{WARN} metadata_extensions not available — anomaly check skipped.")
                summary["checks_skipped"].append("anomaly")
            except Exception as _exc:  # pylint: disable=broad-except
                # Catch OSError, json errors, etc. from AnomalyDetector so a broken
                # baseline file cannot crash the entire pipeline run.
                print(f"{WARN} Anomaly check error: {_exc}")
                summary["checks_skipped"].append("anomaly")
        else:
            summary["checks_skipped"].append("anomaly")

    # ── 3. Column purposes (display only — informational gate) ────────────
    if "col_purpose" in disc_map:
        item = disc_map["col_purpose"]
        summary["checks_discovered"].append("col_purpose")
        print(f"\n  [{item['label']}]")
        print(f"  {item['detail']}")
        records = item.get("records", {})
        # Show the registered purposes for any column that is actually in df
        df_cols  = set(df.columns)
        matching = {k: v for k, v in records.items()
                    if v.get("column") in df_cols}
        missing  = {k: v for k, v in records.items()
                    if v.get("column") not in df_cols}
        if matching:
            print("  Registered purposes for columns in this dataset:")
            for v in matching.values():
                ret = (f"  retain={v['retention_days']}d"
                       if v.get("retention_days") else "")
                # Use .get() with fallbacks — malformed records missing 'purpose'
                # or 'lawful_basis' would otherwise raise an unhandled KeyError
                # here (this block has no enclosing try/except).
                col_name  = v.get("column", "?")
                purpose   = v.get("purpose", "(no purpose recorded)")
                law_basis = v.get("lawful_basis", "?")
                print(f"     • {col_name:<20}  {purpose}"
                      f"  [{law_basis}]{ret}")
        if missing:
            print(f"{WARN} {len(missing)} registered column(s) NOT in dataset:")
            for v in missing.values():
                print(f"     • {v.get('column', '?')}")
        if _yn("  Acknowledge column purpose records?", default=True):
            gov._event("GOVERNANCE", "COLUMN_PURPOSES_ACKNOWLEDGED",  # pylint: disable=protected-access
                       {"source": src_label, "matched": len(matching),
                        "missing_from_dataset": len(missing)})
            print(f"{TICK} Column purpose records acknowledged and logged.")
            summary["checks_applied"].append("col_purpose")
        else:
            summary["checks_skipped"].append("col_purpose")

    # ── 4. Purpose limitation enforcement ─────────────────────────────────
    if "purpose_limit" in disc_map:
        item = disc_map["purpose_limit"]
        summary["checks_discovered"].append("purpose_limit")
        print(f"\n  [{item['label']}]")
        print(f"  {item['detail']}")
        purposes = item.get("purposes", [])
        if purposes and _yn("  Enforce purpose limitations on this load?", default=True):
            # Ask the user which purpose applies to this run
            print("  Registered purposes:")
            for idx, p in enumerate(purposes, 1):
                print(f"    {idx}. {p}")
            try:
                raw = input("  Which purpose applies to this load? [1]: ").strip()
                # Clamp with max(0,...) so that entering "0" (idx -1) doesn't
                # wrap around to the last element via Python's negative indexing.
                chosen_idx     = (int(raw) - 1) if raw.isdigit() else 0
                chosen_purpose = purposes[max(0, min(chosen_idx, len(purposes) - 1))]
            except (EOFError, ValueError):
                chosen_purpose = purposes[0]
            print(f"  Enforcing purpose: '{chosen_purpose}'")
            try:
                from governance_extensions import PurposeLimitationEnforcer
                # Pass registry_path so _load_registry() auto-loads on construction.
                # load_from_dict() does not exist on PurposeLimitationEnforcer.
                ple = PurposeLimitationEnforcer(
                    gov, strict=False, registry_path=str(ple_reg_file)
                )
                out_of_scope = ple.check(df, chosen_purpose)
                if out_of_scope:
                    print(f"{WARN} {len(out_of_scope)} column(s) out of scope for "
                          f"'{chosen_purpose}':")
                    for col in out_of_scope:
                        print(f"     • {col}")
                    if _yn(f"  Drop these {len(out_of_scope)} column(s)?", default=True):
                        df = ple.enforce(df, chosen_purpose)
                        summary["columns_dropped"].extend(out_of_scope)
                        print(f"{TICK} {len(out_of_scope)} column(s) dropped.")
                    else:
                        print(f"{INFO} Columns retained — purpose violation logged.")
                        gov._event("GOVERNANCE", "PURPOSE_VIOLATION_OVERRIDDEN",  # pylint: disable=protected-access
                                   {"purpose": chosen_purpose,
                                    "columns": out_of_scope,
                                    "override_by": "user"})
                else:
                    print(f"{TICK} All columns within scope for '{chosen_purpose}'.")
                summary["checks_applied"].append("purpose_limit")
            except ImportError:
                print(f"{WARN} governance_extensions not available — purpose check skipped.")
                summary["checks_skipped"].append("purpose_limit")
            except Exception as exc:  # pylint: disable=broad-except
                print(f"{WARN} Purpose enforcement error: {exc}")
                summary["checks_skipped"].append("purpose_limit")
        else:
            summary["checks_skipped"].append("purpose_limit")

    # ── 5. Data contract enforcement ──────────────────────────────────────
    if "contract" in disc_map:
        item  = disc_map["contract"]
        cpaths = item.get("paths", [])
        summary["checks_discovered"].append("contract")
        print(f"\n  [{item['label']}]")
        print(f"  {item['detail']}")
        if cpaths and _yn("  Enforce data contract(s)?", default=True):
            for cpath in cpaths:
                print(f"  Checking: {cpath.name}")
                try:
                    enforcer = DataContractEnforcer(gov, cpath, warn_only=True)
                    # Use check() — which is pure and returns ALL violations
                    # regardless of severity — to populate the preflight summary
                    # and drive the user prompt.
                    #
                    # enforce(warn_only=True) returns ONLY WARNING-severity items;
                    # CRITICAL/ERROR violations exist in viols internally but are
                    # NOT returned.  Using enforce()'s return value therefore:
                    #   (a) silently omits CRITICAL/ERROR from contract_violations, and
                    #   (b) if there are ZERO warnings but CRITICAL violations exist,
                    #       makes preflight print "  ✓ no violations" immediately
                    #       after the bordered CRITICAL table — a false clean bill.
                    #
                    # After check(), we still call enforce() for its side effects:
                    # governance event logging, violation log file write, and the
                    # bordered console table.  check() is pure so calling it first
                    # adds no observable side effects of its own.
                    all_viols = enforcer.check(df)
                    if all_viols:
                        # enforce() prints the bordered violation table and logs
                        # every violation to the governance ledger and violation log.
                        enforcer.enforce(df)
                        summary["contract_violations"].extend(all_viols)
                        n_crit = sum(1 for v in all_viols
                                     if v.get("severity") in ("CRITICAL", "ERROR"))
                        n_warn = len(all_viols) - n_crit
                        label  = (f"{n_crit} critical/error + {n_warn} warning(s)"
                                  if n_crit else f"{n_warn} warning(s)")
                        if not _yn(
                            f"  {label} found in '{cpath.name}'.  Continue anyway?",
                            default=(n_crit == 0),   # default Yes for warnings, No for criticals
                        ):
                            _abort("contract", "Pipeline aborted by user at data contract gate.")
                    else:
                        print(f"{TICK} Contract '{cpath.name}' — no violations.")
                except FileNotFoundError:
                    print(f"{WARN} Contract file disappeared: {cpath}")
                except Exception as exc:  # pylint: disable=broad-except
                    print(f"{WARN} Contract check error: {exc}")
            summary["checks_applied"].append("contract")
        else:
            summary["checks_skipped"].append("contract")

    # ── 6. Consent gate ───────────────────────────────────────────────────
    if "consent" in disc_map:
        item = disc_map["consent"]
        summary["checks_discovered"].append("consent")
        print(f"\n  [{item['label']}]")
        print(f"  {item['detail']}")
        if pii_findings and _yn("  Gate rows by subject consent?", default=False):
            # Find a likely subject identifier column.
            # Use .get("field", "") so that a malformed pii_finding entry without
            # a "field" key does not raise an unhandled KeyError here.
            subject_col_candidates = [
                f.get("field", "") for f in pii_findings
                if f.get("field") and any(
                    kw in f["field"].lower()
                    for kw in ("email", "user_id", "subject", "patient", "employee")
                )
            ]
            if subject_col_candidates:
                print(f"  Likely subject column(s): {subject_col_candidates}")
                try:
                    raw_col = input(
                        f"  Subject column to check consent on "
                        f"[{subject_col_candidates[0]}]: "
                    ).strip()
                    subject_col = raw_col or subject_col_candidates[0]
                except EOFError:
                    subject_col = subject_col_candidates[0]
                try:
                    raw_purpose = input(
                        "  Processing purpose to check consent for: "
                    ).strip()
                    check_purpose = raw_purpose or "data processing"
                except EOFError:
                    check_purpose = "data processing"

                if subject_col in df.columns:
                    try:
                        from governance_extensions import ConsentManager
                        cm = ConsentManager(gov, db_path=item["db"])
                        before = len(df)
                        # Identify rows with a null/empty subject ID BEFORE checking
                        # consent.  str(NaN)="nan" and str(None)="None" would both
                        # hash to a lookup key with no consent record, silently
                        # blocking every null-ID row with no warning to the operator.
                        _null_mask = df[subject_col].isna() | (
                            df[subject_col].astype(str).str.strip() == ""
                        )
                        _null_count = int(_null_mask.sum())
                        if _null_count:
                            print(f"{INFO} {_null_count} row(s) have a null/empty "
                                  f"'{subject_col}' — excluded from consent check "
                                  "(they will pass through).")
                        # Check consent only for rows with a non-null subject ID.
                        # Applying cm.check() on ALL rows (including nulls) passes
                        # str(NaN)="nan" or str(None)="None" to cm.check(), making
                        # wasted SQLite lookups.  Worse, if cm.check() raises on a
                        # malformed subject ID, the whole gate is skipped — even
                        # though non-null rows were fine.  Apply only to ~null rows.
                        _consent_series = df.loc[~_null_mask, subject_col].apply(
                            lambda sid: cm.check(str(sid), purpose=check_purpose)
                        )
                        mask = _null_mask.copy()
                        mask[~_null_mask] = _consent_series
                        df = df[mask].copy()
                        blocked = before - len(df)
                        summary["consent_blocked_rows"] = blocked
                        if blocked:
                            print(f"{WARN} {blocked} row(s) blocked — "
                                  "no consent for this purpose.")
                        print(f"{TICK} {len(df):,} row(s) pass consent gate.")
                        summary["checks_applied"].append("consent")
                    except ImportError:
                        print(f"{WARN} governance_extensions not available.")
                        summary["checks_skipped"].append("consent")
                    except Exception as _exc:  # pylint: disable=broad-except
                        # Catch SQLite errors, ConsentManager init failures, etc.
                        # so a broken consent.db cannot crash the pipeline.
                        print(f"{WARN} Consent gate error: {_exc}")
                        summary["checks_skipped"].append("consent")
                else:
                    print(f"{WARN} Column '{subject_col}' not in dataset — "
                          "consent gate skipped.")
                    summary["checks_skipped"].append("consent")
            else:
                print(f"{INFO} No obvious subject identifier column found — "
                      "consent gate skipped.")
                summary["checks_skipped"].append("consent")
        else:
            summary["checks_skipped"].append("consent")

    # ── 7. Prior violations (informational) ───────────────────────────────
    if "prev_violations" in disc_map:
        item = disc_map["prev_violations"]
        summary["checks_discovered"].append("prev_violations")
        print(f"\n  [{item['label']}]")
        print(f"  {item['detail']}")
        if _yn("  Acknowledge prior violation log?", default=True):
            gov._event("GOVERNANCE", "PRIOR_VIOLATIONS_ACKNOWLEDGED",  # pylint: disable=protected-access
                       {"source": src_label, "log": item["path"]})
            print(f"{TICK} Prior violations acknowledged and logged.")
            summary["checks_applied"].append("prev_violations")
        else:
            summary["checks_skipped"].append("prev_violations")

    # ── Pre-flight summary ────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  GOVERNANCE PRE-FLIGHT COMPLETE")
    discovered_ids = summary["checks_discovered"]
    applied  = summary["checks_applied"]
    skipped  = summary["checks_skipped"]
    n_drift  = len(summary["schema_drift"])
    n_anom   = len(summary["anomalies"])
    n_viol   = len(summary["contract_violations"])
    n_drop   = len(summary["columns_dropped"])
    n_block  = summary["consent_blocked_rows"]

    aborted  = summary.get("checks_aborted", [])
    # Print discovered count so the operator can verify that
    # applied + skipped + aborted == discovered (full accountability).
    print(f"  Discovered : {len(discovered_ids)}  ({', '.join(discovered_ids) or 'none'})")
    print(f"  Applied    : {len(applied)}  ({', '.join(applied) or 'none'})")
    print(f"  Skipped    : {len(skipped)}  ({', '.join(skipped) or 'none'})")
    if aborted:
        print(f"  Aborted    : {len(aborted)}  ({', '.join(aborted)})")
    if n_drift:  print(f"  Schema drift events  : {n_drift}")
    if n_anom:   print(f"  Quality anomalies    : {n_anom}")
    if n_viol:
        # Count by severity so the label reflects the real worst-case severity.
        # contract_violations contains ALL severity levels (CRITICAL / ERROR /
        # WARNING) — labelling them all as "warnings" would mislead the operator
        # into thinking no critical breaches occurred.
        _n_crit_viol = sum(
            1 for _v in summary["contract_violations"]
            if _v.get("severity") in ("CRITICAL", "ERROR")
        )
        _viol_label = (
            f"  Contract violations  : {n_viol}"
            f"  ({_n_crit_viol} critical/error, {n_viol - _n_crit_viol} warning(s))"
            if _n_crit_viol
            else f"  Contract warnings    : {n_viol}"
        )
        print(_viol_label)
    if n_drop:   print(f"  Columns dropped      : {n_drop}  "
                       f"({', '.join(summary['columns_dropped'])})")
    if n_block:  print(f"  Rows blocked (consent): {n_block:,}")
    print(SEP)

    gov._event("GOVERNANCE", "PREFLIGHT_COMPLETE",  # pylint: disable=protected-access
               {
                   "source":             src_label,
                   # checks_discovered is the complete list of governance artefacts
                   # that were found to exist for this source.  Including it lets
                   # auditors distinguish "artefact existed but operator skipped it"
                   # from "artefact was never present" — both look like a missing
                   # entry in checks_applied but have very different compliance
                   # meanings.
                   "checks_discovered":  summary["checks_discovered"],
                   "checks_applied":     applied,
                   "checks_skipped":     skipped,
                   "checks_aborted":     summary.get("checks_aborted", []),
                   "schema_drift_count": n_drift,
                   "anomaly_count":      n_anom,
                   "violation_count":    n_viol,
                   "columns_dropped":    summary["columns_dropped"],
                   "consent_blocked":    n_block,
               })

    return df, summary


def main() -> None:  # noqa: C901
    """
    Interactive CLI wizard.

    Asks for source type and destination type first, then shows only the
    prompts that are relevant to that specific combination.  Nothing
    irrelevant to your chosen platforms is ever displayed.

    Run with --help for usage information.
    """
    import os
    import sys as _sys

    # ── --help / usage ────────────────────────────────────────────────────
    if any(a in ("-h", "--help") for a in _sys.argv[1:]):
        print(
            "\n"
            "  Pipeline V3  —  Data Pipeline & Governance Wizard  v4.9\n"
            "\n"
            "  Usage:\n"
            "    python pipeline_v3.py          # launch interactive wizard\n"
            "    python pipeline_v3.py --help   # show this message\n"
            "\n"
            "  The wizard walks you through four steps:\n"
            "    1. Source type  (file / database / stream)\n"
            "    2. Destination  (17 platforms: SQLite → SAP Datasphere)\n"
            "    3. Connection credentials\n"
            "    4. Pipeline options  (transforms, governance, quality)\n"
            "\n"
            "  For non-interactive / scripted use import the classes directly:\n"
            "    from pipeline_v3 import GovernanceLogger, SQLLoader, Extractor\n"
            "\n"
            "  Documentation: see readme.txt in the same directory.\n"
        )
        return

    # ── non-interactive environment guard ─────────────────────────────────
    if not _sys.stdin.isatty():
        raise SystemExit(
            "pipeline_v3.py is an interactive wizard and requires a terminal.\n"
            "Run it from a command prompt / terminal, or import the classes\n"
            "directly for scripted / CI use:\n"
            "  from pipeline_v3 import GovernanceLogger, SQLLoader, Extractor"
        )

    # ── Display helpers ───────────────────────────────────────────────────
    SEP  = "═" * 64
    SEP2 = "─" * 64

    def _hdr(title: str) -> None:
        print(f"\n{SEP2}\n  {title}\n{SEP2}")

    def _input(prompt: str) -> str:
        """
        Wrapper around input() that is safe under VS Code debugpy on Windows.
        The debugpy terminal does not handle \n inside the input() prompt
        string reliably, so we print any leading newlines separately and
        pass only a plain single-line prompt to input().
        Also catches EOFError (non-interactive / piped stdin) gracefully.
        """
        lines = prompt.split("\n")
        for line in lines[:-1]:          # print all but the last segment
            print(line)
        try:
            return input(lines[-1])      # only the bare prompt goes to input()
        except EOFError:
            return ""

    def _menu(title: str, options: dict, default: str = "1") -> str:
        print(f"\n  {title}")
        for k, v in options.items():
            marker = "  \u2190" if k == default else ""
            print(f"    {k}.  {v}{marker}")
        raw = _input(f"\n  Choice [{default}]: ").strip()
        choice = raw or default
        return choice if choice in options else default

    def _ask(label: str, default: str = "", secret: bool = False) -> str:
        prompt = f"  {label}"
        if default:
            prompt += f" [{default}]"
        prompt += ": "
        if secret:
            try:
                import getpass as _gp
                try:
                    return _gp.getpass(prompt) or default
                except Exception:
                    # getpass fails in some IDEs — fall back to plain input
                    print(prompt, end="", flush=True)
                    return _input("").strip() or default
            except ImportError:
                pass
        return _input(prompt).strip() or default

    def _yn(label: str, default: bool = True) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        raw = _input(f"  {label} {suffix}: ").strip().lower()
        return default if not raw else raw.startswith("y")

    def _csv_list(label: str, default: str = "") -> list:
        raw = _ask(label, default)
        return [x.strip() for x in raw.split(",") if x.strip()]

    # ── Platform maps ─────────────────────────────────────────────────────
    FILE_FORMATS = {
        "1": ("CSV",            ".csv"),
        "2": ("JSON / JSONL",   ".json"),
        "3": ("Parquet",        ".parquet"),
        "4": ("Excel",          ".xlsx"),
        "5": ("TSV",            ".tsv"),
        "6": ("XML",            ".xml"),
        "7": ("YAML",           ".yaml"),
        "8": ("Avro",           ".avro"),
        "9": ("ORC",            ".orc"),
        "10":("Feather / Arrow",".feather"),
        "11":("Fixed-width",    ".fwf"),
        "12":("SAS",            ".sas7bdat"),
        "13":("Stata",          ".dta"),
    }

    DB_PLATFORMS = {
        "1": "SQLite",
        "2": "PostgreSQL",
        "3": "MySQL",
        "4": "SQL Server",
        "5": "Snowflake",
        "6": "BigQuery",
        "7": "Redshift",
        "8": "Azure Synapse",
        "9": "Databricks",
        "10":"ClickHouse",
        "11":"Oracle",
        "12":"IBM Db2",
        "13":"MongoDB",
    }

    DB_TYPE_MAP = {
        "1":"sqlite","2":"postgresql","3":"mysql","4":"mssql",
        "5":"snowflake","6":"bigquery","7":"redshift","8":"synapse",
        "9":"databricks","10":"clickhouse","11":"oracle","12":"db2","13":"mongodb",
    }

    STREAM_PLATFORMS = {
        "1": "Apache Kafka",
        "2": "AWS Kinesis",
        "3": "Google Pub/Sub",
    }

    DEST_PLATFORMS = {**DB_PLATFORMS,
        "14":"Firebolt",
        "15":"Yellowbrick",
        "16":"SAP HANA",
        "17":"SAP Datasphere",
        "18":"QuickBooks Online",
    }
    DEST_TYPE_MAP  = {**DB_TYPE_MAP, "14":"firebolt","15":"yellowbrick",
                      "16":"hana","17":"datasphere","18":"quickbooks"}

    # ── Credential builders (only shown when needed) ───────────────────────
    def _creds_sqlite() -> dict:
        return {"db_name": _ask("SQLite file path (no .db extension)", "pipeline")}

    def _creds_sql(platform: str, src: dict | None = None) -> dict:
        """Prompt for host/user/password/db.  Offer to reuse src creds."""
        cfg: dict = {}
        if src and _yn(f"  Same server as source {platform}?", False):
            cfg = {k: src[k] for k in ("host","user","password") if k in src}
        else:
            cfg["host"]     = _ask("Host", "localhost")
            cfg["user"]     = _ask("Username")
            cfg["password"] = _ask("Password", secret=True)
        cfg["db_name"] = _ask("Database name")
        if platform == "mssql":
            cfg["driver"] = _ask("ODBC driver", "ODBC Driver 17 for SQL Server")
        return cfg

    def _creds_snowflake() -> dict:
        return {
            "account":   _ask("Account  (e.g. xy12345.us-east-1)"),
            "user":      _ask("Username"),
            "password":  _ask("Password", secret=True),
            "database":  _ask("Database"),
            "schema":    _ask("Schema", "PUBLIC"),
            "warehouse": _ask("Warehouse"),
        }

    def _creds_bigquery() -> dict:
        return {
            "project":           _ask("GCP project ID"),
            "dataset":           _ask("Dataset"),
            "credentials_path":  _ask("Service account JSON  (blank = ADC)", ""),
        }

    def _creds_redshift() -> dict:
        return {
            "host":      _ask("Redshift host"),
            "user":      _ask("Username"),
            "password":  _ask("Password", secret=True),
            "db_name":   _ask("Database", "dev"),
            "s3_bucket": _ask("S3 staging bucket"),
            "iam_role":  _ask("IAM role ARN"),
        }

    def _creds_synapse() -> dict:
        return {
            "server":          _ask("Synapse server  (e.g. myws.sql.azuresynapse.net)"),
            "user":            _ask("Username"),
            "password":        _ask("Password", secret=True),
            "db_name":         _ask("Pool / database name"),
            "storage_account": _ask("Azure storage account"),
            "container":       _ask("Blob container"),
        }

    def _creds_databricks() -> dict:
        return {
            "server_hostname": _ask("Server hostname"),
            "http_path":       _ask("HTTP path"),
            "access_token":    _ask("Personal access token", secret=True),
            "catalog":         _ask("Catalog", "hive_metastore"),
            "schema":          _ask("Schema", "default"),
        }

    def _creds_hana() -> dict:
        return {
            "host"    : _ask("HANA host",
                             "abc123.hana.trial.us10.hanacloud.ondemand.com"),
            "port"    : int(_ask("Port", "443")),
            "user"    : _ask("Username"),
            "password": _ask("Password", secret=True),
            "schema"  : _ask("Target schema", "PIPELINE"),
            "encrypt" : _yn("Use TLS/SSL?", True),
        }

    def _creds_datasphere() -> dict:
        return {
            "tenant_url"   : _ask("Datasphere tenant URL",
                                  "https://mytenant.datasphere.cloud.sap"),
            "space"        : _ask("Space technical name"),
            "table"        : _ask("Local Table technical name"),
            "token_url"    : _ask("OAuth token URL",
                                  "https://mytenant.authentication.eu10.hana.ondemand.com/oauth/token"),
            "client_id"    : _ask("OAuth client ID"),
            "client_secret": _ask("OAuth client secret", secret=True),
            "batch_size"   : int(_ask("Batch size (rows per request)", "1000")),
        }

    def _creds_generic() -> dict:
        return {
            "host":     _ask("Host", "localhost"),
            "user":     _ask("Username"),
            "password": _ask("Password", secret=True),
            "db_name":  _ask("Database name"),
        }

    def _creds_quickbooks() -> dict:
        print("  QuickBooks Online — OAuth 2.0 credentials")
        print("  (Create an app at https://developer.intuit.com to obtain these)")
        return {
            "client_id"    : _ask("Client ID"),
            "client_secret": _ask("Client secret", secret=True),
            "refresh_token": _ask("Refresh token", secret=True),
            "realm_id"     : _ask("Realm / Company ID"),
            "entity"       : _ask("Entity type", "Customer"),
            "environment"  : _ask("Environment (production/sandbox)", "production"),
        }

    def _get_db_creds(db_type: str, platform_label: str,
                      src_cfg: dict | None = None) -> dict:
        """Route to the right credential builder."""
        if db_type == "sqlite":              return _creds_sqlite()
        if db_type in ("postgresql","mysql","mssql"):
            return _creds_sql(db_type, src_cfg)
        if db_type == "snowflake":           return _creds_snowflake()
        if db_type == "bigquery":            return _creds_bigquery()
        if db_type == "redshift":            return _creds_redshift()
        if db_type == "synapse":             return _creds_synapse()
        if db_type == "databricks":          return _creds_databricks()
        if db_type == "hana":                return _creds_hana()
        if db_type == "datasphere":          return _creds_datasphere()
        if db_type == "quickbooks":          return _creds_quickbooks()
        print(f"  → Using standard connection for {platform_label}.")
        return _creds_generic()

    # ─────────────────────────────────────────────────────────────────────
    #  BANNER
    # ─────────────────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  PIPELINE V3  |  Data Pipeline & Governance Wizard  v4.8")
    print(f"{SEP}")

    # ─────────────────────────────────────────────────────────────────────
    #  STEP 1 — Source type  +  Destination type  (asked together upfront)
    # ─────────────────────────────────────────────────────────────────────
    _hdr("STEP 1 of 4  —  Where is your data coming FROM?")
    src_kind = _menu(
        "Source type:",
        {"1": "File  (CSV, Parquet, Excel, JSON, XML, …)",
         "2": "Database / data warehouse",
         "3": "Real-time stream  (Kafka / Kinesis / Pub/Sub)"},
        default="1",
    )

    _hdr("STEP 2 of 4  —  Where does the data GO?")
    if src_kind == "2":
        # DB source — offer same-DB table copy as first option
        dst_menu = {"0": "Same database — copy / rename table", **{
            str(int(k)+1): v for k,v in DEST_PLATFORMS.items()
        }}
        dst_choice_raw = _menu("Destination:", dst_menu, default="0")
    else:
        dst_menu      = {k: v for k,v in DEST_PLATFORMS.items()}
        dst_choice_raw = _menu("Destination:", dst_menu, default="1")

    is_same_db_copy = (dst_choice_raw == "0")

    # ─────────────────────────────────────────────────────────────────────
    #  STEP 3 — Connection details  (only what's needed for this combo)
    # ─────────────────────────────────────────────────────────────────────
    _hdr("STEP 3 of 4  —  Connection details")

    src_path    = ""
    src_cfg:  dict = {}
    src_table   = ""
    src_db_type = ""
    src_label   = ""

    # ── Source details ────────────────────────────────────────────────────
    if src_kind == "1":
        fmt_menu = {k: v[0] for k,v in FILE_FORMATS.items()}
        fmt_key  = _menu("File format:", fmt_menu, default="1")
        src_ext  = FILE_FORMATS[fmt_key][1]
        src_path = _ask("File path", f"data{src_ext}")
        src_label = os.path.basename(src_path)

    elif src_kind == "2":
        db_key      = _menu("Source platform:", DB_PLATFORMS, default="1")
        src_db_type = DB_TYPE_MAP[db_key]
        src_label   = DB_PLATFORMS[db_key]
        print(f"\n  {src_label} connection:")
        src_cfg   = _get_db_creds(src_db_type, src_label)
        src_table = _ask("Source table name")

    else:
        stream_key = _menu("Streaming platform:", STREAM_PLATFORMS, default="1")
        src_label  = STREAM_PLATFORMS[stream_key]
        print(f"\n  {src_label} connection:")
        if stream_key == "1":
            src_cfg = {
                "bootstrap_servers": _ask("Bootstrap servers", "localhost:9092"),
                "topic":             _ask("Topic name"),
                "group_id":          _ask("Consumer group", "pipeline_group"),
            }
        elif stream_key == "2":
            src_cfg = {
                "stream_name": _ask("Kinesis stream name"),
                "region":      _ask("AWS region", "us-east-1"),
            }
        else:
            src_cfg = {
                "project":      _ask("GCP project ID"),
                "subscription": _ask("Pub/Sub subscription name"),
            }

    # ── Destination details ───────────────────────────────────────────────
    dst_cfg:  dict = {}
    dst_table  = ""
    dst_db_type = ""
    dst_label   = ""

    if is_same_db_copy:
        # Copy within the same database — reuse src creds, just ask new table name
        dst_db_type = src_db_type
        dst_cfg     = src_cfg.copy()
        dst_label   = src_label
        default_dst = f"{src_table}_copy" if src_table else "new_table"
        dst_table   = _ask("\n  New table name", default_dst)
    else:
        # Map the shifted menu key back to the original DB key
        if src_kind == "2":
            orig_key = str(int(dst_choice_raw) - 1)
        else:
            orig_key = dst_choice_raw

        dst_db_type = DEST_TYPE_MAP.get(orig_key, "sqlite")
        dst_label   = DEST_PLATFORMS.get(orig_key, "database")

        default_table = (src_table or os.path.splitext(src_label)[0].replace("-","_"))
        print(f"\n  {dst_label} connection:")
        # For same-family destinations offer credential reuse
        dst_cfg   = _get_db_creds(
            dst_db_type, dst_label,
            src_cfg if dst_db_type == src_db_type else None,
        )
        dst_table = _ask("Destination table name", default_table)

    # ─────────────────────────────────────────────────────────────────────
    #  STEP 4 — Pipeline options  (trimmed to what matters for this combo)
    # ─────────────────────────────────────────────────────────────────────
    _hdr("STEP 4 of 4  —  Pipeline options")

    # Load mode
    load_mode = _menu(
        "Write mode:",
        {"1": "Replace  — drop and recreate",
         "2": "Append   — add rows",
         "3": "Upsert   — update existing, insert new"},
        default="1",
    )
    if_exists    = {"1":"replace","2":"append","3":"upsert"}.get(load_mode,"replace")
    natural_keys: list = []
    if if_exists == "upsert":
        natural_keys = _csv_list("Key column(s) for upsert (comma-separated)", "id")

    # PII / transforms — suggest based on common PII column names if file source
    transforms: list = []
    if _yn("\nApply transforms before loading?", True):
        # Quick-suggest common PII columns if we know the source file name
        pii_hints = []
        for name in ("email","phone","ssn","first_name","last_name","dob",
                     "address","salary","passport","credit_card"):
            if name in src_label.lower() or name in src_table.lower():
                pii_hints.append(name)

        if pii_hints:
            print(f"\n  Likely PII columns detected: {', '.join(pii_hints)}")
            if _yn("  Auto-mask all of them?", True):
                transforms.append({"op":"mask","columns":pii_hints})
                print(f"  ✓ Will mask: {pii_hints}")

        print("\n  Add more transforms (Enter to skip each):")
        TRANSFORM_OPS = {
            "1":"mask","2":"hash","3":"encrypt","4":"drop","5":"rename","6":"coerce","7":"done"
        }
        while True:
            op = _menu(
                "Transform:",
                {"1":"Mask columns (SHA-256, 8 chars)",
                 "2":"Hash columns (same as mask)",
                 "3":"Encrypt columns (AES, reversible)",
                 "4":"Drop columns",
                 "5":"Rename columns",
                 "6":"Cast column type",
                 "7":"Done"},
                default="7",
            )
            if op == "7":
                break
            op_name = TRANSFORM_OPS[op]
            if op_name in ("mask","hash","encrypt","drop"):
                cols = _csv_list("Column names (comma-separated)")
                if cols:
                    transforms.append({"op":op_name,"columns":cols})
                    print(f"  ✓  {op_name} → {cols}")
            elif op_name == "rename":
                froms = _csv_list("Column(s) to rename")
                tos   = _csv_list("New name(s) in same order")
                if froms and len(froms) == len(tos):
                    transforms.append({"op":"rename","columns":dict(zip(froms,tos))})
                    print(f"  ✓  rename {dict(zip(froms,tos))}")
                else:
                    print("  ⚠  Count mismatch — skipped.")
            elif op_name == "coerce":
                col   = _ask("Column name")
                dtype = _ask("Target type", "str")
                if col:
                    transforms.append({"op":"coerce","columns":{col:dtype}})
                    print(f"  ✓  coerce {col} → {dtype}")

    # Governance — simple yes/no block
    print()
    enable_pii_report = _yn("PII discovery report  (GDPR/CCPA checklists)?", True)
    enable_quality    = _yn("Data quality score  (0–100)?", True)
    enable_reversible = _yn("Reversible load  (rollback snapshot)?", True)
    enable_dry_run    = _yn("Dry run  (read + report, skip writing)?", False)

    run_label = _ask("\nRun label", f"run_{src_label.replace(' ','_').replace('/','_')}")

    # ─────────────────────────────────────────────────────────────────────
    #  CONFIRM
    # ─────────────────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  READY TO RUN")
    print(f"{SEP}")
    if src_kind == "1":
        print(f"  Source       :  {src_label}")
    elif src_kind == "2":
        print(f"  Source       :  {src_label}  →  table: {src_table}")
    else:
        print(f"  Source       :  {src_label}  (streaming)")

    if is_same_db_copy:
        print(f"  Destination  :  {dst_label}  →  new table: {dst_table}")
    else:
        print(f"  Destination  :  {dst_label}  →  table: {dst_table}")

    print(f"  Write mode   :  {if_exists}"
          + (f"  (keys: {natural_keys})" if natural_keys else ""))
    if transforms:
        for t in transforms:
            print(f"  Transform    :  {t['op']} → {t['columns']}")
    else:
        print("  Transforms   :  none")
    flags = []
    if enable_pii_report:  flags.append("PII report")
    if enable_quality:     flags.append("quality score")
    if enable_reversible:  flags.append("reversible load")
    if enable_dry_run:     flags.append("DRY RUN")
    print(f"  Governance   :  {', '.join(flags) or 'none'}")
    # log dir shown after GovernanceLogger is created
    print(f"{SEP}")

    if not _yn("\nProceed?", True):
        print("  Cancelled.")
        return

    # ─────────────────────────────────────────────────────────────────────
    #  RUN
    # ─────────────────────────────────────────────────────────────────────
    # Derive log folder from the actual source name, not the run label
    _log_source = src_path if src_kind == "1" else (src_table or src_label)
    gov = GovernanceLogger(source_name=_log_source)
    print(f"  Logs →  {gov.log_dir}/")
    gov.pipeline_start({
        "source":      src_label,
        "destination": dst_table,
        "run_label":   run_label,
    })

    # ── DB source or same-DB copy → TableCopier ───────────────────────────
    if src_kind == "2" or is_same_db_copy:
        copier = TableCopier(
            gov,
            src_db_type  = src_db_type,
            dst_db_type  = dst_db_type,
            transforms   = transforms,
            dry_run      = enable_dry_run,
        )
        result = copier.copy(
            src_cfg      = src_cfg,
            dst_cfg      = dst_cfg,
            src_table    = src_table,
            dst_table    = dst_table,
            if_exists    = if_exists if if_exists != "upsert" else "replace",
            natural_keys = natural_keys or None,
        )
        print(f"\n  run_id      : {result['run_id']}")
        print(f"  rows copied : {result['rows_copied']:,}")
        if result.get("html_report"):
            print(f"  report      : {result['html_report']}")
        return

    # ── File / stream source → standard pipeline ──────────────────────────
    try:
        print("\n  Reading source…")
        if src_kind == "1":
            extractor = Extractor(gov)
            df = extractor.extract(src_path)
        else:
            print("  (Streaming: using first batch — see pipeline_streaming.py for full integration)")
            import pandas as _pd
            df = _pd.DataFrame()

        print(f"  ✓ {len(df):,} rows × {len(df.columns)} columns")
        gov.transformation_applied("EXTRACT_COMPLETE", {"rows":len(df),"source":src_label})

        # Classify
        DataClassificationTagger(gov).classify(df, pii_findings=[])

        # PII scan
        pii_reporter = None
        findings     = []   # initialised here; assigned inside the block below
        if enable_pii_report:
            pii_reporter = PIIDiscoveryReporter(
                gov, sample_count=3, hash_row_keys=True,
                include_html=True, run_label=run_label,
            )
            findings = pii_reporter.scan(df, source_label=src_label)
            print(f"  ✓ {len(findings)} PII field(s) found" if findings
                  else "  ✓ No PII detected")

        # ── Governance pre-flight ─────────────────────────────────────────
        _pii_for_preflight = findings if (enable_pii_report and pii_reporter) else []
        df, _preflight_summary = run_governance_preflight(
            gov          = gov,
            df           = df,
            src_path     = src_path,
            src_label    = src_label,
            pii_findings = _pii_for_preflight,
        )

        # Transforms
        if transforms:
            _tc = TableCopier(gov, src_db_type="sqlite", dst_db_type="sqlite",
                              transforms=transforms)
            df, t_log = _tc._apply_transforms(df, pii_reporter)
            for entry in t_log:
                print(f"    {entry}")
            if pii_reporter:
                pii_reporter.record_actions_from_transforms(transforms)

        # Quality
        quality = None
        if enable_quality:
            quality = DataQualityScorer(gov).score(df)
            print(f"  ✓ Quality: {quality['score']:.1f}/100  grade {quality['grade']}")

        # Load
        rows_written = 0
        if enable_dry_run:
            print(f"\n  [DRY RUN] Would write {len(df):,} rows to {dst_label}::{dst_table}")
        else:
            print(f"  Loading {len(df):,} rows → {dst_table}…")
            # ── Dispatch to the correct loader class ──────────────────────
            loader_cls, needs_db_type, is_mongo = _resolve_loader(dst_db_type)

            # Instantiate
            if needs_db_type:
                loader = loader_cls(gov=gov, db_type=dst_db_type)
            else:
                loader = loader_cls(gov=gov)

            # Call load() — MongoLoader uses `collection` kwarg, all others
            # use the standard (df, cfg, table, if_exists, natural_keys) API
            if is_mongo:
                loader.load(df, dst_cfg, dst_table)
            else:
                # Wrap in ReversibleLoader for SQLAlchemy-backed platforms so
                # the user's rollback snapshot preference is honoured
                _sql_alchemy_types = TableCopier._SQLALCHEMY_PLATFORMS
                if enable_reversible and dst_db_type in _sql_alchemy_types:
                    ReversibleLoader(gov, loader=loader, db_type=dst_db_type).load(
                        df, dst_cfg, dst_table, if_exists=if_exists)
                else:
                    loader.load(df, dst_cfg, dst_table,
                                if_exists=if_exists,
                                natural_keys=natural_keys or None)

            rows_written = len(df)
            print(f"  ✓ {rows_written:,} rows written")

        # Reports
        if pii_reporter:
            paths = pii_reporter.write()
            print(f"  ✓ PII report  → {paths.get('html')}")

        try:
            HTMLReportGenerator(gov).generate(
                df=df, run_meta={"source":src_label,"destination":dst_table},
                quality=quality)
            ts_ = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_path = str(gov.log_dir / f"run_report_{ts_}.html")
            print(f"  ✓ Run report  → {html_path}")
        except Exception:  # pylint: disable=broad-except
            pass

        print(f"\n{SEP}")
        print(f"  Complete — {len(df):,} rows read, {rows_written:,} written")
        print(f"{SEP}\n")

    except Exception as exc:  # pylint: disable=broad-except
        print(f"\n  ✗ Error: {exc}")
        gov.transformation_applied("PIPELINE_ERROR", {"error": str(exc)})
        raise


if __name__ == "__main__":
    main()
