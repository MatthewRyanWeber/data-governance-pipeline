"""
Pipeline-level constants, PII patterns, dependency flags, and run context.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-07   Initial release.
1.1   2026-06-08   Added MAX_DECOMPRESSED_SIZE.
1.2   2026-06-08   Added EventCategory enum for audit event categories.
"""

import enum
import os
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ── Audit event categories ──────────────────────────────────────────────────
# Typed enum prevents typo-induced governance gaps (one misspelled string =
# silent data loss in the audit trail).

class EventCategory(str, enum.Enum):
    LIFECYCLE = "LIFECYCLE"
    TRANSFORMATION = "TRANSFORMATION"
    EXTRACT = "EXTRACT"
    LOAD = "LOAD"
    QUALITY = "QUALITY"
    SCHEMA = "SCHEMA"
    METRICS = "METRICS"
    LINEAGE = "LINEAGE"
    PRIVACY = "PRIVACY"
    CONSENT = "CONSENT"
    RETENTION = "RETENTION"
    VALIDATION = "VALIDATION"
    PROFILING = "PROFILING"
    DLQ = "DLQ"
    INCREMENTAL = "INCREMENTAL"
    RETRY = "RETRY"
    NOTIFICATION = "NOTIFICATION"
    ERROR = "ERROR"
    SLA = "SLA"
    ENCRYPTION = "ENCRYPTION"
    ENRICHMENT = "ENRICHMENT"
    REFERENTIAL = "REFERENTIAL"
    ERASURE = "ERASURE"
    CLASSIFICATION = "CLASSIFICATION"
    TRANSFER = "TRANSFER"
    CHECKPOINT = "CHECKPOINT"
    STANDARDISE = "STANDARDISE"
    RULES = "RULES"


VERSION = "4.34.0"
DEFAULT_CHUNK_SIZE = 50_000

# Safety limit for decompressed archive size (zip bomb protection)
MAX_DECOMPRESSED_SIZE: int = int(
    os.environ.get("PIPELINE_MAX_DECOMPRESSED_SIZE", 1_073_741_824)
)

BASE_DIR = Path(__file__).resolve().parent.parent
WATERMARK_FILE = BASE_DIR / "config" / "pipeline_watermark.json"
CHECKPOINT_FILE = BASE_DIR / "config" / "pipeline_checkpoint.json"
RUN_STATE_DIR = BASE_DIR / "config" / "run_state"

STATE_FILE_LOCK = threading.RLock()


# ── Run context ──────────────────────────────────────────────────────────────
# Replaces the old module-level PIPELINE_ID / RUN_START globals.
# Created once per pipeline invocation and threaded through all classes.

@dataclass
class RunContext:
    pipeline_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_start: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    base_directory: Path = field(default_factory=lambda: BASE_DIR)


def default_run_context() -> RunContext:
    """Factory — each call returns a fresh RunContext with a new pipeline_id."""
    return RunContext()


# Module-level fallback for callers that use ``or DEFAULT_RUN_CONTEXT``.
# Replaced by default_run_context() for new code.
DEFAULT_RUN_CONTEXT = default_run_context()
PIPELINE_ID = DEFAULT_RUN_CONTEXT.pipeline_id
RUN_START = DEFAULT_RUN_CONTEXT.run_start


# ── EU/EEA country codes (GDPR Chapter V cross-border transfer) ─────────────

EU_EEA_COUNTRY_CODES: set[str] = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE", "IS", "LI", "NO",
}

# Countries with EU Adequacy Decisions (GDPR Art. 45) as of 2025
ADEQUATE_COUNTRIES: set[str] = {
    "AD", "AR", "CA", "FO", "GG", "IL", "IM", "JP", "JE", "NZ", "KR",
    "CH", "UY", "UK",
}

CLASSIFICATION_LEVELS = ["RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC"]


# ── PII field-name regex patterns (GDPR Art. 4 / CCPA §1798.140) ────────────
# Pre-compiled for performance — avoids recompilation on every column scan.

_PII_FIELD_PATTERNS_RAW: list[str] = [
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

PII_FIELD_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in _PII_FIELD_PATTERNS_RAW
]

# GDPR Article 9 special-category patterns
_SENSITIVE_CATEGORIES_RAW: set[str] = {
    r"\bhealth", r"\bmedical", r"\brace\b", r"\bethnicity\b",
    r"\breligion", r"\bpolitical", r"\bbiometric", r"\bgenetic",
    r"\bssn\b", r"\bpassport\b",
}

SENSITIVE_CATEGORIES: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in _SENSITIVE_CATEGORIES_RAW
]


# ── Optional dependency flags ────────────────────────────────────────────────
# Each loader does its own import guard, but these flags let the CLI and
# dispatch table check availability without importing the full SDK.
# Uses find_spec to avoid binding unused names (pyflakes clean).

from importlib.util import find_spec as _fs


def _has(*modules: str) -> bool:
    """Return True only if every listed module is importable."""
    try:
        return all(_fs(m) is not None for m in modules)
    except (ModuleNotFoundError, ValueError):
        return False


MISSING: list[str] = []

if not _has("pandas"):
    MISSING.append("pandas")

HAS_GX = _has("great_expectations")
if not HAS_GX:
    MISSING.append("great-expectations")

HAS_DOTENV       = _has("dotenv")
HAS_REQUESTS     = _has("requests")
HAS_CRYPTO       = _has("cryptography")
HAS_PHONENUMBERS = _has("phonenumbers")
HAS_YAML         = _has("yaml")

# Compression formats
HAS_ZSTD = _has("zstandard")
HAS_LZ4  = _has("lz4")

# File formats
HAS_PYARROW = _has("pyarrow")
HAS_AVRO    = _has("fastavro")
HAS_ORC     = _has("pyorc")


# ── Loader-specific dependency flags ────────────────────────────────────────
# Checked by individual loader modules to fail fast at instantiation time.

HAS_SNOWFLAKE   = _has("snowflake.connector")
HAS_REDSHIFT    = _has("redshift_connector")
HAS_BIGQUERY    = _has("google.cloud.bigquery")
HAS_SYNAPSE     = _has("pyodbc", "azure.identity", "azure.storage.blob")
HAS_DATABRICKS  = _has("databricks.sql")
HAS_CLICKHOUSE  = _has("clickhouse_connect")
HAS_ORACLE      = _has("oracledb")
HAS_DB2         = _has("ibm_db", "ibm_db_sa")
HAS_FIREBOLT    = _has("firebolt.db")
HAS_YELLOWBRICK = _has("psycopg2")
HAS_HANA        = _has("hdbcli")
HAS_DATASPHERE  = _has("requests")
HAS_QUICKBOOKS  = _has("requests")
HAS_KAFKA_LOADER = _has("kafka")
HAS_DUCKDB      = _has("duckdb")
HAS_DELTALAKE   = _has("deltalake")
HAS_ICEBERG     = _has("pyiceberg")
HAS_S3          = _has("boto3")
HAS_SFTP        = _has("paramiko")
HAS_FABRIC      = _has("adlfs")
HAS_POSTGIS     = True
HAS_COCKROACH   = _has("sqlalchemy_cockroachdb")
HAS_PGVECTOR    = _has("pgvector")
HAS_CHROMA      = _has("chromadb")
HAS_MILVUS      = _has("pymilvus")
HAS_PINECONE    = _has("pinecone")
HAS_WEAVIATE    = _has("weaviate")
HAS_QDRANT      = _has("qdrant_client")
HAS_LANCEDB     = _has("lancedb")

# OpenTelemetry (optional tracing)
HAS_OTEL = _has("opentelemetry")
