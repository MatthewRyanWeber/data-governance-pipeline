"""
Loader sub-package — lazy dispatch table for all database and file loaders.

Provides ``resolve_loader(db_type)`` which returns the loader class on demand
without importing all SDKs at module load time.

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
1.1   2026-06-08   Added validate_loader_config() for parse-time config checks.
1.2   2026-06-09   Upgraded validate_loader_config to raise ConfigValidationError.
1.3   2026-06-11   resolve_loader() now installs a column-name validation guard
                   on every loader's load() so DataFrame columns are checked for
                   SQL-injection characters before any loader builds DDL/MERGE
                   strings.  Rebuilt the required-keys registry per db_type to
                   match what each loader actually reads (snowflake: account,
                   databricks: server_hostname, firebolt: username|client_id,
                   datasphere: tenant_url, mongodb: db_name, etc.).
1.4   2026-06-12   Added verification tiers (core / emulator / cloud) so the
                   catalog states honestly which destinations are exercised
                   against real engines in CI, which against emulators, and
                   which require live credentials.  destination_catalog() and
                   loader_tier() expose the tier to the CLI and REST API.
"""

import functools
import importlib
import logging

from pipeline.exceptions import ConfigValidationError
from pipeline.loaders.base import validate_column_names, validate_sql_identifier

logger = logging.getLogger(__name__)


# Maps db_type string -> (module_path, class_name, needs_db_type_arg, uses_mongo_sig)
# module_path is relative to pipeline.loaders (or pipeline.loaders.vector).
_LAZY_DISPATCH: dict[str, tuple[str, str, bool, bool]] = {
    # Standard SQL (SQLAlchemy-backed) — need db_type in __init__
    "sqlite":      ("pipeline.loaders.sql_loader",       "SQLLoader",              True,  False),
    "postgresql":  ("pipeline.loaders.sql_loader",       "SQLLoader",              True,  False),
    "postgres":    ("pipeline.loaders.sql_loader",       "SQLLoader",              True,  False),
    "mysql":       ("pipeline.loaders.sql_loader",       "SQLLoader",              True,  False),
    "mssql":       ("pipeline.loaders.sql_loader",       "SQLLoader",              True,  False),
    # Tier-1 cloud warehouses
    "snowflake":   ("pipeline.loaders.snowflake_loader", "SnowflakeLoader",        False, False),
    "bigquery":    ("pipeline.loaders.bigquery_loader",  "BigQueryLoader",         False, False),
    "redshift":    ("pipeline.loaders.redshift_loader",  "RedshiftLoader",         False, False),
    "synapse":     ("pipeline.loaders.synapse_loader",   "SynapseLoader",          False, False),
    # Tier-2
    "databricks":  ("pipeline.loaders.databricks_loader","DatabricksLoader",       False, False),
    "clickhouse":  ("pipeline.loaders.clickhouse_loader","ClickHouseLoader",       False, False),
    # Tier-3
    "oracle":      ("pipeline.loaders.oracle_loader",    "OracleLoader",           False, False),
    "db2":         ("pipeline.loaders.db2_loader",       "Db2Loader",              False, False),
    "firebolt":    ("pipeline.loaders.firebolt_loader",  "FireboltLoader",         False, False),
    "yellowbrick": ("pipeline.loaders.yellowbrick_loader","YellowbrickLoader",     False, False),
    # SAP
    "hana":        ("pipeline.loaders.hana_loader",      "HanaLoader",             False, False),
    "datasphere":  ("pipeline.loaders.datasphere_loader","DatasphereLoader",       False, False),
    # NoSQL
    "mongodb":     ("pipeline.loaders.mongo_loader",     "MongoLoader",            False, True),
    # Accounting
    "quickbooks":  ("pipeline.loaders.quickbooks_loader","QuickBooksLoader",       False, False),
    # Vector databases
    "lancedb":     ("pipeline.loaders.vector.lancedb_loader",     "LanceDBLoader",         False, False),
    "pgvector":    ("pipeline.loaders.vector.pgvector_loader",    "PgvectorLoader",        False, False),
    "snowflake_vector": ("pipeline.loaders.vector.snowflake_vector_loader", "SnowflakeVectorLoader", False, False),
    "bigquery_vector":  ("pipeline.loaders.vector.bigquery_vector_loader",  "BigQueryVectorLoader",  False, False),
    "chroma":      ("pipeline.loaders.vector.chroma_loader",     "ChromaLoader",           False, False),
    "milvus":      ("pipeline.loaders.vector.milvus_loader",     "MilvusLoader",           False, False),
    "pinecone":    ("pipeline.loaders.vector.pinecone_loader",   "PineconeLoader",         False, False),
    "weaviate":    ("pipeline.loaders.vector.weaviate_loader",   "WeaviateLoader",         False, False),
    "qdrant":      ("pipeline.loaders.vector.qdrant_loader",     "QdrantLoader",           False, False),
    # File formats & data lakes
    "duckdb":      ("pipeline.loaders.duckdb_loader",    "DuckDBLoader",           False, False),
    "motherduck":  ("pipeline.loaders.duckdb_loader",    "DuckDBLoader",           False, False),
    "parquet":     ("pipeline.loaders.parquet_loader",   "ParquetLoader",          False, False),
    "deltalake":   ("pipeline.loaders.delta_lake_loader","DeltaLakeLoader",        False, False),
    "iceberg":     ("pipeline.loaders.iceberg_loader",   "IcebergLoader",          False, False),
    "s3":          ("pipeline.loaders.s3_loader",        "S3Loader",               False, False),
    "gcs":         ("pipeline.loaders.s3_loader",        "S3Loader",               False, False),
    "azure_blob":  ("pipeline.loaders.s3_loader",        "S3Loader",               False, False),
    "athena":      ("pipeline.loaders.athena_loader",    "AthenaLoader",           False, False),
    "sftp":        ("pipeline.loaders.sftp_loader",      "SFTPLoader",             False, False),
    "fabric":      ("pipeline.loaders.microsoft_fabric_loader", "MicrosoftFabricLoader", False, False),
    "postgis":     ("pipeline.loaders.postgis_loader",   "PostGISLoader",          False, False),
    "cockroachdb": ("pipeline.loaders.cockroachdb_loader","CockroachDBLoader",     False, False),
    # Streaming destinations
    "kafka":       ("pipeline.loaders.kafka_loader",     "KafkaLoader",            False, False),
}


# Verification tier per db_type — the honesty layer of the catalog:
#   core     — exercised against a real engine in CI on every push
#   emulator — mechanics verified against an emulator; vendor-specific
#              behaviour is NOT covered (see tests/integration docs)
#   cloud    — verified only when live credentials are provided via the
#              integration-cloud workflow; otherwise mock-tested only
TIER_CORE = "core"
TIER_EMULATOR = "emulator"
TIER_CLOUD = "cloud"
TIER_EXPERIMENTAL = "experimental"  # wired + mock/contract-tested, no engine proof yet

_VERIFICATION_TIER: dict[str, str] = {
    # Real engine in CI (testcontainers or embedded)
    "sqlite":           TIER_CORE,
    "postgresql":       TIER_CORE,
    "postgres":         TIER_CORE,
    "mysql":            TIER_CORE,
    "mssql":            TIER_CORE,       # real SQL Server container
    "mongodb":          TIER_CORE,
    "duckdb":           TIER_CORE,
    "parquet":          TIER_CORE,
    "deltalake":        TIER_CORE,
    "iceberg":          TIER_CORE,       # pyiceberg + SQLite catalog, fully local
    "s3":               TIER_CORE,       # MinIO
    "azure_blob":       TIER_CORE,       # Azurite
    "kafka":            TIER_CORE,       # Redpanda
    "clickhouse":       TIER_CORE,
    "pgvector":         TIER_CORE,
    "postgis":          TIER_CORE,
    "cockroachdb":      TIER_CORE,
    "sftp":             TIER_CORE,
    "chroma":           TIER_CORE,       # embedded client
    "lancedb":          TIER_CORE,       # embedded
    "qdrant":           TIER_CORE,
    "weaviate":         TIER_CORE,
    "milvus":           TIER_CORE,
    "oracle":           TIER_CORE,       # gvenzl/oracle-free
    "db2":              TIER_CORE,       # db2 community container
    "synapse":          TIER_CORE,       # T-SQL path via real SQL Server
    "yellowbrick":      TIER_CORE,       # PostgreSQL wire-compatible engine
    "fabric":           TIER_CORE,       # Azurite (same ADLS engine as azure_blob)
    # Emulator-verified — mechanics proven, vendor quirks not
    "snowflake":        TIER_EMULATOR,   # fakesnow
    "bigquery":         TIER_EMULATOR,   # goccy/bigquery-emulator
    "pinecone":         TIER_EMULATOR,   # pinecone-local
    # Experimental — wired and mock/contract-tested, but no emulator/engine
    # test actually drives them yet (don't rely on these in production).
    "athena":           TIER_EXPERIMENTAL,
    # Cloud-credential — verified when secrets are provided
    "gcs":              TIER_CLOUD,      # gcsfs (GCS-native API; not S3-compatible)
    "redshift":         TIER_CLOUD,
    "databricks":       TIER_CLOUD,
    "firebolt":         TIER_CLOUD,
    "hana":             TIER_CLOUD,      # HANA Express needs ~8GB locally
    "datasphere":       TIER_CLOUD,
    "motherduck":       TIER_CLOUD,
    "quickbooks":       TIER_CLOUD,      # Intuit developer sandbox
    "snowflake_vector": TIER_CLOUD,
    "bigquery_vector":  TIER_CLOUD,
}


def loader_tier(db_type: str) -> str:
    """
    Return the verification tier ('core', 'emulator', 'cloud') for a db_type.

    Raises ValueError if db_type is not recognised.
    """
    key = db_type.strip().lower()
    if key not in _LAZY_DISPATCH:
        raise ValueError(
            f"Unknown db_type '{db_type}'. "
            f"Known types: {sorted(_LAZY_DISPATCH.keys())}"
        )
    return _VERIFICATION_TIER[key]


def destination_catalog() -> list[dict]:
    """
    Return every supported destination with its verification tier,
    sorted by tier (core first) then name.

    Each entry: {"db_type": str, "loader_class": str, "tier": str}.
    """
    tier_order = {TIER_CORE: 0, TIER_EMULATOR: 1, TIER_CLOUD: 2, TIER_EXPERIMENTAL: 3}
    entries = [
        {
            "db_type": key,
            "loader_class": class_name,
            "tier": _VERIFICATION_TIER[key],
        }
        for key, (_, class_name, _, _) in _LAZY_DISPATCH.items()
    ]
    entries.sort(key=lambda e: (tier_order[e["tier"]], e["db_type"]))
    return entries


def _install_column_name_guard(loader_class: type) -> type:
    """
    Wrap loader_class.load so DataFrame column names are validated before
    the loader runs.

    Roughly ten loaders interpolate df.columns into DDL/MERGE f-strings, so
    a malicious column name is an injection vector everywhere.  Guarding at
    dispatch covers every loader without touching each implementation.
    The wrap is applied to the class once and preserves the original
    signature via functools.wraps, keeping the dispatch contract intact.
    """
    if loader_class.__dict__.get("_column_guard_installed", False):
        return loader_class

    original_load = getattr(loader_class, "load")

    @functools.wraps(original_load)
    def load_with_column_validation(self, df, *args, **kwargs):
        if hasattr(df, "columns"):
            validate_column_names(df, label=loader_class.__name__)
        return original_load(self, df, *args, **kwargs)

    setattr(loader_class, "load", load_with_column_validation)
    setattr(loader_class, "_column_guard_installed", True)
    return loader_class


def resolve_loader(db_type: str) -> tuple[type, bool, bool]:
    """
    Resolve a db_type string to (LoaderClass, needs_db_type_arg, uses_mongo_sig).

    Imports the loader module lazily on first access so that only the
    required SDK is loaded.  Case-insensitive.

    The returned class has its load() wrapped with column-name validation
    so DataFrame columns are injection-checked before any SQL is built.

    Raises ValueError if db_type is not recognised.
    """
    key = db_type.strip().lower()
    if key not in _LAZY_DISPATCH:
        raise ValueError(
            f"Unknown db_type '{db_type}'. "
            f"Known types: {sorted(_LAZY_DISPATCH.keys())}"
        )
    module_path, class_name, needs_db_type, uses_mongo = _LAZY_DISPATCH[key]
    module = importlib.import_module(module_path)
    loader_class = getattr(module, class_name)
    _install_column_name_guard(loader_class)
    tier = _VERIFICATION_TIER[key]
    if tier == TIER_EMULATOR:
        logger.info(
            "Destination '%s' is emulator-verified: loader mechanics are "
            "tested against an emulator in CI; vendor-specific behaviour "
            "is not.", key,
        )
    elif tier == TIER_CLOUD:
        logger.info(
            "Destination '%s' is cloud-credential tier: it is verified "
            "against the live service only when credentials are configured "
            "in the integration-cloud workflow.", key,
        )
    elif tier == TIER_EXPERIMENTAL:
        logger.warning(
            "Destination '%s' is EXPERIMENTAL: wired and mock-tested only — no "
            "emulator or engine test drives it. Do not rely on it in "
            "production until it earns a higher tier.", key,
        )
    return loader_class, needs_db_type, uses_mongo


def supported_db_types() -> list[str]:
    """Return a sorted list of all supported db_type strings."""
    return sorted(_LAZY_DISPATCH.keys())


# ── Config validation ────────────────────────────────────────────────────────

# db_types whose table names are SQL identifiers
_SQL_TYPES: frozenset[str] = frozenset({
    "sqlite", "postgresql", "postgres", "mysql", "mssql",
    "snowflake", "redshift", "synapse", "databricks", "clickhouse",
    "oracle", "db2", "firebolt", "yellowbrick",
    "hana", "datasphere",
    "cockroachdb", "postgis",
})

# Vector db_types that store into SQL-backed tables
_SQL_VECTOR_TYPES: frozenset[str] = frozenset({
    "pgvector", "snowflake_vector", "bigquery_vector",
})

# All vector db_types (SQL-backed + non-SQL)
_VECTOR_TYPES: frozenset[str] = _SQL_VECTOR_TYPES | frozenset({
    "chroma", "milvus", "pinecone", "weaviate", "qdrant", "lancedb",
})

# Required cfg keys per db_type, mirroring what each loader's own
# _validate_config / load() actually demands.  'a|b' means at least one
# of the alternatives must be present.  db_types with no hard config
# requirement (e.g. clickhouse defaults to localhost) are omitted.
_REQUIRED_KEYS: dict[str, list[str]] = {
    "sqlite":           ["db_name"],
    "postgresql":       ["host", "db_name", "user", "password"],
    "postgres":         ["host", "db_name", "user", "password"],
    "mysql":            ["host", "db_name", "user", "password"],
    "mssql":            ["host", "db_name", "user", "password"],
    "snowflake":        ["account", "user", "password", "database", "warehouse"],
    "bigquery":         ["project", "dataset"],
    "redshift":         ["host", "database", "user", "password"],
    "synapse":          ["host", "database"],
    "databricks":       ["server_hostname", "http_path"],
    "oracle":           ["user", "password", "dsn"],
    "db2":              ["host", "user", "password", "database"],
    "firebolt":         ["username|client_id", "database", "account_name", "engine_name"],
    "yellowbrick":      ["host", "database", "user", "password"],
    "hana":             ["host", "user", "password"],
    "datasphere":       ["tenant_url", "token|token_url"],
    "mongodb":          ["db_name"],
    "quickbooks":       ["client_id", "client_secret", "refresh_token", "realm_id"],
    "sftp":             ["host", "username"],
    "s3":               ["bucket"],
    "gcs":              ["bucket"],
    "azure_blob":       ["bucket"],
    "athena":           ["database", "s3_data_dir", "s3_staging_dir"],
    "duckdb":           ["db_path"],
    "motherduck":       ["db_path"],
    "deltalake":        ["path"],
    "iceberg":          ["namespace"],
    "fabric":           ["workspace_id", "lakehouse_id"],
    "postgis":          ["host", "user", "password", "db_name"],
    "cockroachdb":      ["host", "user", "db_name"],
    "kafka":            ["bootstrap_servers"],
    "pgvector":         ["host", "db_name"],
    "snowflake_vector": ["account", "user", "password", "database", "warehouse"],
    "bigquery_vector":  ["project", "dataset"],
    "chroma":           ["id_column"],
    "milvus":           ["uri"],
    "pinecone":         ["api_key", "index_name"],
    "weaviate":         ["url"],
    "qdrant":           ["url|path|memory"],
    "lancedb":          ["db_path|uri"],
}


def validate_loader_config(db_type: str, cfg: dict, table: str = "") -> None:
    """
    Validate loader configuration at parse-time, before loader instantiation.

    Checks that required cfg keys are present and that table names are valid
    SQL identifiers where appropriate.  Raises ValueError on any problem.
    """
    key = db_type.strip().lower()

    if key not in _LAZY_DISPATCH:
        raise ValueError(
            f"Unknown db_type '{db_type}'. "
            f"Known types: {sorted(_LAZY_DISPATCH.keys())}"
        )

    # ── Table name validation ───────────────────────────────────────────
    if table:
        if key in _SQL_TYPES or key in _SQL_VECTOR_TYPES:
            validate_sql_identifier(table, "table")

    # ── Required config keys ────────────────────────────────────────────
    missing: list[str] = []
    for req in _REQUIRED_KEYS.get(key, []):
        if "|" in req:
            alternatives = req.split("|")
            if not any(cfg.get(alt) for alt in alternatives):
                missing.append("|".join(alternatives))
        else:
            if not cfg.get(req):
                missing.append(req)

    if missing:
        raise ConfigValidationError(db_type=db_type, missing_keys=missing)

    logger.debug(
        "Loader config validated for db_type='%s', table='%s'.",
        db_type, table,
    )
