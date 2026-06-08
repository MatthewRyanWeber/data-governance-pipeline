"""
Loader sub-package — lazy dispatch table for all database and file loaders.

Provides ``resolve_loader(db_type)`` which returns the loader class on demand
without importing all SDKs at module load time.

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
"""

import importlib
import logging

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


def resolve_loader(db_type: str) -> tuple[type, bool, bool]:
    """
    Resolve a db_type string to (LoaderClass, needs_db_type_arg, uses_mongo_sig).

    Imports the loader module lazily on first access so that only the
    required SDK is loaded.  Case-insensitive.

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
    return loader_class, needs_db_type, uses_mongo


def supported_db_types() -> list[str]:
    """Return a sorted list of all supported db_type strings."""
    return sorted(_LAZY_DISPATCH.keys())
