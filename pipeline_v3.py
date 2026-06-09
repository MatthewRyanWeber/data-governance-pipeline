"""
Backward-compatibility shim for pipeline_v3.

.. deprecated:: 4.25.0
    This module will be removed in v5.0. Import directly from the
    ``pipeline`` package instead.

Revision history
────────────────
1.0   2026-06-07   Initial extraction as backward-compat shim.
1.1   2026-06-09   Added deprecation warning (removal planned for v5.0).
"""

import warnings

warnings.warn(
    "pipeline_v3 is deprecated and will be removed in v5.0. "
    "Import directly from the 'pipeline' package instead.",
    DeprecationWarning,
    stacklevel=2,
)

# ── Core classes ─────────────────────────────────────────────────────────────
from pipeline.governance_logger import GovernanceLogger  # noqa: F401
from pipeline.extract import Extractor  # noqa: F401
from pipeline.transform import Transformer  # noqa: F401
from pipeline.profiler import DataProfiler  # noqa: F401
from pipeline.dead_letter_queue import DeadLetterQueue  # noqa: F401
from pipeline.schema_validator import SchemaValidator  # noqa: F401
from pipeline.checkpoint import CheckpointManager  # noqa: F401
from pipeline.type_coercer import TypeCoercer  # noqa: F401
from pipeline.data_standardiser import DataStandardiser  # noqa: F401
from pipeline.business_rules import BusinessRuleEngine  # noqa: F401
from pipeline.data_enricher import DataEnricher  # noqa: F401
from pipeline.referential_integrity import ReferentialIntegrityChecker  # noqa: F401
from pipeline.incremental_filter import IncrementalFilter  # noqa: F401
from pipeline.compression import CompressionHandler  # noqa: F401
from pipeline.secrets_manager import SecretsManager  # noqa: F401

# ── Privacy ──────────────────────────────────────────────────────────────────
from pipeline.privacy.column_encryptor import ColumnEncryptor  # noqa: F401
from pipeline.privacy.classification_tagger import DataClassificationTagger  # noqa: F401
from pipeline.privacy.cross_border_transfer import CrossBorderTransferLogger  # noqa: F401
from pipeline.privacy.erasure_handler import ErasureHandler  # noqa: F401
from pipeline.privacy.pii_discovery import PIIDiscoveryReporter  # noqa: F401

# ── Quality ──────────────────────────────────────────────────────────────────
from pipeline.quality.data_quality_scorer import DataQualityScorer  # noqa: F401
from pipeline.quality.quality_anomaly_alerter import QualityAnomalyAlerter  # noqa: F401
from pipeline.quality.data_diff_reporter import DataDiffReporter  # noqa: F401
from pipeline.quality.schema_evolver import SchemaEvolver  # noqa: F401
from pipeline.quality.data_contract_enforcer import DataContractEnforcer  # noqa: F401
from pipeline.quality.data_contract_enforcer import ContractViolationError  # noqa: F401
from pipeline.quality.synthetic_data_generator import SyntheticDataGenerator  # noqa: F401

# ── Monitoring ───────────────────────────────────────────────────────────────
from pipeline.monitoring.sla_monitor import SLAMonitor  # noqa: F401
from pipeline.monitoring.metrics_collector import MetricsCollector  # noqa: F401
from pipeline.monitoring.notifier import Notifier  # noqa: F401

# ── Reporting ────────────────────────────────────────────────────────────────
from pipeline.reporting.html_report_generator import HTMLReportGenerator  # noqa: F401
from pipeline.reporting.lineage_graph_generator import LineageGraphGenerator  # noqa: F401
from pipeline.reporting.cost_estimator import CostEstimator  # noqa: F401

# ── Loaders ──────────────────────────────────────────────────────────────────
from pipeline.loaders.sql_loader import SQLLoader  # noqa: F401
from pipeline.loaders.mongo_loader import MongoLoader  # noqa: F401
from pipeline.loaders.snowflake_loader import SnowflakeLoader  # noqa: F401
from pipeline.loaders.redshift_loader import RedshiftLoader  # noqa: F401
from pipeline.loaders.bigquery_loader import BigQueryLoader  # noqa: F401
from pipeline.loaders.synapse_loader import SynapseLoader  # noqa: F401
from pipeline.loaders.databricks_loader import DatabricksLoader  # noqa: F401
from pipeline.loaders.clickhouse_loader import ClickHouseLoader  # noqa: F401
from pipeline.loaders.oracle_loader import OracleLoader  # noqa: F401
from pipeline.loaders.db2_loader import Db2Loader  # noqa: F401
from pipeline.loaders.firebolt_loader import FireboltLoader  # noqa: F401
from pipeline.loaders.yellowbrick_loader import YellowbrickLoader  # noqa: F401
from pipeline.loaders.hana_loader import HanaLoader  # noqa: F401
from pipeline.loaders.datasphere_loader import DatasphereLoader  # noqa: F401
from pipeline.loaders.quickbooks_extractor import QuickBooksExtractor  # noqa: F401
from pipeline.loaders.quickbooks_loader import QuickBooksLoader  # noqa: F401
from pipeline.loaders.cockroachdb_loader import CockroachDBLoader  # noqa: F401
from pipeline.loaders.duckdb_loader import DuckDBLoader  # noqa: F401
from pipeline.loaders.parquet_loader import ParquetLoader  # noqa: F401
from pipeline.loaders.delta_lake_loader import DeltaLakeLoader  # noqa: F401
from pipeline.loaders.iceberg_loader import IcebergLoader  # noqa: F401
from pipeline.loaders.s3_loader import S3Loader  # noqa: F401
from pipeline.loaders.athena_loader import AthenaLoader  # noqa: F401
from pipeline.loaders.sftp_loader import SFTPLoader  # noqa: F401
from pipeline.loaders.microsoft_fabric_loader import MicrosoftFabricLoader  # noqa: F401
from pipeline.loaders.postgis_loader import PostGISLoader  # noqa: F401
from pipeline.loaders.kafka_loader import KafkaLoader  # noqa: F401

# ── Vector loaders ───────────────────────────────────────────────────────────
from pipeline.loaders.vector.lancedb_loader import LanceDBLoader  # noqa: F401
from pipeline.loaders.vector.pgvector_loader import PgvectorLoader  # noqa: F401
from pipeline.loaders.vector.snowflake_vector_loader import SnowflakeVectorLoader  # noqa: F401
from pipeline.loaders.vector.bigquery_vector_loader import BigQueryVectorLoader  # noqa: F401
from pipeline.loaders.vector.chroma_loader import ChromaLoader  # noqa: F401
from pipeline.loaders.vector.milvus_loader import MilvusLoader  # noqa: F401
from pipeline.loaders.vector.pinecone_loader import PineconeLoader  # noqa: F401
from pipeline.loaders.vector.weaviate_loader import WeaviateLoader  # noqa: F401
from pipeline.loaders.vector.qdrant_loader import QdrantLoader  # noqa: F401

# ── Advanced ─────────────────────────────────────────────────────────────────
from pipeline.advanced.reversible_loader import ReversibleLoader  # noqa: F401
from pipeline.advanced.table_copier import TableCopier  # noqa: F401
from pipeline.advanced.dlq_replayer import DLQReplayer  # noqa: F401
from pipeline.advanced.nl_pipeline_builder import NLPipelineBuilder  # noqa: F401

# ── Catalog ─────────────────────────────────────────────────────────────────
from pipeline.catalog.catalog_store import CatalogStore  # noqa: F401
from pipeline.catalog.catalog_search import CatalogSearch  # noqa: F401
from pipeline.catalog.glossary import BusinessGlossary  # noqa: F401

# ── Security ────────────────────────────────────────────────────────────────
from pipeline.security.access_policy import AccessPolicy  # noqa: F401

# ── Lineage ─────────────────────────────────────────────────────────────────
from pipeline.lineage.openlineage_emitter import OpenLineageEmitter  # noqa: F401

# ── Versioning ──────────────────────────────────────────────────────────────
from pipeline.versioning.snapshot_store import SnapshotStore  # noqa: F401

# ── ML Governance ───────────────────────────────────────────────────────────
from pipeline.ml_governance.model_registry import ModelRegistry  # noqa: F401

# ── Constants and flags ──────────────────────────────────────────────────────
from pipeline.constants import (  # noqa: F401
    VERSION,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_RUN_CONTEXT,
    EU_EEA_COUNTRY_CODES,
    CLASSIFICATION_LEVELS,
    WATERMARK_FILE,
    CHECKPOINT_FILE,
    STATE_FILE_LOCK as _STATE_FILE_LOCK,
    HAS_GX,
    HAS_DOTENV,
    HAS_REQUESTS,
    HAS_CRYPTO,
    HAS_PHONENUMBERS,
    HAS_SNOWFLAKE,
    HAS_REDSHIFT,
    HAS_BIGQUERY,
    HAS_SYNAPSE,
    HAS_DATABRICKS,
    HAS_CLICKHOUSE,
    HAS_ORACLE,
    HAS_DB2,
    HAS_FIREBOLT,
    HAS_YELLOWBRICK,
    HAS_HANA,
    HAS_DATASPHERE,
    HAS_QUICKBOOKS,
    HAS_KAFKA_LOADER,
    HAS_DUCKDB,
    HAS_DELTALAKE,
    HAS_ICEBERG,
    HAS_S3,
    HAS_SFTP,
    HAS_FABRIC,
    HAS_POSTGIS,
    HAS_COCKROACH,
    HAS_PGVECTOR,
    HAS_CHROMA,
    HAS_MILVUS,
    HAS_PINECONE,
    HAS_WEAVIATE,
    HAS_QDRANT,
    HAS_LANCEDB,
    HAS_PYARROW,
    HAS_AVRO,
    HAS_ORC,
    HAS_YAML,
    HAS_ZSTD,
    HAS_LZ4,
    RunContext,
)

# ── Legacy globals (computed at import time for compat) ──────────────────────
from pipeline.constants import PIPELINE_ID, RUN_START, BASE_DIR  # noqa: F401, E402

# ── Loader dispatch ──────────────────────────────────────────────────────────
# Build eagerly-resolved _LOADER_DISPATCH matching the old 3-tuple format:
#   db_type -> (LoaderClass, needs_db_type, uses_mongo)
from pipeline.loaders import _LAZY_DISPATCH as _LAZY_DISPATCH_RAW  # noqa: F401
from pipeline.loaders import resolve_loader as _resolve_loader  # noqa: F401

_LOADER_DISPATCH: dict[str, tuple[type, bool, bool]] = {}
for _db_type, (_mod, _cls_name, _needs, _mongo) in _LAZY_DISPATCH_RAW.items():
    try:
        import importlib as _il
        _m = _il.import_module(_mod)
        _LOADER_DISPATCH[_db_type] = (getattr(_m, _cls_name), _needs, _mongo)
    except ImportError:
        pass
del _db_type, _mod, _cls_name, _needs, _mongo, _m, _il

# ── Helper functions ─────────────────────────────────────────────────────────
from pipeline.helpers import (  # noqa: F401
    file_hash as _file_hash,
    detect_pii as _detect_pii,
    flatten_record as _flatten_record,
    mask_value as _mask_value,
    interactive_prompt as _prompt,
    confirm_yes_no as _yn,
)

# ── Wizard functions ─────────────────────────────────────────────────────────
from pipeline.compliance_wizard import run_compliance_wizard  # noqa: F401
from pipeline.governance_preflight import run_governance_preflight  # noqa: F401

# ── CLI entry point ──────────────────────────────────────────────────────────
from pipeline.cli import main  # noqa: F401
