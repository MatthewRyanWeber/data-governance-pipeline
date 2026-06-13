# Architecture

## Overview

The data-governance-pipeline is a production-grade Python ETL framework that
embeds GDPR, CCPA, and HIPAA compliance directly into the pipeline rather than
bolting it on as a separate layer. It extracts from 12+ source formats, transforms
and validates data with full PII awareness, loads into 37 destinations (including
9 vector databases), and records every action to a tamper-evident SHA-256 audit
ledger.

The codebase is organized as a 7-layer import DAG (Layers 0-6) enforced by
convention: a module may only import from modules at its own layer or below,
never upward. This prevents circular imports and makes dependency relationships
explicit.

---

## Layer Architecture

```
 Layer 6  ORCHESTRATION     cli, api, scheduler, service, watchdog,
          (entry points)    compliance_wizard, governance_preflight,
                            parallel_runner, crash_recovery

 Layer 5  ADVANCED          reversible_loader, table_copier,
          (cross-cutting)   dlq_replayer, nl_pipeline_builder

 Layer 4  LOADERS +         loaders/ (40 destinations, 3 tiers),
          TRANSFORM PIPE    transform_pipeline

 Layer 3  DOMAIN SERVICES   privacy/        catalog/       quality/
                            security/       monitoring/    lineage/
                            versioning/     ml_governance/ reporting/
                            streaming/      extractors/    load_verifier

 Layer 2  CORE PROCESSING   extract, transform, profiler, schema_validator,
                            business_rules, dead_letter_queue, checkpoint,
                            run_state, compression, type_coercer,
                            data_standardiser, data_enricher,
                            referential_integrity, incremental_filter,
                            secrets_manager

 Layer 1  AUDIT LEDGER      governance_logger

 Layer 0  FOUNDATION        constants, helpers, exceptions, logging_setup
```

**Import rule**: a module at Layer N may import from Layers 0 through N, never
from Layer N+1 or above. GovernanceLogger (Layer 1) is the backbone -- nearly
every module above Layer 0 receives a `gov` instance and logs to the same
chained audit ledger.

### Layer responsibilities

| Layer | Role | Key design decision |
|-------|------|---------------------|
| 0 | Constants, helpers, exceptions, logging config. No internal imports. | Provides `HAS_*` dependency flags so the CLI can check driver availability without importing full SDKs. |
| 1 | Tamper-evident audit ledger. SHA-256 chained JSONL events. | Single logger threaded through every class -- one audit trail per run. |
| 2 | Core ETL primitives: extract, transform, validate, profile, checkpoint. | Stateless processors that take a DataFrame in and return a DataFrame out. |
| 3 | Domain services: privacy, quality, catalog, security, monitoring, lineage, versioning, ML governance, reporting, streaming extractors. | Each subpackage is self-contained with its own `__init__.py` exports. |
| 4 | Destination loaders and the config-driven transform pipeline orchestrator. | Each loader is a separate file; `resolve_loader()` lazily imports only the requested SDK. |
| 5 | Advanced cross-cutting features: reversible loads, DLQ replay, NL builder. | Built on top of Layers 0-4; may import from any lower layer. |
| 6 | Entry points: CLI, REST API, scheduler, Windows service, watchdog, preflight. | These are the only modules that import broadly across the stack. |

---

## Data Flow

A typical pipeline run follows this path through the layers:

```
  SOURCE FILE / DB / STREAM / API
        |
        v
  +------------------+
  |  Extractor        |  Layer 2 -- CSV, JSON, XML, Parquet, Avro, ORC,
  |  (extract.py)     |             Excel, YAML, Feather, SAS, Stata, FW
  +------------------+
        |
        |  (streaming sources go through Layer 3 streaming/ extractors:
        |   KafkaStreamExtractor, KinesisStreamExtractor, PubSubStreamExtractor)
        |
        |  (database/API sources go through Layer 3 extractors/:
        |   DatabaseExtractor, RESTExtractor)
        |
        v
  +------------------+
  |  Transformer      |  Layer 2 -- flatten, sanitise, dedup, PII mask,
  |  (transform.py)   |             minimise columns
  +------------------+
        |
        v
  +------------------+
  |  Schema Validator |  Layer 2 -- Great Expectations integration,
  |  + Type Coercer   |             dtype enforcement
  +------------------+
        |
        v
  +------------------+
  |  Data Profiler    |  Layer 2/3 -- column stats, null rates,
  |  + Quality Scorer |              cardinality, distributions
  +------------------+
        |
        v
  +------------------+
  |  Loader           |  Layer 4 -- resolve_loader() dispatches to one of
  |  (loaders/)       |             37 destination-specific loaders
  +------------------+
        |
        v
  +------------------+
  |  Load Verifier    |  Layer 3 -- reconcile source vs destination row
  |  (load_verifier)  |             counts, detect silent data loss
  +------------------+


  CROSS-CUTTING CONCERNS (run in parallel or at checkpoints):

  +-------------------------------------------------------+
  |  GovernanceLogger (Layer 1)                            |
  |    SHA-256 chained JSONL audit ledger                  |
  |    30+ event types across all stages                   |
  +-------------------------------------------------------+
  |  Privacy (Layer 3): PII detection, encryption,         |
  |    erasure, classification, cross-border transfer       |
  +-------------------------------------------------------+
  |  Quality (Layer 3): contracts, anomaly alerts, drift,  |
  |    schema evolution, synthetic data                     |
  +-------------------------------------------------------+
  |  Monitoring (Layer 3): SLA, metrics, notifications     |
  +-------------------------------------------------------+
  |  Lineage (Layer 3): OpenLineage event emission         |
  +-------------------------------------------------------+
  |  Checkpoint (Layer 2): chunk-level crash recovery      |
  +-------------------------------------------------------+
```

### Chunk processing and crash recovery

The CLI processes data in chunks (default 50,000 rows). After each chunk:

1. The chunk is transformed, validated, profiled, and loaded.
2. `RunStateManager` writes a checkpoint with the chunk offset.
3. On crash, `crash_recovery.py` (Layer 5) finds runs stuck in `running`
   status and resumes from the last successful chunk offset.
4. The `resume` CLI subcommand triggers this manually.

---

## Module Map

### Root-level modules (pipeline/)

| Module | Layer | Purpose |
|--------|-------|---------|
| `constants.py` | 0 | Version, paths, PII patterns, `HAS_*` flags, `RunContext`, `EventCategory` enum |
| `helpers.py` | 0 | Pure utility functions: `file_hash`, `flatten_record`, `mask_value`, `interactive_prompt` |
| `exceptions.py` | 0 | `ConfigValidationError`, `LoaderError`, `ExtractionError`, `ValidationError` |
| `logging_setup.py` | 0 | Rotating file handlers, JSON structured logging, sensitive data scrubbing |
| `governance_logger.py` | 1 | SHA-256 chained JSONL audit ledger, 30+ event types, 7 report writers |
| `extract.py` | 2 | File-based extraction: 12+ formats with compression support |
| `transform.py` | 2 | Flatten, sanitise, dedup, PII mask, column minimisation |
| `profiler.py` | 2 | Column-level statistical profiling (nulls, uniques, ranges) |
| `schema_validator.py` | 2 | Great Expectations integration, baseline expectation generation |
| `business_rules.py` | 2 | JSON-config rule engine: rename, fill, map, derive, filter, flag |
| `type_coercer.py` | 2 | DataFrame dtype enforcement and coercion |
| `data_standardiser.py` | 2 | Standardise formats: phone numbers, dates, addresses |
| `data_enricher.py` | 2 | External data enrichment hooks |
| `referential_integrity.py` | 2 | Cross-table foreign key validation |
| `dead_letter_queue.py` | 2 | DLQ for rejected rows (written to CSV) |
| `compression.py` | 2 | gz/bz2/zip/zstd/lz4 decompression with bomb protection |
| `incremental_filter.py` | 2 | Watermark-based incremental extraction |
| `checkpoint.py` | 2 | Backward-compat shim delegating to `run_state` |
| `run_state.py` | 2 | Run-state tracking and chunk-level checkpointing |
| `secrets_manager.py` | 2 | Credential loading from env/.env files |
| `load_verifier.py` | 3 | Post-load row-count reconciliation |
| `transform_pipeline.py` | 4 | Config-driven orchestrator chaining all transformers |
| `crash_recovery.py` | 5 | Detect and resume incomplete runs |
| `cli.py` | 6 | CLI entry point: run, validate, profile, resume, schedule |
| `api.py` | 6 | Flask REST API with auth, rate limiting, background execution |
| `scheduler.py` | 6 | Cron-style repeating pipeline runs |
| `service.py` | 6 | Windows Service wrapper (SCM integration) |
| `watchdog.py` | 6 | Process supervisor with exponential backoff restart |
| `parallel_runner.py` | 6 | ThreadPoolExecutor-based multi-file processing |
| `compliance_wizard.py` | 6 | Interactive GDPR/CCPA pre-run questionnaire |
| `governance_preflight.py` | 6 | Pre-flight governance state check with confirmation prompts |

### Subpackages

| Package | Layer | Key classes | Purpose |
|---------|-------|-------------|---------|
| `loaders/` | 4 | `BaseLoader`, `SQLLoader`, `SnowflakeLoader`, `BigQueryLoader`, ... | 40 destinations across 3 verification tiers, lazy dispatch + a column-injection guard |
| `loaders/vector/` | 4 | `PgvectorLoader`, `ChromaLoader`, `MilvusLoader`, `PineconeLoader`, ... | 9 vector database loaders |
| `privacy/` | 3 | `ColumnEncryptor`, `ErasureHandler`, `PIIDiscoveryReporter`, `NLPPIIDetector`, `DataClassificationTagger`, `CrossBorderTransferLogger` | PII detection, encryption, erasure, GDPR classification |
| `quality/` | 3 | `DataQualityScorer`, `QualityAnomalyAlerter`, `DataDiffReporter`, `SchemaEvolver`, `DataContractEnforcer`, `SyntheticDataGenerator`, `ColumnProfiler`, `TestGenerator` | Quality scoring, anomaly detection, contracts, schema evolution |
| `catalog/` | 3 | `CatalogStore`, `CatalogSearch`, `BusinessGlossary` | SQLite-backed data catalog with FTS5 search |
| `security/` | 3 | `AccessPolicy` | RBAC column/row access policies, fail-closed enforcement |
| `monitoring/` | 3 | `SLAMonitor`, `MetricsCollector`, `Notifier`, `DataObserver` | SLA monitoring, metrics collection, email/Slack notifications |
| `lineage/` | 3 | `OpenLineageEmitter` | OpenLineage v2.0.2 event emission |
| `versioning/` | 3 | `SnapshotStore` | Content-addressable dataset snapshots with diff and checkout |
| `ml_governance/` | 3 | `ModelRegistry` | ML model registration, training lineage, impact analysis |
| `reporting/` | 3 | `HTMLReportGenerator`, `LineageGraphGenerator`, `CostEstimator`, `ReportWriter` | HTML reports, lineage visualisation, cost estimation |
| `streaming/` | 3 | `KafkaStreamExtractor`, `KinesisStreamExtractor`, `PubSubStreamExtractor` | Message queue source extractors |
| `extractors/` | 3 | `DatabaseExtractor`, `RESTExtractor` | Database and REST API source readers |
| `advanced/` | 5 | `ReversibleLoader`, `TableCopier`, `DLQReplayer`, `NLPipelineBuilder` | Reversible loads, DLQ replay, natural language pipeline builder |
| `extensions/` | -- | (namespace package) | Extension point for governance, compliance, epic, grafana modules |

### Extension modules (pipeline/extensions/)

| Module | Purpose |
|--------|---------|
| `pipeline.extensions.governance_extensions` | 8 GDPR/CCPA classes: RoPA, retention, DSAR, breach detection, consent, differential privacy, purpose limitation, pseudonym vault |
| `pipeline.extensions.epic_extensions` | 6 HIPAA/healthcare classes: Safe Harbor filter, Clarity extractor, BAA tracker, IRB gate, OMOP transformer, k-anonymity checker |
| `pipeline.extensions.compliance_extensions` | 3 continuous compliance classes: ComplianceMonitor, TrustReportGenerator, VendorRiskTracker |
| `pipeline.extensions.grafana_extensions` | 3 Grafana classes: MetricsSink, PrometheusExporter, GrafanaDashboardGenerator |

Root-level shims with the original filenames remain until v5.0;
`pipeline_v3.py` re-exports all public names for monolith-era callers.

---

## Decision Log

The major architectural bets, why they were made, and what would cause a
revisit. New entries go at the top.

**Tiered destination catalog (2026-06).** Every destination declares how
it is verified — core (real engine in CI), emulator, or cloud-credential —
enforced by a lockstep test against the dispatch registry. Chosen because
mocked tests had allowed loaders to ship that could never work against
their real engine. Revisit if: a CI-runnable emulator appears for a cloud
tier service (promote it).

**Column-injection guard at dispatch, not per loader (2026-06).**
`resolve_loader()` wraps every loader's `load()` with column-name
validation. One chokepoint instead of ~40 call sites; the cost is
action-at-a-distance (documented in base.py and EXTENDING.md). Revisit
if: loaders gain a shared template-method `load()` in BaseLoader, which
would give the guard a natural home.

**Family contract as a parameterized suite (2026-06).** Behavioral rules
(dry-run returns 0, keyless upsert raises, …) are enforced by one test
iterating the registry, because sibling drift — a fix applied to one
loader and missed in seven copies — was the dominant defect class.
Revisit: never; extend the contract instead.

**Layered monolith over services (2026-06).** One deployable, seven
import layers, layer declared in every module docstring. A single
maintainer gets monolith debuggability; the layer DAG keeps the
boundaries honest. Revisit if: an operational need appears for
independent scaling of the API vs. pipeline runs.

**Governance via one shared `gov` object (2026-06).** Every class takes a
`GovernanceLogger` first argument rather than emitting events to a bus.
Explicit, synchronous, crash-durable (per-event fsync via
AppendOnlyWriter). The cost is coupling to one class — mitigated by
extracting ReportWriter (4.1) and RunArtifacts (4.4). Revisit if: event
volume makes per-event fsync the bottleneck (buffer per checkpoint
interval; the hook is documented in governance_logger.py).

**Per-record streaming with checkpoints, never batch (2026-06).** Chunked
processing with a checkpoint after every chunk; resume must continue from
the next unprocessed record. Non-negotiable: batch pipelines with no
mid-phase resume have repeatedly cost multi-day reruns.

---

## Integration Points

### Cloud Warehouses

| Destination | Loader class | SDK / Driver | Install extra |
|-------------|-------------|--------------|---------------|
| PostgreSQL | `SQLLoader` | psycopg2 | (core) |
| MySQL | `SQLLoader` | PyMySQL | (core) |
| SQL Server | `SQLLoader` | pyodbc | (core) |
| SQLite | `SQLLoader` | stdlib sqlite3 | (core) |
| MongoDB | `MongoLoader` | pymongo | (core) |
| Snowflake | `SnowflakeLoader` | snowflake-connector-python | `[cloud]` |
| BigQuery | `BigQueryLoader` | google-cloud-bigquery | `[cloud]` |
| Redshift | `RedshiftLoader` | redshift_connector | `[cloud]` |
| Azure Synapse | `SynapseLoader` | pyodbc + azure-identity | `[cloud]` |
| Databricks | `DatabricksLoader` | databricks-sql-connector | `[cloud]` |
| ClickHouse | `ClickHouseLoader` | clickhouse-connect | `[cloud]` |
| Oracle | `OracleLoader` | oracledb | `[cloud]` |
| DB2 | `Db2Loader` | ibm_db | `[cloud]` |
| Firebolt | `FireboltLoader` | firebolt.db | `[cloud]` |
| Yellowbrick | `YellowbrickLoader` | psycopg2 | `[cloud]` |

### SAP

| Destination | Loader class | SDK / Driver | Install extra |
|-------------|-------------|--------------|---------------|
| SAP HANA | `HanaLoader` | hdbcli | `[sap]` |
| SAP Datasphere | `DatasphereLoader` | requests | `[sap]` |

### Accounting

| Destination | Loader class | SDK / Driver | Install extra |
|-------------|-------------|--------------|---------------|
| QuickBooks Online | `QuickBooksLoader` | requests | `[quickbooks]` |

### Data Lake Formats

| Destination | Loader class | SDK / Driver | Install extra |
|-------------|-------------|--------------|---------------|
| DuckDB / MotherDuck | `DuckDBLoader` | duckdb | `[datalake]` |
| Parquet files | `ParquetLoader` | pyarrow | `[datalake]` |
| Delta Lake | `DeltaLakeLoader` | deltalake | `[datalake]` |
| Apache Iceberg | `IcebergLoader` | pyiceberg | `[datalake]` |

### Object Storage

| Destination | Loader class | SDK / Driver | Install extra |
|-------------|-------------|--------------|---------------|
| S3 / GCS / Azure Blob | `S3Loader` | boto3 / s3fs | `[objectstorage]` |
| Athena | `AthenaLoader` | boto3 | `[objectstorage]` |
| Microsoft Fabric | `MicrosoftFabricLoader` | adlfs | `[objectstorage]` |
| SFTP | `SFTPLoader` | paramiko | `[sftp]` |

### Distributed SQL

| Destination | Loader class | SDK / Driver | Install extra |
|-------------|-------------|--------------|---------------|
| CockroachDB | `CockroachDBLoader` | sqlalchemy-cockroachdb | `[cockroachdb]` |
| PostGIS | `PostGISLoader` | psycopg2 | (core) |

### Streaming

| Destination | Loader class | SDK / Driver | Install extra |
|-------------|-------------|--------------|---------------|
| Kafka | `KafkaLoader` | kafka-python | `[streaming]` |

### Streaming Extractors (sources)

| Source | Extractor class | SDK / Driver | Install extra |
|--------|----------------|--------------|---------------|
| Kafka | `KafkaStreamExtractor` | kafka-python | `[streaming]` |
| Kinesis | `KinesisStreamExtractor` | boto3 | `[streaming]` |
| Pub/Sub | `PubSubStreamExtractor` | google-cloud-pubsub | `[streaming]` |

### Vector Databases

| Destination | Loader class | SDK / Driver | Install extra |
|-------------|-------------|--------------|---------------|
| pgvector | `PgvectorLoader` | pgvector | `[vector]` |
| Snowflake Vector | `SnowflakeVectorLoader` | snowflake-connector-python | `[cloud]` |
| BigQuery Vector | `BigQueryVectorLoader` | google-cloud-bigquery | `[cloud]` |
| Chroma | `ChromaLoader` | chromadb | `[vector]` |
| Milvus | `MilvusLoader` | pymilvus | `[vector]` |
| Pinecone | `PineconeLoader` | pinecone-client | `[vector]` |
| Weaviate | `WeaviateLoader` | weaviate-client | `[vector]` |
| Qdrant | `QdrantLoader` | qdrant-client | `[vector]` |
| LanceDB | `LanceDBLoader` | lancedb | `[lancedb]` |

### File Format Extractors (sources)

| Format | Module | SDK / Driver |
|--------|--------|--------------|
| CSV / TSV | `extract.py` | pandas (core) |
| JSON / JSONL | `extract.py` | pandas (core) |
| Excel (.xlsx) | `extract.py` | openpyxl (core) |
| XML | `extract.py` | lxml + defusedxml (core) |
| YAML | `extract.py` | PyYAML |
| Parquet / Feather | `extract.py` | pyarrow |
| Avro | `extract.py` | fastavro |
| ORC | `extract.py` | pyorc |
| SAS / Stata | `extract.py` | pandas (core) |
| Fixed-width | `extract.py` | pandas (core) |

---

## Security Model

### Tamper-evident audit ledger

Every governance event is written to a JSONL ledger file. Each entry includes
a SHA-256 hash of the previous entry, forming a cryptographic chain. If any
historical entry is modified, deleted, or reordered, the chain breaks and
`verify_chain()` detects it. This satisfies GDPR Art. 32 requirements for
integrity of processing.

The `EventCategory` enum (27 categories) enforces typed event classification
so typos cannot silently create gaps in the audit trail.

### PII handling

- **Discovery**: Pattern-based regex (36 patterns covering GDPR Art. 4 / CCPA
  SS1798.140 field names) plus NLP-based NER detection via spaCy for
  unstructured text (50+ entity types).
- **Masking**: `mask_value()` in helpers.py truncates PII before logging.
  The `Transformer` applies configurable PII strategies (mask, hash, redact,
  encrypt) per column.
- **Encryption**: `ColumnEncryptor` uses Fernet symmetric encryption
  (cryptography library) with per-column keys and context separation.
- **Pseudonymisation**: `PseudonymVault` (governance_extensions) provides
  consistent keyed pseudonyms with key rotation (GDPR Art. 4(5)).
- **Erasure**: `ErasureHandler` implements GDPR Art. 17 right-to-erasure
  across all 37 destination types in a single call.
- **Differential privacy**: `DifferentialPrivacyTransformer` adds calibrated
  Laplace/Gaussian noise with per-column epsilon budget tracking.

### Encryption

- Column-level Fernet encryption with key rotation
- Credentials loaded from environment variables via `SecretsManager`
- `.env` files gitignored; `SensitiveDataFilter` scrubs secrets from log output
- Atomic config writes (write-to-temp-then-rename) prevent corruption on crash

### RBAC

`AccessPolicy` (security/access_policy.py) enforces:
- Column whitelists and blacklists per role
- Row-level filters with injection-safe expression evaluation
- Fail-closed enforcement: if no policy matches, access is denied
- All enforcement decisions logged to the audit ledger

### Input validation

- `validate_sql_identifier()` runs on all table, schema, and column names
  across every loader -- rejects SQL injection attempts before any connection
  is opened
- `defusedxml` for all XML parsing (XXE protection)
- Path traversal and zip bomb protection in decompression (`MAX_DECOMPRESSED_SIZE`)
- API authentication via Bearer token on all endpoints (except `/health`)
- Rate limiting on the REST API (token bucket, configurable per key)

---

## Extension System

### Adding a new loader

1. Create `pipeline/loaders/my_loader.py` with a class extending `BaseLoader`:

```python
"""
My custom loader.

Layer 4 -- imports from Layer 0 (constants), Layer 1 (governance_logger).
"""
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

class MyLoader(BaseLoader):
    REQUIRED_CONFIG = ["host", "database"]  # validated at init

    def __init__(self, gov, config, dry_run=False):
        super().__init__(gov, config, dry_run=dry_run)

    def load(self, df, table, mode="append"):
        validate_sql_identifier(table)
        if self.dry_run:
            return {"rows": len(df), "dry_run": True}
        # ... write to destination ...
```

2. Register in `pipeline/loaders/__init__.py`:

```python
_LAZY_DISPATCH["mydb"] = (
    "pipeline.loaders.my_loader", "MyLoader", False, False
)
```

3. Add a `HAS_MYDB` flag in `pipeline/constants.py`:

```python
HAS_MYDB = _has("mydb_driver")
```

4. Add tests in `tests/test_loaders/test_my_loader.py`.

### Adding a new extractor (file format)

Register a format handler in `extract.py`'s `_FORMAT_REGISTRY` dict. The
handler receives a file path (or IO stream) and returns a DataFrame or
DataFrame iterator for chunked reads.

### Adding a new streaming source

Create a class in `pipeline/streaming/` that yields DataFrames from a message
queue. Follow the pattern of `KafkaStreamExtractor`: accept a `gov` instance,
support `dry_run`, and emit `EXTRACT` audit events.

### Adding a new privacy / quality / catalog module

Place the module in the appropriate subpackage at Layer 3. Import from
Layer 0-1 only. Export the class from the subpackage `__init__.py`.

---

## Deployment

### CLI

The primary entry point. Installed as the `pipeline` console script via
pyproject.toml.

```bash
pipeline run data.csv postgresql --table customers
pipeline validate data.csv --schema schema.json
pipeline profile data.csv
pipeline resume                     # resume crashed runs
pipeline schedule data.csv postgresql --cron "0 * * * *"
```

Or run as a Python module:

```bash
python -m pipeline run data.csv postgresql
```

### REST API

A Flask application (`pipeline/api.py`) that exposes:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check (no auth) |
| `/run` | POST | Trigger a pipeline run (background thread) |
| `/status/<run_id>` | GET | Check run status |
| `/metrics` | GET | Pipeline metrics |
| `/docs` | GET | Swagger / OpenAPI documentation |

Authentication: Bearer token via `PIPELINE_API_KEYS` environment variable.
Rate limiting: 100 requests per minute per key (configurable).

```bash
# Start the API server
python -m pipeline.api

# Or via Docker
docker compose up pipeline-api
```

### Scheduler

`PipelineScheduler` (pipeline/scheduler.py) runs pipeline functions on a
cron-like schedule. Uses the `schedule` package when available; falls back
to a built-in minute-level time matcher.

```bash
pipeline schedule data.csv postgresql --cron "0 * * * *"
```

### Windows Service

`pipeline/service.py` wraps the pipeline as a Windows Service for automatic
start on boot, automatic restart after crash, and management via `sc`,
`services.msc`, or `net start/stop`.

```bash
# Install (run as Administrator)
python -m pipeline.service install

# Start / stop
python -m pipeline.service start
python -m pipeline.service stop
```

### Watchdog

`pipeline/watchdog.py` is a lightweight process supervisor that spawns the
pipeline as a child process and restarts it on unexpected exit with exponential
backoff.

```bash
python -m pipeline.watchdog schedule data.csv postgresql --cron "*/5 * * * *"
```

### Docker

Multi-stage Dockerfile (Python 3.12-slim). Docker Compose provides two
services:

```bash
# API server on port 5000
docker compose up pipeline-api

# Run test suite
docker compose --profile test up test
```

### Parallel file processing

`parallel_runner.py` uses `ThreadPoolExecutor` to run a pipeline function
against multiple files concurrently with bounded concurrency.

---

## Dependency Management

Optional dependencies are grouped into install extras in `pyproject.toml`:

| Extra | What it installs |
|-------|-----------------|
| `[cloud]` | Snowflake, BigQuery, Databricks, ClickHouse, Oracle, DB2, Azure |
| `[streaming]` | Kafka, Kinesis (boto3), Pub/Sub |
| `[healthcare]` | pyodbc, pyarrow (Epic Clarity + OMOP) |
| `[sap]` | hdbcli, requests |
| `[vector]` | pgvector, Chroma, Milvus, Pinecone, Weaviate, Qdrant, sentence-transformers |
| `[lancedb]` | LanceDB, pyarrow |
| `[datalake]` | DuckDB, Delta Lake, Iceberg, pyarrow |
| `[objectstorage]` | boto3, s3fs, gcsfs, adlfs |
| `[sftp]` | paramiko |
| `[cockroachdb]` | sqlalchemy-cockroachdb |
| `[grafana]` | prometheus_client |
| `[dev]` | pytest, mypy, black, ruff, flask, faker |
| `[all]` | Everything above |

Each loader checks its `HAS_*` flag at instantiation time and raises a clear
install hint if the driver is missing. The pipeline never silently falls back
to a different destination.
