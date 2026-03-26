# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [4.23.0] — 2026-03-24

### Fixed
- **CockroachDBLoader.load(): table name not validated** — table name was
  interpolated into `to_sql()` and raw SQL without `_validate_sql_identifier()`.
  Fixed: validates table name before any database operation.
- **CockroachDBLoader._upsert(): column names from DataFrame interpolated
  into SQL** — DataFrame column names were used directly in
  `f"{c} = EXCLUDED.{c}"` f-strings. A column named e.g. `col; DROP TABLE t`
  would have injected SQL. Fixed: all columns and natural_keys validated with
  `_validate_sql_identifier()` before SQL construction.
- **pipeline_v3.py: undefined name `_re`** — `DataStandardiser.standardise_names()`
  used `_re.sub()` after a previous session removed the `import re as _re` alias.
  Fixed: replaced `_re.sub` with `re.sub` (module-level `re` import).

---

## [4.22.0] — 2026-03-24

### Added
- **`CockroachDBLoader`** (destination #29) — distributed PostgreSQL-compatible
  database loader; uses the `cockroachdb://` SQLAlchemy dialect when
  `sqlalchemy-cockroachdb` is installed (automatic SAVEPOINT retry logic,
  CockroachDB-specific optimisations) or falls back to `postgresql+psycopg2`
  for zero-extra-dependency installs. Supports local dev clusters (SSL disable),
  CockroachDB Cloud (SSL verify-full + cluster name prefix), and custom ports
  (default 26257). Load modes: append, replace, upsert (ON CONFLICT DO UPDATE).
  Includes `table_info()` helper. 16 new tests (156 loader dispatch total,
  435 across all suites).

---

## [4.21.0] — 2026-03-24

### Fixed (full new-code scan)
- **WeaviateLoader: URL parsing — 3 bugs** (REAL):
  - `http://localhost` (no port) defaulted to port 80 instead of Weaviate's
    default 8080.
  - `https://host` (no port) defaulted to 80 instead of 443.
  - `http://host:8080/some/path` raised `ValueError: invalid literal for
    int()` because `split(":")[-1]` returned `"8080/some/path"`.
  Fixed: rewrote URL parsing to strip the path component first, then
  `rsplit(":", 1)` the host:port portion, with correct per-scheme port
  defaults (8080 for HTTP, 443 for HTTPS). All 7 URL edge cases verified.
- **KafkaLoader: acks type coercion bug** (REAL): `str(cfg.get("acks",
  "all"))` converted integer `1` to string `"1"`. kafka-python requires
  `acks` as integer `0`/`1` or string `"all"` — passing `"1"` (string)
  is sent as-is to the broker which expects a numeric value. Fixed: coerces
  `"all"` and `"-1"` to the string `"all"`, and all other values to `int()`.
- Removed unused `import math` from `test_loader_dispatch.py` regression test.

---

## [4.20.0] — 2026-03-24

### Fixed (Tier 3 deep scan — second pass)
- **BigQueryVectorLoader.search(): vec_literal built before float validation**
  (CRITICAL) — `str(v) for v in query_vector` ran before `_validate_float_vector`,
  so `NaN`/`inf` still reached the SQL literal even after last session's fix.
  Fixed: moved `vec_literal` construction to after `_validate_float_vector`.
- **BigQueryVectorLoader: project/dataset/table not validated** — all three were
  interpolated into a SQL backtick literal without identifier validation.
  Fixed: `_validate_sql_identifier()` called for project, dataset, and table in
  both `load()` and `search()`.
- **BigQueryVectorLoader: inline `import re` on every search call** — `import re
  as _re` was inside the method body, re-importing on every invocation. Fixed:
  removed the inline import; uses module-level `re` directly.
- **PgvectorLoader.search(): SELECT * returns raw vector bytes** — returning
  the full embedding column bloats result DataFrames (1536+ floats per row).
  Fixed: default SELECT now uses `* EXCEPT (vector_col)` in PostgreSQL syntax;
  callers can override with `select_cols`.
- **PgvectorLoader.create_index(): IVFFlat/HNSW on empty table** — creating
  a vector index on an empty table is silently incorrect (the index is useless
  and must be rebuilt after data loads). Fixed: checks row count before
  proceeding; logs a warning and returns early if table is empty.
- **SnowflakeVectorLoader: no Cortex availability note** — VECTOR type requires
  Snowflake Cortex which is not available in all editions/regions; callers had
  no indication of this in code comments. Fixed: added inline documentation.

---

## [4.19.0] — 2026-03-24

### Fixed (Tier 3 vector loader bug scan)
- **PgvectorLoader: SQL identifier injection** — table and vector_col names were
  interpolated directly into SQL without validation. Fixed: added
  `_validate_sql_identifier()` helper that enforces `[A-Za-z_][\w.]*` via
  `re.fullmatch`; called in `load()`, `create_index()`, and `search()`.
- **PgvectorLoader / SnowflakeVectorLoader: float injection in query_vector** —
  `str(v) for v in query_vector` concatenated directly into SQL literals. NaN,
  inf, or a non-numeric value would produce malformed or exploitable SQL. Fixed:
  added `_validate_float_vector()` helper that validates all values are finite
  floats before SQL construction.
- **SnowflakeVectorLoader.load(): ALTER COLUMN not guarded** — on a second
  append load the vector column already exists as VECTOR type; `ALTER COLUMN`
  raised an error. Fixed: wrapped in `try/except` with `conn.rollback()` on
  failure (column already VECTOR — safe to continue).
- **BigQueryVectorLoader.load(): job.result() no timeout** — a stalled BQ job
  hung the pipeline thread indefinitely. Fixed: added configurable
  `job_timeout_seconds` (default 600) via `cfg`.
- **BigQueryVectorLoader.search(): options string injection** — raw `options`
  parameter interpolated into SQL. Fixed: validated against `[\w=.,\s]+`
  allowlist; `distance` validated against `("COSINE", "EUCLIDEAN")`.
- **All three Tier 3 loaders: no empty DataFrame guard** — passing an empty
  DataFrame could reach the database client with 0 rows. Fixed: early return 0
  before any DB connection is made.
- Added `_validate_sql_identifier()` and `_validate_float_vector()` as shared
  module-level helpers used by all three loaders.
- Removed unused `import numpy as np` from TestVectorLoaders._df().
- 9 new regression tests (140 loader dispatch tests, 419 total).

---

## [4.18.0] — 2026-03-24

### Added
- **`PgvectorLoader`** (destination #26) — PostgreSQL with pgvector extension;
  `CREATE EXTENSION IF NOT EXISTS vector` on first load; auto-adds vector column
  via `ALTER TABLE`; IVFFlat and HNSW ANN index creation; cosine/L2/inner-product
  `search()` using native pgvector distance operators.
- **`SnowflakeVectorLoader`** (destination #27) — Snowflake native `VECTOR(FLOAT,N)`
  type; writes via pandas `to_sql` then `ALTER COLUMN` to cast to VECTOR;
  similarity search via `VECTOR_COSINE_SIMILARITY()`, `VECTOR_L2_DISTANCE()`,
  `VECTOR_INNER_PRODUCT()`.
- **`BigQueryVectorLoader`** (destination #28) — BigQuery `ARRAY<FLOAT64>` vector
  column via `load_table_from_dataframe`; nearest-neighbour search via
  `VECTOR_SEARCH()` table-valued function (BigQuery 2023+); configurable
  distance type and ANN options.
- 23 new tests in `test_loader_dispatch.py` (131 total, 410 across all suites).
- Fixed `test_all_destinations_registered` which was missing the 3 new
  Tier 3 dispatch keys left over from the previous incomplete session.

---

## [4.17.0] — 2026-03-24

### Added
- **`ChromaLoader`** (destination #24) — embedded open-source vector database;
  append / upsert / overwrite modes, in-memory (ephemeral), persistent file, or
  server connection; maps DataFrame columns to Chroma ids/embeddings/documents/
  metadatas; `query()` for similarity search with optional metadata filtering.
  Fully tested round-trip with persistent storage. 12 new tests.
- **`MilvusLoader`** (destination #25) — enterprise-grade vector database for
  billion-scale workloads; Lite (local file), Standalone server, and Zilliz Cloud
  modes; append / upsert / overwrite modes; auto collection creation with
  configurable distance metric; `search()` with scalar filter support. 8 new
  tests (server tests use mocks; Lite tested with real in-memory operations).
- 20 new tests in `test_loader_dispatch.py` (108 total, 387 across all suites).

---

## [4.16.0] — 2026-03-24

### Fixed (bug scan session 4)
- **ComplianceMonitor._check_vendor_risk() — KeyError on missing key**: direct
  `rec["next_review_date"]` access raised `KeyError` if a vendor registry entry
  was missing that field (e.g. manually edited file or partial write). The
  entire compliance check crashed instead of returning a warning. Fixed: uses
  `rec.get("next_review_date", "")` with a try/except around fromisoformat,
  returning WARN with a descriptive message for missing or malformed dates.
- 2 regression tests added to `test_compliance_extensions.py` (58 total).

### Confirmed clean (not bugs)
- `OMOPTransformer.to_visit_occurrence()` — scanner false positive; both
  `to_datetime()` calls already have `errors='coerce'`.
- `PurposeLimitationEnforcer` — thread safety scanner false positive; class
  has `threading.Lock()` correctly.
- All 21 loader `load()` signatures correct.
- `PHIKAnonymityChecker` multi-key suppress works correctly end-to-end.
- `MetricsSink` negative `rows_failed` correctly clamped to 0.
- Dashboard SQL is hardcoded — no injection risk.
- The two `except: pass` in `pipeline_v3.py` are intentional archive-peeking
  fallbacks, not bugs.

---

## [4.16.0] — 2026-03-24

### Fixed (full project bug scan)
- **ComplianceMonitor._check_vendor_risk() — KeyError on missing key**: direct
  access to `rec["next_review_date"]` raised `KeyError` if a vendor record was
  missing that key (manually edited registry or partial write). Fixed: uses
  `.get()` with empty-string fallback, guards against missing or malformed date
  strings, appends vendor to overdue list with a clear message instead of
  crashing.
- **OMOPTransformer.to_visit_occurrence() — to_datetime without errors='coerce'**:
  `HOSP_ADMSN_TIME` and `HOSP_DISCH_TIME` columns often contain `'N/A'`,
  empty strings, or `None`-as-string for outpatient encounters. Missing
  `errors='coerce'` caused the entire domain mapping to crash on a single
  bad value. Fixed: both calls use `errors='coerce'`.
- **test_refresh_window_blocked — time-dependent flaky test**: used
  `refresh_window_end=23` which excluded hour 23 (11 PM local), causing the
  test to fail if run late at night. Fixed: mock `datetime.now()` to a
  controlled hour inside the window.
- 2 new tests added (346 total).

### Verified clean (scan confirmed not bugs)
- RetentionEnforcer SQL: table/column names validated via SQLAlchemy inspector
- ClarityExtractor ZC_ table injection: all names validated via table_exists()
- PHIKAnonymityChecker multi-key suppress: correct behavior confirmed by live test
- MetricsSink negative rows_failed: correctly clamped to 0
- All 21 loader load() signatures: correct
- Dashboard SQL: all hardcoded, no injection risk
- PurposeLimitationEnforcer: has threading.Lock — scanner false positive

---

## [4.16.0] — 2026-03-24

### Added
- **`PineconeLoader`** (destination #21) — managed cloud vector database;
  upsert by ID with configurable batch size, namespace support, metadata
  filtering, pre-computed or sentence-transformer generated embeddings,
  and a `query()` method for nearest-neighbour search.
- **`WeaviateLoader`** (destination #22) — open-source vector database with
  hybrid search; append / overwrite / upsert modes, auto-UUID generation
  from any column, local or cloud connection, optional pre-computed vectors.
- **`QdrantLoader`** (destination #23) — high-performance Rust-backed vector
  database; local file, in-memory, and server modes; full `search()` API
  using `query_points()` (qdrant-client v1.9+); auto collection creation
  with configurable distance metric.
- 21 new tests in `test_loader_dispatch.py` (88 total, 367 across all suites).
- Fixed duplicate `lancedb` entry in `_LOADER_DISPATCH`.
- Fixed `QdrantLoader.search()` to use `query_points()` API (qdrant-client
  v1.9+ removed the legacy `search()` method).

---

## [4.15.0] — 2026-03-24

### Fixed (bug scan session 3)
- **MetricsSink — no WAL mode (database locked errors)**: Grafana reads
  `metrics.db` while the pipeline writes to it. SQLite's default journal mode
  raises `database is locked` under concurrent access. Fixed: added
  `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL` in `_init_db()`.
- **PrometheusExporter — unhandled port binding error**: if port 8000 was
  already in use, `HTTPServer()` raised a bare `OSError` with a cryptic
  message. Fixed: wrapped in try/except with a clear `RuntimeError` explaining
  the issue and suggesting a different port.
- **DifferentialPrivacyTransformer — sensitivity=0 division by zero**: the
  Laplace and Gaussian mechanisms divide by `sensitivity` internally. Passing
  `sensitivity=0` crashed with `ZeroDivisionError`. Fixed: validates
  `sensitivity > 0` at the top of `apply()`.
- **KafkaExtractor — malformed JSON crashes entire consumer**: the
  `value_deserializer` lambda called `json.loads()` directly — one malformed
  message stopped all processing. Fixed: replaced with `_safe_json_decode()`
  helper that catches `JSONDecodeError` and `UnicodeDecodeError`, logs a
  warning, and returns `None`; `None` messages are skipped in the loop.
- **test_refresh_window_blocked — time-dependent test failure**: the test used
  `refresh_window_end=23` which excludes hour 23 (11 PM), causing the test to
  fail if run at that hour. Fixed: mock `datetime.now()` to return a
  controlled hour inside the window — test now passes at any time of day.

---

## [4.14.0] — 2026-03-24

### Fixed (bug scan session 2)
- **KafkaLoader._publish_upsert — tombstone serialization (CRITICAL)**: the
  `value_serializer` lambda converted `None → b'null'` (JSON string) instead of
  passing `None` through unchanged. Kafka log compaction requires a true null
  bytes value to delete a key — `b'null'` creates a record instead of a
  tombstone. Fixed: serializer now short-circuits on `None`.
- **LanceDBLoader._write_upsert — empty DataFrame crash**: passing an empty
  DataFrame called `db.create_table(table, data=[])` which raises in lancedb
  (needs at least one record to infer schema). Fixed: returns 0 immediately.
- **LanceDBLoader.search() — None/empty query_vector**: passing `None` or `[]`
  crashed inside lancedb with a cryptic error. Fixed: raises `ValueError` with
  a clear message before touching lancedb.
- **BAATracker.register_baa() — no date validation**: a malformed `expiry_date`
  string stored silently, then crashed `check_phi_load()` at enforcement time.
  Fixed: validates both date strings at registration with a clear error message.
- **IRBApprovalGate.register_protocol() — same date validation gap**: same
  pattern as BAATracker. Fixed with the same validation.
- **`NoReturn` missing from typing imports** in `pipeline_v3.py` — used as
  a string annotation but never imported.
- **3 spurious `f"..."` strings** with no placeholders in `pipeline_v3.py`.
- **1 unused variable** (`entry`) in `GovernanceLogger._event`.
- **7 pyflakes issues** in test files (unused imports and variables).
- 8 new tests added covering all 5 bug fixes (344 total).

---

## [4.13.0] — 2026-03-24

### Added
- **`KafkaLoader`** (destination #20) in `pipeline_v3.py` — publish governed,
  PII-masked DataFrames to Kafka topics with configurable keying, compression
  (gzip/snappy/lz4/zstd), delivery guarantees (acks=all), and upsert/tombstone
  support for log-compacted topics; `publish_governance_event()` method streams
  audit events to a dedicated Kafka topic in real time
- `KafkaLoader` also added to `pipeline_streaming.py` alongside `KafkaExtractor`
  for standalone streaming use
- 13 new Kafka tests in `test_loader_dispatch.py` (63 total)

### Fixed (bug scan)
- `KafkaLoader._publish_append` and `_publish_upsert` referenced bare `logger`
  which is not accessible inside class methods — fixed to use
  `import logging as _log` inline inside the except blocks
- 7 pyflakes issues across 4 test files: unused imports (`shutil`, `patch`,
  `QuickBooksExtractor`, `ReversibleLoader`, `ComplianceControlFailedError`),
  unused local variables (`clean`, `sink`) — all cleaned

---

## [4.12.0] — 2026-03-23

### Added
- **`grafana_extensions.py`** — three Grafana observability classes:
  - `MetricsSink` — writes pipeline run summaries, per-stage timing (rows/sec per stage), compliance control status, and audit ledger summaries to a SQLite database (`metrics.db`) queryable by Grafana's SQLite data source plugin
  - `PrometheusExporter` — exposes pipeline and compliance metrics on a local HTTP `/metrics` endpoint in Prometheus text exposition format; Grafana scrapes directly with no Prometheus server required; thread-safe counter/gauge updates; background daemon thread
  - `GrafanaDashboardGenerator` — generates a ready-to-import Grafana dashboard JSON with 12 pre-wired panels across 5 rows: pipeline overview stats, throughput time series, compliance controls table and pass-rate trend, audit event volume, PII detection and DLQ trends; supports both SQLite and Prometheus data source variants
- **`test_grafana_extensions.py`** — 60 tests covering all three classes

### Fixed
- `LanceDBLoader._write_upsert` used incorrect `merge_insert()` API (wrong keyword arguments); fixed to use the correct builder pattern: `.merge_insert(on).when_matched_update_all().when_not_matched_insert_all().execute(data)`
- Added two upsert-specific tests to lock correct behaviour

---

## [4.11.0] — 2026-03-23

### Added
- **`LanceDBLoader`** (destination #19) in `pipeline_v3.py` — serverless vector database loader; supports append, overwrite, and upsert (merge_insert builder pattern); pre-computed embedding column support; auto-generate embeddings via sentence-transformers; ANN index creation; vector similarity search; works with local paths and cloud URIs (S3, GCS, Azure Blob)
- 13 new LanceDB tests in `test_loader_dispatch.py` (50 total)

---

## [4.10.0] — 2026-03-11

### Added
- **`epic_extensions.py`** — six new classes for Epic EHR / HIPAA healthcare governance:
  - `HIPAASafeHarborFilter` — full 45 CFR §164.514(b) Safe Harbor de-identification; all 18 identifier types, ZIP restriction rules, age-≥-90 capping
  - `ClarityExtractor` — Epic Clarity (SQL Server) extractor with automatic ZC_ code-table decoding and nightly ETL refresh-window guard
  - `BAATracker` — Business Associate Agreement registry; gates PHI loads, warns on expiry, HTML register report
  - `IRBApprovalGate` — IRB/QI protocol registry; column-level gating per approved data elements, JSONL usage log for annual IRB reporting
  - `OMOPTransformer` — maps six Clarity tables to OMOP CDM v5.4 (PERSON, VISIT_OCCURRENCE, CONDITION_OCCURRENCE, DRUG_EXPOSURE, MEASUREMENT, PROCEDURE_OCCURRENCE); optional vocabulary concept_id resolution
  - `PHIKAnonymityChecker` — k-anonymity and l-diversity enforcement with suppress / report / raise actions
- **`test_epic_extensions.py`** — 76 tests covering all six epic_extensions classes
- External code review applied to `governance_extensions.py`: fixed `IN (:sid, :shash)` SQL portability (→ OR clause), added `logger.warning()` to three silent bare `except` blocks, removed 7 unused imports, fixed spurious f-string prefix

### Changed
- `governance_extensions.py` — pyflakes clean; test suite 81/81

---

## [4.9.0] — 2026-03-10

### Added
- `HanaLoader` (destination #16) — SAP HANA via `hdbcli`
- `DatasphereLoader` (destination #17) — SAP Datasphere via OData v4 / OAuth2
- `QuickBooksExtractor` + `QuickBooksLoader` (destination #18) — QuickBooks Online OAuth2 REST API

### Fixed
- Loader dispatch bug: `_dispatch_loader()` now correctly routes to all 18 destinations
- 10 failing tests in `test_governance_extensions.py` (SQLite WAL mode, shared temp dir isolation, logging handler leaks)

---

## [4.8.0] — 2026-03-09

### Added
- `run_governance_preflight()` in `pipeline_v3.py` — pre-run governance gate checking 7 artefacts (schema baseline, anomaly baseline, column purpose registry, purpose registry, data contracts, consent DB, prior violations)
- `governance_extensions.py` — 8 governance classes: `RoPAGenerator`, `RetentionEnforcer`, `DSARResponder`, `BreachDetector`, `ConsentManager`, `DifferentialPrivacyTransformer`, `PurposeLimitationEnforcer`, `PseudonymVault`
- `test_governance_extensions.py` — 81 tests

### Fixed
- 27 bugs across pipeline_v3.py, pipeline_v2.py, pipeline_streaming.py, pipeline_api.py, governance_extensions.py, pipeline_scheduler.py (bug scan sessions 1–10)

---

## [4.7.0] — 2026-02-28

### Added
- `PIIDiscoveryReporter` — GDPR/CCPA annotated PII scan with HTML + JSON report
- `TableCopier` — copy tables between any two supported SQL destinations
- `NLPipelineBuilder` — natural language pipeline configuration via Claude API
- `DLQReplayer` — dead letter queue replay with fix functions

---

## [4.6.0] — 2026-02-20

### Added
- `DataContractEnforcer` — YAML-defined schema/SLA/quality contracts with CRITICAL/ERROR/WARNING severity
- `CostEstimator` — pre-run cost estimation across all 15 destinations
- `ReversibleLoader` — snapshot + rollback support for any loader

### Changed
- Governance wizard simplified to 5 questions (previously 12)
- All log output unified into single `gov_logs/` directory

---

## [4.5.0] — 2026-02-10

### Added
- `LineageGraphGenerator` v2 — full column-level lineage with HTML visualisation
- `QualityAnomalyAlerter` — statistical anomaly detection with rolling baselines
- `DataQualityScorer` — composite quality score with dimension breakdown
- `HTMLReportGenerator` — pipeline run summary HTML report
- `SchemaEvolver` — automatic schema migration (add/drop/rename columns)
- `SyntheticDataGenerator` — GDPR-safe synthetic data generation for testing
- `DataDiffReporter` — before/after comparison with diff highlighting

---

## [4.0.0] — 2026-01-15

### Added
- `pipeline_streaming.py` — Kafka, Kinesis, Pub/Sub extractors
- `pipeline_scheduler.py` — cron-style pipeline scheduler
- `pipeline_api.py` — REST API server (`/run`, `/status` endpoints)
- `catalog_connectors.py` — Collibra, Alation, Atlan, Informatica connectors
- `metadata_extensions.py` — 16 metadata and lineage management classes
- `pipeline_additions.py` — 10 data product and observability classes

---

## [3.0.0] — 2025-12-01

### Added
- 15 cloud/enterprise loader destinations (Snowflake, Redshift, BigQuery, Synapse, Databricks, ClickHouse, Oracle, DB2, Firebolt, Yellowbrick, Hana, Datasphere, ...)
- AES-256 column encryption (`ColumnEncryptor`)
- Tamper-evident SHA-256 audit ledger chain (`GovernanceLogger`)
- GDPR Art. 17 erasure across all destinations (`ErasureHandler`)
- Cross-border transfer logging (`CrossBorderTransferLogger`)
- Great Expectations-style schema validation (`SchemaValidator`)
- SLA monitoring (`SLAMonitor`), metrics collection (`MetricsCollector`)
- Checkpoint/resume (`CheckpointManager`), dead letter queue (`DeadLetterQueue`)
- Parallel chunked processing, compression (gz/bz2/zip), incremental loading

---

## [2.0.0] — 2025-10-01

### Added
- `pipeline_v2.py` — extended pipeline with 5 destinations, secrets management, retry logic
- PII detection and masking
- Interactive GDPR/CCPA compliance wizard
- Business rules engine, data enrichment, referential integrity checking

---

## [1.0.0] — 2025-08-01

### Added
- `pipeline.py` — original minimal ETL (CSV/JSON → SQLite/PostgreSQL/MySQL/MSSQL/MongoDB)
- Basic transformation, type coercion, data standardisation
