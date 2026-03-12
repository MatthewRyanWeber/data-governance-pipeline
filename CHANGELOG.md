# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
