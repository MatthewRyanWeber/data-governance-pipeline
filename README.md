[![Tests](https://github.com/MatthewRyanWeber/data-governance-pipeline/actions/workflows/test.yml/badge.svg)](https://github.com/MatthewRyanWeber/data-governance-pipeline/actions/workflows/test.yml)
[![Docker](https://github.com/MatthewRyanWeber/data-governance-pipeline/actions/workflows/docker.yml/badge.svg)](https://github.com/MatthewRyanWeber/data-governance-pipeline/actions/workflows/docker.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

# Data Governance Pipeline

**Production-grade Python ETL with built-in GDPR, CCPA, and HIPAA compliance.**

Most data pipelines make you bolt governance on afterwards -- a separate catalog tool, a separate compliance layer, a separate audit system. This project builds all of it into the pipeline itself: extract, transform, load, and govern in one Python stack with no external orchestration services required. Multi-tenant data catalog, OpenLineage lineage tracking, field-level encryption, append-only audit ledger, circuit breakers with retry backoff, Prometheus metrics, and a live HTML dashboard -- all included out of the box.

---

## Quick Start

**1. Install**

```bash
git clone https://github.com/matthewryanweber/data-governance-pipeline.git
cd data-governance-pipeline
pip install -e ".[dev]"
```

**2. Configure credentials**

```bash
cp .env.example .env
# Edit .env with your database credentials and SMTP settings
```

**3. Run your first pipeline**

```bash
# Load a CSV into PostgreSQL
pipeline run data.csv postgresql --table customers

# Profile a dataset
pipeline profile data.csv

# Validate against a schema
pipeline validate data.csv --schema schema.json

# Resume an interrupted run
pipeline resume
```

**4. Start the REST API**

```bash
python -m pipeline.api
# Swagger docs at http://localhost:5000/docs

# Or with Docker:
docker compose up pipeline-api
```

**5. Install optional drivers**

```bash
pip install -e ".[cloud]"        # Snowflake, BigQuery, Databricks, etc.
pip install -e ".[streaming]"    # Kafka / Kinesis / Pub/Sub
pip install -e ".[healthcare]"   # Epic Clarity (pyodbc + pyarrow for OMOP)
pip install -e ".[vector]"       # Chroma, Milvus, Pinecone, Weaviate, Qdrant
pip install -e ".[all]"          # Everything
```

---

## What It Does

Point it at a data source, tell it where to send the data, and it handles everything in between: cleaning, validating, masking PII, auditing every action to a tamper-evident ledger, and loading into your chosen destination. A full interactive wizard walks you through GDPR/CCPA compliance questions before anything runs.

```bash
pipeline run <source> <destination>
```

For healthcare data from Epic EHR systems, `pipeline.extensions.epic_extensions` adds a complete HIPAA compliance layer on top.

This is **governance-first ETL** — compliance is the spine, not a bolt-on.
It is deliberately *not* an iPaaS connector marketplace, a transformation
framework, or an orchestrator; [docs/SCOPE.md](docs/SCOPE.md) states
exactly what it is and what it refuses to be.

### Watch the governance happen

Everything below is the **actual output** of one run — not an illustration.
Load a CSV containing PII into SQLite:

```bash
$ cat customers.csv
id,name,email,phone,ssn,city
1,Alice Larsen,alice.larsen@example.com,555-0101,123-45-6789,Oslo
2,Bob Chen,bob.chen@example.com,555-0102,987-65-4321,Austin
3,Carol Diaz,carol.diaz@example.com,555-0103,555-12-3456,Madrid

$ pipeline run customers.csv sqlite --table customers --config cfg.json --verify
```

What lands in the destination — PII pseudonymized, lineage stamped:

```
sqlite> SELECT id, name, email, ssn, _pipeline_id FROM customers;
1 | Alice Larsen | MASKED_f37b65a9fd59 | MASKED_01a54629efb9 | 7b99aefd-74ab-...
2 | Bob Chen     | MASKED_3c994d9355c7 | MASKED_ecdbc061a36d | 7b99aefd-74ab-...
3 | Carol Diaz   | MASKED_f12699088c27 | MASKED_175dbb7c6c96 | 7b99aefd-74ab-...
```

What lands in the audit ledger — every action chained by SHA-256, each
event's `prev_hash` binding it to the one before:

```json
{"action": "PII_MASKED", "category": "PRIVACY", "detail": {"field": "ssn"},
 "prev_hash": "d155955232d2f17d…", "self_hash": "bbf4efa9dc778bc8…"}
{"action": "LOAD_COMPLETE", "category": "LINEAGE",
 "detail": {"destination_table": "customers", "rows_written": 3},
 "prev_hash": "83c59e3b29dc937b…", "self_hash": "1019f0d26535b7ae…"}
```

And the anchor sidecar that makes deleting or truncating the ledger
detectable:

```json
{"last_hash": "d62a8bb0cc21d352…", "entry_count": 15,
 "ledger_file": "audit_ledger_20260612_142451.jsonl"}
```

The full regulation-to-code map — which GDPR/CCPA/HIPAA article each of
these artifacts answers — is in [docs/GOVERNANCE.md](docs/GOVERNANCE.md).

---

## Architecture

The codebase is organized as a **7-layer import DAG** (Layers 0-6). Each module
may only import from its own layer or below, never upward. This prevents circular
imports and keeps dependency relationships explicit.

```
  Layer 6  ORCHESTRATION       cli, api, scheduler, service, watchdog
  Layer 5  ADVANCED            reversible loads, DLQ replay, NL builder
  Layer 4  LOADERS             41 destinations across 4 verification tiers
  Layer 3  DOMAIN SERVICES     privacy, quality, catalog, security,
                               monitoring, lineage, versioning, ml_governance,
                               reporting, streaming, extractors
  Layer 2  CORE PROCESSING     extract, transform, validate, profile,
                               checkpoint, compression, business rules
  Layer 1  AUDIT LEDGER        governance_logger (SHA-256 chained)
  Layer 0  FOUNDATION          constants, helpers, exceptions, logging
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full layer diagram,
data flow, module map, and extension guide.

---

## Feature Highlights

**ETL core**
- 17 source file formats plus SQL tables, Kafka, Kinesis, Pub/Sub, and QuickBooks Online — full reference in [docs/SOURCES.md](docs/SOURCES.md)
- 41 destinations across four verification tiers (27 core real-engine-verified, 3 emulator, 10 cloud-credential, 1 experimental — see Supported Destinations)
- Chunked parallel processing, compression (gz/bz2/zip/zstd/lz4), incremental loading, checkpoint/resume
- Optional DuckDB read engine (`compute_engine: duckdb`) for ~2x faster
  delimited-text ingestion; rows are handed to the *same* governance stages, so
  output is byte-identical (enforced by `tests/test_compute_engine_equivalence.py`)
- Modular architecture: 138 Python modules across 15 subpackages with a 7-layer import DAG

**Data governance -- GDPR / CCPA**
- Append-only tamper-evident SHA-256 audit ledger -- every event is chained; seek/truncate blocked at the file handle level; external truncation detected
- PII discovery with GDPR Article / CCPA section annotations and HTML report
- NLP-powered PII detection -- spaCy NER + regex fallback for unstructured text (50+ entity types)
- GDPR Art. 17 erasure across all destinations in a single call
- Consent management with per-subject, per-purpose consent, expiry, and withdrawal
- Purpose limitation -- drops columns not approved for the declared purpose
- Pseudonymization vault with Fernet encryption, context separation, and key rotation
- Differential privacy with per-column noise injection and privacy budget tracking
- Record of Processing Activities (RoPA) generator -- GDPR Art. 30
- Data Subject Access Request (DSAR) workflow -- GDPR Art. 15/20
- Breach detector with statistical anomaly patterns
- Data contracts (YAML-defined schema/SLA/quality) with CRITICAL/ERROR/WARNING enforcement
- Schema drift detection, anomaly alerting, cross-border transfer logging
- RBAC access policies -- column whitelist/blacklist, row-level filtering, fail-closed enforcement

**Data catalog and metadata**
- Multi-tenant SQLite-backed data catalog with FTS5 full-text search and tenant isolation
- Business glossary -- maps business terms to physical columns with domain tagging
- Automated column profiling -- null rates, cardinality, distributions, value frequency
- Automated test generation -- creates Great Expectations suites from column profiles
- ML model registry -- tracks models, training datasets, lineage, and version comparison
- Data versioning -- content-addressable snapshots with diff and time-travel checkout
- OpenLineage event emitter -- interoperable lineage in OpenLineage JSON spec v2.0.2, multi-tenant facets

**Data observability**
- Freshness monitoring, volume anomaly detection, distribution drift alerts
- Null-spike detection on critical fields; **business-key duplicate detection**
  (catches same-key-different-timestamp duplicates that row counts and full-row
  dedup miss — configure `observability.business_keys`)
- Column-level data lineage graph with HTML visualisation
- Quality scoring, anomaly alerts, SLA monitoring, run metrics
- Prometheus `/metrics/prometheus` endpoint for scraping, plus Grafana dashboard export
- Cost estimator (pre-run), reversible loads with snapshot rollback
- Natural language pipeline builder (Claude API)
- REST API server with live HTML dashboard, cron-style scheduler, process watchdog
- Circuit breakers with exponential-backoff retry on all loaders
- Field-level transparent Fernet encryption on load (opt-in per column)
- Property-based testing with Hypothesis for security-critical paths

**Healthcare / HIPAA** -- `pipeline.extensions.epic_extensions`
- HIPAA Safe Harbor de-identification (45 CFR SS164.514(b)) -- all 18 identifier types, ZIP restriction rules, age->=90 capping
- Epic Clarity extractor with automatic ZC_ code-table decoding and ETL refresh-window guard
- Business Associate Agreement (BAA) registry -- gates every PHI load
- IRB/QI protocol registry -- column-level enforcement of approved data elements
- OMOP CDM v5.4 transformer -- maps 6 Clarity tables to research-standard domain tables
- k-anonymity and l-diversity checker with suppress / report / raise enforcement modes

**Continuous compliance monitoring** -- `pipeline.extensions.compliance_extensions`
- 8 automated controls: audit ledger integrity, encryption keys, consent DB, BAA/IRB expiry, vendor reviews, log directory
- Vendor risk registry -- SOC 2 status, DPA tracking, risk classification
- Trust report generator -- customer-facing security posture HTML report

**Grafana integration** -- `pipeline.extensions.grafana_extensions`
- MetricsSink -- SQLite for Grafana's SQLite data source plugin
- PrometheusExporter -- `/metrics` HTTP endpoint in Prometheus text format
- GrafanaDashboardGenerator -- ready-to-import JSON dashboard

**Performance and scale**
- Single node: streaming, per-chunk, checkpointed (flat memory, resume from the
  last chunk) — sized for the **~1 GB–1 TB/day** range
- Transform PII masking is **~2.7x faster** with byte-identical output
  (per-distinct-value masking + an `infer_dtype` pre-filter); optional DuckDB
  read engine is **~2x faster** on delimited text — same governance stages,
  output byte-identical (enforced by `tests/test_compute_engine_equivalence.py`)
- Scales out (Path A): per-partition governance under Spark into a partitionable
  Merkle ledger — no shared-writer bottleneck. Measured **governance-compute** on
  one 12-core box (full PII masking + tamper-evident ledger, verified each run):
  **~22k rows/s** at 100 partitions, **~100k rows/s** at 20 larger partitions
  (the 4.5x swing is per-partition fixed cost — use fewer, larger partitions).
  That's ~0.38–1.73 TB/day/box; **100 TB/day is ~58 such boxes**, a design
  property (no shared write path), not a single process scaled up.
- Honest caveat: these are governance-compute numbers in Spark local mode, **not**
  end-to-end throughput to a destination (network + warehouse write dominate in
  production and are destination-dependent). Full method:
  [docs/DISTRIBUTED_GOVERNANCE.md](docs/DISTRIBUTED_GOVERNANCE.md), benchmark:
  `scripts/bench_distributed_governance.py`

---

## Supported Destinations

Every destination carries a **verification tier** that states honestly how
it is tested.  `pipeline destinations` prints this catalog; the
`/destinations` API endpoint serves it as JSON. (The CLI lists 42 rows —
41 distinct destinations across four tiers below, plus the `postgres` alias
of PostgreSQL.)

<!-- TIER-COUNTS: core=28 emulator=3 cloud=10 experimental=1 -->

### Core — tested against a real engine in CI on every push (27)

| Category | Destinations |
|----------|-------------|
| Relational SQL | PostgreSQL, MySQL, SQL Server, SQLite |
| Analytical | ClickHouse, DuckDB, Oracle Free, DB2 |
| Wire-compatible | Azure Synapse (T-SQL via real SQL Server), Yellowbrick (PostgreSQL protocol), CockroachDB |
| Geo / vector SQL | PostGIS, pgvector |
| Data lake formats | Parquet, Delta Lake, Apache Iceberg |
| Object storage | S3 (MinIO), Azure Blob (Azurite), SFTP, Microsoft Fabric / OneLake (ADLS via Azurite) |
| Streaming | Kafka (Redpanda) |
| NoSQL / vector | MongoDB, Chroma, LanceDB, Qdrant, Weaviate, Milvus |

Each runs append / replace / upsert round-trips against the live engine
and reads the data back through the engine's own client
(`tests/integration/`).

Confirmed live-service verifications are logged in
[docs/CLOUD_VERIFICATION.md](docs/CLOUD_VERIFICATION.md) (MotherDuck and
Databricks: both CI-confirmed 2026-06-13).

### Emulator-verified — mechanics proven, vendor quirks not (3)

| Destination | Emulator | Not covered |
|-------------|----------|-------------|
| Snowflake | fakesnow | stages/PUT+COPY bulk path, warehouses, roles |
| BigQuery | goccy/bigquery-emulator | LOAD jobs, slots, IAM |
| Pinecone | pinecone-local | serverless scaling, pod indexes |

### Cloud-credential — verified against the live service when secrets are configured (10)

GCS (gcsfs), Redshift, Databricks, Firebolt, SAP HANA, SAP Datasphere,
MotherDuck, QuickBooks Online (sandbox), Snowflake Vector, BigQuery Vector.

The weekly `integration-cloud` workflow runs each of these the moment its
repository secrets exist — adding a credential automatically upgrades that
destination's verification. Without credentials they are mock-tested only
(every loader passes the shared behavioral contract in
`tests/test_loaders/test_loader_contract.py`).

### Experimental — wired and mock-tested only, no engine/emulator proof (1)

| Destination | Status |
|-------------|--------|
| Athena | Loader wired; the S3 staging path can be exercised against MinIO, but the Athena query API (MSCK REPAIR) is only mock-tested — no free real engine for it. Do not rely on the query path in production. |

Resolving an experimental destination logs a warning to that effect.

---

## API Documentation

The REST API server exposes a Swagger / OpenAPI documentation page:

```bash
python -m pipeline.api
# Open http://localhost:5000/docs
```

Key endpoints:

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/health` | GET | No | Health check with circuit breaker state |
| `/dashboard` | GET | No | Live HTML dashboard (status, runs, breakers) |
| `/destinations` | GET | Yes | Destination catalog with verification tiers |
| `/run` | POST | Yes | Trigger a pipeline run |
| `/status` | GET | Yes | Current run status with progress |
| `/runs` | GET | Yes | Run history with pagination |
| `/runs/<id>/cancel` | POST | Yes | Cancel a queued or running pipeline |
| `/metrics` | GET | Yes | Pipeline run metrics |
| `/metrics/prometheus` | GET | No | Prometheus text exposition endpoint |
| `/auth/token` | POST | Yes | Exchange API key for JWT |
| `/auth/revoke` | POST | Yes | Revoke a JWT by jti |
| `/docs` | GET | No | Swagger UI documentation |
| `/openapi.json` | GET | No | OpenAPI 3.0 spec |

Authenticated endpoints require a Bearer token or `X-API-Key` header set via
the `PIPELINE_API_KEYS` environment variable. JWT auth is available when
`PIPELINE_JWT_SECRET` is configured.

---

## Project Layout

```
data-governance-pipeline/
+-- pipeline_v3.py                    # Backward-compat shim
+-- pipeline/                         # Modular package (136 files, 14 subpackages)
|   +-- constants.py                  # Layer 0 -- flags, paths, version
|   +-- governance_logger.py          # Layer 1 -- tamper-evident audit ledger
|   +-- append_only_writer.py         # Layer 0 -- write-once file handle (seek/truncate blocked)
|   +-- extract.py                    # Layer 2 -- 12-format extractor
|   +-- transform.py                  # Layer 2 -- cleaning, dedup, PII masking
|   +-- profiler.py                   # Layer 2 -- column profiling
|   +-- schema_validator.py           # Layer 2 -- Great Expectations integration
|   +-- business_rules.py             # Layer 2 -- rule engine
|   +-- loaders/                      # destination loaders (tiered catalog, see Supported Destinations)
|   |   +-- base.py                   # BaseLoader, SQL identifier validation
|   |   +-- sql_loader.py             # PostgreSQL / MySQL / SQL Server
|   |   +-- snowflake_loader.py
|   |   +-- bigquery_loader.py
|   |   +-- vector/                   # 9 vector DB loaders
|   |   +-- ...
|   +-- privacy/                      # PII detection, encryption, erasure, GDPR
|   |   +-- nlp_pii_detector.py       # NER-based PII scanner
|   |   +-- column_encryptor.py
|   |   +-- erasure_handler.py
|   |   +-- ...
|   +-- quality/                      # Scoring, anomalies, contracts, profiling
|   |   +-- column_profiler.py        # Automated column statistics
|   |   +-- test_generator.py         # Auto-generate Great Expectations
|   |   +-- data_quality_scorer.py
|   |   +-- ...
|   +-- catalog/                      # Data catalog + business glossary
|   |   +-- catalog_store.py          # SQLite-backed metadata store
|   |   +-- catalog_search.py         # FTS5 full-text search
|   |   +-- glossary.py               # Business glossary
|   +-- security/                     # RBAC access policies
|   |   +-- access_policy.py
|   +-- monitoring/                   # SLA, metrics, observability
|   |   +-- observability.py          # Freshness, volume, drift, null-spike, dup-keys
|   |   +-- sla_monitor.py
|   |   +-- metrics_collector.py
|   +-- lineage/                      # OpenLineage event emitter
|   |   +-- openlineage_emitter.py
|   +-- versioning/                   # Content-addressable data snapshots
|   |   +-- snapshot_store.py
|   +-- ml_governance/                # AI/ML model registry
|   |   +-- model_registry.py
|   +-- dashboard.py                  # Layer 6 -- self-contained HTML dashboard
|   +-- advanced/                     # Reversible loads, DLQ replay, NL builder
|   +-- reporting/                    # HTML reports, lineage graphs, cost estimator
|   +-- streaming/                    # Kafka/Kinesis/Pub/Sub extractors
+-- tests/                            # ~1,990 unit + 63 live-engine tests, 88 files
|   +-- test_loaders/                 # Per-loader tests + the shared loader contract
|   |   +-- test_loader_contract.py   # Family contract enforced on every registry entry
|   +-- test_extensions/              # Governance, HIPAA, compliance, Grafana
|   +-- integration/                  # 61 live-engine tests (containers + emulators)
|   +-- test_property_based.py        # Hypothesis property-based testing (deterministic)
+-- docs/                             # Legal, architecture, and extension docs
|   +-- ARCHITECTURE.md               # Full architecture reference
|   +-- EXTENDING.md                  # Guide for writing custom loaders
|   +-- DEPLOYMENT.md                 # Production deployment guide
|   +-- PRIVACY.md                    # Privacy policy
|   +-- TERMS.md                      # Terms of service
|   +-- CCPA.md                       # CCPA compliance mapping
+-- pyproject.toml                    # Package metadata and optional install extras
+-- .github/workflows/test.yml        # CI: lint, test (3 Python versions), 5-way engine matrix
+-- .github/workflows/integration-cloud.yml  # Weekly cloud-tier verification
+-- Dockerfile                        # Multi-stage Python 3.12 image
+-- docker-compose.yml                # Production-ready API server + test runner
+-- CLAUDE.md                         # Coding standards
+-- .env.example                      # Credential template
```

---

## Usage Examples

### Data catalog and profiling

```python
from pipeline.catalog import CatalogStore, CatalogSearch, BusinessGlossary
from pipeline.quality.column_profiler import ColumnProfiler
from pipeline.governance_logger import GovernanceLogger

gov = GovernanceLogger(run_id="run_001", src="crm_export")

# Register a dataset in the catalog
cat = CatalogStore(gov)
cat.register_dataset(df, "customers", owner="data-team", domain="CRM",
                     tags=["production", "pii"])

# Profile columns automatically
profiler = ColumnProfiler(gov)
profile = profiler.profile(df, dataset_name="customers")
# -> null rates, cardinality, distributions, top values per column

# Full-text search across all registered datasets
search = CatalogSearch(gov)
results = search.search("customer email PII")

# Business glossary
glossary = BusinessGlossary(gov)
glossary.add_term("Customer LTV", "Lifetime value in USD",
                  domain="Finance", columns=["customers.ltv_usd"])
```

### RBAC access control

```python
from pipeline.security import AccessPolicy

policy = AccessPolicy(gov)
policy.add_role("analyst",
                allowed_columns=["name", "revenue", "region"],
                denied_columns=["ssn", "salary"],
                row_filter="region == 'US'")
policy.assign_role("alice", "analyst")

safe_df = policy.enforce(df, user="alice", dataset="customers")
# -> ssn and salary dropped, only US rows returned
```

### Data versioning and lineage

```python
from pipeline.versioning import SnapshotStore
from pipeline.lineage import OpenLineageEmitter

# Content-addressable snapshots
store = SnapshotStore(gov)
v1 = store.snapshot(df, "customers", message="Initial load")
v2 = store.snapshot(df_updated, "customers", message="Added email column")
diff = store.diff("customers", version_a=1, version_b=2)
old_df = store.checkout("customers", version=1)  # time travel

# OpenLineage events (compatible with Marquez, DataHub, OpenMetadata)
emitter = OpenLineageEmitter(gov, namespace="production")
emitter.emit_start("extract", inputs=["s3://bucket/raw.csv"])
emitter.emit_complete("extract", outputs=["postgres://db/staging"])
```

### ML model governance

```python
from pipeline.ml_governance import ModelRegistry

reg = ModelRegistry(gov)
reg.register_model("churn_predictor", framework="sklearn",
                   datasets=["customers", "transactions"])
reg.log_training_run("churn_predictor",
                     metrics={"accuracy": 0.92, "f1": 0.88})

# Which models break if the customers table changes?
affected = reg.impact_analysis("customers")
```

### NLP PII detection

```python
from pipeline.privacy.nlp_pii_detector import NLPPIIDetector

detector = NLPPIIDetector(gov)
findings = detector.scan(df, text_columns=["notes", "comments"])
# -> finds emails, phone numbers, SSNs, credit cards via regex
# -> finds person names, locations, organizations via spaCy NER
classification = detector.scan_and_classify(df)
```

### GDPR governance

```python
from pipeline.governance_logger import GovernanceLogger
from governance_extensions import RoPAGenerator, ConsentManager, PseudonymVault

gov = GovernanceLogger(run_id="run_001", src="hr_system")

# Record of Processing Activities (GDPR Art. 30)
ropa = RoPAGenerator(gov)
ropa.add_activity(
    id="HR-001", name="Employee payroll",
    purpose="payroll", legal_basis="contractual necessity",
    data_subjects=["employees"],
    data_categories=["salary", "bank_account"],
    recipients=["payroll_provider"],
    retention="7 years",
    security_measures=["AES-256 encryption", "access logging"],
)
ropa.save_html("ropa_report.html")
```

### HIPAA Safe Harbor de-identification

```python
from pipeline.governance_logger import GovernanceLogger
from pipeline.extensions.epic_extensions import HIPAASafeHarborFilter, BAATracker

gov  = GovernanceLogger(run_id="run_001", src="clarity_extract")
safe = HIPAASafeHarborFilter(gov, hash_identifiers=True)

# De-identify -- all 18 HIPAA identifiers, ZIP rules, age capping
clean_df = safe.apply(clarity_df, source_label="PAT_ENC")

# Gate PHI loads behind valid BAA
tracker = BAATracker(gov)
tracker.register_baa(
    destination_id="snowflake_research",
    vendor="Snowflake Inc.",
    signed_date="2024-01-15",
    expiry_date="2026-01-14",
    phi_types=["encounter_data", "diagnosis_codes"],
)
tracker.check_phi_load("snowflake_research")  # raises if BAA missing/expired
```

---

## Running Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q
```

**~1,970 unit tests plus 63 live-engine integration tests, all passing.**

> **Expected skips:** two tests in `tests/test_schema_validator.py` skip
> unless Great Expectations 1.x is importable. GX is an optional dependency
> (not in the default CI deps) and GX 1.x is uninstallable on Python 3.14
> (it requires `<3.14`), so a stock run reports `2 skipped` — this is the
> optional-dependency signal, not a failure. To run them, install GX on a
> supported interpreter (3.10–3.13): `pip install "great_expectations>=1.0"`.

The suite spans three fidelity levels so bugs are caught wherever they hide:

- **Unit tests** -- every public method, validation guard, and error path.
- **The loader family contract** -- one parameterized suite
  (`tests/test_loaders/test_loader_contract.py`) runs the same behavioral
  assertions against every entry in the dispatch registry: dry-run returns
  0, keyless upsert raises, empty config raises, injection column names
  are rejected. New loaders are covered automatically the moment they are
  registered.
- **Real round-trips** -- every core-tier destination runs append /
  replace / upsert against its genuine engine via
  [testcontainers](https://testcontainers.com) or an embedded runtime,
  and the data is read back through the engine's own client. Emulator-tier
  destinations run against fakesnow, bigquery-emulator, and
  pinecone-local with the uncovered surface documented per engine.

Every loader also shares a verified **safety contract**: SQL injection in
table and column names is rejected before any connection is opened, and
optional-driver loaders fail with a clear install hint when the driver is
absent.

### Live integration tests (Docker)

`tests/integration/` starts real engine containers and runs the loaders
end-to-end. They require a running Docker engine and **skip cleanly when
Docker is unavailable**, so the unit suite is never blocked.

```bash
pip install -e ".[dev,integration]"
python -m pytest tests/integration tests/test_integration_db.py -v -m integration
```

### Coverage

```bash
pip install pytest-cov
python -m pytest tests/ --cov=pipeline --cov-report=term-missing
```

### Docker

```bash
docker build -t data-governance-pipeline .
docker run --rm data-governance-pipeline python -m pytest tests/ -q
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values.

| Variable | Purpose |
|---|---|
| `DB_HOST` | Database host |
| `DB_PORT` | Database port |
| `DB_NAME` | Database name |
| `DB_USER` | Database username |
| `DB_PASSWORD` | Database password |
| `DB_TABLE` | Target table name |
| `MONGO_URI` | MongoDB connection string |
| `PIPELINE_API_KEYS` | Comma-separated API keys for REST API auth |
| `SMTP_HOST` | SMTP host for email notifications |
| `SMTP_USER` | SMTP username |
| `SMTP_PASSWORD` | SMTP password |
| `NOTIFY_FROM` | Notification sender address |
| `NOTIFY_TO` | Comma-separated notification recipients |
| `SLACK_WEBHOOK` | Slack incoming webhook URL |

---

## Compliance Coverage

| Standard | Coverage |
|---|---|
| GDPR Art. 17 -- right to erasure | `ErasureHandler` -- all destinations |
| GDPR Art. 15/20 -- subject access | `DSARResponder` -- portable export |
| GDPR Art. 25 -- privacy by design | Consent gate, purpose limitation, pseudonymisation |
| GDPR Art. 30 -- records of processing | `RoPAGenerator` |
| GDPR Art. 32 -- security | AES-256 encryption, tamper-evident audit chain |
| GDPR Art. 33/34 -- breach notification | `BreachDetector` with statistical detection |
| CCPA SS1798.100-199 | PII detection, consent, erasure, portability |
| HIPAA Safe Harbor SS164.514(b) | All 18 identifiers, ZIP rules, age->=90 |
| HIPAA BAA SS164.308(b)(1) | `BAATracker` -- gates every PHI load |
| HIPAA Minimum Necessary | `IRBApprovalGate` -- column-level enforcement |
| OMOP CDM v5.4 | `OMOPTransformer` -- 6 domain table mappings |

---

## Security

- **RBAC enforcement** -- fail-closed column/row access policies with injection-safe row filters
- **SQL injection protection** -- `validate_sql_identifier()` on all table/schema/column names across all loaders
- **XXE protection** -- `defusedxml` for all XML parsing
- **Archive safety** -- path traversal and zip bomb protection in decompression
- **Atomic config writes** -- write-to-temp-then-rename prevents corruption on crash
- **Credential management** -- .env files gitignored, secrets never logged, SensitiveDataFilter scrubs log output
- **Input validation** -- path traversal protection, identifier regex validation on all API inputs
- **API authentication** -- Bearer token required on all endpoints (except /health)
- **Audit trail** -- SHA-256 chained tamper-evident ledger of all operations

---

## Documentation

Start at **[docs/README.md](docs/README.md)** — it routes you to the right
doc by why you're here (using it, evaluating the compliance story, running
it in production, or changing the code) so you don't have to wade through
all of them. Highlights: [SCOPE.md](docs/SCOPE.md) (what it is / is not),
[GOVERNANCE.md](docs/GOVERNANCE.md) (regulation → code → artifact),
[ARCHITECTURE.md](docs/ARCHITECTURE.md) (layers + decision log),
[EXTENDING.md](docs/EXTENDING.md) (custom loaders).

## License

MIT -- see [LICENSE](LICENSE).

## Legal

- [Privacy Policy](docs/PRIVACY.md) -- Pipeline itself collects zero data. Guidance for processing PII/PHI.
- [Terms of Service](docs/TERMS.md) -- MIT license, data controller responsibilities, compliance tools are not compliance guarantees.
- [CCPA Compliance](docs/CCPA.md) -- Maps each CCPA right to specific pipeline features.

## Contributing

Issues and pull requests are welcome. Run the full test suite before submitting:

```bash
pytest -v
```
