# Data Governance Pipeline

**Production-grade Python ETL with built-in GDPR, CCPA, and HIPAA compliance.**

Most data pipelines make you bolt governance on afterwards — a separate catalog tool, a separate compliance layer, a separate audit system. This project builds all of it into the pipeline itself: extract, transform, load, and govern in one Python stack with no external orchestration services required.

---

## What it does

Point it at a data source, tell it where to send the data, and it handles everything in between: cleaning, validating, masking PII, auditing every action to a tamper-evident ledger, and loading into your chosen destination. A full interactive wizard walks you through GDPR/CCPA compliance questions before anything runs.

```bash
python pipeline_v3.py
```

For healthcare data from Epic EHR systems, `epic_extensions.py` adds a complete HIPAA compliance layer on top.

---

## Feature highlights

**ETL core**
- 12 source formats: CSV, JSON, Excel, XML, Parquet, Avro, ORC, SQL tables, Kafka, Kinesis, Pub/Sub, QuickBooks Online
- 37 destination loaders (28 standard + 9 vector): PostgreSQL, MySQL, SQL Server, MongoDB, Snowflake, Redshift, BigQuery, Azure Synapse, Databricks, ClickHouse, Oracle, DB2, Firebolt, Yellowbrick, SAP HANA, SAP Datasphere, QuickBooks, Kafka, CockroachDB, DuckDB, Parquet, Delta Lake, Iceberg, S3, Athena, SFTP, Microsoft Fabric, PostGIS
- 9 vector database loaders: pgvector, Snowflake Vector, BigQuery Vector, Chroma, Milvus, Pinecone, Weaviate, Qdrant, LanceDB
- Chunked parallel processing, compression (gz/bz2/zip/zstd/lz4), incremental loading, checkpoint/resume
- Modular architecture: 122 Python modules across 13 packages with a 7-layer import DAG

**Data governance — GDPR / CCPA**
- Tamper-evident SHA-256 audit ledger — every event is chained; any modification is detectable
- PII discovery with GDPR Article / CCPA section annotations and HTML report
- NLP-powered PII detection — spaCy NER + regex fallback for unstructured text (50+ entity types)
- GDPR Art. 17 erasure across all destinations in a single call
- Consent management with per-subject, per-purpose consent, expiry, and withdrawal
- Purpose limitation — drops columns not approved for the declared purpose
- Pseudonymization vault with Fernet encryption, context separation, and key rotation
- Differential privacy with per-column noise injection and privacy budget tracking
- Record of Processing Activities (RoPA) generator — GDPR Art. 30
- Data Subject Access Request (DSAR) workflow — GDPR Art. 15/20
- Breach detector with statistical anomaly patterns
- Data contracts (YAML-defined schema/SLA/quality) with CRITICAL/ERROR/WARNING enforcement
- Schema drift detection, anomaly alerting, cross-border transfer logging
- RBAC access policies — column whitelist/blacklist, row-level filtering, fail-closed enforcement

**Data catalog and metadata**
- SQLite-backed data catalog with FTS5 full-text search
- Business glossary — maps business terms to physical columns with domain tagging
- Automated column profiling — null rates, cardinality, distributions, value frequency
- Automated test generation — creates Great Expectations suites from column profiles
- ML model registry — tracks models, training datasets, lineage, and version comparison
- Data versioning — content-addressable snapshots with diff and time-travel checkout
- OpenLineage event emitter — interoperable lineage in OpenLineage JSON spec v2.0.2

**Data observability**
- Freshness monitoring, volume anomaly detection, distribution drift alerts
- Column-level data lineage graph with HTML visualisation
- Quality scoring, anomaly alerts, SLA monitoring, run metrics
- Cost estimator (pre-run), reversible loads with snapshot rollback
- Natural language pipeline builder (Claude API)
- REST API server and cron-style scheduler

**Healthcare / HIPAA** — `epic_extensions.py`
- HIPAA Safe Harbor de-identification (45 CFR §164.514(b)) — all 18 identifier types, ZIP restriction rules, age-≥-90 capping
- Epic Clarity extractor with automatic ZC_ code-table decoding and ETL refresh-window guard
- Business Associate Agreement (BAA) registry — gates every PHI load
- IRB/QI protocol registry — column-level enforcement of approved data elements
- OMOP CDM v5.4 transformer — maps 6 Clarity tables to research-standard domain tables
- k-anonymity and l-diversity checker with suppress / report / raise enforcement modes

**Continuous compliance monitoring** — `compliance_extensions.py`
- 8 automated controls: audit ledger integrity, encryption keys, consent DB, BAA/IRB expiry, vendor reviews, log directory
- Vendor risk registry — SOC 2 status, DPA tracking, risk classification
- Trust report generator — customer-facing security posture HTML report

**Grafana integration** — `grafana_extensions.py`
- MetricsSink — SQLite for Grafana's SQLite data source plugin
- PrometheusExporter — `/metrics` HTTP endpoint in Prometheus text format
- GrafanaDashboardGenerator — ready-to-import JSON dashboard

---

## Project layout

```
data-governance-pipeline/
├── pipeline_v3.py                    # Backward-compat shim — re-exports all public names
├── pipeline/                         # Modular package (112 files, 13 subpackages)
│   ├── constants.py                  # Layer 0 — flags, paths, version
│   ├── governance_logger.py          # Layer 1 — tamper-evident audit ledger
│   ├── extract.py                    # Layer 2 — 12-format extractor
│   ├── transform.py                  # Layer 2 — cleaning, dedup, PII masking
│   ├── profiler.py                   # Layer 2 — column profiling
│   ├── schema_validator.py           # Layer 2 — Great Expectations integration
│   ├── business_rules.py             # Layer 2 — rule engine
│   ├── loaders/                      # 28 standard + 9 vector destination loaders
│   │   ├── base.py                   # BaseLoader, SQL identifier validation
│   │   ├── sql_loader.py             # PostgreSQL / MySQL / SQL Server
│   │   ├── snowflake_loader.py
│   │   ├── bigquery_loader.py
│   │   ├── vector/                   # 9 vector DB loaders
│   │   └── ...
│   ├── privacy/                      # PII detection, encryption, erasure, GDPR
│   │   ├── nlp_pii_detector.py       # NER-based PII scanner
│   │   ├── column_encryptor.py
│   │   ├── erasure_handler.py
│   │   └── ...
│   ├── quality/                      # Scoring, anomalies, contracts, profiling
│   │   ├── column_profiler.py        # Automated column statistics
│   │   ├── test_generator.py         # Auto-generate Great Expectations
│   │   ├── data_quality_scorer.py
│   │   └── ...
│   ├── catalog/                      # Data catalog + business glossary
│   │   ├── catalog_store.py          # SQLite-backed metadata store
│   │   ├── catalog_search.py         # FTS5 full-text search
│   │   └── glossary.py               # Business glossary
│   ├── security/                     # RBAC access policies
│   │   └── access_policy.py
│   ├── monitoring/                   # SLA, metrics, observability
│   │   ├── observability.py          # Freshness, volume, drift
│   │   ├── sla_monitor.py
│   │   └── metrics_collector.py
│   ├── lineage/                      # OpenLineage event emitter
│   │   └── openlineage_emitter.py
│   ├── versioning/                   # Content-addressable data snapshots
│   │   └── snapshot_store.py
│   ├── ml_governance/                # AI/ML model registry
│   │   └── model_registry.py
│   ├── advanced/                     # Reversible loads, DLQ replay, NL builder
│   ├── reporting/                    # HTML reports, lineage graphs, cost estimator
│   └── streaming/                    # Kafka/Kinesis/Pub/Sub extractors
├── tests/                            # 1128 tests across 30+ test files
│   ├── test_new_features.py          # 38 tests for catalog, RBAC, lineage, etc.
│   ├── test_security.py              # Security hardening tests
│   ├── test_loaders/                 # Loader dispatch tests
│   └── test_extensions/              # Governance, HIPAA, compliance, Grafana
├── governance_extensions.py          # 8 GDPR/CCPA governance classes
├── epic_extensions.py                # 6 Epic EHR / HIPAA classes
├── compliance_extensions.py          # 3 continuous compliance monitoring classes
├── grafana_extensions.py             # 3 Grafana observability classes
├── pyproject.toml                    # Package metadata and optional install extras
├── CLAUDE.md                         # Coding standards
└── .env.example                      # Credential template — copy to .env
```

---

## Quick start

**1. Clone and install**

```bash
git clone https://github.com/matthewryanweber/data-governance-pipeline.git
cd data-governance-pipeline
pip install -e ".[dev]"
```

**2. Copy the credential template**

```bash
cp .env.example .env
# Edit .env with your database credentials and SMTP settings
```

**3. Run the CLI**

```bash
# Single pipeline run
pipeline run data.csv postgresql --table customers

# Validate a file against a schema
pipeline validate data.csv --schema schema.json

# Profile a dataset
pipeline profile data.csv

# Resume interrupted runs
pipeline resume

# Or run as a Python module
python -m pipeline run data.csv postgresql
```

**4. Run the REST API**

```bash
python -m pipeline.api
# Or with Docker:
docker compose up pipeline-api
```

**5. Optional: cloud and enterprise drivers**

```bash
pip install -e ".[cloud]"        # Snowflake, BigQuery, Databricks, etc.
pip install -e ".[streaming]"    # Kafka / Kinesis / Pub/Sub
pip install -e ".[healthcare]"   # Epic Clarity (pyodbc + pyarrow for OMOP)
pip install -e ".[sap]"          # SAP HANA and Datasphere
pip install -e ".[all]"          # Everything
```

---

## Usage examples

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
# → null rates, cardinality, distributions, top values per column

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
# → ssn and salary dropped, only US rows returned
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
# → finds emails, phone numbers, SSNs, credit cards via regex
# → finds person names, locations, organizations via spaCy NER
classification = detector.scan_and_classify(df)
```

### GDPR governance

```python
from pipeline_v3 import GovernanceLogger
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
from pipeline_v3 import GovernanceLogger
from epic_extensions import HIPAASafeHarborFilter, BAATracker

gov  = GovernanceLogger(run_id="run_001", src="clarity_extract")
safe = HIPAASafeHarborFilter(gov, hash_identifiers=True)

# De-identify — all 18 HIPAA identifiers, ZIP rules, age capping
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

## Running tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q
```

**1128 tests, all passing.**

| Suite | Tests |
|-------|------:|
| Loader dispatch | 232 |
| Extensions (governance, HIPAA, compliance, Grafana) | 257 |
| Governance logger | 31 |
| Privacy (PII, encryption, erasure, NLP) | 41 |
| Quality (scoring, contracts, anomalies, profiling) | 39 |
| Monitoring (metrics, SLA, observability, notifier) | 28 |
| Reporting (HTML, lineage, cost estimator) | 18 |
| Catalog (store, search, glossary) | 22 |
| CLI (arg parsing, dispatch, config loading) | 18 |
| Streaming (Kafka, Kinesis, Pub/Sub) | 12 |
| ML governance (model registry) | 18 |
| Lineage (OpenLineage emitter) | 10 |
| Advanced (NL builder, reversible loader, DLQ) | 16 |
| Security, logging, crash recovery, transform, etc. | 386 |
| **Total** | **1128** |

### Docker

```bash
docker build -t data-governance-pipeline .
docker run --rm data-governance-pipeline python -m pytest tests/ -q
```

---

## Environment variables

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
| `SMTP_HOST` | SMTP host for email notifications |
| `SMTP_USER` | SMTP username |
| `SMTP_PASSWORD` | SMTP password |
| `NOTIFY_FROM` | Notification sender address |
| `NOTIFY_TO` | Comma-separated notification recipients |
| `SLACK_WEBHOOK` | Slack incoming webhook URL |

---

## Compliance coverage

| Standard | Coverage |
|---|---|
| GDPR Art. 17 — right to erasure | `ErasureHandler` — all destinations |
| GDPR Art. 15/20 — subject access | `DSARResponder` — portable export |
| GDPR Art. 25 — privacy by design | Consent gate, purpose limitation, pseudonymisation |
| GDPR Art. 30 — records of processing | `RoPAGenerator` |
| GDPR Art. 32 — security | AES-256 encryption, tamper-evident audit chain |
| GDPR Art. 33/34 — breach notification | `BreachDetector` with statistical detection |
| CCPA §1798.100–199 | PII detection, consent, erasure, portability |
| HIPAA Safe Harbor §164.514(b) | All 18 identifiers, ZIP rules, age-≥-90 |
| HIPAA BAA §164.308(b)(1) | `BAATracker` — gates every PHI load |
| HIPAA Minimum Necessary | `IRBApprovalGate` — column-level enforcement |
| OMOP CDM v5.4 | `OMOPTransformer` — 6 domain table mappings |

---

## Security

- **RBAC enforcement** — fail-closed column/row access policies with injection-safe row filters
- **SQL injection protection** — `validate_sql_identifier()` on all table/schema/column names across all loaders
- **XXE protection** — `defusedxml` for all XML parsing
- **Archive safety** — path traversal and zip bomb protection in decompression
- **Atomic config writes** — write-to-temp-then-rename prevents corruption on crash
- **Credential management** — .env files gitignored, secrets never logged, SensitiveDataFilter scrubs log output
- **Input validation** — path traversal protection, identifier regex validation on all API inputs
- **API authentication** — Bearer token required on all endpoints (except /health)
- **Audit trail** — SHA-256 chained tamper-evident ledger of all operations

---

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [Privacy Policy](docs/PRIVACY.md) — Pipeline itself collects zero data. Guidance for processing PII/PHI.
- [Terms of Service](docs/TERMS.md) — MIT license, data controller responsibilities, compliance tools ≠ compliance guarantees.
- [CCPA Compliance](docs/CCPA.md) — Maps each CCPA right to specific pipeline features.

## Contributing

Issues and pull requests are welcome. Run the full test suite before submitting:

```bash
pytest -v
```
