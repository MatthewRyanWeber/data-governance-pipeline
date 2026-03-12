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
- 18 destination loaders: PostgreSQL, MySQL, SQL Server, MongoDB, Snowflake, Redshift, BigQuery, Azure Synapse, Databricks, ClickHouse, Oracle, DB2, Firebolt, Yellowbrick, SAP HANA, SAP Datasphere, QuickBooks
- Chunked parallel processing, compression (gz/bz2/zip), incremental loading, checkpoint/resume

**Data governance — GDPR / CCPA**
- Tamper-evident SHA-256 audit ledger — every event is chained; any modification is detectable
- PII discovery with GDPR Article / CCPA section annotations and HTML report
- GDPR Art. 17 erasure across all 18 destinations in a single call
- Consent management with per-subject, per-purpose consent, expiry, and withdrawal
- Purpose limitation — drops columns not approved for the declared purpose
- Pseudonymization vault with Fernet encryption, context separation, and key rotation
- Differential privacy with per-column noise injection and privacy budget tracking
- Record of Processing Activities (RoPA) generator — GDPR Art. 30
- Data Subject Access Request (DSAR) workflow — GDPR Art. 15/20
- Breach detector with statistical anomaly patterns
- Data contracts (YAML-defined schema/SLA/quality) with CRITICAL/ERROR/WARNING enforcement
- Schema drift detection, anomaly alerting, cross-border transfer logging

**Healthcare / HIPAA** — `epic_extensions.py`
- HIPAA Safe Harbor de-identification (45 CFR §164.514(b)) — all 18 identifier types, ZIP restriction rules, age-≥-90 capping
- Epic Clarity extractor with automatic ZC_ code-table decoding and ETL refresh-window guard
- Business Associate Agreement (BAA) registry — gates every PHI load
- IRB/QI protocol registry — column-level enforcement of approved data elements, JSONL usage log for annual reporting
- OMOP CDM v5.4 transformer — maps 6 Clarity tables to research-standard domain tables
- k-anonymity and l-diversity checker with suppress / report / raise enforcement modes

**Observability**
- Column-level data lineage graph with HTML visualisation
- Quality scoring, anomaly alerts, SLA monitoring, run metrics
- Cost estimator (pre-run), reversible loads with snapshot rollback
- Natural language pipeline builder (Claude API)
- Data catalog connectors: Collibra, Alation, Atlan, Informatica
- REST API server and cron-style scheduler

---

## Project layout

```
data-governance-pipeline/
├── pipeline_v3.py              # Main pipeline — 53 classes, 18 loaders, wizard
├── governance_extensions.py    # 8 GDPR/CCPA governance classes
├── epic_extensions.py          # 6 Epic EHR / HIPAA classes
├── metadata_extensions.py      # 16 metadata and lineage classes
├── pipeline_additions.py       # 10 data product and observability classes
├── catalog_connectors.py       # 4 data catalog connectors
├── pipeline_streaming.py       # Kafka, Kinesis, Pub/Sub extractors
├── pipeline_scheduler.py       # Cron-style pipeline scheduler
├── pipeline_api.py             # REST API server (/run, /status)
├── pipeline_v2.py              # Earlier standalone pipeline (5 destinations)
├── pipeline.py                 # Original minimal pipeline
├── test_loader_dispatch.py     # 37 loader dispatch tests
├── test_governance_extensions.py  # 81 governance tests
├── test_epic_extensions.py     # 76 Epic/HIPAA tests
├── requirements.txt            # Core dependencies
├── requirements_v2.txt         # Optional cloud/enterprise drivers
├── sample_data.json            # Synthetic sample data
├── sample_data_v3.json         # Extended synthetic sample
└── .env.example                # Credential template
```

| File | Lines |
|------|------:|
| `pipeline_v3.py` | 16,562 |
| `catalog_connectors.py` | 2,291 |
| `metadata_extensions.py` | 2,606 |
| `governance_extensions.py` | 2,320 |
| `epic_extensions.py` | 2,249 |
| `pipeline_additions.py` | 1,788 |
| `pipeline_v2.py` | 2,583 |
| `test_epic_extensions.py` | 939 |
| `test_governance_extensions.py` | 708 |
| `test_loader_dispatch.py` | 472 |

---

## Quick start

**1. Clone and install core dependencies**

```bash
git clone https://github.com/matthewryanweber/data-governance-pipeline.git
cd data-governance-pipeline
pip install -r requirements.txt
```

**2. Copy the credential template**

```bash
cp .env.example .env
# Edit .env with your database credentials and SMTP settings
```

**3. Run the interactive wizard**

```bash
python pipeline_v3.py
```

The wizard asks:
- Where is your source? (file path, database table, API, or stream)
- GDPR / CCPA compliance questions (purpose, legal basis, data subjects)
- Which destination? (choose from 18 platforms)
- Review the run plan, then confirm

**4. Optional: cloud and enterprise drivers**

```bash
pip install -r requirements_v2.txt   # all optional extras

# Or install only what you need:
pip install ".[cloud]"        # Snowflake, BigQuery, Databricks, etc.
pip install ".[streaming]"    # Kafka / Kinesis / Pub/Sub
pip install ".[healthcare]"   # Epic Clarity (pyodbc + pyarrow for OMOP)
pip install ".[sap]"          # SAP HANA and Datasphere
```

---

## Usage examples

### File → PostgreSQL

```python
# Non-interactive run with all options specified upfront
import subprocess
subprocess.run([
    "python", "pipeline_v3.py",
    "--src",     "employees.csv",
    "--dest",    "postgresql",
    "--purpose", "analytics",
    "--no-wizard",
])
```

### GDPR governance

```python
from pipeline_v3 import GovernanceLogger
from governance_extensions import (
    RoPAGenerator, ConsentManager, PseudonymVault
)

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

# Pseudonymization vault (preserves cross-table joins)
vault = PseudonymVault(gov, context="hr")
df["employee_id"] = df["employee_id"].apply(
    lambda v: vault.pseudonymise(str(v))
)

# Consent gate — filter out rows without marketing consent
cm = ConsentManager(gov)
cm.record("E001", purpose="marketing", granted=True, expiry_days=365)
df = cm.filter_dataframe(df, subject_col="employee_id", purpose="marketing")
```

### HIPAA Safe Harbor de-identification

```python
from pipeline_v3 import GovernanceLogger
from epic_extensions import HIPAASafeHarborFilter, BAATracker, IRBApprovalGate

gov     = GovernanceLogger(run_id="run_001", src="clarity_extract")
safe    = HIPAASafeHarborFilter(gov, hash_identifiers=True)
tracker = BAATracker(gov)
gate    = IRBApprovalGate(gov)

# Register BAA for the research destination
tracker.register_baa(
    destination_id = "snowflake_research",
    vendor         = "Snowflake Inc.",
    signed_date    = "2024-01-15",
    expiry_date    = "2026-01-14",
    phi_types      = ["encounter_data", "diagnosis_codes"],
)

# Register IRB protocol
gate.register_protocol(
    protocol_id      = "IRB-2024-1234",
    study_title      = "30-day readmission prediction",
    pi_name          = "Dr. Jane Smith",
    approved_date    = "2024-03-01",
    expiry_date      = "2025-03-01",
    approved_columns = ["PAT_ENC_CSN_ID", "CONTACT_DATE",
                        "CURRENT_ICD10_LIST"],
    phi_allowed      = False,
)

# De-identify and gate
clean_df = safe.apply(clarity_df, source_label="PAT_ENC")
clean_df = gate.gate_dataframe(clean_df, protocol_id="IRB-2024-1234")
tracker.check_phi_load("snowflake_research")   # raises if BAA missing/expired
# → load to Snowflake
```

### OMOP CDM transformation

```python
from epic_extensions import ClarityExtractor, OMOPTransformer

cx = ClarityExtractor(gov, cfg={
    "host":     "clarity-db.hospital.org",
    "db_name":  "Clarity",
    "user":     "svc_analytics",
    "password": "...",
})
omop = OMOPTransformer(gov, vocabulary_path="omop_vocab.csv")

encounters = cx.get_encounters(start_date="2024-01-01", decode_codes=True)
diagnoses  = cx.get_diagnoses(start_date="2024-01-01")

visit_df = omop.to_visit_occurrence(encounters)
cond_df  = omop.to_condition_occurrence(diagnoses)
```

### k-anonymity enforcement

```python
from epic_extensions import PHIKAnonymityChecker

checker = PHIKAnonymityChecker(gov, k=5, l_diversity=3)

safe_df = checker.enforce(
    de_identified_df,
    quasi_ids     = ["age_group", "zip3", "gender_concept_id"],
    sensitive_col = "condition_concept_id",
    action        = "suppress",  # removes groups that violate k=5
)
checker.save_report("kanon_report.html")
```

---

## Running tests

```bash
python test_loader_dispatch.py
python test_governance_extensions.py
python test_epic_extensions.py

# Or with pytest
pytest -v
```

**194 tests, all passing.**

| Suite | Tests |
|-------|------:|
| `test_loader_dispatch.py` | 37 |
| `test_governance_extensions.py` | 81 |
| `test_epic_extensions.py` | 76 |
| **Total** | **194** |

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
| GDPR Art. 17 — right to erasure | `ErasureHandler` — all 18 destinations |
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

## License

MIT — see [LICENSE](LICENSE).

---

## Contributing

Issues and pull requests are welcome. Run the full test suite before submitting:

```bash
pytest -v
```
