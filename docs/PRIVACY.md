# Privacy Policy

**Data Governance Pipeline** — Last updated: June 2, 2026

## Summary

The Data Governance Pipeline is an ETL (Extract, Transform, Load) tool that processes structured data across sources and destinations you configure. It is designed to handle sensitive data — including PII and PHI — with built-in compliance controls for GDPR, CCPA, and HIPAA.

This policy describes the pipeline's own data practices, not the data it processes on your behalf.

## The Pipeline's Own Data Collection

The Data Governance Pipeline itself does not phone home, track usage, or collect telemetry.

| Category | Collected by the pipeline? | Details |
|----------|---------------------------|---------|
| Personal information | No | — |
| Usage analytics | No | — |
| Telemetry | No | — |
| Crash reports | No | — |
| API keys / credentials | Stored locally only | In your `.env` file and config, never transmitted to us |

## Data the Pipeline Processes on Your Behalf

The pipeline is designed to process data that may include personal information. When you run the pipeline, it:

1. **Extracts** data from sources you configure (databases, files, streaming platforms, APIs)
2. **Transforms** data according to your data contracts (schema validation, PII discovery, pseudonymization, de-identification)
3. **Loads** data to destinations you configure (data warehouses, databases, vector stores, cloud storage)

**You are the data controller.** The pipeline is a tool you operate. It processes data according to your configuration and data contracts.

## Data Sources and Destinations

The pipeline connects to external systems you configure:

### Sources (inbound connections)
- SQL databases (PostgreSQL, MySQL, SQL Server, Oracle, DB2)
- File formats (CSV, JSON, Excel, XML, Parquet, Avro, ORC)
- Streaming platforms (Apache Kafka, Amazon Kinesis, Google Pub/Sub)
- Business applications (QuickBooks Online)

### Destinations (outbound connections)
- Cloud data warehouses (Snowflake, BigQuery, Redshift, Databricks, Azure Synapse, ClickHouse)
- Relational databases (PostgreSQL, MySQL, SQL Server, Oracle, CockroachDB)
- NoSQL stores (MongoDB)
- Vector databases (Pinecone, Weaviate, Qdrant, Chroma, Milvus, LanceDB, pgvector)
- Cloud storage (S3, GCS, Azure Blob, Delta Lake, Apache Iceberg)
- Healthcare systems (Epic Clarity EHR, OMOP CDM)
- Monitoring (Grafana, Prometheus)

### Notification channels
- Slack webhooks (for alerts)
- SMTP email (for compliance notifications)

All connections are initiated by you through configuration. No connections are made without explicit setup.

## Built-In Privacy Controls

The pipeline includes controls to help you comply with data protection regulations:

| Control | Description |
|---------|-------------|
| **PII Discovery** | Automatic detection of personal information in data streams |
| **Pseudonymization** | Fernet-encrypted reversible pseudonymization of PII fields |
| **HIPAA Safe Harbor** | De-identification per 45 CFR §164.514(b) — removes 18 identifier categories |
| **k-Anonymity** | Ensures k=5 anonymity with l-diversity for quasi-identifiers |
| **Differential Privacy** | Optional noise injection for aggregate queries |
| **Consent Management** | Column-level consent tracking and enforcement |
| **Data Contracts** | YAML-defined schemas with SLA and quality enforcement |
| **Audit Ledger** | SHA-256 chained audit log — tamper-evident record of all operations |
| **Column-Level Lineage** | Tracks data provenance from source to destination |
| **Retention Policies** | Automated data expiration and deletion |
| **Encryption** | AES-256 encryption with key rotation for data at rest |

## Credential Storage

Database credentials, API keys, and connection strings are stored in your local `.env` file and configuration files. They are:
- Never transmitted to us
- Never logged in audit trails (redacted)
- Used only to establish connections you configure

You are responsible for securing your credential files.

## Audit and Logging

The pipeline maintains a local audit ledger (SHA-256 chained) that records:
- What data was processed
- When operations occurred
- What transformations were applied
- Compliance actions taken (pseudonymization, de-identification, consent checks)

Audit logs are stored locally or in a database you configure. They do not contain raw PII — only metadata and hashed references.

## Third-Party Services

When you configure destinations, the pipeline transmits data to those services. Each service has its own privacy practices:
- Cloud providers (AWS, GCP, Azure) — governed by their respective DPAs
- SaaS platforms (Snowflake, Databricks) — governed by their terms
- Healthcare systems (Epic) — governed by BAAs you establish

The pipeline's BAA tracker helps you manage Business Associate Agreements for HIPAA-covered destinations.

## Changes to This Policy

Changes will be documented in the repository's commit history.

## Contact

For privacy questions, open an issue at: https://github.com/MatthewRyanWeber/data-governance-pipeline/issues

Or contact: matt@nyss.nyc
