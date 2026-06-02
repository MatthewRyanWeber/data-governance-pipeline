# CCPA Compliance Statement

**Data Governance Pipeline** — Last updated: June 2, 2026

## Overview

The California Consumer Privacy Act (CCPA) and the California Privacy Rights Act (CPRA) grant California residents specific rights regarding their personal information. The Data Governance Pipeline includes built-in tools to help organizations comply with CCPA when processing data containing personal information of California residents.

## The Pipeline's Own CCPA Status

The Data Governance Pipeline software itself does not collect personal information from users. There is no telemetry, analytics, or usage tracking. API keys and credentials are stored locally in your configuration files.

## CCPA Compliance Tools

The pipeline provides the following tools to support your organization's CCPA compliance:

### Right to Know (§1798.100)

| Tool | How it helps |
|------|-------------|
| **PII Discovery** | Automatically identifies fields containing personal information across data sources |
| **Column-Level Lineage** | Tracks where personal information flows from source to destination |
| **Data Contracts** | Documents what data is collected, its format, and retention period |
| **Audit Ledger** | Provides tamper-evident records of all data processing operations |

When a consumer requests to know what personal information you hold, lineage tracking and PII discovery help you locate it across all connected systems.

### Right to Delete (§1798.105)

| Tool | How it helps |
|------|-------------|
| **Retention Policies** | Automated data expiration and deletion schedules |
| **Reversible Loads** | Snapshot-based rollback to remove data from destinations |
| **Consent Management** | Tracks deletion requests and propagates them through the pipeline |
| **Audit Ledger** | Records deletion operations for compliance documentation |

When a consumer requests deletion, the pipeline can propagate the request to configured destinations and log the action.

### Right to Opt-Out of Sale/Sharing (§1798.120)

| Tool | How it helps |
|------|-------------|
| **Consent Management** | Column-level consent tracking with opt-out enforcement |
| **Data Contracts** | Define which fields require consent and which destinations are authorized |
| **PII Pseudonymization** | Fernet-encrypted reversible pseudonymization prevents unauthorized use |

The pipeline does not sell data. If your organization shares data with third parties via configured destinations, consent management enforces opt-out preferences before data reaches those destinations.

### Right to Correct (§1798.106)

| Tool | How it helps |
|------|-------------|
| **Reversible Loads** | Roll back and re-process corrected data |
| **Column-Level Lineage** | Identify all destinations where incorrect data was sent |
| **Audit Ledger** | Record correction operations |

### Right to Limit Sensitive PI (§1798.121)

| Tool | How it helps |
|------|-------------|
| **PII Discovery** | Classifies sensitive personal information (SSN, financial, health, biometric) |
| **HIPAA Safe Harbor** | De-identifies 18 categories of sensitive identifiers |
| **k-Anonymity** | Enforces k=5 anonymity with l-diversity for quasi-identifiers |
| **Differential Privacy** | Optional noise injection for aggregate analytics |
| **Encryption** | AES-256 encryption with key rotation for sensitive fields at rest |

### Right to Non-Discrimination (§1798.125)

Not directly applicable to an ETL tool. Your organization is responsible for ensuring that exercising CCPA rights does not result in discriminatory treatment.

## Categories of Personal Information

Per CCPA §1798.140(v), the pipeline can process all categories. PII Discovery detects and classifies:

| Category | Detected by PII Discovery | De-identification available |
|----------|--------------------------|---------------------------|
| Identifiers (name, SSN, email, IP) | Yes | Pseudonymization, Safe Harbor |
| Customer records (financial, medical) | Yes | Safe Harbor, encryption |
| Protected classifications | Partial | Manual classification |
| Commercial information | Yes | Pseudonymization |
| Biometric information | Partial | Safe Harbor removal |
| Internet activity | Yes | Pseudonymization |
| Geolocation data | Yes | Safe Harbor removal, k-anonymity |
| Sensory data (audio, visual) | No | Manual handling required |
| Professional/employment information | Yes | Pseudonymization |
| Education information | Yes | Pseudonymization |
| Inferences | No | Manual handling required |

## CCPA Compliance Checklist for Pipeline Operators

1. **Configure PII Discovery** — Enable automatic PII detection in your data contracts
2. **Define retention policies** — Set expiration periods for each data category
3. **Enable consent management** — Track opt-in/opt-out preferences per data subject
4. **Establish data contracts** — Document what data you collect and why
5. **Configure audit logging** — Ensure the SHA-256 audit ledger is enabled
6. **Review lineage reports** — Understand where personal information flows
7. **Set up deletion workflows** — Configure reversible loads for deletion request propagation
8. **Classify sensitive PI** — Tag sensitive fields for enhanced protection
9. **Monitor compliance** — Review trust scores and compliance reports regularly
10. **Maintain vendor registry** — Track all destination services and their DPAs

## Service Provider Obligations

If your organization uses the pipeline as part of a service you provide to others, you may qualify as a "service provider" under CCPA §1798.140(ag). In this case:

- Process personal information only as directed by the business (your client)
- Do not sell or share personal information received from the business
- Implement appropriate security measures
- Assist the business in responding to consumer requests
- The pipeline's audit ledger and lineage tracking support these obligations

## No Data Broker Activity

The Data Governance Pipeline does not:
- Sell personal information
- Share personal information for cross-context behavioral advertising
- Act as a data broker as defined by CCPA §1798.140(d)

If your organization uses the pipeline to transfer data to third parties, you are responsible for determining whether that constitutes a "sale" or "sharing" under CCPA.

## Verification and Recordkeeping

The pipeline's audit ledger provides:
- Tamper-evident SHA-256 chained records of all processing operations
- Timestamps for all data ingestion, transformation, and loading
- Records of compliance actions (pseudonymization, deletion, consent enforcement)
- Column-level lineage for tracing data subject requests

These records support CCPA's 24-month recordkeeping requirement (§1798.130(a)(7)).

## Important Disclaimer

The Data Governance Pipeline provides compliance tools, not compliance certification. These tools assist your compliance program but do not replace:
- Legal counsel familiar with CCPA/CPRA
- A formal data protection impact assessment
- Consumer-facing privacy notices and opt-out mechanisms
- Staff training on data protection obligations

## Contact

For CCPA-related questions, open an issue at: https://github.com/MatthewRyanWeber/data-governance-pipeline/issues

Or contact: matt@nyss.nyc
