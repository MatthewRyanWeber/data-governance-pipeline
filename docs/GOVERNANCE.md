# Governance: Regulation → Code → Artifact

How each compliance obligation maps to a concrete API and the artifact it
produces. Every sample below is real output from a pipeline run, not an
illustration. Read this top to bottom and you know how compliance
engineering works in this codebase; read one section and you know how to
answer one auditor question.

---

## GDPR

### Art. 5(1)(c) — Data minimisation

**Code:** PII detection runs on every column (including columns created by
flattening nested records) before load; detected fields are masked or
dropped per policy — `pipeline/helpers.py:detect_pii`,
`pipeline/transform.py`.

**Artifact:** masked values in the destination plus one `PII_MASKED`
ledger event per field:

```json
{"action": "PII_MASKED", "category": "PRIVACY", "detail": {"field": "ssn"},
 "prev_hash": "d155955232d2f17d…", "self_hash": "bbf4efa9dc778bc8…"}
```

**Auditor question answered:** "Show me that direct identifiers never
reach the warehouse unprotected."

### Art. 6 — Lawful basis

**Code:** the compliance wizard records the lawful basis before any run
(`pipeline/compliance_wizard.py`); `GovernanceLogger.consent_recorded`
writes it to the ledger.

**Artifact:** `CONSENT_RECORDED` ledger event carrying the basis
("Contract", "Legitimate interests", …) and confirmation.

**Auditor question:** "Under which lawful basis was this dataset
processed, and when was that decided?"

### Art. 17 — Right to erasure

**Code:** `ErasureHandler` (`pipeline/privacy/erasure_handler.py`) deletes
a data subject across every registered destination in one call;
`GovernanceLogger.erasure_executed` records subject (hashed), table, and
row count.

**Artifact:** `GDPR_ERASURE_EXECUTED` ledger event per destination — the
proof-of-deletion trail.

**Auditor question:** "Prove this subject was erased everywhere, and
when."

### Art. 30 — Records of processing activities (RoPA)

**Code:** `RoPAGenerator`
(`pipeline/extensions/governance_extensions.py`) builds the RoPA from
recorded activities — or ingests them straight from the audit ledger via
`ingest_from_ledger()`.

**Artifact:** the controller-ready HTML RoPA report (activities, purposes,
legal bases, retention, third-country transfers).

**Auditor question:** "Show me your Art. 30 register."

### Art. 32 — Integrity of processing

**Code:** every ledger event carries a SHA-256 of the previous event
(`GovernanceLogger._event`); the chain head only advances after a
successful write; `AppendOnlyWriter` blocks seek/truncate on the ledger
file; an anchor sidecar (last hash + entry count) is rewritten atomically
on every event; `verify_ledger()` walks the chain and checks the anchor.

**Artifact:** the ledger itself plus its anchor:

```json
{"last_hash": "d62a8bb0cc21d352…", "entry_count": 15,
 "ledger_file": "audit_ledger_20260612_142451.jsonl"}
```

Tampering anywhere — edit, reorder, tail-truncation, or deleting the
whole file — fails `verify_ledger()`.

**Auditor question:** "How do you know your audit log hasn't been
altered?"

### Art. 5(1)(e) — Storage limitation

**Code:** `RetentionEnforcer`
(`pipeline/extensions/governance_extensions.py`) deletes or archives rows
past the configured policy, driven by the `_loaded_at_utc` lineage column
every load stamps; `GovernanceLogger.retention_policy` records the policy.

**Artifact:** `POLICY_RECORDED` and `RETENTION_DELETE` events plus
parquet archives for the archive action.

### Chapter V — Cross-border transfers

**Code:** transfers are inferred from destination endpoints (Snowflake
account regions, Redshift hosts, BigQuery locations —
`pipeline/governance_logger.py:_infer_cross_border_transfer`) and logged
with safeguard annotations; `CrossBorderTransferLogger` handles explicit
declarations.

**Artifact:** the transfer log JSON report per run.

---

## CCPA

### §1798.100 — Right to know

**Code:** `PIIDiscoveryReporter` (`pipeline/privacy/pii_discovery.py`)
inventories every detected personal-data field with risk levels.

**Artifact:** `pii_report_<ts>.json` + HTML — the machine- and
human-readable answer to a consumer data request scope question.

### §1798.105 — Right to delete

Same machinery as GDPR Art. 17 (`ErasureHandler`); the ledger events are
the deletion evidence.

### §1798.120 — Right to opt out of sale

**Code:** the compliance wizard asks the sale/sharing question per
pipeline and records the opt-out status (`pipeline/compliance_wizard.py`).

**Artifact:** `CONSENT_EVENT` ledger entries.

---

## HIPAA (via `pipeline.extensions.epic_extensions`)

### §164.514(b) — Safe Harbor de-identification

**Code:** `HIPAASafeHarborFilter` removes/transforms all 18 identifier
classes, applies ZIP-code restriction rules and age-90 capping.

**Artifact:** the PHI scan HTML report listing every column, its
category, the action taken, and truncated samples.

### §164.308 — Business associate agreements

**Code:** `BAATracker.check_phi_load(destination)` raises before any PHI
load to a destination without a current BAA.

**Artifact:** the BAA registry JSON + the blocked-load exception trail.

### Research use — IRB/QI protocols

**Code:** `IRBApprovalGate` enforces column-level approved data elements
per protocol before extraction.

### k-anonymity / l-diversity

**Code:** `PHIKAnonymityChecker` computes k and l over quasi-identifiers
with suppress / report / raise enforcement modes.

**Artifact:** the k-anonymity HTML report.

---

## Working with existing governance

The pipeline drops into an environment that already has governance instead of
replacing it: it discovers existing policy and enforces it, imports policy that
lives in an external catalog, coexists with data already in a destination, and
feeds the lineage tools an organisation already runs. Nothing existing gets
steamrolled.

### Discover and enforce existing policy

**Code:** on every run a pre-flight gate (`pipeline/governance_preflight.py`)
discovers whatever policy already exists — schema baselines, column purposes,
purpose-limitation rules, quality baselines, a consent database, and data
contracts — and reconciles the incoming data against each. It enforces by
dropping out-of-purpose columns, filtering rows without consent, and flagging
schema drift and quality anomalies, surfacing what it found rather than silently
overriding. Each check only runs when its state file exists, so a first run with
no prior policy stays clean.

**Artifact:** `PREFLIGHT_GATE_COMPLETE` (plus `PURPOSE_LIMITATION_APPLIED` /
`CONSENT_FILTER_APPLIED` where enforced) ledger events recording what was found
and applied.

### Import policy from an external catalog

**Code:** where policy already lives in a catalog (Atlan, Collibra, a home-grown
store), `PolicyImporter` (`pipeline/catalog/policy_importer.py`) maps a
normalised catalog export onto the very files the pre-flight gate enforces —
`schema_registry.json`, `column_purpose.json`, `purpose_registry.json`,
`anomaly_baseline.json` — so the organisation's rules apply here without
re-entry. It **merges rather than clobbers**, touching only the entries it is
given. `JsonExportAdapter` is the dependency-free path; `AtlanCatalogAdapter`
pulls the same shape from an Atlan tenant.

**Artifact:** the populated `config/*.json` policy files (see
`examples/policy_import/`).

### Coexist with data already in a destination

**Code:** loads append, replace, or **idempotently upsert by natural key** via a
staging table (the loader family), so existing rows are never blindly
overwritten; `pipeline/advanced/reversible_loader.py` can snapshot the prior
table first, and `pipeline/load_verifier.py` reconciles source vs destination
row counts after the load.

### Extend, never rewrite, the audit trail

**Code:** the hash-chained ledger is append-only (`AppendOnlyWriter` blocks
seek/truncate), so new runs extend the audit trail and never alter prior
evidence; distributed runs compose into a single Merkle root
(`pipeline/partitioned_ledger.py`).

### Feed existing lineage tools

**Code:** `pipeline/lineage/openlineage_emitter.py` emits events in the
OpenLineage spec, so existing lineage and catalog backends (Marquez, DataHub,
OpenMetadata, Atlan) ingest this pipeline's runs. Policy flows in; lineage flows
out.

---

## How to verify any of this yourself

```bash
pip install -e ".[dev]"
pipeline run yourdata.csv sqlite --table t --config cfg.json
python - <<'PY'
from pipeline.governance_logger import GovernanceLogger
# point at the run's log dir, then:
# gov.verify_ledger()  -> True only if the chain and anchor are intact
PY
```

Every claim in this document is exercised by the test suite
(`tests/test_governance_logger.py`, `tests/test_privacy.py`,
`tests/test_extensions/`) — if a section here drifts from the code, a
test fails before this document lies to you.
