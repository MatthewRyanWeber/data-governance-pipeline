# Scope — what this is, and what it is not

Borrowed from SQLite's discipline: the most useful thing a project can
state is the boundary it refuses to cross. This document is referenced in
planning and used to say "no" to good ideas that don't fit.

## What this is

**A governance-first ETL pipeline.** One Python stack that extracts data,
governs it, and loads it — where "governs" is not a bolt-on but the spine:
every load runs through PII detection and masking, a tamper-evident
SHA-256 audit ledger, lineage capture, classification, and configurable
GDPR/CCPA/HIPAA controls. The thesis is that compliance belongs *inside*
the pipeline, not stitched on afterward from three separate products.

The one-sentence test for any feature: **does it make a governed load
safer, more auditable, or reach a destination data needs to land in?** If
yes, it's in scope. If it's a capability that happens to be adjacent to
data movement but doesn't serve governance, it's out.

## What this is NOT

- **Not an iPaaS / connector marketplace.** The 40 destinations exist to
  get *governed* data where it needs to go, not to be a catalog competing
  with Fivetran/Airbyte on connector count. Breadth serves the governance
  core; it is not the product. This is why destinations carry honest
  verification tiers (core / emulator / cloud) rather than a flat "we
  support everything" count — see the README and `CLOUD_VERIFICATION.md`.
- **Not a transformation framework.** It does cleaning, typing,
  standardisation, and rule application in service of a governed load. It
  is not trying to be dbt; complex modelling DAGs belong upstream.
- **Not an orchestrator.** It runs per-record with checkpoint/resume and a
  cron entry point, but it is not Airflow/Dagster/Prefect. If you need
  multi-pipeline scheduling, DAG dependencies, and backfill management,
  run this *under* an orchestrator.
- **Not reverse-ETL or a BI tool.** It lands governed data in
  warehouses/lakes/stores. It does not sync back to SaaS apps or render
  dashboards (the built-in HTML dashboard is operational status, not
  analytics).
- **Not a multi-tenant SaaS platform.** Multi-tenancy scopes the catalog
  and lineage; it is not a hosted control plane with billing and RBAC for
  external customers.
- **Not a distributed big-data engine.** It is a single-process, streaming,
  checkpointed pipeline sized for roughly the **1 GB–1 TB/day** range — flat
  memory, per-chunk processing, resume-from-last-chunk. At ~100 TB/day you
  want Spark/Flink and partition-level parallelism; the right move there is to
  apply this pipeline's *governance* per partition under such an engine, not
  to scale this process up.

## On the breadth (Epic EHR, QuickBooks, 9 vector DBs)

These look like scope creep and deserve an explicit answer. They are in
scope **only** because each is a place governed data legitimately flows:

- **Epic EHR / OMOP** (`pipeline.extensions.epic_extensions`) is a
  HIPAA-governed *source/transform* layer — it is governance applied to
  the hardest regulated domain, which is the project's whole point. It
  lives in `extensions/` as an opt-in layer, not the core.
- **QuickBooks** and the **vector databases** are destinations in the
  **cloud / experimental tiers** — clearly labeled as such, mock- and
  contract-tested, verified live only when credentials exist. They are
  "reach further if you need it," not load-bearing claims.

The rule going forward: new destinations are welcome (the dispatch seam
makes them cheap), but they enter at the honest tier their verification
earns, and nothing in the **core** tier ships without a real-engine CI
test. Capabilities that are not about governed data movement — workflow
orchestration, analytics, app sync — are out, and this document is the
place that says so.

## Revisit conditions

- A cloud-tier destination gains a CI-runnable emulator → it can be
  promoted toward core (verification, not scope, changes).
- If the governance core ever becomes optional rather than the default
  path, that contradicts the thesis here and should be challenged against
  this document first.
