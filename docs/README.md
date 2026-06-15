# Documentation — start here

Pick the path that matches why you're here. You should never need to read
all of these; each audience has one or two relevant docs.

## I want to use it
1. [Main README](../README.md) — install, quick start, the `pipeline run`
   walkthrough with real output.
2. [SCOPE.md](SCOPE.md) — what this is and, importantly, what it is **not**.
   Read this before deciding it's the right tool.
3. [SOURCES.md](SOURCES.md) — every source format and streaming input the
   EXTRACT stage reads.

## I'm evaluating the governance / compliance story
1. [GOVERNANCE.md](GOVERNANCE.md) — the regulation → code → artifact map.
   For each GDPR/CCPA/HIPAA obligation: the API that satisfies it and the
   audit artifact it produces, with real ledger output.
2. [examples/sample_run/](../examples/sample_run/) — the **actual artifacts**
   of a real run (hash-chained ledger + anchor, PII-masked events, metrics),
   committed as evidence, with a snippet to verify the chain yourself.
2. [CLOUD_VERIFICATION.md](CLOUD_VERIFICATION.md) — the log of which cloud
   destinations have been verified against the live service, and how the
   weekly verification stays green without spamming.
3. Legal templates: [PRIVACY.md](PRIVACY.md), [TERMS.md](TERMS.md),
   [CCPA.md](CCPA.md).

## I'm going to run it in production
1. [DEPLOYMENT.md](DEPLOYMENT.md) — sizing, TLS, env vars, Docker,
   troubleshooting.
2. The verification tiers in the [main README](../README.md#supported-destinations)
   — know which destinations are CI-verified vs credential-gated before
   you depend on one.

## I'm going to change the code
1. [ARCHITECTURE.md](ARCHITECTURE.md) — the 7-layer import DAG, the
   dispatch/registry seam, and the **decision log** (why the monolith, why
   the dispatch-level injection guard, why LedgerWriter was extracted).
2. [EXTENDING.md](EXTENDING.md) — how to write a custom loader, register
   it, and the family contract + verification tier it must earn.
3. [SCOPE.md](SCOPE.md) — check a proposed feature against the boundary
   before building it.
4. [DISTRIBUTED_GOVERNANCE.md](DISTRIBUTED_GOVERNANCE.md) — running this
   pipeline's governance per-partition under Spark/Ray/Dask at distributed
   scale, with a partitionable Merkle-root audit ledger (Path A).
