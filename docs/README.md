# Documentation — start here

Every document, what it covers, and when to read it. You should never need to
read all of them — find your row in the table, or jump to the path that matches
why you're here.

## Table of contents

| Document | What it is | Read it when… |
|----------|-----------|---------------|
| [Main README](../README.md) | Install, quick start, the `pipeline run` walkthrough with real output | You're getting started or evaluating the project at a glance |
| [SCOPE.md](SCOPE.md) | What this is — and, importantly, what it is **not**; the single-node size envelope | You're deciding whether it's the right tool, or proposing a feature |
| [SOURCES.md](SOURCES.md) | Every source format and streaming input the EXTRACT stage reads | You need to know if your input type is supported |
| [GOVERNANCE.md](GOVERNANCE.md) | The regulation → code → artifact map: each GDPR/CCPA/HIPAA obligation, the API that satisfies it, the audit artifact it produces | You're evaluating the compliance story or need to cite an obligation |
| [CLOUD_VERIFICATION.md](CLOUD_VERIFICATION.md) | The log of which cloud destinations were verified against the live service, and how the weekly check stays green | You depend on a cloud-tier destination and want its proof status |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Sizing, TLS, env vars, Docker, troubleshooting | You're putting it into production |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The 7-layer import DAG, the dispatch/registry seam, and the decision log | You're changing the code and need the why behind the structure |
| [EXTENDING.md](EXTENDING.md) | How to write a custom loader, register it, and the family contract + verification tier it must earn | You're adding a destination or extractor |
| [DISTRIBUTED_GOVERNANCE.md](DISTRIBUTED_GOVERNANCE.md) | Running governance per-partition under Spark/Ray/Dask with a partitionable Merkle-root ledger — the 100TB/day path, with measured throughput | You're scaling past a single node (Path A) |
| [PRIVACY.md](PRIVACY.md) | Privacy policy template | You need the legal privacy template |
| [TERMS.md](TERMS.md) | Terms of service template | You need the legal terms template |
| [CCPA.md](CCPA.md) | CCPA compliance statement template | You need the CCPA-specific statement |

**Worked examples (committed artifacts, not prose):**

| Example | What it shows |
|---------|---------------|
| [examples/sample_run/](../examples/sample_run/) | The actual artifacts of a real run — hash-chained ledger + anchor, PII-masked events, metrics — with a snippet to verify the chain yourself |
| [examples/distributed_run/](../examples/distributed_run/) | A distributed Path A run: per-partition ledger segments composed into one verified Merkle root |

**Project meta:** [CHANGELOG.md](../CHANGELOG.md) (release history) · [CONTRIBUTING.md](../CONTRIBUTING.md) (how to contribute) · [CLAUDE.md](../CLAUDE.md) (coding standards and conventions).

---

## Pick the path that matches why you're here

### I want to use it
1. [Main README](../README.md) — install, quick start, the `pipeline run` walkthrough with real output.
2. [SCOPE.md](SCOPE.md) — what this is and what it is **not**. Read this before deciding it's the right tool.
3. [SOURCES.md](SOURCES.md) — every source format and streaming input the EXTRACT stage reads.

### I'm evaluating the governance / compliance story
1. [GOVERNANCE.md](GOVERNANCE.md) — the regulation → code → artifact map, with real ledger output.
2. [examples/sample_run/](../examples/sample_run/) — the **actual artifacts** of a real run, committed as evidence, with a snippet to verify the chain yourself.
3. [CLOUD_VERIFICATION.md](CLOUD_VERIFICATION.md) — which cloud destinations have been verified against the live service, and how the weekly verification stays green.
4. Legal templates: [PRIVACY.md](PRIVACY.md), [TERMS.md](TERMS.md), [CCPA.md](CCPA.md).

### I'm going to run it in production
1. [DEPLOYMENT.md](DEPLOYMENT.md) — sizing, TLS, env vars, Docker, troubleshooting.
2. The verification tiers in the [main README](../README.md#supported-destinations) — know which destinations are CI-verified vs credential-gated before you depend on one.
3. [DISTRIBUTED_GOVERNANCE.md](DISTRIBUTED_GOVERNANCE.md) — if you need to scale governance past a single node.

### I'm going to change the code
1. [ARCHITECTURE.md](ARCHITECTURE.md) — the 7-layer import DAG, the dispatch/registry seam, and the **decision log** (why the monolith, why the dispatch-level injection guard, why LedgerWriter was extracted).
2. [EXTENDING.md](EXTENDING.md) — how to write a custom loader, register it, and the family contract + verification tier it must earn.
3. [SCOPE.md](SCOPE.md) — check a proposed feature against the boundary before building it.
4. [DISTRIBUTED_GOVERNANCE.md](DISTRIBUTED_GOVERNANCE.md) — running this pipeline's governance per-partition under Spark/Ray/Dask at distributed scale (Path A).
