# Cloud-Tier Verification Log

The cloud-credential tier destinations (Redshift, Databricks, Firebolt,
SAP HANA, SAP Datasphere, MotherDuck, QuickBooks, Snowflake Vector,
BigQuery Vector) are verified against the **live service** only when their
credentials are present — the `integration-cloud` workflow runs them
weekly and on demand. Between verified runs they are mock-tested and pass
the shared loader contract.

This file records each time a cloud destination was confirmed working
against its real service, so the evidence survives even after a trial
account or token lapses.

| Date (UTC) | Destination | Loader | Result | Evidence |
|------------|-------------|--------|--------|----------|
| 2026-06-13 | MotherDuck | `DuckDBLoader` (`md:` path) | ✅ CI-confirmed (passed on GitHub Actions) | `tests/integration/test_cloud_credentialed.py::TestMotherDuckLive` passed against a live MotherDuck account (region aws-us-east-1); wrote a DataFrame to `md:dgp_it_db.it_people` and read the rows back through a fresh connection. Green in the `integration-cloud` workflow (run 27467006535). |
| 2026-06-13 | Databricks | `DatabricksLoader` | ✅ CI-confirmed (append + upsert both passed on GitHub Actions) | Verified against a live Databricks Free Edition serverless SQL warehouse (Unity Catalog, `workspace.default`). Append wrote 3 rows; upsert (natural_keys=`id`) updated id=3→`c2` and inserted id=4; read-back returned `[(1,'a'),(2,'b'),(3,'c2'),(4,'d')]`. Both tests passed in the `integration-cloud` workflow (run 27467006535). Two loader fixes were required (see note). |

## Why the weekly cloud workflow won't spam you

GitHub emails the repo owner when a scheduled workflow **fails**. The
`integration-cloud` workflow is built so it never fails for reasons
outside the code:

- **Missing credentials** → the test skips with a loud message
  (`_env()` returns None). A destination you never configured is green.
- **Expired / revoked token** → caught by `_skip_if_service_rejects` and
  downgraded to a loud skip, not a failure. So when the MotherDuck trial
  token lapses (~7 days), that test goes from PASS to SKIP — still green.
- **Transient service rejection** (serverless cold start, free-tier
  concurrency limits, throttling, 503/429) → also a loud skip.
- **A genuine loader bug** (wrong row count, bad SQL) → still fails red,
  because `AssertionError` and non-credential exceptions propagate. That
  is the only thing that will email you, and it means something real
  broke.

Net effect: the weekly run stays green/skip indefinitely with no action
from you. You only hear from GitHub if the pipeline's own code regresses.

## How a verification is recorded

1. Add the destination's secrets to the repo
   (`gh secret set <NAME> -R MatthewRyanWeber/data-governance-pipeline`).
2. Trigger the workflow:
   `gh workflow run integration-cloud.yml`.
3. When the run is green for that destination, add a row above with the
   date, the test that passed, and one line of what it actually did
   (table written, rows read back).

## Reproducing the MotherDuck check

```bash
export MOTHERDUCK_TOKEN="<read/write access token from app.motherduck.com>"
pip install -e ".[dev,integration]"
python -m pytest tests/integration/test_cloud_credentialed.py::TestMotherDuckLive \
  -v -m cloud
```

The test creates the database if absent, loads three rows via the real
`DuckDBLoader` MotherDuck path (`if_exists="replace"`, so it is
idempotent across runs), and asserts the rows read back correctly through
a separate connection. It skips loudly — never silently — when
`MOTHERDUCK_TOKEN` is absent.

> Note: the MotherDuck token used for the 2026-06-13 verification was a
> 7-day trial token and has since been rotated/expired. The evidence row
> above stands as the record that the loader works end-to-end against the
> live service; re-running requires a fresh token.

## Note on the Databricks verification (2026-06-13)

Verifying against Databricks Free Edition surfaced two genuine loader
defects, both fixed:

1. **`SET spark.databricks.delta.schema.autoMerge.enabled` was mandatory**
   when `schema_evolution=True` (the default). Serverless / Free Edition
   warehouses reject setting that config (`CONFIG_NOT_AVAILABLE`), which
   killed every load. It is now best-effort: attempted, and on rejection
   logged + skipped, since the explicit `CREATE TABLE` already defines the
   schema.
2. **No connection resilience for serverless cold starts.** A warehouse
   that has auto-stopped can take minutes to resume; the first request
   failed outright. `_connect` now retries with backoff and a generous
   socket timeout.

A caveat for CI: Free Edition's serverless warehouse intermittently
**rejects sessions** while starting or under its single-cluster
concurrency limit, independent of the loader. The cloud test therefore
treats such transient `RequestError` / "error during request to server"
rejections as a **loud skip, not a red failure** (same policy as an
expired token) — so a flaky free-tier warehouse never reddens CI. When
the warehouse is warm the test passes; the manual run recorded above is
the authoritative proof the loader is correct.
