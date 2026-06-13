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
| 2026-06-13 | MotherDuck | `DuckDBLoader` (`md:` path) | ✅ append + read-back, 3 rows | `tests/integration/test_cloud_credentialed.py::TestMotherDuckLive` passed against a live MotherDuck account (region aws-us-east-1) using a read/write access token; wrote a DataFrame to `md:dgp_it_db.it_people` and read the rows back through a fresh connection. |

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
