"""
Cloud-credential tier verification — runs ONLY when the relevant
credentials are present in the environment (integration-cloud workflow).

Each test announces loudly when its credentials are absent, so a skipped
verification is always visible, never silent.  Add the secret and the
loader's verification upgrades automatically:

    REDSHIFT_HOST/REDSHIFT_DATABASE/REDSHIFT_USER/REDSHIFT_PASSWORD
    DATABRICKS_SERVER_HOSTNAME/DATABRICKS_HTTP_PATH/DATABRICKS_TOKEN
    FIREBOLT_CLIENT_ID/FIREBOLT_CLIENT_SECRET/FIREBOLT_DATABASE/
        FIREBOLT_ACCOUNT_NAME/FIREBOLT_ENGINE_NAME
    DATASPHERE_TENANT_URL/DATASPHERE_TOKEN
    MOTHERDUCK_TOKEN
    QB_CLIENT_ID/QB_CLIENT_SECRET/QB_REFRESH_TOKEN/QB_REALM_ID  (sandbox)
    SNOWFLAKE_ACCOUNT/SNOWFLAKE_USER/SNOWFLAKE_PASSWORD/
        SNOWFLAKE_DATABASE/SNOWFLAKE_WAREHOUSE   (also covers vector)
    BQ_PROJECT/BQ_DATASET/GOOGLE_APPLICATION_CREDENTIALS (also covers vector)

Revision history
────────────────
1.0   2026-06-12   Initial release.
1.1   2026-06-13   Present-but-rejected credentials (expired/revoked token,
                   unreachable host) skip loudly instead of failing red, so
                   a lapsed trial account never turns CI red or spams the
                   owner.  Genuine loader bugs (assertion failures) still
                   fail — only auth/connection errors are downgraded.
1.2   2026-06-22   Treat managed-service/client version skew as an
                   environment problem too: MotherDuck refusing a newer
                   DuckDB ("not yet supported by MotherDuck") now skips
                   loudly instead of failing the weekly cron red.
"""

import contextlib
import os
import unittest
from unittest.mock import MagicMock

import pandas as pd
import pytest

from pipeline.loaders import resolve_loader


def _df():
    return pd.DataFrame({"id": [1, 2, 3], "name": ["a", "b", "c"]})


def _loader(db_type: str):
    loader_class, needs_db_type, _ = resolve_loader(db_type)
    if needs_db_type:
        return loader_class(MagicMock(), db_type)
    return loader_class(MagicMock())


def _env(*names) -> dict | None:
    """Collect env vars; None (and a loud message) if any is missing."""
    values = {n: os.environ.get(n, "") for n in names}
    missing = [n for n, v in values.items() if not v]
    if missing:
        print(f"\n[CLOUD-TIER] credentials absent: {', '.join(missing)} — "
              f"verification NOT performed for this service.")
        return None
    return values


# Substrings (case-insensitive) that mark an exception as a credential,
# connectivity, or transient service problem — NOT a loader bug.  Kept
# specific so a loader's own "no such table" / wrong-column errors are
# never misread.  Matched against "<ExceptionType>: <message>", so an
# exception class name (e.g. RequestError) can match too.
# Anchored phrases, not bare substrings: a genuine loader-bug message that
# merely contains the word "token" or a number like "503 rows" must NOT be
# downgraded to a skip.  Each marker is specific enough that only an
# auth/connectivity/transient condition produces it.
_CREDENTIAL_ERROR_MARKERS = (
    # Auth
    "invalid token", "token expired", "token is expired", "expired token",
    "invalid or expired", "authentication failed", "authenticationerror",
    "invalid credential", "unauthorized", "http 401", " 401 ",
    "access denied", "permission denied", "forbidden", "http 403", " 403 ",
    "invalid api key", "invalid client", "login failed",
    "not authenticated", "please check your motherduck token",
    # Connectivity
    "could not connect", "connection refused", "connection timed out",
    "could not translate host", "name or service not known", "getaddrinfo",
    "no route to host", "could not resolve",
    # Transient service-side (serverless cold start, throttling, capacity).
    # Free Edition / serverless warehouses intermittently reject sessions
    # while starting — a platform limit, not a loader regression.
    "error during request to server", "service unavailable",
    "temporarily unavailable", "http 503", "http 429", "too many requests",
    "warehouse is starting", "cluster is starting",
    # Platform/runtime version skew — the managed service lags a client
    # release.  MotherDuck's server extension trails new DuckDB versions by
    # days; until it catches up it refuses the session.  That is the
    # service's release cadence, not a loader regression, so it must not
    # turn the weekly cron red.  The CI job pins duckdb below the breaking
    # release to keep the test actually running; this marker is the safety
    # net for the window where even the pinned version outruns MotherDuck.
    "not yet supported by motherduck",
    "please downgrade to use motherduck",
)


def _is_credential_failure(exc: BaseException) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(marker in text for marker in _CREDENTIAL_ERROR_MARKERS)


@contextlib.contextmanager
def _skip_if_service_rejects(test_case: unittest.TestCase, service: str):
    """Downgrade auth/connectivity failures to a loud skip.

    A present credential that the service rejects (expired trial token,
    revoked key, unreachable host) is an environment problem, not a code
    regression — failing CI red for it would spam the repo owner on every
    weekly run.  AssertionError and everything else propagate, so a real
    loader bug still fails.
    """
    try:
        yield
    except AssertionError:
        raise
    except Exception as exc:
        if _is_credential_failure(exc):
            test_case.skipTest(
                f"{service}: credentials present but the service was "
                f"unavailable — expired/revoked token, or a transient "
                f"rejection (serverless cold start / throttling): {exc}"
            )
        raise


@pytest.mark.integration
@pytest.mark.cloud
class TestRedshiftLive(unittest.TestCase):
    def test_append_round_trip(self):
        env = _env("REDSHIFT_HOST", "REDSHIFT_DATABASE",
                   "REDSHIFT_USER", "REDSHIFT_PASSWORD")
        if env is None:
            self.skipTest("REDSHIFT_* credentials not configured")
        loader = _loader("redshift")
        cfg = {
            "host": env["REDSHIFT_HOST"],
            "database": env["REDSHIFT_DATABASE"],
            "user": env["REDSHIFT_USER"],
            "password": env["REDSHIFT_PASSWORD"],
        }
        with _skip_if_service_rejects(self, "Redshift"):
            rows = loader.load(_df(), cfg, table="it_people")
            self.assertEqual(rows, 3)


@pytest.mark.integration
@pytest.mark.cloud
class TestDatabricksLive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # A serverless / Free Edition warehouse auto-stops when idle and
        # can take minutes to resume.  Wake it once here (polling up to
        # 5 min) so the per-test loads hit a warm warehouse — otherwise the
        # first test races the cold start and fails non-deterministically.
        import os
        import time
        host = os.environ.get("DATABRICKS_SERVER_HOSTNAME", "")
        path = os.environ.get("DATABRICKS_HTTP_PATH", "")
        token = os.environ.get("DATABRICKS_TOKEN", "")
        if not (host and path and token):
            return
        from databricks import sql
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                conn = sql.connect(server_hostname=host, http_path=path,
                                   access_token=token, _socket_timeout=180)
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchall()
                conn.close()
                return
            except Exception:
                time.sleep(15)

    def test_append_round_trip(self):
        env = _env("DATABRICKS_SERVER_HOSTNAME", "DATABRICKS_HTTP_PATH",
                   "DATABRICKS_TOKEN")
        if env is None:
            self.skipTest("DATABRICKS_* credentials not configured")
        loader = _loader("databricks")
        cfg = {
            "server_hostname": env["DATABRICKS_SERVER_HOSTNAME"],
            "http_path": env["DATABRICKS_HTTP_PATH"],
            "access_token": env["DATABRICKS_TOKEN"],
        }
        with _skip_if_service_rejects(self, "Databricks"):
            rows = loader.load(_df(), cfg, table="it_people")
            self.assertEqual(rows, 3)

    def test_upsert_round_trip(self):
        env = _env("DATABRICKS_SERVER_HOSTNAME", "DATABRICKS_HTTP_PATH",
                   "DATABRICKS_TOKEN")
        if env is None:
            self.skipTest("DATABRICKS_* credentials not configured")
        loader = _loader("databricks")
        cfg = {
            "server_hostname": env["DATABRICKS_SERVER_HOSTNAME"],
            "http_path": env["DATABRICKS_HTTP_PATH"],
            "access_token": env["DATABRICKS_TOKEN"],
        }
        with _skip_if_service_rejects(self, "Databricks"):
            loader.load(_df(), cfg, table="it_upsert")
            rows = loader.load(_df(), cfg, table="it_upsert",
                               if_exists="upsert", natural_keys=["id"])
            self.assertEqual(rows, 3)


@pytest.mark.integration
@pytest.mark.cloud
class TestFireboltLive(unittest.TestCase):
    def test_append_round_trip(self):
        env = _env("FIREBOLT_CLIENT_ID", "FIREBOLT_CLIENT_SECRET",
                   "FIREBOLT_DATABASE", "FIREBOLT_ACCOUNT_NAME",
                   "FIREBOLT_ENGINE_NAME")
        if env is None:
            self.skipTest("FIREBOLT_* credentials not configured")
        loader = _loader("firebolt")
        cfg = {
            "client_id": env["FIREBOLT_CLIENT_ID"],
            "client_secret": env["FIREBOLT_CLIENT_SECRET"],
            "database": env["FIREBOLT_DATABASE"],
            "account_name": env["FIREBOLT_ACCOUNT_NAME"],
            "engine_name": env["FIREBOLT_ENGINE_NAME"],
        }
        with _skip_if_service_rejects(self, "Firebolt"):
            rows = loader.load(_df(), cfg, table="it_people")
            self.assertEqual(rows, 3)


@pytest.mark.integration
@pytest.mark.cloud
class TestDatasphereLive(unittest.TestCase):
    def test_append_round_trip(self):
        env = _env("DATASPHERE_TENANT_URL", "DATASPHERE_TOKEN")
        if env is None:
            self.skipTest("DATASPHERE_* credentials not configured")
        loader = _loader("datasphere")
        cfg = {
            "tenant_url": env["DATASPHERE_TENANT_URL"],
            "token": env["DATASPHERE_TOKEN"],
        }
        with _skip_if_service_rejects(self, "SAP Datasphere"):
            rows = loader.load(_df(), cfg, table="it_people")
            self.assertEqual(rows, 3)


@pytest.mark.integration
@pytest.mark.cloud
class TestMotherDuckLive(unittest.TestCase):
    DB_NAME = "dgp_it_db"

    def test_append_round_trip(self):
        env = _env("MOTHERDUCK_TOKEN")
        if env is None:
            self.skipTest("MOTHERDUCK_TOKEN not configured")

        import os
        import duckdb
        os.environ["MOTHERDUCK_TOKEN"] = env["MOTHERDUCK_TOKEN"]
        with _skip_if_service_rejects(self, "MotherDuck"):
            # MotherDuck only auto-creates a default 'my_db'; a named
            # database must exist before the loader can attach md:<name>.
            admin = duckdb.connect("md:")
            try:
                admin.execute(
                    f"CREATE DATABASE IF NOT EXISTS {self.DB_NAME}")
            finally:
                admin.close()

            loader = _loader("motherduck")
            cfg = {
                "db_path": f"md:{self.DB_NAME}",
                "motherduck_token": env["MOTHERDUCK_TOKEN"],
            }
            # if_exists="replace" keeps the test idempotent — appending
            # would accumulate rows across repeated CI runs.
            rows = loader.load(_df(), cfg, table="it_people",
                               if_exists="replace")
            self.assertEqual(rows, 3)

            # Read back through a fresh MotherDuck connection
            conn = duckdb.connect(f"md:{self.DB_NAME}")
            try:
                out = conn.execute(
                    "SELECT name FROM it_people ORDER BY id").fetchall()
            finally:
                conn.close()
            self.assertEqual([r[0] for r in out], ["a", "b", "c"])


@pytest.mark.integration
@pytest.mark.cloud
class TestQuickBooksSandbox(unittest.TestCase):
    def test_batch_create(self):
        env = _env("QB_CLIENT_ID", "QB_CLIENT_SECRET",
                   "QB_REFRESH_TOKEN", "QB_REALM_ID")
        if env is None:
            self.skipTest("QB_* sandbox credentials not configured")
        loader = _loader("quickbooks")
        cfg = {
            "client_id": env["QB_CLIENT_ID"],
            "client_secret": env["QB_CLIENT_SECRET"],
            "refresh_token": env["QB_REFRESH_TOKEN"],
            "realm_id": env["QB_REALM_ID"],
            "environment": "sandbox",
            "entity": "Customer",
        }
        df = pd.DataFrame({
            "DisplayName": [f"IT Test Customer {i}" for i in range(3)],
        })
        with _skip_if_service_rejects(self, "QuickBooks"):
            rows = loader.load(df, cfg, table="Customer")
            self.assertEqual(rows, 3)


@pytest.mark.integration
@pytest.mark.cloud
class TestSnowflakeVectorLive(unittest.TestCase):
    def test_vector_table_round_trip(self):
        env = _env("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER",
                   "SNOWFLAKE_PASSWORD", "SNOWFLAKE_DATABASE",
                   "SNOWFLAKE_WAREHOUSE")
        if env is None:
            self.skipTest("SNOWFLAKE_* credentials not configured")
        loader = _loader("snowflake_vector")
        cfg = {
            "account": env["SNOWFLAKE_ACCOUNT"],
            "user": env["SNOWFLAKE_USER"],
            "password": env["SNOWFLAKE_PASSWORD"],
            "database": env["SNOWFLAKE_DATABASE"],
            "warehouse": env["SNOWFLAKE_WAREHOUSE"],
            "vector_column": "embedding",
            "vector_dim": 3,
        }
        df = pd.DataFrame({
            "id": [1, 2, 3],
            "name": ["a", "b", "c"],
            "embedding": [[float(i), 0.5, 0.25] for i in (1, 2, 3)],
        })
        with _skip_if_service_rejects(self, "Snowflake"):
            rows = loader.load(df, cfg, table="it_vectors")
            self.assertEqual(rows, 3)


@pytest.mark.integration
@pytest.mark.cloud
class TestBigQueryVectorLive(unittest.TestCase):
    def test_vector_table_round_trip(self):
        env = _env("BQ_PROJECT", "BQ_DATASET",
                   "GOOGLE_APPLICATION_CREDENTIALS")
        if env is None:
            self.skipTest("BQ_* credentials not configured")
        loader = _loader("bigquery_vector")
        cfg = {
            "project": env["BQ_PROJECT"],
            "dataset": env["BQ_DATASET"],
            "vector_column": "embedding",
        }
        df = pd.DataFrame({
            "id": [1, 2, 3],
            "name": ["a", "b", "c"],
            "embedding": [[float(i), 0.5, 0.25] for i in (1, 2, 3)],
        })
        with _skip_if_service_rejects(self, "BigQuery"):
            rows = loader.load(df, cfg, table="it_vectors")
            self.assertEqual(rows, 3)


if __name__ == "__main__":
    unittest.main()
