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
"""

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
        rows = loader.load(_df(), cfg, table="it_people")
        self.assertEqual(rows, 3)


@pytest.mark.integration
@pytest.mark.cloud
class TestDatabricksLive(unittest.TestCase):
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
        # MotherDuck only auto-creates a default 'my_db'; a named database
        # must exist before the loader can attach to md:<name>.
        admin = duckdb.connect("md:")
        try:
            admin.execute(f"CREATE DATABASE IF NOT EXISTS {self.DB_NAME}")
        finally:
            admin.close()

        loader = _loader("motherduck")
        cfg = {
            "db_path": f"md:{self.DB_NAME}",
            "motherduck_token": env["MOTHERDUCK_TOKEN"],
        }
        rows = loader.load(_df(), cfg, table="it_people")
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
        rows = loader.load(df, cfg, table="it_vectors")
        self.assertEqual(rows, 3)


if __name__ == "__main__":
    unittest.main()
