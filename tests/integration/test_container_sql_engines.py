"""
Integration tests for container-backed SQL engines.

Real servers via testcontainers: ClickHouse, CockroachDB, pgvector,
PostGIS, SQL Server (mssql directly, and the Synapse loader's T-SQL
path against the same engine), Yellowbrick via its PostgreSQL
wire-compatible protocol.

Requires a running Docker engine; the module skips cleanly without it
so the unit suite is unaffected.

Revision history
────────────────
1.0   2026-06-12   Initial release.
"""

import os
import unittest
from unittest.mock import MagicMock

import pandas as pd
import pytest

os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")


def _docker_available() -> bool:
    try:
        import docker
        docker.from_env().ping()
        return True
    except Exception:
        return False


DOCKER = _docker_available()

from pipeline.loaders import resolve_loader  # noqa: E402


def _df(ids=(1, 2, 3), names=("a", "b", "c")):
    return pd.DataFrame({"id": list(ids), "name": list(names)})


def _loader(db_type: str):
    loader_class, needs_db_type, _ = resolve_loader(db_type)
    if needs_db_type:
        return loader_class(MagicMock(), db_type)
    return loader_class(MagicMock())


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestClickHouseIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import time
        import urllib.request
        from testcontainers.core.container import DockerContainer
        cls.container = (
            DockerContainer("clickhouse/clickhouse-server:24.8")
            .with_env("CLICKHOUSE_PASSWORD", "it_pass")
            .with_exposed_ports(8123)
        )
        cls.container.start()
        port = int(cls.container.get_exposed_port(8123))
        # The 24.x ready-log message changed; the /ping HTTP endpoint is the
        # stable readiness signal.
        deadline = time.monotonic() + 90
        while True:
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/ping", timeout=2) as resp:
                    if resp.read().strip() == b"Ok.":
                        break
            except Exception:
                if time.monotonic() > deadline:
                    raise TimeoutError("ClickHouse /ping never became ready")
                time.sleep(1)
        cls.cfg = {
            "host": "127.0.0.1",
            "port": port,
            "username": "default",
            "password": "it_pass",
            "database": "default",
        }

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _read(self, table):
        import clickhouse_connect
        client = clickhouse_connect.get_client(
            host=self.cfg["host"], port=self.cfg["port"],
            username="default", password="it_pass",
        )
        try:
            return client.query_df(f"SELECT * FROM {table} ORDER BY id")
        finally:
            client.close()

    def test_append_then_read_back(self):
        loader = _loader("clickhouse")
        rows = loader.load(_df(), self.cfg, table="people_append")
        self.assertEqual(rows, 3)
        out = self._read("people_append")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_upsert_deduplicates_on_key(self):
        loader = _loader("clickhouse")
        loader.load(_df(), self.cfg, table="people_upsert",
                    if_exists="upsert", natural_keys=["id"])
        loader.load(_df(ids=(3, 4), names=("c2", "d")), self.cfg,
                    table="people_upsert", if_exists="upsert",
                    natural_keys=["id"])
        import clickhouse_connect
        client = clickhouse_connect.get_client(
            host=self.cfg["host"], port=self.cfg["port"],
            username="default", password="it_pass",
        )
        try:
            out = client.query_df(
                "SELECT id, name FROM people_upsert FINAL ORDER BY id")
        finally:
            client.close()
        self.assertEqual(out["id"].tolist(), [1, 2, 3, 4])
        self.assertEqual(out.loc[out["id"] == 3, "name"].iloc[0], "c2")


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestCockroachDBIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("cockroachdb/cockroach:v24.3.5")
            .with_command("start-single-node --insecure")
            .with_exposed_ports(26257)
        )
        cls.container.start()
        wait_for_logs(cls.container, "nodeID:", timeout=90)
        cls.cfg = {
            "host": "127.0.0.1",
            "port": int(cls.container.get_exposed_port(26257)),
            "user": "root",
            "db_name": "defaultdb",
            "sslmode": "disable",
        }

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _read(self, table):
        from sqlalchemy import create_engine
        # The cockroachdb dialect is required: plain postgresql+psycopg2
        # cannot parse CockroachDB's server version string.
        url = (f"cockroachdb://root@{self.cfg['host']}:"
               f"{self.cfg['port']}/defaultdb?sslmode=disable")
        engine = create_engine(url)
        try:
            return pd.read_sql(f"SELECT * FROM {table} ORDER BY id", engine)
        finally:
            engine.dispose()

    def test_append_then_read_back(self):
        loader = _loader("cockroachdb")
        rows = loader.load(_df(), self.cfg, table="people_append")
        self.assertEqual(rows, 3)
        out = self._read("people_append")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_upsert_updates_and_inserts(self):
        loader = _loader("cockroachdb")
        loader.load(_df(), self.cfg, table="people_upsert")
        loader.load(_df(ids=(3, 4), names=("c2", "d")), self.cfg,
                    table="people_upsert", if_exists="upsert",
                    natural_keys=["id"])
        out = self._read("people_upsert")
        self.assertEqual(out["id"].tolist(), [1, 2, 3, 4])
        self.assertEqual(out.loc[out["id"] == 3, "name"].iloc[0], "c2")


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestPgvectorIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from testcontainers.postgres import PostgresContainer
        cls.container = PostgresContainer("pgvector/pgvector:pg16")
        cls.container.start()
        cls.cfg = {
            "host": "127.0.0.1",
            "port": int(cls.container.get_exposed_port(5432)),
            "db_name": cls.container.dbname,
            "user": cls.container.username,
            "password": cls.container.password,
            "vector_column": "embedding",
            "vector_dim": 3,
        }
        from sqlalchemy import create_engine, text
        engine = create_engine(cls.container.get_connection_url())
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        engine.dispose()

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _vec_df(self, ids=(1, 2, 3)):
        return pd.DataFrame({
            "id": list(ids),
            "name": [f"doc{i}" for i in ids],
            "embedding": [[float(i), 0.5, 0.25] for i in ids],
        })

    def test_load_creates_vector_column_and_search_works(self):
        loader = _loader("pgvector")
        rows = loader.load(self._vec_df(), self.cfg, table="docs")
        self.assertEqual(rows, 3)

        from sqlalchemy import create_engine, text
        engine = create_engine(self.container.get_connection_url())
        try:
            with engine.connect() as conn:
                col_type = conn.execute(text(
                    "SELECT format_type(atttypid, atttypmod) "
                    "FROM pg_attribute WHERE attrelid = 'docs'::regclass "
                    "AND attname = 'embedding'"
                )).scalar()
                self.assertIn("vector", col_type)
                nearest = conn.execute(text(
                    "SELECT id FROM docs "
                    "ORDER BY embedding <=> '[1.0,0.5,0.25]' LIMIT 1"
                )).scalar()
                self.assertEqual(nearest, 1)
        finally:
            engine.dispose()


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestPostGISIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from testcontainers.postgres import PostgresContainer
        cls.container = PostgresContainer("postgis/postgis:16-3.4")
        cls.container.start()
        cls.cfg = {
            "host": "127.0.0.1",
            "port": int(cls.container.get_exposed_port(5432)),
            "db_name": cls.container.dbname,
            "user": cls.container.username,
            "password": cls.container.password,
        }

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def test_geometry_lands_on_the_right_rows(self):
        df = pd.DataFrame({
            "id": [1, 2, 3],
            "name": ["alpha", "beta", "gamma"],
            "geometry": ["POINT(1 1)", "POINT(2 2)", None],
        })
        loader = _loader("postgis")
        rows = loader.load(df, self.cfg, table="places")
        self.assertEqual(rows, 3)

        from sqlalchemy import create_engine, text
        engine = create_engine(self.container.get_connection_url())
        try:
            with engine.connect() as conn:
                out = conn.execute(text(
                    "SELECT id, name, ST_AsText(geometry) AS wkt "
                    "FROM places ORDER BY id"
                )).fetchall()
        finally:
            engine.dispose()
        self.assertEqual(out[0].wkt, "POINT(1 1)")
        self.assertEqual(out[1].wkt, "POINT(2 2)")
        self.assertIsNone(out[2].wkt)


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestSqlServerFamilyIntegration(unittest.TestCase):
    """mssql via SQLLoader and the Synapse loader's T-SQL fallback path,
    both against a real SQL Server container."""

    PASSWORD = "ItStrong!Pass1"

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("mcr.microsoft.com/mssql/server:2022-latest")
            .with_env("ACCEPT_EULA", "Y")
            .with_env("MSSQL_SA_PASSWORD", cls.PASSWORD)
            .with_exposed_ports(1433)
        )
        cls.container.start()
        wait_for_logs(cls.container,
                      "SQL Server is now ready for client connections",
                      timeout=180)
        cls.host = "127.0.0.1"
        cls.port = int(cls.container.get_exposed_port(1433))

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    @staticmethod
    def _best_driver() -> str:
        """Prefer the modern MS ODBC drivers; fall back to the in-box
        legacy 'SQL Server' driver (works on Win11 against 2022)."""
        import pyodbc
        for name in ("ODBC Driver 18 for SQL Server",
                     "ODBC Driver 17 for SQL Server",
                     "SQL Server"):
            if name in pyodbc.drivers():
                return name
        raise RuntimeError("No SQL Server ODBC driver installed")

    def _driver_params(self) -> str:
        driver = self._best_driver().replace(" ", "+")
        params = f"driver={driver}"
        # Encrypt/TrustServerCertificate keywords only exist in 17/18;
        # the legacy driver does not encrypt by default.
        if "18" in driver or "17" in driver:
            params += "&TrustServerCertificate=yes&Encrypt=no"
        return params

    def _cfg(self):
        return {
            "host": f"{self.host},{self.port}",
            "db_name": "master",
            "database": "master",
            "user": "sa",
            "password": self.PASSWORD,
            "driver": self._best_driver().replace(" ", "+"),
            # ODBC 17/18 encrypt by default and reject the container's
            # self-signed certificate
            "encrypt": "no",
            "trust_server_certificate": "yes",
        }

    def _read(self, table):
        from sqlalchemy import create_engine
        from urllib.parse import quote_plus
        url = (f"mssql+pyodbc://sa:{quote_plus(self.PASSWORD)}"
               f"@{self.host},{self.port}/master?{self._driver_params()}")
        engine = create_engine(url)
        try:
            return pd.read_sql(f"SELECT * FROM {table} ORDER BY id", engine)
        finally:
            engine.dispose()

    def test_mssql_append_then_read_back(self):
        loader = _loader("mssql")
        rows = loader.load(_df(), self._cfg(), table="people_mssql")
        self.assertEqual(rows, 3)
        out = self._read("people_mssql")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_synapse_sql_fallback_append(self):
        loader = _loader("synapse")
        cfg = self._cfg()
        rows = loader.load(_df(), cfg, table="people_synapse")
        self.assertEqual(rows, 3)
        out = self._read("people_synapse")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_synapse_wide_frame_exceeding_old_param_limit(self):
        # 10 columns x 500 rows = 5,000 params — the old chunksize=500
        # exceeded SQL Server's 2,100-parameter cap for >=5 columns
        wide = pd.DataFrame({
            "id": range(500),
            **{f"col{i}": [f"v{i}"] * 500 for i in range(9)},
        })
        loader = _loader("synapse")
        rows = loader.load(wide, self._cfg(), table="wide_synapse")
        self.assertEqual(rows, 500)
        out = self._read("wide_synapse")
        self.assertEqual(len(out), 500)


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestYellowbrickWireCompatible(unittest.TestCase):
    """Yellowbrick speaks the PostgreSQL wire protocol; its loader is
    verified against a real Postgres engine.  Vendor-specific behaviour
    (DISTRIBUTE ON, etc.) is NOT covered here — documented limitation."""

    @classmethod
    def setUpClass(cls):
        from testcontainers.postgres import PostgresContainer
        cls.container = PostgresContainer("postgres:16-alpine")
        cls.container.start()
        cls.cfg = {
            "host": "127.0.0.1",
            "port": int(cls.container.get_exposed_port(5432)),
            "database": cls.container.dbname,
            "user": cls.container.username,
            "password": cls.container.password,
            "sslmode": "disable",
        }

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _read(self, table):
        from sqlalchemy import create_engine
        engine = create_engine(self.container.get_connection_url())
        try:
            return pd.read_sql(f"SELECT * FROM {table} ORDER BY id", engine)
        finally:
            engine.dispose()

    def test_append_then_read_back(self):
        loader = _loader("yellowbrick")
        rows = loader.load(_df(), self.cfg, table="people_yb")
        self.assertEqual(rows, 3)
        out = self._read("people_yb")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_upsert_updates_and_inserts(self):
        loader = _loader("yellowbrick")
        loader.load(_df(), self.cfg, table="people_yb_upsert")
        loader.load(_df(ids=(3, 4), names=("c2", "d")), self.cfg,
                    table="people_yb_upsert", if_exists="upsert",
                    natural_keys=["id"])
        out = self._read("people_yb_upsert")
        self.assertEqual(out["id"].tolist(), [1, 2, 3, 4])
        self.assertEqual(out.loc[out["id"] == 3, "name"].iloc[0], "c2")


if __name__ == "__main__":
    unittest.main()
