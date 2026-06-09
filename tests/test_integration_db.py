"""
Live database integration tests via testcontainers (real Docker containers).

These spin up genuine PostgreSQL, MySQL, and MongoDB servers and run the
loaders end-to-end — the highest-fidelity coverage possible, catching wire/
dialect/transaction bugs that mocks never could.

Requires a running Docker engine.  When Docker is unavailable the whole module
skips cleanly, so the normal unit suite is unaffected.

Run just these with:  pytest tests/test_integration_db.py -v

Revision history
────────────────
1.0   2026-06-09   Initial release: Postgres/MySQL SQLLoader + Mongo round-trips.
1.1   2026-06-09   Added pytest.mark.integration markers and expanded test coverage.
"""

import os
import unittest
from unittest.mock import MagicMock

import pandas as pd
import pytest

# Ryuk (the testcontainers reaper) needs a registry pull/handshake; disable it
# since images are pre-pulled and we stop containers explicitly in tearDown.
os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")


def _docker_available() -> bool:
    try:
        import docker
        docker.from_env().ping()
        return True
    except Exception:
        return False


DOCKER = _docker_available()

from pipeline.loaders.sql_loader import SQLLoader          # noqa: E402
from pipeline.loaders.mongo_loader import MongoLoader      # noqa: E402
from pipeline.load_verifier import LoadVerifier            # noqa: E402


def _df():
    return pd.DataFrame({"id": [1, 2, 3], "name": ["a", "b", "c"]})


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestPostgresIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from testcontainers.postgres import PostgresContainer
        from sqlalchemy.engine import make_url
        from sqlalchemy import create_engine
        cls.container = PostgresContainer("postgres:16-alpine")
        cls.container.start()
        url = make_url(cls.container.get_connection_url())
        cls.cfg = {"host": url.host, "port": url.port, "user": url.username,
                   "password": url.password, "db_name": url.database}
        cls.read_engine = create_engine(cls.container.get_connection_url())

    @classmethod
    def tearDownClass(cls):
        cls.read_engine.dispose()
        cls.container.stop()

    def setUp(self):
        self.loader = SQLLoader(MagicMock(), db_type="postgresql")

    def _read(self, table):
        return pd.read_sql(f"SELECT * FROM {table} ORDER BY id", self.read_engine)

    def test_append_then_replace(self):
        self.loader.load(_df(), self.cfg, "t_pg", if_exists="replace")
        self.assertEqual(len(self._read("t_pg")), 3)
        self.loader.load(pd.DataFrame({"id": [9], "name": ["z"]}),
                         self.cfg, "t_pg", if_exists="append")
        self.assertEqual(len(self._read("t_pg")), 4)
        self.loader.load(pd.DataFrame({"id": [1], "name": ["only"]}),
                         self.cfg, "t_pg", if_exists="replace")
        self.assertEqual(list(self._read("t_pg")["name"]), ["only"])

    def test_upsert_updates_and_inserts(self):
        self.loader.load(_df(), self.cfg, "t_up", if_exists="replace")
        update = pd.DataFrame({"id": [2, 5], "name": ["B", "e"]})
        self.loader.load(update, self.cfg, "t_up", natural_keys=["id"])
        out = self._read("t_up")
        self.assertEqual(out.loc[out["id"] == 2, "name"].iloc[0], "B")  # updated
        self.assertIn(5, list(out["id"]))                                # inserted
        self.assertEqual(len(out), 4)

    def test_load_verifier_against_real_postgres(self):
        self.loader.load(_df(), self.cfg, "t_verify", if_exists="replace")
        verifier = LoadVerifier(MagicMock())
        cfg = {**self.cfg, "db_type": "postgresql",
               "connection_string": self.container.get_connection_url()}
        result = verifier.verify_row_count(_df(), cfg, "t_verify")
        self.assertTrue(result["match"])
        self.assertEqual(result["dest_rows"], 3)

    def test_large_batch_10k_rows(self):
        large_df = pd.DataFrame({
            "id": range(10_000),
            "name": [f"row_{i}" for i in range(10_000)],
        })
        self.loader.load(large_df, self.cfg, "t_10k", if_exists="replace")
        result = self._read("t_10k")
        self.assertEqual(len(result), 10_000)


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestMySQLIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from testcontainers.mysql import MySqlContainer
        from sqlalchemy.engine import make_url
        from sqlalchemy import create_engine
        cls.container = MySqlContainer("mysql:8.4")
        cls.container.start()
        url = make_url(cls.container.get_connection_url())
        cls.cfg = {"host": url.host, "port": url.port, "user": url.username,
                   "password": url.password, "db_name": url.database}
        # Force the pymysql driver for read-back (MySQLdb is not installed; the
        # loader uses pymysql too).
        cls.read_engine = create_engine(url.set(drivername="mysql+pymysql"))

    @classmethod
    def tearDownClass(cls):
        cls.read_engine.dispose()
        cls.container.stop()

    def setUp(self):
        self.loader = SQLLoader(MagicMock(), db_type="mysql")

    def _read(self, table):
        return pd.read_sql(f"SELECT * FROM {table} ORDER BY id", self.read_engine)

    def test_append_and_upsert(self):
        self.loader.load(_df(), self.cfg, "t_my", if_exists="replace")
        self.assertEqual(len(self._read("t_my")), 3)
        self.loader.load(pd.DataFrame({"id": [2, 7], "name": ["B", "g"]}),
                         self.cfg, "t_my", natural_keys=["id"])
        out = self._read("t_my")
        self.assertEqual(out.loc[out["id"] == 2, "name"].iloc[0], "B")
        self.assertIn(7, list(out["id"]))
        self.assertEqual(len(out), 4)

    def test_replace_clears_existing(self):
        self.loader.load(_df(), self.cfg, "t_repl", if_exists="replace")
        self.assertEqual(len(self._read("t_repl")), 3)
        replacement = pd.DataFrame({"id": [99], "name": ["only"]})
        self.loader.load(replacement, self.cfg, "t_repl", if_exists="replace")
        out = self._read("t_repl")
        self.assertEqual(len(out), 1)
        self.assertEqual(out.iloc[0]["name"], "only")


@pytest.mark.integration
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestMongoIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from testcontainers.mongodb import MongoDbContainer
        cls.container = MongoDbContainer("mongo:7")
        cls.container.start()
        cls.uri = cls.container.get_connection_url()

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def setUp(self):
        self.loader = MongoLoader(MagicMock())

    def test_insert_many_real(self):
        from pymongo import MongoClient
        self.loader.load(_df(), {"uri": self.uri, "db_name": "appdb"}, "users")
        with MongoClient(self.uri) as client:
            count = client["appdb"]["users"].count_documents({})
        self.assertEqual(count, 3)

    def test_verify_row_count(self):
        self.loader.load(_df(), {"uri": self.uri, "db_name": "appdb"}, "verify_col")
        verifier = LoadVerifier(MagicMock())
        cfg = {"db_type": "mongodb", "connection_string": self.uri, "db_name": "appdb"}
        result = verifier.verify_row_count(_df(), cfg, "verify_col")
        self.assertTrue(result["match"])
        self.assertEqual(result["dest_rows"], 3)


if __name__ == "__main__":
    unittest.main()
