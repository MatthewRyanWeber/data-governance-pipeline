"""
Integration tests for heavyweight database containers: Oracle Free, Db2.

Both images take minutes to initialise — marked slow in addition to
integration so quick local integration runs can exclude them with
-m "integration and not slow".

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
    loader_class, _, _ = resolve_loader(db_type)
    return loader_class(MagicMock())


@pytest.mark.integration
@pytest.mark.slow
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestOracleIntegration(unittest.TestCase):

    PASSWORD = "ItOracle1"

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("gvenzl/oracle-free:23-slim")
            .with_env("ORACLE_PASSWORD", cls.PASSWORD)
            .with_exposed_ports(1521)
        )
        cls.container.start()
        wait_for_logs(cls.container, "DATABASE IS READY TO USE", timeout=600)
        cls.dsn = (f"127.0.0.1:{cls.container.get_exposed_port(1521)}"
                   f"/FREEPDB1")

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _cfg(self):
        return {"user": "system", "password": self.PASSWORD, "dsn": self.dsn}

    def _read(self, table):
        import oracledb
        conn = oracledb.connect(user="system", password=self.PASSWORD,
                                dsn=self.dsn)
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT id, name FROM {table} ORDER BY id")
            return cur.fetchall()
        finally:
            conn.close()

    def test_append_then_read_back(self):
        loader = _loader("oracle")
        rows = loader.load(_df(), self._cfg(), table="people_append")
        self.assertEqual(rows, 3)
        out = self._read("people_append")
        self.assertEqual([r[1] for r in out], ["a", "b", "c"])

    def test_upsert_updates_and_inserts(self):
        loader = _loader("oracle")
        loader.load(_df(), self._cfg(), table="people_upsert")
        loader.load(_df(ids=(3, 4), names=("c2", "d")), self._cfg(),
                    table="people_upsert", if_exists="upsert",
                    natural_keys=["id"])
        out = self._read("people_upsert")
        self.assertEqual([r[0] for r in out], [1, 2, 3, 4])
        self.assertEqual(out[2][1], "c2")


@pytest.mark.integration
@pytest.mark.slow
@unittest.skipUnless(DOCKER, "Docker engine not available")
class TestDb2Integration(unittest.TestCase):

    PASSWORD = "ItDb2Pass1"

    @classmethod
    def setUpClass(cls):
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
        cls.container = (
            DockerContainer("icr.io/db2_community/db2:latest")
            .with_env("LICENSE", "accept")
            .with_env("DB2INST1_PASSWORD", cls.PASSWORD)
            .with_env("DBNAME", "itdb")
            .with_kwargs(privileged=True)
            .with_exposed_ports(50000)
        )
        cls.container.start()
        # First boot creates the database from scratch — routinely 15-25
        # minutes on a cold volume
        wait_for_logs(cls.container, "Setup has completed", timeout=1800)
        cls.cfg_base = {
            "host": "127.0.0.1",
            "port": int(cls.container.get_exposed_port(50000)),
            "user": "db2inst1",
            "password": cls.PASSWORD,
            "database": "itdb",
        }

    @classmethod
    def tearDownClass(cls):
        cls.container.stop()

    def _read(self, table):
        import ibm_db
        conn_str = (
            f"DATABASE=itdb;HOSTNAME=127.0.0.1;"
            f"PORT={self.cfg_base['port']};PROTOCOL=TCPIP;"
            f"UID=db2inst1;PWD={self.PASSWORD};"
        )
        conn = ibm_db.connect(conn_str, "", "")
        try:
            stmt = ibm_db.exec_immediate(
                conn, f"SELECT id, name FROM {table} ORDER BY id")
            rows = []
            row = ibm_db.fetch_tuple(stmt)
            while row:
                rows.append(row)
                row = ibm_db.fetch_tuple(stmt)
            return rows
        finally:
            ibm_db.close(conn)

    def test_append_then_read_back(self):
        loader = _loader("db2")
        rows = loader.load(_df(), dict(self.cfg_base), table="people_append")
        self.assertEqual(rows, 3)
        out = self._read("people_append")
        self.assertEqual([r[1] for r in out], ["a", "b", "c"])

    def test_upsert_updates_and_inserts(self):
        loader = _loader("db2")
        loader.load(_df(), dict(self.cfg_base), table="people_upsert")
        loader.load(_df(ids=(3, 4), names=("c2", "d")), dict(self.cfg_base),
                    table="people_upsert", if_exists="upsert",
                    natural_keys=["id"])
        out = self._read("people_upsert")
        self.assertEqual([int(r[0]) for r in out], [1, 2, 3, 4])
        self.assertEqual(out[2][1], "c2")


if __name__ == "__main__":
    unittest.main()
