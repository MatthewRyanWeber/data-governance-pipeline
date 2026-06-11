"""
Regression tests for the 2026-06-11 loader bug-fix batch.

Covers:
  1. Column-name SQL-injection guard wired into the loader dispatch
     (backtick added to the banned characters).
  2. Partial executemany batches rolled back before retry (Db2; the Oracle
     twin lives in test_oracle_loader.py).
  4. PostGIS geometry written in the same INSERT via ST_GeomFromText —
     no ctid-offset matching.
  8. All-columns-are-keys MERGE omits WHEN MATCHED instead of emitting a
     bogus __noop__ / ROWID no-op clause.
  9. if_exists='upsert' without natural_keys raises instead of silently
     appending (CockroachDB, DuckDB; Kafka twin in test_loader_dispatch.py).
 21. validate_loader_config accepts each loader's real required keys.

Revision history
────────────────
1.0   2026-06-11   Initial release.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

import pipeline.loaders.bigquery_loader as bq_mod
import pipeline.loaders.databricks_loader as db_mod
import pipeline.loaders.db2_loader as db2_mod
import pipeline.loaders.firebolt_loader as fb_mod
import pipeline.loaders.redshift_loader as rs_mod
import pipeline.loaders.snowflake_loader as sf_mod
import pipeline.loaders.synapse_loader as syn_mod
from pipeline.exceptions import ConfigValidationError
from pipeline.loaders import resolve_loader, validate_loader_config
from pipeline.loaders.base import validate_column_names
from pipeline.loaders.cockroachdb_loader import CockroachDBLoader
from pipeline.loaders.databricks_loader import DatabricksLoader
from pipeline.loaders.db2_loader import Db2Loader
from pipeline.loaders.duckdb_loader import DuckDBLoader
from pipeline.loaders.firebolt_loader import FireboltLoader
from pipeline.loaders.postgis_loader import PostGISLoader
from pipeline.loaders.redshift_loader import RedshiftLoader
from pipeline.loaders.snowflake_loader import SnowflakeLoader
from pipeline.loaders.sql_loader import SQLLoader
from pipeline.loaders.synapse_loader import SynapseLoader

_KEYS_ONLY = pd.DataFrame({"id": [1, 2]})
_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})


def _cursor_sql(cursor):
    calls = list(cursor.execute.call_args_list) + list(cursor.executemany.call_args_list)
    return [str(c[0][0]) for c in calls if c[0]]


class TestColumnNameInjectionGuard(unittest.TestCase):
    """Finding 1 — df.columns validated before any loader builds SQL."""

    def test_backtick_in_column_name_rejected(self):
        df = pd.DataFrame({"evil`col": [1]})
        with self.assertRaises(ValueError) as ctx:
            validate_column_names(df)
        self.assertIn("disallowed", str(ctx.exception))

    def test_quote_in_column_name_rejected(self):
        df = pd.DataFrame({'evil"; DROP TABLE x--': [1]})
        with self.assertRaises(ValueError):
            validate_column_names(df)

    def test_dispatch_guard_blocks_bad_columns_before_load(self):
        """A loader resolved through dispatch must reject malicious column
        names before connecting anywhere."""
        cls, needs_db_type, _ = resolve_loader("duckdb")
        loader = cls(MagicMock())
        df = pd.DataFrame({"name`); DROP TABLE x--": ["a"]})
        with self.assertRaises(ValueError) as ctx:
            loader.load(df, {"db_path": ":memory:"}, table="t")
        self.assertIn("disallowed", str(ctx.exception))

    def test_dispatch_guard_covers_sql_loader(self):
        cls, needs_db_type, _ = resolve_loader("sqlite")
        loader = cls(MagicMock(), db_type="sqlite")
        df = pd.DataFrame({"a'b": [1]})
        with self.assertRaises(ValueError):
            loader.load(df, {"db_name": "x"}, table="t")

    def test_guard_preserves_load_signature(self):
        import inspect
        cls, _, _ = resolve_loader("duckdb")
        params = inspect.signature(cls.load).parameters
        self.assertIn("if_exists", params)
        self.assertIn("natural_keys", params)

    def test_clean_columns_pass_through_guard(self):
        cls, _, _ = resolve_loader("duckdb")
        loader = cls(MagicMock(), dry_run=True)
        rows = loader.load(_DF, {"db_path": ":memory:"}, table="t")
        self.assertEqual(rows, 0)


class TestDb2PartialBatchRollback(unittest.TestCase):
    """Finding 2 — Db2 disables autocommit and rolls back before retry."""

    def setUp(self):
        self.gov = MagicMock()
        with patch.object(db2_mod, "HAS_DB2", True):
            self.loader = Db2Loader(self.gov)
        self.cfg = {"host": "h", "user": "u", "password": "p", "database": "d"}

    def test_rollback_called_before_retry(self):
        ibm = MagicMock()
        ibm.execute_many.side_effect = [Exception("partial batch"), None]
        with patch.dict(sys.modules, {"ibm_db": ibm}), \
             patch("pipeline.loaders.db2_loader.time.sleep"):
            self.loader.load(_DF, self.cfg, "t", if_exists="append")
        ibm.rollback.assert_called()
        # Autocommit disabled so the partial batch is actually revocable.
        ibm.autocommit.assert_called_once_with(
            ibm.connect.return_value, ibm.SQL_AUTOCOMMIT_OFF
        )
        ibm.commit.assert_called()

    def test_insert_has_explicit_column_list(self):
        ibm = MagicMock()
        with patch.dict(sys.modules, {"ibm_db": ibm}):
            self.loader.load(_DF, self.cfg, "t", if_exists="append")
        prepared = str(ibm.prepare.call_args[0][1])
        self.assertIn('("ID", "NAME") VALUES (?, ?)', prepared)


class TestPostGISGeometryInsert(unittest.TestCase):
    """Finding 4 — geometry bound into the row INSERT, no ctid matching."""

    def setUp(self):
        self.gov = MagicMock()
        self.loader = PostGISLoader(self.gov)
        self.cfg = {"host": "h", "user": "u", "password": "p", "db_name": "d"}

    def _df(self):
        return pd.DataFrame({
            "id": [1, 2],
            "geometry": ["POINT(1 2)", None],
        })

    def test_geometry_inserted_with_st_geomfromtext(self):
        engine = MagicMock()
        conn = engine.connect.return_value.__enter__.return_value
        with patch("sqlalchemy.create_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql"):
            rows = self.loader.load(self._df(), self.cfg, table="places")
        self.assertEqual(rows, 2)
        executed = [str(c[0][0]) for c in conn.execute.call_args_list]
        insert = next(s for s in executed if "INSERT INTO" in s)
        self.assertIn("ST_GeomFromText(:wkt, :srid)", insert)
        self.assertNotIn("ctid", " ".join(executed))

    def test_geometry_params_one_per_row(self):
        engine = MagicMock()
        conn = engine.connect.return_value.__enter__.return_value
        with patch("sqlalchemy.create_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql"):
            self.loader.load(self._df(), self.cfg, table="places")
        insert_call = next(c for c in conn.execute.call_args_list
                           if "INSERT INTO" in str(c[0][0]))
        params = insert_call[0][1]
        self.assertEqual(len(params), 2)
        self.assertEqual(params[0]["wkt"], "POINT(1 2)")
        self.assertIsNone(params[1]["wkt"])


class TestAllKeyMergeOmitsWhenMatched(unittest.TestCase):
    """Finding 8 — all-columns-are-keys MERGE has no WHEN MATCHED / __noop__."""

    def _assert_clean_merge(self, merge_sql):
        self.assertNotIn("WHEN MATCHED", merge_sql)
        self.assertNotIn("__noop__", merge_sql.lower())
        self.assertIn("WHEN NOT MATCHED", merge_sql)

    def test_snowflake(self):
        gov = MagicMock()
        with patch.object(sf_mod, "HAS_SNOWFLAKE", True):
            loader = SnowflakeLoader(gov)
        conn = MagicMock()
        cursor = conn.cursor.return_value
        cfg = {"account": "a", "user": "u", "password": "p",
               "database": "DB", "warehouse": "WH"}
        with patch.object(loader, "_connect", return_value=conn), \
             patch.object(loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            loader.load(_KEYS_ONLY, cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(cursor) if "MERGE INTO" in s)
        self._assert_clean_merge(merge)

    def test_snowflake_upsert_creates_target_table(self):
        """Finding 10 — first upsert must create the target before MERGE."""
        gov = MagicMock()
        with patch.object(sf_mod, "HAS_SNOWFLAKE", True):
            loader = SnowflakeLoader(gov)
        conn = MagicMock()
        cursor = conn.cursor.return_value
        cfg = {"account": "a", "user": "u", "password": "p",
               "database": "DB", "warehouse": "WH"}
        with patch.object(loader, "_connect", return_value=conn), \
             patch.object(loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            loader.load(_DF, cfg, "t", natural_keys=["id"])
        sql = _cursor_sql(cursor)
        self.assertTrue(any("CREATE TABLE IF NOT EXISTS" in s for s in sql))

    @unittest.skipUnless(bq_mod.HAS_BIGQUERY, "google-cloud-bigquery not installed")
    def test_bigquery(self):
        from pipeline.loaders.bigquery_loader import BigQueryLoader
        gov = MagicMock()
        loader = BigQueryLoader(gov)
        client = MagicMock()
        cfg = {"project": "p", "dataset": "ds"}
        with patch.object(loader, "_client", return_value=client):
            loader.load(_KEYS_ONLY, cfg, "t", natural_keys=["id"])
        merge = client.query.call_args[0][0]
        self._assert_clean_merge(merge)

    def test_redshift(self):
        gov = MagicMock()
        with patch.object(rs_mod, "HAS_REDSHIFT", True):
            loader = RedshiftLoader(gov)
        conn = MagicMock()
        cursor = conn.cursor.return_value
        cfg = {"host": "h", "database": "d", "user": "u", "password": "p"}
        with patch.object(loader, "_connect", return_value=conn), \
             patch.object(loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            loader.load(_KEYS_ONLY, cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(cursor) if "MERGE INTO" in s)
        self._assert_clean_merge(merge)

    def test_synapse(self):
        gov = MagicMock()
        with patch.object(syn_mod, "HAS_SYNAPSE", True):
            loader = SynapseLoader(gov)
        conn = MagicMock()
        cursor = conn.cursor.return_value
        cfg = {"host": "h", "database": "d", "user": "u", "password": "p"}
        with patch.object(loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"), \
             patch("pyodbc.connect", return_value=conn):
            loader.load(_KEYS_ONLY, cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(cursor)
                     if "MERGE" in s and "USING" in s)
        self._assert_clean_merge(merge)

    def test_firebolt(self):
        gov = MagicMock()
        with patch.object(fb_mod, "HAS_FIREBOLT", True):
            loader = FireboltLoader(gov)
        conn = MagicMock()
        cursor = conn.cursor.return_value
        cfg = {"username": "u", "password": "p", "database": "d",
               "account_name": "acct", "engine_name": "eng"}
        with patch.object(loader, "_connect", return_value=conn):
            loader.load(_KEYS_ONLY, cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(cursor) if "MERGE INTO" in s)
        self._assert_clean_merge(merge)

    def test_db2(self):
        gov = MagicMock()
        with patch.object(db2_mod, "HAS_DB2", True):
            loader = Db2Loader(gov)
        cfg = {"host": "h", "user": "u", "password": "p", "database": "d"}
        ibm = MagicMock()
        with patch.dict(sys.modules, {"ibm_db": ibm}), \
             patch.object(loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql"):
            loader.load(_KEYS_ONLY, cfg, "t", natural_keys=["id"])
        executed = [str(c[0][1]) for c in ibm.exec_immediate.call_args_list
                    if len(c[0]) > 1]
        merge = next(s for s in executed if "MERGE INTO" in s)
        self._assert_clean_merge(merge)

    def test_databricks(self):
        gov = MagicMock()
        with patch.object(db_mod, "HAS_DATABRICKS", True):
            loader = DatabricksLoader(gov)
        conn = MagicMock()
        cursor = conn.cursor.return_value
        cfg = {"server_hostname": "h", "http_path": "/p"}
        with patch.object(loader, "_connect", return_value=conn):
            loader.load(_KEYS_ONLY, cfg, "t", natural_keys=["id"])
        merge = next(s for s in _cursor_sql(cursor) if "MERGE INTO" in s)
        self._assert_clean_merge(merge)


class TestUpsertRequiresNaturalKeys(unittest.TestCase):
    """Finding 9 — upsert without natural_keys raises, never appends."""

    def test_cockroachdb_raises(self):
        loader = CockroachDBLoader(MagicMock())
        cfg = {"host": "h", "user": "u", "db_name": "d"}
        with patch.object(loader, "_engine", return_value=MagicMock()), \
             patch("pandas.DataFrame.to_sql") as to_sql:
            with self.assertRaises(ValueError) as ctx:
                loader.load(_DF, cfg, table="t", if_exists="upsert")
        self.assertIn("natural_keys", str(ctx.exception))
        to_sql.assert_not_called()

    def test_duckdb_raises(self):
        loader = DuckDBLoader(MagicMock())
        with self.assertRaises(ValueError) as ctx:
            loader.load(_DF, {"db_path": ":memory:"}, table="t",
                        if_exists="upsert")
        self.assertIn("natural_keys", str(ctx.exception))


class TestSQLLoaderDottedTable(unittest.TestCase):
    """Finding 24 — dotted table names split into schema + table."""

    def test_split_table_name(self):
        self.assertEqual(SQLLoader._split_table_name("s.t"), ("s", "t"))
        self.assertEqual(SQLLoader._split_table_name("t"), (None, "t"))

    def test_to_sql_receives_schema(self):
        loader = SQLLoader(MagicMock(), db_type="postgresql")
        engine = MagicMock()
        with patch.object(loader, "_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql") as to_sql:
            loader.load(_DF, {"db_name": "d"}, "myschema.mytable")
        args, kwargs = to_sql.call_args
        self.assertEqual(args[0], "mytable")
        self.assertEqual(kwargs.get("schema"), "myschema")


class TestValidateLoaderConfigRegistry(unittest.TestCase):
    """Finding 21 — registry matches each loader's real required keys."""

    def test_snowflake_accepts_account(self):
        validate_loader_config("snowflake", {
            "account": "a", "user": "u", "password": "p",
            "database": "d", "warehouse": "w",
        })

    def test_snowflake_rejects_host_only(self):
        with self.assertRaises(ConfigValidationError):
            validate_loader_config("snowflake", {"host": "h"})

    def test_databricks_accepts_server_hostname(self):
        validate_loader_config("databricks", {
            "server_hostname": "h", "http_path": "/p",
        })

    def test_firebolt_accepts_client_credentials(self):
        validate_loader_config("firebolt", {
            "client_id": "ci", "client_secret": "cs", "database": "d",
            "account_name": "a", "engine_name": "e",
        })

    def test_firebolt_accepts_username_password(self):
        validate_loader_config("firebolt", {
            "username": "u", "password": "p", "database": "d",
            "account_name": "a", "engine_name": "e",
        })

    def test_datasphere_requires_tenant_url(self):
        validate_loader_config("datasphere", {
            "tenant_url": "https://x", "token": "t",
        })
        with self.assertRaises(ConfigValidationError):
            validate_loader_config("datasphere", {"host": "h"})

    def test_mongodb_requires_db_name_not_connection_string(self):
        validate_loader_config("mongodb", {"db_name": "d"})
        with self.assertRaises(ConfigValidationError):
            validate_loader_config("mongodb", {"connection_string": "mongodb://x"})

    def test_snowflake_vector_requires_account(self):
        with self.assertRaises(ConfigValidationError):
            validate_loader_config("snowflake_vector", {"host": "h"})

    def test_bigquery_vector_requires_project(self):
        validate_loader_config("bigquery_vector", {"project": "p", "dataset": "d"})
        with self.assertRaises(ConfigValidationError):
            validate_loader_config("bigquery_vector", {"host": "h"})


class TestFireboltAuthValidation(unittest.TestCase):
    """Finding 18 — loader accepts client_id/client_secret auth."""

    def test_client_credentials_pass_loader_validation(self):
        gov = MagicMock()
        with patch.object(fb_mod, "HAS_FIREBOLT", True):
            loader = FireboltLoader(gov)
        conn = MagicMock()
        cfg = {"client_id": "ci", "client_secret": "cs", "database": "d",
               "account_name": "acct", "engine_name": "eng"}
        with patch.object(loader, "_connect", return_value=conn):
            loader.load(_DF, cfg, "t", if_exists="append")
        gov.load_complete.assert_called_once()


if __name__ == "__main__":
    unittest.main()
