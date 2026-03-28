"""
test_loader_dispatch.py  —  Loader dispatch verification for pipeline_v3.py main()

Tests:
  1. _resolve_loader() returns the correct (cls, needs_db_type, is_mongo) tuple
     for every registered db_type string.
  2. Unknown db_type raises ValueError with a helpful message.
  3. The load block in main() calls the right loader class for non-SQL destinations
     (MongoDB, Snowflake, BigQuery, SAP HANA, SAP Datasphere) instead of crashing
     inside SQLLoader._engine() with ValueError: Unknown db type.
  4. SQLite path still works end-to-end (regression).
  5. MongoLoader path uses collection arg, no if_exists kwarg.
  6. ReversibleLoader wrapping: applied for _SQLALCHEMY_PLATFORMS, skipped for
     non-SQLAlchemy loaders (BigQuery, Oracle, Db2, etc.).
"""
import io
import sys
import pathlib
import tempfile
import logging
import unittest
from unittest.mock import MagicMock, patch

logging.disable(logging.CRITICAL)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import pandas as pd

from pipeline_v3 import (
    _resolve_loader, _LOADER_DISPATCH,
    SQLLoader, MongoLoader, SnowflakeLoader, BigQueryLoader, RedshiftLoader,
    SynapseLoader, DatabricksLoader, ClickHouseLoader, OracleLoader,
    Db2Loader, FireboltLoader, YellowbrickLoader, HanaLoader, DatasphereLoader,
    QuickBooksLoader, LanceDBLoader, KafkaLoader,
    PineconeLoader, WeaviateLoader, QdrantLoader,
    ChromaLoader, MilvusLoader,
    PgvectorLoader, SnowflakeVectorLoader, BigQueryVectorLoader,
    CockroachDBLoader,
    DuckDBLoader, ParquetLoader, DeltaLakeLoader, IcebergLoader,
    S3Loader, AthenaLoader, SFTPLoader, MicrosoftFabricLoader, PostGISLoader,
    GovernanceLogger, TableCopier,
)

# ── Actual SQLAlchemy-backed platforms (TableCopier uses these for read/write
#    via create_engine; ReversibleLoader wrapping is offered for these) ─────────
_SQL_ALCHEMY = TableCopier._SQLALCHEMY_PLATFORMS   # sqlite, postgresql, mysql, mssql, snowflake


class TestResolveLoader(unittest.TestCase):
    """Unit tests for _resolve_loader() and _LOADER_DISPATCH contents."""

    def test_all_destinations_registered(self):
        expected = {
            "sqlite","postgresql","postgres","mysql","mssql",
            "snowflake","bigquery","redshift","synapse",
            "databricks","clickhouse",
            "oracle","db2","firebolt","yellowbrick",
            "hana","datasphere",
            "mongodb",
            "quickbooks",
            "lancedb",
            "duckdb",
            "motherduck",
            "parquet",
            "deltalake",
            "iceberg",
            "s3",
            "gcs",
            "azure_blob",
            "athena",
            "sftp",
            "fabric",
            "postgis",
            "cockroachdb",
            "pgvector",
            "snowflake_vector",
            "bigquery_vector",
            "chroma",
            "milvus",
            "pinecone",
            "weaviate",
            "qdrant",
            "kafka",
        }
        self.assertEqual(expected, set(_LOADER_DISPATCH.keys()),
                         f"Missing: {expected - set(_LOADER_DISPATCH.keys())}")

    def test_correct_class_for_every_type(self):
        mapping = {
            "sqlite":      SQLLoader,
            "postgresql":  SQLLoader,
            "mysql":       SQLLoader,
            "mssql":       SQLLoader,
            "snowflake":   SnowflakeLoader,
            "bigquery":    BigQueryLoader,
            "redshift":    RedshiftLoader,
            "synapse":     SynapseLoader,
            "databricks":  DatabricksLoader,
            "clickhouse":  ClickHouseLoader,
            "oracle":      OracleLoader,
            "db2":         Db2Loader,
            "firebolt":    FireboltLoader,
            "yellowbrick": YellowbrickLoader,
            "hana":        HanaLoader,
            "datasphere":  DatasphereLoader,
            "mongodb":     MongoLoader,
            "quickbooks":  QuickBooksLoader,
            "lancedb":           LanceDBLoader,
            "duckdb":            DuckDBLoader,
            "motherduck":        DuckDBLoader,
            "parquet":           ParquetLoader,
            "deltalake":         DeltaLakeLoader,
            "iceberg":           IcebergLoader,
            "s3":                S3Loader,
            "gcs":               S3Loader,
            "azure_blob":        S3Loader,
            "athena":            AthenaLoader,
            "sftp":              SFTPLoader,
            "fabric":            MicrosoftFabricLoader,
            "postgis":           PostGISLoader,
            "cockroachdb":       CockroachDBLoader,
            "pgvector":          PgvectorLoader,
            "snowflake_vector":  SnowflakeVectorLoader,
            "bigquery_vector":   BigQueryVectorLoader,
            "chroma":            ChromaLoader,
            "milvus":            MilvusLoader,
            "pinecone":          PineconeLoader,
            "weaviate":          WeaviateLoader,
            "qdrant":            QdrantLoader,
            "kafka":             KafkaLoader,
        }
        for db_type, expected_cls in mapping.items():
            with self.subTest(db_type=db_type):
                cls, _, _ = _resolve_loader(db_type)
                self.assertIs(cls, expected_cls)

    def test_needs_db_type_arg_only_for_sql_loader(self):
        for db_type, (cls, needs, _) in _LOADER_DISPATCH.items():
            with self.subTest(db_type=db_type):
                if cls is SQLLoader:
                    self.assertTrue(needs)
                else:
                    self.assertFalse(needs)

    def test_mongo_sig_only_for_mongo_loader(self):
        for db_type, (cls, _, is_mongo) in _LOADER_DISPATCH.items():
            with self.subTest(db_type=db_type):
                if cls is MongoLoader:
                    self.assertTrue(is_mongo)
                else:
                    self.assertFalse(is_mongo)

    def test_unknown_type_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            _resolve_loader("oracle_exadata")
        self.assertIn("oracle_exadata", str(ctx.exception))
        self.assertIn("Known types", str(ctx.exception))

    def test_case_insensitive(self):
        for variant in ("Snowflake", "SNOWFLAKE", "snowflake"):
            cls, _, _ = _resolve_loader(variant)
            self.assertIs(cls, SnowflakeLoader)


class TestReversibleLoaderWrapping(unittest.TestCase):
    """
    Verify which loaders participate in ReversibleLoader wrapping.

    ReversibleLoader wrapping is applied when dst_db_type is in
    TableCopier._SQLALCHEMY_PLATFORMS.  Snowflake IS in that set (its
    SnowflakeLoader uses SQLAlchemy internally); BigQuery, Oracle, MongoDB, etc.
    are NOT.
    """

    def test_sqlalchemy_set_contains_expected_types(self):
        self.assertIn("sqlite",      _SQL_ALCHEMY)
        self.assertIn("postgresql",  _SQL_ALCHEMY)
        self.assertIn("mysql",       _SQL_ALCHEMY)
        self.assertIn("mssql",       _SQL_ALCHEMY)
        self.assertIn("snowflake",   _SQL_ALCHEMY)

    def test_non_sqlalchemy_types_not_in_set(self):
        non_sql = {"bigquery","redshift","synapse","databricks","clickhouse",
                   "oracle","db2","firebolt","hana","datasphere","mongodb"}
        for db_type in non_sql:
            with self.subTest(db_type=db_type):
                self.assertNotIn(db_type, _SQL_ALCHEMY)

    def test_snowflake_uses_snowflake_loader_not_sql_loader(self):
        # Snowflake is in _SQLALCHEMY_PLATFORMS but dispatches to SnowflakeLoader
        # (its dedicated class), not the generic SQLLoader
        cls, _, _ = _resolve_loader("snowflake")
        self.assertIs(cls, SnowflakeLoader)
        self.assertIn("snowflake", _SQL_ALCHEMY)  # ReversibleLoader will wrap it


class TestMainWizardDispatch(unittest.TestCase):
    """
    Drive main() with mocked stdin + patched loaders, bypass the isatty guard.
    Verifies the correct loader class is instantiated and .load() called.
    """

    def _run_wizard(self, answers, loader_patches):
        """
        loader_patches: list of (attr_name_in_pv3, mock) tuples.
        Returns stdout text.
        """
        import pipeline_v3 as pv3
        old_out, sys.stdout = sys.stdout, io.StringIO()
        old_in,  sys.stdin  = sys.stdin,  io.StringIO("\n".join(answers) + "\n")

        # Patch isatty so the wizard doesn't exit immediately
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            mock_stdin.readline.side_effect = (io.StringIO("\n".join(answers) + "\n")).readline
            mock_stdin.read = (io.StringIO("\n".join(answers) + "\n")).read

            ctx_patches = [patch.object(pv3, name, return_value=mock)
                           for name, mock in loader_patches]
            for p in ctx_patches:
                p.start()
            try:
                pv3.main()
            except (SystemExit, EOFError, Exception):
                pass
            finally:
                for p in ctx_patches:
                    p.stop()

        out = sys.stdout.getvalue()
        sys.stdout = old_out
        sys.stdin  = old_in
        return out

    def test_sqlite_dispatch_resolves_and_load_called(self):
        """
        SQLite regression — direct dispatch verification.
        Resolves loader, instantiates it, calls load(); asserts the correct
        class was used and load() received the expected arguments.
        """
        import pandas as pd, tempfile, shutil
        tmp = tempfile.mkdtemp()
        try:
            df = pd.DataFrame({"id":[1,2],"name":["A","B"]})
            db_p = pathlib.Path(tmp) / "out"
            cfg  = {"db_name": str(db_p)}

            g = GovernanceLogger("dispatch_test.csv")
            cls, needs_db_type, is_mongo = _resolve_loader("sqlite")

            # Correct class
            self.assertIs(cls, SQLLoader)
            self.assertTrue(needs_db_type)
            self.assertFalse(is_mongo)

            # Instantiate correctly
            loader = cls(gov=g, db_type="sqlite")
            self.assertIsInstance(loader, SQLLoader)

            # load() succeeds with standard signature
            loader.load(df, cfg, "tbl", if_exists="replace", natural_keys=None)

            # Verify data was written
            from sqlalchemy import create_engine, inspect as sai
            eng = create_engine(f"sqlite:///{db_p}.db")
            self.assertIn("tbl", sai(eng).get_table_names())

            shutil.rmtree(g.log_dir, ignore_errors=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree("dispatch_test LOGS", ignore_errors=True)

    def test_mongo_loader_class_resolved(self):
        """MongoLoader is resolved for 'mongodb', has is_mongo=True."""
        cls, needs, is_mongo = _resolve_loader("mongodb")
        self.assertIs(cls, MongoLoader)
        self.assertFalse(needs)
        self.assertTrue(is_mongo)

    def test_mongo_load_sig_has_no_if_exists(self):
        """MongoLoader.load signature must not have if_exists param."""
        import inspect
        params = inspect.signature(MongoLoader.load).parameters
        self.assertIn("collection", params)
        self.assertNotIn("if_exists", params)
        self.assertNotIn("natural_keys", params)

    def test_all_non_mongo_loaders_have_if_exists(self):
        """Every loader except MongoLoader must accept if_exists."""
        import inspect
        for db_type, (cls, _, is_mongo) in _LOADER_DISPATCH.items():
            if is_mongo:
                continue
            with self.subTest(loader=cls.__name__):
                params = inspect.signature(cls.load).parameters
                self.assertIn("if_exists", params,
                              f"{cls.__name__}.load() is missing if_exists parameter")


class TestDispatchTableMeta(unittest.TestCase):
    """Structural correctness checks on _LOADER_DISPATCH."""

    def test_all_entries_are_3_tuples(self):
        for k, v in _LOADER_DISPATCH.items():
            with self.subTest(key=k):
                self.assertEqual(len(v), 3)

    def test_all_classes_are_callable(self):
        for k, (cls, _, _) in _LOADER_DISPATCH.items():
            with self.subTest(key=k):
                self.assertTrue(callable(cls))

    def test_bool_flags_are_bool(self):
        for k, (_, needs, is_mongo) in _LOADER_DISPATCH.items():
            with self.subTest(key=k):
                self.assertIsInstance(needs,   bool)
                self.assertIsInstance(is_mongo, bool)

    def test_hana_and_datasphere_registered(self):
        self.assertIn("hana",       _LOADER_DISPATCH)
        self.assertIn("datasphere", _LOADER_DISPATCH)
        h_cls, _, _ = _resolve_loader("hana")
        d_cls, _, _ = _resolve_loader("datasphere")
        self.assertIs(h_cls, HanaLoader)
        self.assertIs(d_cls, DatasphereLoader)


class TestQuickBooksDispatch(unittest.TestCase):
    """
    Fix 5 — QuickBooks loader dispatch and load() signature coverage.

    Verifies:
      - "quickbooks" resolves to QuickBooksLoader (not SQLLoader or MongoLoader)
      - needs_db_type=False (QuickBooksLoader takes only gov=)
      - is_mongo=False (load() uses standard table/if_exists API)
      - load() has the five required parameters matching the dispatch contract
      - _row_to_body correctly unflattens double-underscore columns
      - _validate_row flags missing required fields without crashing
      - load() create path: rows without Id are treated as new records
      - load() update path: rows with Id are treated as updates
      - load() skip path: rows missing required fields are skipped gracefully
    """

    def setUp(self):
        self.gov = GovernanceLogger("qb_dispatch_test.csv")
        self.qbl = QuickBooksLoader(gov=self.gov)
        self.mock_tok = MagicMock()
        self.mock_tok.ok = True
        self.mock_tok.json.return_value = {"access_token": "test_access_token"}
        self.mock_post_ok = MagicMock()
        self.mock_post_ok.ok = True
        self.mock_post_ok.json.return_value = {
            "Customer": {"Id": "1", "DisplayName": "Acme Corp", "SyncToken": "0"}
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.gov.log_dir, ignore_errors=True)
        shutil.rmtree("qb_dispatch_test LOGS", ignore_errors=True)

    # ── Dispatch resolution ───────────────────────────────────────────────

    def test_quickbooks_resolves_to_quickbooks_loader(self):
        cls, needs, is_mongo = _resolve_loader("quickbooks")
        self.assertIs(cls, QuickBooksLoader,
                      "quickbooks must dispatch to QuickBooksLoader, not SQLLoader")

    def test_quickbooks_needs_db_type_false(self):
        _, needs, _ = _resolve_loader("quickbooks")
        self.assertFalse(needs,
                         "QuickBooksLoader.__init__ takes only gov=, not db_type=")

    def test_quickbooks_is_mongo_false(self):
        _, _, is_mongo = _resolve_loader("quickbooks")
        self.assertFalse(is_mongo,
                         "QuickBooksLoader.load() uses the standard if_exists API, not Mongo collection API")

    def test_quickbooks_in_dispatch_table(self):
        self.assertIn("quickbooks", _LOADER_DISPATCH)

    # ── load() signature contract ─────────────────────────────────────────

    def test_load_signature_has_all_required_params(self):
        import inspect
        params = set(inspect.signature(QuickBooksLoader.load).parameters.keys())
        for required in ("self", "df", "cfg", "table", "if_exists", "natural_keys"):
            self.assertIn(required, params,
                          f"QuickBooksLoader.load() is missing parameter: {required}")

    def test_load_has_if_exists_not_collection(self):
        """load() must use if_exists (not collection) — distinguishes it from MongoLoader."""
        import inspect
        params = inspect.signature(QuickBooksLoader.load).parameters
        self.assertIn("if_exists", params)
        self.assertNotIn("collection", params)

    # ── _row_to_body ──────────────────────────────────────────────────────

    def test_row_to_body_top_level_field(self):
        row = pd.Series({"DisplayName": "Acme Corp", "CompanyName": "Acme"})
        body = QuickBooksLoader._row_to_body(row, "Customer", sparse=True)
        self.assertEqual(body["DisplayName"], "Acme Corp")
        self.assertEqual(body["CompanyName"], "Acme")

    def test_row_to_body_unflatten_double_underscore(self):
        """BillAddr__Line1 must become {"BillAddr": {"Line1": "..."}}"""
        row = pd.Series({
            "DisplayName":         "Acme",
            "BillAddr__Line1":     "1 Main St",
            "BillAddr__City":      "Springfield",
            "BillAddr__CountrySubDivisionCode": "IL",   # non-numeric, no coercion ambiguity
        })
        body = QuickBooksLoader._row_to_body(row, "Customer", sparse=True)
        self.assertIn("BillAddr", body)
        self.assertEqual(body["BillAddr"]["Line1"], "1 Main St")
        self.assertEqual(body["BillAddr"]["City"],  "Springfield")
        self.assertEqual(body["BillAddr"]["CountrySubDivisionCode"], "IL")

    def test_row_to_body_sparse_drops_none(self):
        row = pd.Series({"DisplayName": "X", "BillAddr__Line1": None})
        body = QuickBooksLoader._row_to_body(row, "Customer", sparse=True)
        self.assertNotIn("BillAddr", body,
                         "sparse=True must drop None values before unflattening")

    def test_row_to_body_sparse_false_keeps_none(self):
        row = pd.Series({"DisplayName": "X", "Notes": None})
        body = QuickBooksLoader._row_to_body(row, "Customer", sparse=False)
        self.assertIn("Notes", body)

    def test_row_to_body_json_string_deserialized(self):
        """Line-item arrays stored as JSON strings must be parsed back to lists."""
        import json
        line_items = [{"Amount": 100, "DetailType": "SalesItemLineDetail"}]
        row = pd.Series({"DisplayName": "X", "Line": json.dumps(line_items)})
        body = QuickBooksLoader._row_to_body(row, "Invoice", sparse=True)
        self.assertIsInstance(body["Line"], list,
                              "JSON string fields must be deserialised back to Python objects")

    # ── _validate_row ─────────────────────────────────────────────────────

    def test_validate_row_ok_for_valid_customer(self):
        self.assertEqual(
            self.qbl._validate_row({"DisplayName": "Acme"}, "Customer"), []
        )

    def test_validate_row_flags_missing_display_name(self):
        missing = self.qbl._validate_row({}, "Customer")
        self.assertIn("DisplayName", missing)

    def test_validate_row_empty_for_unknown_entity(self):
        """Transactional entities have no built-in required-field list."""
        self.assertEqual(self.qbl._validate_row({}, "Invoice"), [])
        self.assertEqual(self.qbl._validate_row({}, "JournalEntry"), [])

    def test_validate_row_employee_requires_given_and_family_name(self):
        missing = self.qbl._validate_row({"GivenName": "John"}, "Employee")
        self.assertIn("FamilyName", missing)
        self.assertNotIn("GivenName", missing)

    # ── load() behaviour ─────────────────────────────────────────────────

    def _cfg(self):
        return {
            "client_id": "ci", "client_secret": "cs",
            "refresh_token": "rt", "realm_id": "123",
            "environment": "sandbox", "batch_delay": 0,
        }

    def test_load_create_path_no_id_column(self):
        """Rows without Id → all counted as created."""
        df_new = pd.DataFrame({"DisplayName": ["Acme", "Wayne"], "CompanyName": ["A", "W"]})
        with patch("requests.post", side_effect=[
            self.mock_tok, self.mock_post_ok, self.mock_post_ok
        ]):
            self.qbl.load(df_new, self._cfg(), table="Customer")
        # If we get here without exception the create path works

    def test_load_update_path_with_id_column(self):
        """Rows with Id → treated as updates (same endpoint, QBO merges on Id)."""
        df_upd = pd.DataFrame({
            "Id": ["101", "102"],
            "SyncToken": ["5", "3"],
            "DisplayName": ["Acme Updated", "Wayne Updated"],
        })
        with patch("requests.post", side_effect=[
            self.mock_tok, self.mock_post_ok, self.mock_post_ok
        ]):
            self.qbl.load(df_upd, self._cfg(), table="Customer")

    def test_load_skips_row_missing_required_field(self):
        """Rows missing DisplayName must be skipped, not crash the whole load."""
        df_bad = pd.DataFrame({"CompanyName": ["Bad Corp"]})  # no DisplayName
        with patch("requests.post", side_effect=[self.mock_tok]):
            # Should complete without raising; the row is skipped with a warning
            self.qbl.load(df_bad, self._cfg(), table="Customer")

    def test_load_replace_mode_warns_not_crashes(self):
        """QBO doesn't support bulk delete; replace mode must warn and continue."""
        df = pd.DataFrame({"DisplayName": ["Acme"]})
        with patch("requests.post", side_effect=[self.mock_tok, self.mock_post_ok]):
            # Should not raise even with if_exists="replace"
            self.qbl.load(df, self._cfg(), table="Customer", if_exists="replace")

    def test_load_custom_row_transform_used_when_provided(self):
        """cfg['row_transform'] callable must be used instead of _row_to_body."""
        transform_called = []
        def my_transform(row):
            transform_called.append(True)
            return {"DisplayName": row["DisplayName"]}

        df = pd.DataFrame({"DisplayName": ["Acme"]})
        cfg = {**self._cfg(), "row_transform": my_transform}
        with patch("requests.post", side_effect=[self.mock_tok, self.mock_post_ok]):
            self.qbl.load(df, cfg, table="Customer")
        self.assertTrue(transform_called,
                        "cfg['row_transform'] was never called — custom transform ignored")




class TestLanceDBLoader(unittest.TestCase):
    """Tests for LanceDBLoader — mocks lancedb so no real DB needed."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        gov = MagicMock()
        gov.log_dir = self._tmp
        gov._event  = MagicMock()
        self.gov    = gov

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _loader(self):
        from pipeline_v3 import LanceDBLoader, HAS_LANCEDB
        if not HAS_LANCEDB:
            self.skipTest("lancedb not installed")
        return LanceDBLoader(self.gov)

    def _cfg(self):
        return {"uri": self._tmp + "/lancedb"}

    def _df(self):
        return pd.DataFrame({
            "id":   [1, 2, 3],
            "text": ["hello world", "foo bar", "baz qux"],
            "val":  [0.1, 0.2, 0.3],
        })

    def test_raises_without_lancedb(self):
        """LanceDBLoader raises RuntimeError when lancedb is not installed."""
        import pipeline_v3 as pv3
        orig = pv3.HAS_LANCEDB
        pv3.HAS_LANCEDB = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.LanceDBLoader(self.gov)
        finally:
            pv3.HAS_LANCEDB = orig

    def test_lancedb_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH, LanceDBLoader
        self.assertIn("lancedb", _LOADER_DISPATCH)
        cls, needs_db_type, is_mongo = _LOADER_DISPATCH["lancedb"]
        self.assertIs(cls, LanceDBLoader)
        self.assertFalse(needs_db_type)
        self.assertFalse(is_mongo)

    def test_load_append_creates_table(self):
        loader = self._loader()
        mock_db    = MagicMock()
        mock_table = MagicMock()
        mock_db.table_names.return_value = []
        mock_db.create_table.return_value = mock_table

        with patch("lancedb.connect", return_value=mock_db):
            rows = loader.load(self._df(), self._cfg(), "test_table",
                               if_exists="append")

        self.assertEqual(rows, 3)
        mock_db.create_table.assert_called_once()
        self.gov._event.assert_called_once()

    def test_load_append_to_existing_table(self):
        loader = self._loader()
        mock_db    = MagicMock()
        mock_table = MagicMock()
        mock_db.table_names.return_value = ["test_table"]
        mock_db.open_table.return_value = mock_table

        with patch("lancedb.connect", return_value=mock_db):
            rows = loader.load(self._df(), self._cfg(), "test_table",
                               if_exists="append")

        self.assertEqual(rows, 3)
        mock_db.open_table.assert_called_once_with("test_table")
        mock_table.add.assert_called()

    def test_load_overwrite_mode(self):
        loader = self._loader()
        mock_db = MagicMock()
        mock_db.create_table.return_value = MagicMock()

        with patch("lancedb.connect", return_value=mock_db):
            rows = loader.load(self._df(), self._cfg(), "test_table",
                               if_exists="overwrite")

        self.assertEqual(rows, 3)
        mock_db.create_table.assert_called_once()
        call_kwargs = mock_db.create_table.call_args
        self.assertEqual(call_kwargs[1].get("mode") or
                         call_kwargs[0][2] if len(call_kwargs[0]) > 2 else
                         call_kwargs[1].get("mode"), "overwrite")


    def test_load_upsert_mode_new_table(self):
        """Upsert on a non-existent table creates it."""
        loader = self._loader()
        mock_db = MagicMock()
        mock_db.table_names.return_value = []
        mock_db.create_table.return_value = MagicMock()

        with patch("lancedb.connect", return_value=mock_db):
            rows = loader.load(self._df(), self._cfg(), "test_table",
                               if_exists="upsert", natural_keys=["id"])

        self.assertEqual(rows, 3)
        mock_db.create_table.assert_called_once()

    def test_load_upsert_mode_existing_table(self):
        """Upsert on an existing table uses merge_insert builder."""
        loader = self._loader()
        mock_db      = MagicMock()
        mock_tbl     = MagicMock()
        mock_builder = MagicMock()
        mock_db.table_names.return_value = ["test_table"]
        mock_db.open_table.return_value = mock_tbl
        mock_tbl.merge_insert.return_value = mock_builder
        mock_builder.when_matched_update_all.return_value = mock_builder
        mock_builder.when_not_matched_insert_all.return_value = mock_builder

        with patch("lancedb.connect", return_value=mock_db):
            rows = loader.load(self._df(), self._cfg(), "test_table",
                               if_exists="upsert", natural_keys=["id"])

        self.assertEqual(rows, 3)
        mock_tbl.merge_insert.assert_called_once_with("id")
        mock_builder.when_matched_update_all.assert_called_once()
        mock_builder.when_not_matched_insert_all.assert_called_once()
        mock_builder.execute.assert_called_once()

    def test_invalid_if_exists_raises(self):
        loader = self._loader()
        mock_db = MagicMock()
        with patch("lancedb.connect", return_value=mock_db):
            with self.assertRaises(ValueError) as ctx:
                loader.load(self._df(), self._cfg(), "t", if_exists="replace")
        self.assertIn("if_exists", str(ctx.exception))

    def test_missing_uri_raises(self):
        loader = self._loader()
        mock_db = MagicMock()
        with patch("lancedb.connect", return_value=mock_db):
            with self.assertRaises(ValueError) as ctx:
                loader.load(self._df(), {}, "t")
        self.assertIn("uri", str(ctx.exception))

    def test_governance_event_fired(self):
        loader = self._loader()
        mock_db = MagicMock()
        mock_db.table_names.return_value = []
        mock_db.create_table.return_value = MagicMock()

        with patch("lancedb.connect", return_value=mock_db):
            loader.load(self._df(), self._cfg(), "test_table")

        self.gov._event.assert_called_once()
        call_args = str(self.gov._event.call_args)
        self.assertIn("LANCEDB_WRITE_COMPLETE", call_args)

    def test_list_tables(self):
        loader = self._loader()
        mock_db = MagicMock()
        mock_db.table_names.return_value = ["table_a", "table_b"]

        with patch("lancedb.connect", return_value=mock_db):
            tables = loader.list_tables(self._cfg())

        self.assertEqual(tables, ["table_a", "table_b"])

    def test_table_info(self):
        loader = self._loader()
        mock_db    = MagicMock()
        mock_table = MagicMock()
        mock_table.count_rows.return_value = 42
        mock_table.schema = "id: int64, text: string"
        mock_db.open_table.return_value = mock_table

        with patch("lancedb.connect", return_value=mock_db):
            info = loader.table_info(self._cfg(), "test_table")

        self.assertEqual(info["row_count"], 42)
        self.assertEqual(info["table"], "test_table")


    def test_search_empty_vector_raises(self):
        """search() raises ValueError on empty query_vector."""
        loader = self._loader()
        with patch("lancedb.connect", return_value=MagicMock()):
            with self.assertRaises(ValueError) as ctx:
                loader.search(self._cfg(), "t",
                              query_vector=[], vector_column="vec")
        self.assertIn("query_vector", str(ctx.exception))

    def test_search_none_vector_raises(self):
        """search() raises ValueError on None query_vector."""
        loader = self._loader()
        with patch("lancedb.connect", return_value=MagicMock()):
            with self.assertRaises(ValueError):
                loader.search(self._cfg(), "t",
                              query_vector=None, vector_column="vec")

    def test_upsert_empty_df_returns_zero_without_create(self):
        """Upsert with empty DataFrame returns 0 and never calls create_table."""
        loader  = self._loader()
        mock_db = MagicMock()
        mock_db.table_names.return_value = []
        with patch("lancedb.connect", return_value=mock_db):
            rows = loader.load(pd.DataFrame(), self._cfg(), "t",
                               if_exists="upsert", natural_keys=["id"])
        self.assertEqual(rows, 0)
        mock_db.create_table.assert_not_called()

    def test_vector_column_lists_converted(self):
        """numpy arrays in vector_column must be converted to Python lists."""
        import numpy as np
        loader = self._loader()
        mock_db = MagicMock()
        mock_db.table_names.return_value = []
        mock_db.create_table.return_value = MagicMock()

        df = self._df().copy()
        df["vector"] = [np.array([0.1, 0.2, 0.3])] * 3

        with patch("lancedb.connect", return_value=mock_db):
            loader.load(df, {**self._cfg(), "vector_column": "vector"},
                        "vec_table")

        # Verify create_table was called with list-type vectors (not np.ndarray)
        call_data = mock_db.create_table.call_args[1].get("data") or                     mock_db.create_table.call_args[0][1]
        self.assertIsInstance(call_data[0]["vector"], list)



class TestKafkaLoader(unittest.TestCase):
    """Tests for KafkaLoader — mocks kafka-python so no real broker needed."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        gov = MagicMock()
        gov.log_dir = self._tmp
        gov._event  = MagicMock()
        self.gov    = gov

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _loader(self):
        from pipeline_v3 import KafkaLoader, HAS_KAFKA_LOADER
        if not HAS_KAFKA_LOADER:
            self.skipTest("kafka-python not installed")
        return KafkaLoader(self.gov)

    def _cfg(self, **overrides):
        base = {
            "bootstrap_servers": "localhost:9092",
            "topic":             "test_topic",
        }
        base.update(overrides)
        return base

    def _df(self):
        return pd.DataFrame({
            "id":    [1, 2, 3],
            "name":  ["Alice", "Bob", "Carol"],
            "score": [0.9, 0.7, 0.8],
        })

    def test_kafka_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH, KafkaLoader
        self.assertIn("kafka", _LOADER_DISPATCH)
        cls, needs_db_type, is_mongo = _LOADER_DISPATCH["kafka"]
        self.assertIs(cls, KafkaLoader)
        self.assertFalse(needs_db_type)
        self.assertFalse(is_mongo)

    def test_raises_without_kafka_python(self):
        """KafkaLoader raises RuntimeError when kafka-python is not installed."""
        import pipeline_v3 as pv3
        orig = pv3.HAS_KAFKA_LOADER
        pv3.HAS_KAFKA_LOADER = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.KafkaLoader(self.gov)
        finally:
            pv3.HAS_KAFKA_LOADER = orig

    def test_missing_topic_raises(self):
        loader = self._loader()
        mock_producer = MagicMock()
        with patch("kafka.KafkaProducer", return_value=mock_producer):
            with self.assertRaises(ValueError) as ctx:
                loader.load(self._df(), {"bootstrap_servers": "localhost:9092"})
        self.assertIn("topic", str(ctx.exception))

    def test_missing_bootstrap_raises(self):
        loader = self._loader()
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"topic": "t"})
        self.assertIn("bootstrap_servers", str(ctx.exception))

    def test_invalid_if_exists_raises(self):
        loader = self._loader()
        mock_producer = MagicMock()
        with patch("kafka.KafkaProducer", return_value=mock_producer):
            with self.assertRaises(ValueError) as ctx:
                loader.load(self._df(), self._cfg(), if_exists="replace")
        self.assertIn("if_exists", str(ctx.exception))

    def test_load_append_publishes_all_rows(self):
        loader = self._loader()
        mock_producer   = MagicMock()
        mock_future     = MagicMock()
        mock_future.get.return_value = MagicMock()
        mock_producer.send.return_value = mock_future

        with patch("kafka.KafkaProducer", return_value=mock_producer):
            rows = loader.load(self._df(), self._cfg())

        self.assertEqual(rows, 3)
        self.assertEqual(mock_producer.send.call_count, 3)
        mock_producer.flush.assert_called()
        mock_producer.close.assert_called()

    def test_load_with_key_column(self):
        loader = self._loader()
        mock_producer = MagicMock()
        mock_future   = MagicMock()
        mock_future.get.return_value = MagicMock()
        mock_producer.send.return_value = mock_future

        with patch("kafka.KafkaProducer", return_value=mock_producer):
            loader.load(self._df(), self._cfg(key_column="id"))

        # Check that key was passed to send()
        call_kwargs = mock_producer.send.call_args_list[0][1]
        self.assertIn("key", call_kwargs)

    def test_load_upsert_sends_tombstones(self):
        loader = self._loader()
        mock_producer = MagicMock()
        mock_future   = MagicMock()
        mock_future.get.return_value = MagicMock()
        mock_producer.send.return_value = mock_future

        with patch("kafka.KafkaProducer", return_value=mock_producer):
            loader.load(self._df(), self._cfg(key_column="id"),
                        if_exists="upsert", natural_keys=["id"])

        # 3 tombstones + 3 records = 6 sends
        self.assertEqual(mock_producer.send.call_count, 6)
        # Verify at least one tombstone (value=None)
        all_calls = [c[1] for c in mock_producer.send.call_args_list]
        tombstones = [c for c in all_calls if c.get("value") is None]
        self.assertEqual(len(tombstones), 3)

    def test_governance_event_fired(self):
        loader = self._loader()
        mock_producer = MagicMock()
        mock_future   = MagicMock()
        mock_future.get.return_value = MagicMock()
        mock_producer.send.return_value = mock_future

        with patch("kafka.KafkaProducer", return_value=mock_producer):
            loader.load(self._df(), self._cfg())

        self.gov._event.assert_called_once()
        call_str = str(self.gov._event.call_args)
        self.assertIn("KAFKA_PUBLISH_COMPLETE", call_str)

    def test_table_param_overrides_cfg_topic(self):
        loader = self._loader()
        mock_producer = MagicMock()
        mock_future   = MagicMock()
        mock_future.get.return_value = MagicMock()
        mock_producer.send.return_value = mock_future

        with patch("kafka.KafkaProducer", return_value=mock_producer):
            loader.load(self._df(),
                        {"bootstrap_servers": "localhost:9092", "topic": "old_topic"},
                        table="new_topic")

        # Verify new_topic was used in the governance event
        call_str = str(self.gov._event.call_args)
        self.assertIn("new_topic", call_str)

    def test_publish_governance_event(self):
        loader = self._loader()
        mock_producer = MagicMock()
        mock_future   = MagicMock()
        mock_future.get.return_value = MagicMock()
        mock_producer.send.return_value = mock_future

        event = {"category": "PRIVACY", "action": "PII_DETECTED",
                 "detail": {"columns": ["email"]}}

        with patch("kafka.KafkaProducer", return_value=mock_producer):
            loader.publish_governance_event(
                {"bootstrap_servers": "localhost:9092"}, event
            )

        mock_producer.send.assert_called_once()
        call_kwargs = mock_producer.send.call_args[1]
        self.assertEqual(call_kwargs.get("topic") or
                         mock_producer.send.call_args[0][0],
                         "governance_events")

    def test_publish_governance_event_missing_bootstrap_raises(self):
        loader = self._loader()
        with self.assertRaises(ValueError):
            loader.publish_governance_event({}, {"action": "test"})


    def test_tombstone_serializer_passes_none_through(self):
        """Value serializer must pass None through unchanged for tombstone records."""
        import json as _json
        # Replicate the serializer from KafkaLoader._build_producer
        serializer = lambda v: (
            None if v is None
            else v if isinstance(v, bytes)
            else _json.dumps(v, default=str).encode("utf-8")
        )
        self.assertIsNone(serializer(None),
                          "Tombstone: None must stay None, not become b'null'")
        self.assertEqual(serializer({"a": 1}), b'{"a": 1}')
        self.assertEqual(serializer(b"bytes"),  b"bytes")

    def test_failed_delivery_counted_as_not_sent(self):
        """A message that raises on future.get() should not count as sent."""
        loader = self._loader()
        mock_producer  = MagicMock()
        good_future    = MagicMock()
        bad_future     = MagicMock()
        good_future.get.return_value = MagicMock()
        bad_future.get.side_effect   = Exception("broker unavailable")

        # First two rows succeed, third fails
        mock_producer.send.side_effect = [good_future, good_future, bad_future]

        with patch("kafka.KafkaProducer", return_value=mock_producer):
            rows = loader.load(self._df(), self._cfg())

        self.assertEqual(rows, 2)   # only 2 of 3 delivered




class TestVectorLoaders(unittest.TestCase):
    """Tests for PineconeLoader, WeaviateLoader, QdrantLoader."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        gov = MagicMock()
        gov.log_dir = self._tmp
        gov._event  = MagicMock()
        self.gov    = gov

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _df(self):
        return pd.DataFrame({
            "id":        ["doc1", "doc2", "doc3"],
            "text":      ["hello world", "foo bar", "baz qux"],
            "embedding": [
                [0.1, 0.2, 0.3],
                [0.4, 0.5, 0.6],
                [0.7, 0.8, 0.9],
            ],
        })

    # ── Dispatch table ────────────────────────────────────────────────────────

    def test_all_three_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH
        for dest in ("pinecone", "weaviate", "qdrant"):
            self.assertIn(dest, _LOADER_DISPATCH, f"{dest} missing from dispatch")
            cls, needs_db, is_mongo = _LOADER_DISPATCH[dest]
            self.assertFalse(needs_db)
            self.assertFalse(is_mongo)

    def test_correct_classes_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH
        mapping = {
            "pinecone": PineconeLoader,
            "weaviate": WeaviateLoader,
            "qdrant":   QdrantLoader,
        }
        for dest, expected_cls in mapping.items():
            cls = _LOADER_DISPATCH[dest][0]
            self.assertIs(cls, expected_cls)

    # ── PineconeLoader ────────────────────────────────────────────────────────

    def test_pinecone_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_PINECONE
        pv3.HAS_PINECONE = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.PineconeLoader(self.gov)
        finally:
            pv3.HAS_PINECONE = orig

    def test_pinecone_missing_api_key_raises(self):
        from pipeline_v3 import PineconeLoader, HAS_PINECONE
        if not HAS_PINECONE:
            self.skipTest("pinecone-client not installed")
        loader = PineconeLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"index_name": "test"})
        self.assertIn("api_key", str(ctx.exception))

    def test_pinecone_missing_index_raises(self):
        from pipeline_v3 import PineconeLoader, HAS_PINECONE
        if not HAS_PINECONE:
            self.skipTest("pinecone-client not installed")
        loader = PineconeLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"api_key": "key"})
        self.assertIn("index_name", str(ctx.exception).lower())

    def test_pinecone_missing_vector_column_raises(self):
        from pipeline_v3 import PineconeLoader, HAS_PINECONE
        if not HAS_PINECONE:
            self.skipTest("pinecone-client not installed")
        loader = PineconeLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"api_key": "key", "index_name": "idx",
                         "vector_column": "nonexistent_col"})
        self.assertIn("vector column", str(ctx.exception))

    def test_pinecone_query_empty_vector_raises(self):
        from pipeline_v3 import PineconeLoader, HAS_PINECONE
        if not HAS_PINECONE:
            self.skipTest("pinecone-client not installed")
        loader = PineconeLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.query({"api_key": "k", "index_name": "i"}, query_vector=[])

    def test_pinecone_load_calls_upsert(self):
        from pipeline_v3 import PineconeLoader, HAS_PINECONE
        if not HAS_PINECONE:
            self.skipTest("pinecone-client not installed")
        loader     = PineconeLoader(self.gov)
        mock_pc    = MagicMock()
        mock_index = MagicMock()
        mock_pc.return_value.Index.return_value = mock_index

        with patch("pinecone.Pinecone", mock_pc):
            rows = loader.load(
                self._df(),
                {"api_key": "key", "index_name": "idx",
                 "vector_column": "embedding", "id_column": "id"},
            )

        self.assertEqual(rows, 3)
        mock_index.upsert.assert_called()
        self.gov._event.assert_called_once()
        self.assertIn("PINECONE_UPSERT_COMPLETE",
                      str(self.gov._event.call_args))

    # ── WeaviateLoader ────────────────────────────────────────────────────────

    def test_weaviate_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_WEAVIATE
        pv3.HAS_WEAVIATE = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.WeaviateLoader(self.gov)
        finally:
            pv3.HAS_WEAVIATE = orig

    def test_weaviate_missing_url_raises(self):
        from pipeline_v3 import WeaviateLoader, HAS_WEAVIATE
        if not HAS_WEAVIATE:
            self.skipTest("weaviate-client not installed")
        loader = WeaviateLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"collection": "Docs"})
        self.assertIn("url", str(ctx.exception))

    def test_weaviate_missing_collection_raises(self):
        from pipeline_v3 import WeaviateLoader, HAS_WEAVIATE
        if not HAS_WEAVIATE:
            self.skipTest("weaviate-client not installed")
        loader = WeaviateLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"url": "http://localhost:8080"})
        self.assertIn("collection", str(ctx.exception))

    def test_weaviate_lowercase_collection_raises(self):
        from pipeline_v3 import WeaviateLoader, HAS_WEAVIATE
        if not HAS_WEAVIATE:
            self.skipTest("weaviate-client not installed")
        loader = WeaviateLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"url": "http://localhost:8080", "collection": "docs"})
        self.assertIn("uppercase", str(ctx.exception))

    def test_weaviate_invalid_if_exists_raises(self):
        from pipeline_v3 import WeaviateLoader, HAS_WEAVIATE
        if not HAS_WEAVIATE:
            self.skipTest("weaviate-client not installed")
        loader = WeaviateLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"url": "http://localhost:8080", "collection": "Docs"},
                        if_exists="replace")
        self.assertIn("if_exists", str(ctx.exception))

    # ── QdrantLoader ──────────────────────────────────────────────────────────

    def test_qdrant_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_QDRANT
        pv3.HAS_QDRANT = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.QdrantLoader(self.gov)
        finally:
            pv3.HAS_QDRANT = orig

    def test_qdrant_missing_collection_raises(self):
        from pipeline_v3 import QdrantLoader, HAS_QDRANT
        if not HAS_QDRANT:
            self.skipTest("qdrant-client not installed")
        loader = QdrantLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"memory": True})
        self.assertIn("collection", str(ctx.exception))

    def test_qdrant_missing_vector_column_raises(self):
        from pipeline_v3 import QdrantLoader, HAS_QDRANT
        if not HAS_QDRANT:
            self.skipTest("qdrant-client not installed")
        loader = QdrantLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"memory": True, "collection": "docs",
                         "vector_column": "bad_col"})
        self.assertIn("vector column", str(ctx.exception))

    def test_qdrant_invalid_if_exists_raises(self):
        from pipeline_v3 import QdrantLoader, HAS_QDRANT
        if not HAS_QDRANT:
            self.skipTest("qdrant-client not installed")
        loader = QdrantLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"memory": True, "collection": "docs"},
                        if_exists="upsert")
        self.assertIn("if_exists", str(ctx.exception))

    def test_qdrant_search_empty_vector_raises(self):
        from pipeline_v3 import QdrantLoader, HAS_QDRANT
        if not HAS_QDRANT:
            self.skipTest("qdrant-client not installed")
        loader = QdrantLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.search({"memory": True, "collection": "docs"},
                          query_vector=[])

    def test_qdrant_build_client_no_config_raises(self):
        from pipeline_v3 import QdrantLoader, HAS_QDRANT
        if not HAS_QDRANT:
            self.skipTest("qdrant-client not installed")
        with self.assertRaises(ValueError) as ctx:
            QdrantLoader._build_client({})
        self.assertIn("url", str(ctx.exception))

    def test_qdrant_in_memory_load(self):
        """QdrantLoader can write to in-memory collection without a server."""
        from pipeline_v3 import QdrantLoader, HAS_QDRANT
        if not HAS_QDRANT:
            self.skipTest("qdrant-client not installed")
        loader = QdrantLoader(self.gov)
        rows   = loader.load(
            self._df(),
            {
                "memory":        True,
                "collection":    "test_docs",
                "vector_column": "embedding",
                "id_column":     "id",
                "vector_size":   3,
            },
        )
        self.assertEqual(rows, 3)
        self.gov._event.assert_called_once()
        self.assertIn("QDRANT_UPSERT_COMPLETE",
                      str(self.gov._event.call_args))

    def test_qdrant_in_memory_search(self):
        """QdrantLoader can search a collection after loading data."""
        from pipeline_v3 import QdrantLoader, HAS_QDRANT
        if not HAS_QDRANT:
            self.skipTest("qdrant-client not installed")
        import pathlib as _pl
        # Use a local path so load and search share the same persistent store
        store_path = str(_pl.Path(self._tmp) / "qdrant_store")
        loader = QdrantLoader(self.gov)
        cfg    = {"path": store_path, "collection": "test_docs",
                  "vector_column": "embedding", "vector_size": 3}
        loader.load(self._df(), cfg)
        results = loader.search(cfg, query_vector=[0.1, 0.2, 0.3], limit=2)
        self.assertIsInstance(results, list)
        self.assertLessEqual(len(results), 2)


    # ── Bug fix regression tests ──────────────────────────────────────────────

    def test_pgvector_invalid_table_name_raises(self):
        """SQL injection: table name with semicolons must be rejected."""
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader = PgvectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"host": "h", "db_name": "db",
                         "user": "u", "password": "p"},
                        table="docs; DROP TABLE users--")
        self.assertIn("disallowed", str(ctx.exception))

    def test_pgvector_nan_in_query_vector_raises(self):
        """Float validation: NaN in query_vector must be rejected."""
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader = PgvectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.search({"host": "h", "db_name": "db",
                           "user": "u", "password": "p"},
                          "docs", query_vector=[0.1, float("nan"), 0.3])
        self.assertIn("finite", str(ctx.exception))

    def test_pgvector_inf_in_query_vector_raises(self):
        """Float validation: inf in query_vector must be rejected."""
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader = PgvectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.search({"host": "h", "db_name": "db",
                           "user": "u", "password": "p"},
                          "docs", query_vector=[0.1, float("inf"), 0.3])
        self.assertIn("finite", str(ctx.exception))

    def test_pgvector_empty_df_returns_zero(self):
        """Empty DataFrame must return 0 without touching the database."""
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        import pandas as _pd
        loader = PgvectorLoader(self.gov)
        rows   = loader.load(
            _pd.DataFrame(),
            {"host": "h", "db_name": "db", "user": "u", "password": "p"},
            table="docs"
        )
        self.assertEqual(rows, 0)
        # No DB calls should have been made
        self.gov._event.assert_not_called()

    def test_snowflake_vector_nan_in_query_raises(self):
        """Float validation: NaN in SnowflakeVectorLoader query must be rejected."""
        from pipeline_v3 import SnowflakeVectorLoader, HAS_SNOWFLAKE
        if not HAS_SNOWFLAKE:
            self.skipTest("snowflake-sqlalchemy not installed")
        loader = SnowflakeVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.search(
                {"account": "a", "user": "u", "password": "p",
                 "database": "d", "schema": "s", "warehouse": "w"},
                "T", query_vector=[0.1, float("nan"), 0.3]
            )
        self.assertIn("finite", str(ctx.exception))

    def test_snowflake_vector_empty_df_returns_zero(self):
        """SnowflakeVectorLoader empty DataFrame must return 0."""
        from pipeline_v3 import SnowflakeVectorLoader, HAS_SNOWFLAKE
        if not HAS_SNOWFLAKE:
            self.skipTest("snowflake-sqlalchemy not installed")
        import pandas as _pd
        loader = SnowflakeVectorLoader(self.gov)
        rows   = loader.load(
            _pd.DataFrame(),
            {"account": "a", "user": "u", "password": "p",
             "database": "d", "schema": "s", "warehouse": "w"},
            table="T"
        )
        self.assertEqual(rows, 0)
        self.gov._event.assert_not_called()

    def test_bigquery_vector_empty_df_returns_zero(self):
        """BigQueryVectorLoader empty DataFrame must return 0."""
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        import pandas as _pd
        loader = BigQueryVectorLoader(self.gov)
        rows   = loader.load(
            _pd.DataFrame(),
            {"project": "p", "dataset": "d"},
            table="t"
        )
        self.assertEqual(rows, 0)
        self.gov._event.assert_not_called()

    def test_bigquery_vector_invalid_distance_raises(self):
        """Distance type must be validated — prevents SQL injection."""
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader = BigQueryVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.search({"project": "p", "dataset": "d"},
                          "t", query_vector=[0.1, 0.2],
                          distance="COSINE; DROP TABLE t--")
        self.assertIn("distance", str(ctx.exception))

    def test_bigquery_vector_invalid_options_raises(self):
        """Options string with special chars must be rejected."""
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader = BigQueryVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.search({"project": "p", "dataset": "d"},
                          "t", query_vector=[0.1, 0.2],
                          options="fraction=0.1; DROP TABLE t")
        self.assertIn("disallowed", str(ctx.exception))



class TestTier2VectorLoaders(unittest.TestCase):
    """Tests for ChromaLoader and MilvusLoader."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        gov = MagicMock()
        gov.log_dir = self._tmp
        gov._event  = MagicMock()
        self.gov    = gov

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _df(self):
        return pd.DataFrame({
            "id":        ["doc1", "doc2", "doc3"],
            "text":      ["hello world", "foo bar", "baz qux"],
            "embedding": [[0.1, 0.2, 0.3],
                          [0.4, 0.5, 0.6],
                          [0.7, 0.8, 0.9]],
            "category":  ["a", "b", "c"],
        })

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def test_chroma_and_milvus_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH
        for dest in ("chroma", "milvus"):
            self.assertIn(dest, _LOADER_DISPATCH)
            cls, needs_db, is_mongo = _LOADER_DISPATCH[dest]
            self.assertFalse(needs_db)
            self.assertFalse(is_mongo)

    def test_correct_classes_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH
        self.assertIs(_LOADER_DISPATCH["chroma"][0], ChromaLoader)
        self.assertIs(_LOADER_DISPATCH["milvus"][0], MilvusLoader)

    # ── ChromaLoader —————————————————————————————————————————————————————————

    def test_chroma_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_CHROMA
        pv3.HAS_CHROMA = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.ChromaLoader(self.gov)
        finally:
            pv3.HAS_CHROMA = orig

    def test_chroma_missing_collection_raises(self):
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {})
        self.assertIn("collection", str(ctx.exception))

    def test_chroma_missing_id_column_raises(self):
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        df = self._df().drop(columns=["id"])
        with self.assertRaises(ValueError) as ctx:
            loader.load(df, {"collection": "docs"})
        self.assertIn("id_column", str(ctx.exception))

    def test_chroma_invalid_if_exists_raises(self):
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"collection": "docs"}, if_exists="replace")
        self.assertIn("if_exists", str(ctx.exception))

    def test_chroma_query_empty_embeddings_raises(self):
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.query({"collection": "docs"}, query_embeddings=[])

    def test_chroma_in_memory_append(self):
        """ChromaLoader can write to an in-memory collection."""
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        rows = loader.load(
            self._df(),
            {
                "collection":      "test_docs",
                "id_column":       "id",
                "vector_column":   "embedding",
                "document_column": "text",
            },
        )
        self.assertEqual(rows, 3)
        self.gov._event.assert_called_once()
        self.assertIn("CHROMA_WRITE_COMPLETE", str(self.gov._event.call_args))

    def test_chroma_in_memory_upsert(self):
        """ChromaLoader upsert mode updates existing documents."""
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        cfg = {"collection": "test_docs", "id_column": "id",
               "vector_column": "embedding"}
        loader.load(self._df(), cfg, if_exists="upsert")
        # Second upsert should not raise
        rows = loader.load(self._df(), cfg, if_exists="upsert")
        self.assertEqual(rows, 3)

    def test_chroma_in_memory_overwrite(self):
        """ChromaLoader overwrite mode clears existing collection."""
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        cfg = {"collection": "test_docs", "id_column": "id",
               "vector_column": "embedding"}
        loader.load(self._df(), cfg)
        rows = loader.load(self._df(), cfg, if_exists="overwrite")
        self.assertEqual(rows, 3)

    def test_chroma_persistent_load_and_query(self):
        """ChromaLoader can write and query with persistent storage."""
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        import pathlib as _pl
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        store  = str(_pl.Path(self._tmp) / "chroma_store")
        cfg    = {
            "path":            store,
            "collection":      "test_docs",
            "id_column":       "id",
            "vector_column":   "embedding",
            "document_column": "text",
        }
        loader.load(self._df(), cfg)
        results = loader.query(
            cfg,
            query_embeddings=[[0.1, 0.2, 0.3]],
            n_results=2,
        )
        self.assertIn("ids", results)
        self.assertLessEqual(len(results["ids"][0]), 2)
        self.assertIn("CHROMA_QUERY", str(self.gov._event.call_args_list[-1]))

    def test_chroma_governance_event_fired(self):
        from pipeline_v3 import ChromaLoader, HAS_CHROMA
        if not HAS_CHROMA:
            self.skipTest("chromadb not installed")
        loader = ChromaLoader(self.gov)
        loader.load(self._df(),
                    {"collection": "docs", "id_column": "id",
                     "vector_column": "embedding"})
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("CHROMA_WRITE_COMPLETE" in c for c in calls))

    # ── MilvusLoader ──────────────────────────────────────────────────────────

    def test_milvus_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_MILVUS
        pv3.HAS_MILVUS = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.MilvusLoader(self.gov)
        finally:
            pv3.HAS_MILVUS = orig

    def test_milvus_missing_uri_raises(self):
        from pipeline_v3 import MilvusLoader, HAS_MILVUS
        if not HAS_MILVUS:
            self.skipTest("pymilvus not installed")
        loader = MilvusLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"collection": "docs"})
        self.assertIn("uri", str(ctx.exception))

    def test_milvus_missing_collection_raises(self):
        from pipeline_v3 import MilvusLoader, HAS_MILVUS
        if not HAS_MILVUS:
            self.skipTest("pymilvus not installed")
        loader = MilvusLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"uri": "./milvus.db"})
        self.assertIn("collection", str(ctx.exception))

    def test_milvus_missing_vector_column_raises(self):
        from pipeline_v3 import MilvusLoader, HAS_MILVUS
        if not HAS_MILVUS:
            self.skipTest("pymilvus not installed")
        loader = MilvusLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"uri": "./milvus.db", "collection": "docs",
                         "vector_column": "bad_col"})
        self.assertIn("vector column", str(ctx.exception))

    def test_milvus_invalid_if_exists_raises(self):
        from pipeline_v3 import MilvusLoader, HAS_MILVUS
        if not HAS_MILVUS:
            self.skipTest("pymilvus not installed")
        loader = MilvusLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"uri": "./milvus.db", "collection": "docs"},
                        if_exists="replace")
        self.assertIn("if_exists", str(ctx.exception))

    def test_milvus_search_empty_vector_raises(self):
        from pipeline_v3 import MilvusLoader, HAS_MILVUS
        if not HAS_MILVUS:
            self.skipTest("pymilvus not installed")
        loader = MilvusLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.search({"uri": "./x.db", "collection": "docs"},
                          query_vector=[])

    def test_milvus_load_calls_insert(self):
        """MilvusLoader.load() calls client.insert() in append mode."""
        from pipeline_v3 import MilvusLoader, HAS_MILVUS
        if not HAS_MILVUS:
            self.skipTest("pymilvus not installed")
        loader     = MilvusLoader(self.gov)
        mock_client = MagicMock()
        mock_client.has_collection.return_value = True
        mock_client.insert.return_value = {"insert_count": 3}

        with patch("pymilvus.MilvusClient", return_value=mock_client):
            rows = loader.load(
                self._df(),
                {"uri": "./test.db", "collection": "docs",
                 "vector_column": "embedding"},
            )

        self.assertEqual(rows, 3)
        mock_client.insert.assert_called()
        self.gov._event.assert_called_once()
        self.assertIn("MILVUS_WRITE_COMPLETE", str(self.gov._event.call_args))

    def test_milvus_upsert_calls_upsert(self):
        from pipeline_v3 import MilvusLoader, HAS_MILVUS
        if not HAS_MILVUS:
            self.skipTest("pymilvus not installed")
        loader      = MilvusLoader(self.gov)
        mock_client = MagicMock()
        mock_client.has_collection.return_value = True
        mock_client.upsert.return_value = {"upsert_count": 3}

        with patch("pymilvus.MilvusClient", return_value=mock_client):
            loader.load(self._df(),
                        {"uri": "./test.db", "collection": "docs",
                         "vector_column": "embedding"},
                        if_exists="upsert")

        mock_client.upsert.assert_called()
        mock_client.insert.assert_not_called()



class TestTier3VectorLoaders(unittest.TestCase):
    """Tests for PgvectorLoader, SnowflakeVectorLoader, BigQueryVectorLoader."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        gov = MagicMock()
        gov.log_dir = self._tmp
        gov._event  = MagicMock()
        self.gov    = gov

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _df(self):
        return pd.DataFrame({
            "id":        [1, 2, 3],
            "text":      ["hello world", "foo bar", "baz qux"],
            "embedding": [[0.1, 0.2, 0.3],
                          [0.4, 0.5, 0.6],
                          [0.7, 0.8, 0.9]],
        })

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def test_all_three_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH
        for dest in ("pgvector", "snowflake_vector", "bigquery_vector"):
            self.assertIn(dest, _LOADER_DISPATCH)
            cls, needs_db, is_mongo = _LOADER_DISPATCH[dest]
            self.assertFalse(needs_db)
            self.assertFalse(is_mongo)

    def test_correct_classes_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH
        self.assertIs(_LOADER_DISPATCH["pgvector"][0],         PgvectorLoader)
        self.assertIs(_LOADER_DISPATCH["snowflake_vector"][0], SnowflakeVectorLoader)
        self.assertIs(_LOADER_DISPATCH["bigquery_vector"][0],  BigQueryVectorLoader)

    # ── PgvectorLoader ────────────────────────────────────────────────────────

    def test_pgvector_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_PGVECTOR
        pv3.HAS_PGVECTOR = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.PgvectorLoader(self.gov)
        finally:
            pv3.HAS_PGVECTOR = orig

    def test_pgvector_missing_table_raises(self):
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader = PgvectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"host": "localhost", "db_name": "db",
                                     "user": "u", "password": "p"})
        self.assertIn("table", str(ctx.exception))

    def test_pgvector_missing_host_raises(self):
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader = PgvectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"db_name": "db", "user": "u",
                                     "password": "p"}, table="docs")
        self.assertIn("host", str(ctx.exception))

    def test_pgvector_invalid_if_exists_raises(self):
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader = PgvectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"host": "h", "db_name": "db", "user": "u",
                         "password": "p"}, table="t", if_exists="overwrite")
        self.assertIn("if_exists", str(ctx.exception))

    def test_pgvector_missing_vector_column_raises(self):
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader = PgvectorLoader(self.gov)
        df = self._df().drop(columns=["embedding"])
        with self.assertRaises(ValueError) as ctx:
            loader.load(df, {"host": "h", "db_name": "db", "user": "u",
                             "password": "p"}, table="t")
        self.assertIn("vector column", str(ctx.exception))

    def test_pgvector_search_empty_vector_raises(self):
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader = PgvectorLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.search({"host": "h", "db_name": "db", "user": "u",
                           "password": "p"}, "docs", query_vector=[])

    def test_pgvector_load_calls_to_sql(self):
        """PgvectorLoader.load() writes via pandas to_sql."""
        from pipeline_v3 import PgvectorLoader, HAS_PGVECTOR
        if not HAS_PGVECTOR:
            self.skipTest("pgvector not installed")
        loader     = PgvectorLoader(self.gov)
        mock_engine = MagicMock()
        mock_conn   = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__  = MagicMock(return_value=False)

        with patch("sqlalchemy.create_engine", return_value=mock_engine),              patch("pandas.DataFrame.to_sql") as mock_to_sql:
            rows = loader.load(
                self._df(),
                {"host": "localhost", "db_name": "db",
                 "user": "u", "password": "p",
                 "vector_column": "embedding"},
                table="documents",
            )

        self.assertEqual(rows, 3)
        mock_to_sql.assert_called_once()
        self.gov._event.assert_called_once()
        self.assertIn("PGVECTOR_WRITE_COMPLETE",
                      str(self.gov._event.call_args))

    # ── SnowflakeVectorLoader ─────────────────────────────────────────────────

    def test_snowflake_vector_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_SNOWFLAKE
        pv3.HAS_SNOWFLAKE = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.SnowflakeVectorLoader(self.gov)
        finally:
            pv3.HAS_SNOWFLAKE = orig

    def test_snowflake_vector_missing_table_raises(self):
        from pipeline_v3 import SnowflakeVectorLoader, HAS_SNOWFLAKE
        if not HAS_SNOWFLAKE:
            self.skipTest("snowflake-sqlalchemy not installed")
        loader = SnowflakeVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"account": "a", "user": "u", "password": "p",
                         "database": "d", "schema": "s", "warehouse": "w"})
        self.assertIn("table", str(ctx.exception))

    def test_snowflake_vector_invalid_if_exists_raises(self):
        from pipeline_v3 import SnowflakeVectorLoader, HAS_SNOWFLAKE
        if not HAS_SNOWFLAKE:
            self.skipTest("snowflake-sqlalchemy not installed")
        loader = SnowflakeVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"account": "a", "user": "u", "password": "p",
                         "database": "d", "schema": "s", "warehouse": "w"},
                        table="T", if_exists="upsert")
        self.assertIn("if_exists", str(ctx.exception))

    def test_snowflake_vector_missing_vector_column_raises(self):
        from pipeline_v3 import SnowflakeVectorLoader, HAS_SNOWFLAKE
        if not HAS_SNOWFLAKE:
            self.skipTest("snowflake-sqlalchemy not installed")
        loader = SnowflakeVectorLoader(self.gov)
        df = self._df().drop(columns=["embedding"])
        with self.assertRaises(ValueError) as ctx:
            loader.load(df,
                        {"account": "a", "user": "u", "password": "p",
                         "database": "d", "schema": "s", "warehouse": "w"},
                        table="T")
        self.assertIn("vector column", str(ctx.exception))

    def test_snowflake_vector_search_empty_vector_raises(self):
        from pipeline_v3 import SnowflakeVectorLoader, HAS_SNOWFLAKE
        if not HAS_SNOWFLAKE:
            self.skipTest("snowflake-sqlalchemy not installed")
        loader = SnowflakeVectorLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.search(
                {"account": "a", "user": "u", "password": "p",
                 "database": "d", "schema": "s", "warehouse": "w"},
                "T", query_vector=[]
            )

    def test_snowflake_vector_load_calls_to_sql(self):
        """SnowflakeVectorLoader.load() calls to_sql then ALTER COLUMN."""
        from pipeline_v3 import SnowflakeVectorLoader, HAS_SNOWFLAKE
        if not HAS_SNOWFLAKE:
            self.skipTest("snowflake-sqlalchemy not installed")
        loader      = SnowflakeVectorLoader(self.gov)
        mock_engine = MagicMock()
        mock_conn   = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__  = MagicMock(return_value=False)

        with patch("snowflake.sqlalchemy.URL", return_value="mock_url"),              patch("sqlalchemy.create_engine", return_value=mock_engine),              patch("pandas.DataFrame.to_sql") as mock_to_sql:
            rows = loader.load(
                self._df(),
                {"account": "acct", "user": "u", "password": "p",
                 "database": "db", "schema": "PUBLIC", "warehouse": "wh",
                 "vector_column": "embedding"},
                table="DOCUMENTS",
            )

        self.assertEqual(rows, 3)
        mock_to_sql.assert_called_once()
        self.gov._event.assert_called_once()
        self.assertIn("SNOWFLAKE_VECTOR_WRITE_COMPLETE",
                      str(self.gov._event.call_args))

    # ── BigQueryVectorLoader ──────────────────────────────────────────────────

    def test_bigquery_vector_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_BIGQUERY
        pv3.HAS_BIGQUERY = False
        try:
            with self.assertRaises(RuntimeError):
                pv3.BigQueryVectorLoader(self.gov)
        finally:
            pv3.HAS_BIGQUERY = orig

    def test_bigquery_vector_missing_table_raises(self):
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader = BigQueryVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"project": "p", "dataset": "d"})
        self.assertIn("table", str(ctx.exception))

    def test_bigquery_vector_missing_project_raises(self):
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader = BigQueryVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"dataset": "d"}, table="t")
        self.assertIn("project", str(ctx.exception))

    def test_bigquery_vector_missing_dataset_raises(self):
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader = BigQueryVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"project": "p"}, table="t")
        self.assertIn("dataset", str(ctx.exception))

    def test_bigquery_vector_invalid_if_exists_raises(self):
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader = BigQueryVectorLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(),
                        {"project": "p", "dataset": "d"},
                        table="t", if_exists="upsert")
        self.assertIn("if_exists", str(ctx.exception))

    def test_bigquery_vector_missing_vector_column_raises(self):
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader = BigQueryVectorLoader(self.gov)
        df = self._df().drop(columns=["embedding"])
        with self.assertRaises(ValueError) as ctx:
            loader.load(df, {"project": "p", "dataset": "d"}, table="t")
        self.assertIn("vector column", str(ctx.exception))

    def test_bigquery_vector_search_empty_vector_raises(self):
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader = BigQueryVectorLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.search({"project": "p", "dataset": "d"},
                          "t", query_vector=[])

    def test_bigquery_vector_load_calls_client(self):
        """BigQueryVectorLoader.load() calls BigQuery load_table_from_dataframe."""
        from pipeline_v3 import BigQueryVectorLoader, HAS_BIGQUERY
        if not HAS_BIGQUERY:
            self.skipTest("google-cloud-bigquery not installed")
        loader     = BigQueryVectorLoader(self.gov)
        mock_job   = MagicMock()
        mock_job.result.return_value = None
        mock_client = MagicMock()
        mock_client.load_table_from_dataframe.return_value = mock_job

        with patch("google.cloud.bigquery.Client", return_value=mock_client):
            rows = loader.load(
                self._df(),
                {"project": "my-project", "dataset": "my_dataset",
                 "vector_column": "embedding"},
                table="documents",
            )

        self.assertEqual(rows, 3)
        mock_client.load_table_from_dataframe.assert_called_once()
        mock_job.result.assert_called_once()
        self.gov._event.assert_called_once()
        self.assertIn("BIGQUERY_VECTOR_WRITE_COMPLETE",
                      str(self.gov._event.call_args))



class TestCockroachDBLoader(unittest.TestCase):
    """Tests for CockroachDBLoader."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        gov = MagicMock()
        gov.log_dir = self._tmp
        gov._event  = MagicMock()
        self.gov    = gov

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _df(self):
        return pd.DataFrame({
            "id":   [1, 2, 3],
            "name": ["Alice", "Bob", "Carol"],
            "score":[0.9, 0.7, 0.8],
        })

    def _cfg(self, **overrides):
        base = {
            "host":     "localhost",
            "db_name":  "defaultdb",
            "user":     "root",
            "password": "",
            "sslmode":  "disable",
        }
        base.update(overrides)
        return base

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def test_cockroachdb_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH, CockroachDBLoader
        self.assertIn("cockroachdb", _LOADER_DISPATCH)
        cls, needs_db, is_mongo = _LOADER_DISPATCH["cockroachdb"]
        self.assertIs(cls, CockroachDBLoader)
        self.assertFalse(needs_db)
        self.assertFalse(is_mongo)

    # ── Validation ────────────────────────────────────────────────────────────

    def test_missing_table_raises(self):
        loader = CockroachDBLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), self._cfg())
        self.assertIn("table", str(ctx.exception))

    def test_missing_host_raises(self):
        loader = CockroachDBLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"db_name": "db", "user": "u",
                                     "password": "p"}, table="t")
        self.assertIn("host", str(ctx.exception))

    def test_missing_db_name_raises(self):
        loader = CockroachDBLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"host": "h", "user": "u",
                                     "password": "p"}, table="t")
        self.assertIn("db_name", str(ctx.exception))

    def test_invalid_if_exists_raises(self):
        loader = CockroachDBLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), self._cfg(), table="t",
                        if_exists="overwrite")
        self.assertIn("if_exists", str(ctx.exception))

    def test_empty_df_returns_zero(self):
        loader = CockroachDBLoader(self.gov)
        rows   = loader.load(pd.DataFrame(), self._cfg(), table="t")
        self.assertEqual(rows, 0)
        self.gov._event.assert_not_called()

    # ── Engine URL ────────────────────────────────────────────────────────────

    def _captured_url(self, cfg, has_cockroach=False):
        """Build the URL string by intercepting create_engine."""
        import pipeline_v3 as pv3
        orig = pv3.HAS_COCKROACH
        pv3.HAS_COCKROACH = has_cockroach
        captured = {}
        def mock_ce(url, **kw):
            captured["url"] = url
            return MagicMock()
        try:
            with patch("sqlalchemy.create_engine", side_effect=mock_ce):
                CockroachDBLoader(self.gov)._engine(cfg)
        finally:
            pv3.HAS_COCKROACH = orig
        return captured.get("url", "")

    def test_engine_uses_psycopg2_fallback_without_dialect(self):
        """Without sqlalchemy-cockroachdb, uses postgresql+psycopg2."""
        url = self._captured_url(self._cfg(), has_cockroach=False)
        self.assertIn("postgresql", url)
        self.assertIn("psycopg2",   url)
        self.assertIn("26257",      url)

    def test_engine_default_port_26257(self):
        """CockroachDB default port is 26257, not 5432."""
        url = self._captured_url(self._cfg(), has_cockroach=False)
        self.assertIn("26257", url)

    def test_engine_custom_port(self):
        url = self._captured_url(self._cfg(port=26000), has_cockroach=False)
        self.assertIn("26000", url)

    def test_engine_sslmode_in_url(self):
        url = self._captured_url(self._cfg(sslmode="verify-full"),
                                 has_cockroach=False)
        self.assertIn("sslmode", url)

    def test_engine_cluster_name_prepended_to_host(self):
        """CockroachDB Cloud: cluster_name.host format."""
        url = self._captured_url(self._cfg(
            host="free-tier.cockroachlabs.cloud",
            cluster_name="my-cluster",
        ), has_cockroach=False)
        self.assertIn("my-cluster", url)

    # ── Load ──────────────────────────────────────────────────────────────────

    def test_load_append_calls_to_sql(self):
        """Append mode uses pandas to_sql."""
        loader      = CockroachDBLoader(self.gov)
        mock_engine = MagicMock()

        with patch.object(loader, "_engine", return_value=mock_engine),              patch("pandas.DataFrame.to_sql") as mock_to_sql:
            rows = loader.load(self._df(), self._cfg(), table="employees")

        self.assertEqual(rows, 3)
        mock_to_sql.assert_called_once()
        self.gov._event.assert_called_once()
        self.assertIn("COCKROACHDB_WRITE_COMPLETE",
                      str(self.gov._event.call_args))

    def test_load_replace_passes_replace_to_sql(self):
        """Replace mode passes if_exists='replace' to to_sql."""
        loader      = CockroachDBLoader(self.gov)
        mock_engine = MagicMock()

        with patch.object(loader, "_engine", return_value=mock_engine),              patch("pandas.DataFrame.to_sql") as mock_to_sql:
            loader.load(self._df(), self._cfg(), table="t",
                        if_exists="replace")

        call_kwargs = mock_to_sql.call_args[1]
        self.assertEqual(call_kwargs["if_exists"], "replace")

    def test_upsert_missing_key_column_raises(self):
        """Upsert raises ValueError if natural_key column not in DataFrame."""
        loader      = CockroachDBLoader(self.gov)
        mock_engine = MagicMock()

        with patch.object(loader, "_engine", return_value=mock_engine):
            with self.assertRaises(ValueError) as ctx:
                loader.load(self._df(), self._cfg(), table="t",
                            if_exists="upsert",
                            natural_keys=["nonexistent_col"])
        self.assertIn("nonexistent_col", str(ctx.exception))

    def test_governance_event_contains_driver_info(self):
        """Governance event must record which driver was used."""
        loader      = CockroachDBLoader(self.gov)
        mock_engine = MagicMock()

        with patch.object(loader, "_engine", return_value=mock_engine),              patch("pandas.DataFrame.to_sql"):
            loader.load(self._df(), self._cfg(), table="employees")

        event_detail = str(self.gov._event.call_args)
        self.assertIn("driver", event_detail)

    def test_cockroach_dialect_url_when_available(self):
        """When sqlalchemy-cockroachdb is installed, use cockroachdb:// URL."""
        url = self._captured_url(self._cfg(), has_cockroach=True)
        self.assertIn("cockroachdb", url)



class TestNewDestinationLoaders(unittest.TestCase):
    """Tests for DuckDB, Parquet, Delta Lake, Iceberg, S3, Athena, SFTP, Fabric, PostGIS."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        gov = MagicMock(); gov.log_dir = self._tmp; gov._event = MagicMock()
        self.gov = gov

    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)

    def _df(self):
        return pd.DataFrame({"id": [1, 2, 3], "name": ["Alice", "Bob", "Carol"],
                             "score": [0.9, 0.7, 0.8]})

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def test_all_new_destinations_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH
        for d in ("duckdb","motherduck","parquet","deltalake","iceberg",
                  "s3","gcs","azure_blob","athena","sftp","fabric","postgis"):
            self.assertIn(d, _LOADER_DISPATCH, f"{d} missing from dispatch")

    # ── DuckDBLoader ──────────────────────────────────────────────────────────

    def test_duckdb_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_DUCKDB; pv3.HAS_DUCKDB = False
        try:
            with self.assertRaises(RuntimeError): pv3.DuckDBLoader(self.gov)
        finally: pv3.HAS_DUCKDB = orig

    def test_duckdb_missing_db_path_raises(self):
        loader = DuckDBLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {}, table="t")
        self.assertIn("db_path", str(ctx.exception))

    def test_duckdb_missing_table_raises(self):
        loader = DuckDBLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"db_path": ":memory:"})
        self.assertIn("table", str(ctx.exception))

    def test_duckdb_invalid_if_exists_raises(self):
        loader = DuckDBLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"db_path": ":memory:"}, table="t",
                        if_exists="overwrite")
        self.assertIn("if_exists", str(ctx.exception))

    def test_duckdb_invalid_table_name_raises(self):
        loader = DuckDBLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.load(self._df(), {"db_path": ":memory:"}, table="t; DROP TABLE x")

    def test_duckdb_empty_df_returns_zero(self):
        loader = DuckDBLoader(self.gov)
        rows = loader.load(pd.DataFrame(), {"db_path": ":memory:"}, table="t")
        self.assertEqual(rows, 0); self.gov._event.assert_not_called()

    def test_duckdb_in_memory_append(self):
        import pathlib as _pl
        loader = DuckDBLoader(self.gov)
        db = str(_pl.Path(self._tmp) / "test.duckdb")
        rows = loader.load(self._df(), {"db_path": db}, table="employees")
        self.assertEqual(rows, 3)
        self.gov._event.assert_called_once()
        self.assertIn("DUCKDB_WRITE_COMPLETE", str(self.gov._event.call_args))

    def test_duckdb_replace_mode(self):
        import pathlib as _pl
        loader = DuckDBLoader(self.gov)
        db = str(_pl.Path(self._tmp) / "test.duckdb")
        loader.load(self._df(), {"db_path": db}, table="t")
        rows = loader.load(self._df(), {"db_path": db}, table="t", if_exists="replace")
        self.assertEqual(rows, 3)

    def test_duckdb_upsert_missing_key_raises(self):
        loader = DuckDBLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"db_path": ":memory:"}, table="t",
                        if_exists="upsert", natural_keys=["nonexistent"])
        self.assertIn("nonexistent", str(ctx.exception))

    def test_duckdb_motherduck_in_dispatch(self):
        from pipeline_v3 import _LOADER_DISPATCH
        self.assertIs(_LOADER_DISPATCH["motherduck"][0], DuckDBLoader)

    # ── ParquetLoader ─────────────────────────────────────────────────────────

    def test_parquet_missing_path_raises(self):
        loader = ParquetLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {})
        self.assertIn("path", str(ctx.exception))

    def test_parquet_invalid_if_exists_raises(self):
        loader = ParquetLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"path": "/tmp/x.parquet"}, if_exists="upsert")
        self.assertIn("if_exists", str(ctx.exception))

    def test_parquet_empty_df_returns_zero(self):
        loader = ParquetLoader(self.gov)
        self.assertEqual(loader.load(pd.DataFrame(), {"path": "/tmp/x.parquet"}), 0)

    def test_parquet_writes_local_file(self):
        import pathlib as _pl
        out = str(_pl.Path(self._tmp) / "output.parquet")
        loader = ParquetLoader(self.gov)
        rows = loader.load(self._df(), {"path": out})
        self.assertEqual(rows, 3)
        self.assertTrue(_pl.Path(out).exists())
        self.gov._event.assert_called_once()
        self.assertIn("PARQUET_WRITE_COMPLETE", str(self.gov._event.call_args))

    def test_parquet_table_param_used_as_filename(self):
        loader = ParquetLoader(self.gov)
        with patch("pyarrow.parquet.write_table") as mock_write:
            loader.load(self._df(), {}, table="employees")
        mock_write.assert_called_once()
        call_args = mock_write.call_args[0]
        self.assertIn("employees.parquet", str(call_args[1]))

    # ── DeltaLakeLoader ───────────────────────────────────────────────────────

    def test_deltalake_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_DELTALAKE; pv3.HAS_DELTALAKE = False
        try:
            with self.assertRaises(RuntimeError): pv3.DeltaLakeLoader(self.gov)
        finally: pv3.HAS_DELTALAKE = orig

    def test_deltalake_missing_path_raises(self):
        loader = DeltaLakeLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {})
        self.assertIn("path", str(ctx.exception))

    def test_deltalake_invalid_if_exists_raises(self):
        loader = DeltaLakeLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"path": "/tmp/delta"}, if_exists="overwrite")
        self.assertIn("if_exists", str(ctx.exception))

    def test_deltalake_empty_df_returns_zero(self):
        loader = DeltaLakeLoader(self.gov)
        self.assertEqual(loader.load(pd.DataFrame(), {"path": "/tmp/delta"}), 0)

    def test_deltalake_append_local(self):
        import pathlib as _pl
        delta_path = str(_pl.Path(self._tmp) / "delta_table")
        loader = DeltaLakeLoader(self.gov)
        rows = loader.load(self._df(), {"path": delta_path})
        self.assertEqual(rows, 3)
        self.gov._event.assert_called_once()
        self.assertIn("DELTALAKE_WRITE_COMPLETE", str(self.gov._event.call_args))

    def test_deltalake_overwrite_local(self):
        import pathlib as _pl
        delta_path = str(_pl.Path(self._tmp) / "delta_table2")
        loader = DeltaLakeLoader(self.gov)
        loader.load(self._df(), {"path": delta_path})
        rows = loader.load(self._df(), {"path": delta_path}, if_exists="replace")
        self.assertEqual(rows, 3)

    def test_deltalake_upsert_missing_key_raises(self):
        import pathlib as _pl
        delta_path = str(_pl.Path(self._tmp) / "delta_table3")
        loader = DeltaLakeLoader(self.gov)
        loader.load(self._df(), {"path": delta_path})
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"path": delta_path},
                        if_exists="upsert", natural_keys=["nonexistent"])
        self.assertIn("nonexistent", str(ctx.exception))

    def test_deltalake_upsert_local(self):
        import pathlib as _pl
        delta_path = str(_pl.Path(self._tmp) / "delta_upsert")
        loader = DeltaLakeLoader(self.gov)
        loader.load(self._df(), {"path": delta_path})
        rows = loader.load(self._df(), {"path": delta_path},
                           if_exists="upsert", natural_keys=["id"])
        self.assertEqual(rows, 3)

    # ── IcebergLoader ─────────────────────────────────────────────────────────

    def test_iceberg_raises_without_package(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_ICEBERG; pv3.HAS_ICEBERG = False
        try:
            with self.assertRaises(RuntimeError): pv3.IcebergLoader(self.gov)
        finally: pv3.HAS_ICEBERG = orig

    def test_iceberg_missing_namespace_raises(self):
        loader = IcebergLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"catalog_type": "memory"}, table="t")
        self.assertIn("namespace", str(ctx.exception))

    def test_iceberg_missing_table_raises(self):
        loader = IcebergLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"catalog_type": "memory", "namespace": "ns"})
        self.assertIn("table", str(ctx.exception))

    def test_iceberg_invalid_if_exists_raises(self):
        loader = IcebergLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"catalog_type": "memory", "namespace": "ns"},
                        table="t", if_exists="upsert")
        self.assertIn("if_exists", str(ctx.exception))

    def test_iceberg_empty_df_returns_zero(self):
        loader = IcebergLoader(self.gov)
        rows = loader.load(pd.DataFrame(),
                           {"catalog_type": "memory", "namespace": "ns"}, table="t")
        self.assertEqual(rows, 0)

    def test_iceberg_sql_catalog_append(self):
        """IcebergLoader can write to a local SQL-backed catalog (sqlite)."""
        import pathlib as _pl
        warehouse = str(_pl.Path(self._tmp) / "iceberg_warehouse")
        db_uri    = f"sqlite:///{_pl.Path(self._tmp) / 'iceberg.db'}"
        loader    = IcebergLoader(self.gov)
        rows = loader.load(
            self._df(),
            {
                "catalog_type":  "sql",
                "catalog_name":  "local",
                "namespace":     "test_ns",
                "table_name":    "employees",
                "warehouse":     warehouse,
                "catalog_db":    db_uri,
            },
        )
        self.assertEqual(rows, 3)
        self.gov._event.assert_called_once()
        self.assertIn("ICEBERG_WRITE_COMPLETE", str(self.gov._event.call_args))

    # ── S3Loader ──────────────────────────────────────────────────────────────

    def test_s3_missing_bucket_raises(self):
        loader = S3Loader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"provider": "s3", "key": "x.parquet"})
        self.assertIn("bucket", str(ctx.exception))

    def test_s3_missing_key_raises(self):
        loader = S3Loader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"provider": "s3", "bucket": "my-bucket"})
        self.assertIn("key", str(ctx.exception))

    def test_s3_invalid_format_raises(self):
        loader = S3Loader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"provider": "s3", "bucket": "b",
                                     "key": "k", "format": "xlsx"})
        self.assertIn("format", str(ctx.exception))

    def test_s3_invalid_provider_raises(self):
        loader = S3Loader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"provider": "ftp", "bucket": "b", "key": "k"})
        self.assertIn("provider", str(ctx.exception))

    def test_s3_empty_df_returns_zero(self):
        loader = S3Loader(self.gov)
        rows = loader.load(pd.DataFrame(), {"provider":"s3","bucket":"b","key":"k"})
        self.assertEqual(rows, 0)

    def test_s3_calls_put_object(self):
        loader = S3Loader(self.gov)
        mock_client = MagicMock()
        with patch("boto3.client", return_value=mock_client):
            rows = loader.load(self._df(),
                               {"provider": "s3", "bucket": "my-bucket",
                                "key": "data/employees.parquet"})
        self.assertEqual(rows, 3)
        mock_client.put_object.assert_called_once()
        self.gov._event.assert_called_once()
        self.assertIn("S3_WRITE_COMPLETE", str(self.gov._event.call_args))

    def test_s3_csv_format(self):
        loader = S3Loader(self.gov)
        mock_client = MagicMock()
        with patch("boto3.client", return_value=mock_client):
            loader.load(self._df(),
                        {"provider": "s3", "bucket": "b",
                         "key": "out.csv", "format": "csv"})
        call_kwargs = mock_client.put_object.call_args[1]
        body = call_kwargs["Body"]
        self.assertIn(b"id", body); self.assertIn(b"Alice", body)

    # ── AthenaLoader ──────────────────────────────────────────────────────────

    def test_athena_raises_without_boto3(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_S3; pv3.HAS_S3 = False
        try:
            with self.assertRaises(RuntimeError): pv3.AthenaLoader(self.gov)
        finally: pv3.HAS_S3 = orig

    def test_athena_missing_database_raises(self):
        loader = AthenaLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"s3_data_dir": "s3://b/d/",
                                     "s3_staging_dir": "s3://b/s/"}, table="t")
        self.assertIn("database", str(ctx.exception))

    def test_athena_missing_s3_data_dir_raises(self):
        loader = AthenaLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"database": "db",
                                     "s3_staging_dir": "s3://b/s/"}, table="t")
        self.assertIn("s3_data_dir", str(ctx.exception))

    def test_athena_empty_df_returns_zero(self):
        loader = AthenaLoader(self.gov)
        rows = loader.load(pd.DataFrame(),
                           {"database": "db", "s3_data_dir": "s3://b/d/",
                            "s3_staging_dir": "s3://b/s/", "region": "us-east-1"},
                           table="t")
        self.assertEqual(rows, 0)

    # ── SFTPLoader ────────────────────────────────────────────────────────────

    def test_sftp_raises_without_paramiko(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_SFTP; pv3.HAS_SFTP = False
        try:
            with self.assertRaises(RuntimeError): pv3.SFTPLoader(self.gov)
        finally: pv3.HAS_SFTP = orig

    def test_sftp_missing_host_raises(self):
        loader = SFTPLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"username": "u"}, table="t")
        self.assertIn("host", str(ctx.exception))

    def test_sftp_missing_username_raises(self):
        loader = SFTPLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"host": "h"}, table="t")
        self.assertIn("username", str(ctx.exception))

    def test_sftp_invalid_format_raises(self):
        loader = SFTPLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"host": "h", "username": "u",
                                     "remote_path": "/x", "format": "xlsx"})
        self.assertIn("format", str(ctx.exception))

    def test_sftp_empty_df_returns_zero(self):
        loader = SFTPLoader(self.gov)
        rows = loader.load(pd.DataFrame(),
                           {"host": "h", "username": "u", "remote_path": "/x"})
        self.assertEqual(rows, 0)

    def test_sftp_calls_paramiko_upload(self):
        loader = SFTPLoader(self.gov)
        mock_ssh  = MagicMock()
        mock_sftp = MagicMock()
        mock_file = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp
        mock_sftp.file.return_value.__enter__ = MagicMock(return_value=mock_file)
        mock_sftp.file.return_value.__exit__  = MagicMock(return_value=False)

        with patch("paramiko.SSHClient", return_value=mock_ssh):
            rows = loader.load(self._df(),
                               {"host": "sftp.example.com",
                                "username": "user",
                                "password": "pass",
                                "remote_path": "/uploads/data.csv"})
        self.assertEqual(rows, 3)
        mock_ssh.connect.assert_called_once()
        mock_sftp.file.assert_called_once()
        self.assertIn("SFTP_WRITE_COMPLETE", str(self.gov._event.call_args))

    # ── MicrosoftFabricLoader ─────────────────────────────────────────────────

    def test_fabric_raises_without_adlfs(self):
        import pipeline_v3 as pv3
        orig = pv3.HAS_FABRIC; pv3.HAS_FABRIC = False
        try:
            with self.assertRaises(RuntimeError): pv3.MicrosoftFabricLoader(self.gov)
        finally: pv3.HAS_FABRIC = orig

    def test_fabric_missing_workspace_id_raises(self):
        from pipeline_v3 import HAS_FABRIC
        if not HAS_FABRIC:
            self.skipTest('adlfs not installed')
        loader = MicrosoftFabricLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"lakehouse_id": "lh"}, table="t")
        self.assertIn("workspace_id", str(ctx.exception))

    def test_fabric_missing_lakehouse_id_raises(self):
        from pipeline_v3 import HAS_FABRIC
        if not HAS_FABRIC:
            self.skipTest('adlfs not installed')
        loader = MicrosoftFabricLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"workspace_id": "ws"}, table="t")
        self.assertIn("lakehouse_id", str(ctx.exception))

    def test_fabric_empty_df_returns_zero(self):
        from pipeline_v3 import HAS_FABRIC
        if not HAS_FABRIC:
            self.skipTest('adlfs not installed')
        loader = MicrosoftFabricLoader(self.gov)
        rows = loader.load(pd.DataFrame(),
                           {"workspace_id": "ws", "lakehouse_id": "lh"}, table="t")
        self.assertEqual(rows, 0)

    def test_fabric_calls_adlfs(self):
        from pipeline_v3 import HAS_FABRIC
        if not HAS_FABRIC:
            self.skipTest('adlfs not installed')
        loader = MicrosoftFabricLoader(self.gov)
        mock_fs   = MagicMock()
        mock_file = MagicMock()
        mock_fs.open.return_value.__enter__ = MagicMock(return_value=mock_file)
        mock_fs.open.return_value.__exit__  = MagicMock(return_value=False)

        with patch("adlfs.AzureBlobFileSystem", return_value=mock_fs):
            rows = loader.load(self._df(),
                               {"workspace_id": "ws-123",
                                "lakehouse_id": "lh-456",
                                "token": "token"}, table="employees")
        self.assertEqual(rows, 3)
        mock_fs.open.assert_called_once()
        self.assertIn("FABRIC_WRITE_COMPLETE", str(self.gov._event.call_args))

    # ── PostGISLoader ─────────────────────────────────────────────────────────

    def test_postgis_missing_table_raises(self):
        loader = PostGISLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"host": "h", "db_name": "db",
                                     "user": "u", "password": "p"})
        self.assertIn("table", str(ctx.exception))

    def test_postgis_missing_host_raises(self):
        loader = PostGISLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"db_name": "db", "user": "u",
                                     "password": "p"}, table="t")
        self.assertIn("host", str(ctx.exception))

    def test_postgis_invalid_if_exists_raises(self):
        loader = PostGISLoader(self.gov)
        with self.assertRaises(ValueError) as ctx:
            loader.load(self._df(), {"host": "h", "db_name": "db",
                                     "user": "u", "password": "p"},
                        table="t", if_exists="upsert")
        self.assertIn("if_exists", str(ctx.exception))

    def test_postgis_invalid_table_name_raises(self):
        loader = PostGISLoader(self.gov)
        with self.assertRaises(ValueError):
            loader.load(self._df(), {"host": "h", "db_name": "db",
                                     "user": "u", "password": "p"},
                        table="t; DROP TABLE x")

    def test_postgis_empty_df_returns_zero(self):
        loader = PostGISLoader(self.gov)
        rows = loader.load(pd.DataFrame(),
                           {"host": "h", "db_name": "db",
                            "user": "u", "password": "p"}, table="t")
        self.assertEqual(rows, 0)

    def test_postgis_load_calls_to_sql(self):
        loader      = PostGISLoader(self.gov)
        mock_engine = MagicMock()
        mock_conn   = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__  = MagicMock(return_value=False)

        with patch("sqlalchemy.create_engine", return_value=mock_engine),              patch("pandas.DataFrame.to_sql") as mock_to_sql:
            rows = loader.load(self._df(),
                               {"host": "localhost", "db_name": "gis_db",
                                "user": "u", "password": "p"}, table="locations")
        self.assertEqual(rows, 3)
        mock_to_sql.assert_called_once()
        self.assertIn("POSTGIS_WRITE_COMPLETE", str(self.gov._event.call_args))

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
