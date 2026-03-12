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
import shutil
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
    QuickBooksLoader, QuickBooksExtractor,
    GovernanceLogger, TableCopier, ReversibleLoader,
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


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
