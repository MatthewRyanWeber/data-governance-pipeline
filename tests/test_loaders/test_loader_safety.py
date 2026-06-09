"""
Universal safety-contract tests for the SQL/cloud loaders.

Every SQL-backed loader must, before ever opening a connection:
  • reject SQL-injection in the table name (validate_sql_identifier),
  • honour dry_run by returning without connecting,
and loaders that wrap an optional driver must raise a clear RuntimeError
(with an install hint) when that driver is absent.

These run without Docker and without the real drivers: the injection and
dry_run paths execute before any connection is attempted, so no driver is
imported.  Missing-driver flags are patched to True only to reach that
pre-connection logic.

Revision history
────────────────
1.0   2026-06-09   Initial release: cross-loader safety contract.
"""

import importlib
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})
_BAD_TABLE = "evil; DROP TABLE users"

# module, class, HAS-flag attr, driver_installed, cfg sufficient to reach the
# table-name check, cfg sufficient to reach (and pass) the dry_run guard.
SQL_LOADERS = [
    ("snowflake_loader",  "SnowflakeLoader",  "HAS_SNOWFLAKE",  True,  {}, {}),
    ("bigquery_loader",   "BigQueryLoader",   "HAS_BIGQUERY",   True,  {}, {"dataset": "ds"}),
    ("redshift_loader",   "RedshiftLoader",   "HAS_REDSHIFT",   False, {}, {}),
    ("synapse_loader",    "SynapseLoader",    "HAS_SYNAPSE",    True,  {}, {}),
    ("databricks_loader", "DatabricksLoader", "HAS_DATABRICKS", False, {}, {}),
    ("clickhouse_loader", "ClickHouseLoader", "HAS_CLICKHOUSE", False, {}, {}),
    ("oracle_loader",     "OracleLoader",     "HAS_ORACLE",     True,  {}, {}),
    ("db2_loader",        "Db2Loader",        "HAS_DB2",        False, {}, {}),
    ("firebolt_loader",   "FireboltLoader",   "HAS_FIREBOLT",   False, {}, {}),
    ("yellowbrick_loader","YellowbrickLoader","HAS_YELLOWBRICK",True,  {}, {}),
    ("hana_loader",       "HanaLoader",       "HAS_HANA",       True,  {}, {}),
    ("cockroachdb_loader","CockroachDBLoader",None,             True,
     {"host": "h", "db_name": "d"}, {"host": "h", "db_name": "d", "user": "u"}),
]

# Loaders that gate construction on an optional driver and must raise when absent.
DRIVER_GATED = [
    ("redshift_loader",   "RedshiftLoader",   "HAS_REDSHIFT"),
    ("databricks_loader", "DatabricksLoader", "HAS_DATABRICKS"),
    ("clickhouse_loader", "ClickHouseLoader", "HAS_CLICKHOUSE"),
    ("db2_loader",        "Db2Loader",        "HAS_DB2"),
    ("firebolt_loader",   "FireboltLoader",   "HAS_FIREBOLT"),
]


def _get_class(module_name, class_name):
    mod = importlib.import_module(f"pipeline.loaders.{module_name}")
    return mod, getattr(mod, class_name)


def _construct(mod, cls, has_flag):
    """Build a loader, patching its HAS-flag True so construction succeeds."""
    gov = MagicMock()
    if has_flag is not None:
        with patch.object(mod, has_flag, True):
            return cls(gov), gov
    return cls(gov), gov


class TestInjectionRejected(unittest.TestCase):
    def test_table_injection_rejected_for_every_sql_loader(self):
        for module_name, class_name, has_flag, _inst, inj_cfg, _dry in SQL_LOADERS:
            with self.subTest(loader=class_name):
                mod, cls = _get_class(module_name, class_name)
                loader, _gov = _construct(mod, cls, has_flag)
                with self.assertRaises(ValueError):
                    loader.load(_DF, dict(inj_cfg), _BAD_TABLE)


class TestDryRunNeverConnects(unittest.TestCase):
    def test_dry_run_returns_without_connecting(self):
        for module_name, class_name, has_flag, _inst, _inj, dry_cfg in SQL_LOADERS:
            with self.subTest(loader=class_name):
                mod, cls = _get_class(module_name, class_name)
                gov = MagicMock()
                flag_ctx = (patch.object(mod, has_flag, True)
                            if has_flag is not None else patch.object(mod, "logger", mod.logger))
                with flag_ctx:
                    loader = cls(gov, dry_run=True)
                    # A connect attempt would raise long before returning; a clean
                    # return proves the dry_run guard short-circuited first.
                    result = loader.load(_DF, dict(dry_cfg), "valid_table")
                self.assertIn(result, (0, None))


class TestDriverGatedConstruction(unittest.TestCase):
    def test_missing_driver_raises_runtime_error(self):
        for module_name, class_name, has_flag in DRIVER_GATED:
            with self.subTest(loader=class_name):
                mod, cls = _get_class(module_name, class_name)
                with patch.object(mod, has_flag, False):
                    with self.assertRaises(RuntimeError):
                        cls(MagicMock())

    def test_present_driver_constructs(self):
        for module_name, class_name, has_flag in DRIVER_GATED:
            with self.subTest(loader=class_name):
                mod, cls = _get_class(module_name, class_name)
                with patch.object(mod, has_flag, True):
                    loader = cls(MagicMock())
                self.assertIsNotNone(loader)


if __name__ == "__main__":
    unittest.main()
