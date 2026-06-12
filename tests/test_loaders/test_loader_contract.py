"""
Shared behavioral contract for EVERY loader in the dispatch registry.

Iterates pipeline.loaders._LAZY_DISPATCH so a newly registered loader is
covered automatically — the mechanism that prevents sibling drift (the
__noop__ MERGE bug shipped in 8 loaders because nothing enforced a family
contract).

Contract legs:
    1. dry_run=True            -> load() returns 0
    2. upsert without keys     -> raises ValueError (explicit N/A allowlist)
    3. empty config            -> raises ValueError/ConfigValidationError
    4. injection column name   -> rejected by the dispatch column guard

Deliberately NOT here:
- governance-event-on-success: asserting a successful mocked load
  generically requires per-SDK response shapes — bespoke per loader.
- empty-DataFrame behavior: 'return 0 before connecting' is not
  universally correct (replace + empty df must still truncate), and a
  generic version with locally-installed SDKs makes real connections.
  Covered bespoke with targeted patches per loader.

Revision history
────────────────
1.0   2026-06-12   Initial release.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.exceptions import ConfigValidationError


def _ensure_mock_module(*names):
    """Insert a MagicMock module into sys.modules for each name that isn't
    already importable, so lazy SDK imports inside load() succeed.  Real
    installs are never clobbered."""
    from importlib.util import find_spec
    for dotted in names:
        try:
            if find_spec(dotted) is not None:
                continue
        except (ModuleNotFoundError, ValueError):
            pass
        parts = dotted.split(".")
        for i in range(len(parts)):
            partial = ".".join(parts[: i + 1])
            if partial not in sys.modules:
                mock_mod = MagicMock()
                mock_mod.__path__ = []
                mock_mod.__name__ = partial
                sys.modules[partial] = mock_mod


_ensure_mock_module(
    "deltalake", "pyiceberg", "adlfs", "kafka", "lancedb",
    "google.cloud.bigquery", "snowflake.sqlalchemy", "snowflake.connector",
    "databricks", "databricks.sql", "firebolt_db", "clickhouse_connect",
    "clickhouse_driver", "redshift_connector", "ibm_db", "ibm_db_dbi",
    "oracledb", "hdbcli", "hdbcli.dbapi", "pymilvus", "pinecone",
    "weaviate", "qdrant_client", "chromadb",
)

_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})

# Dummy values shaped well enough to pass each loader's own validation.
_VALUE_OVERRIDES: dict[str, str] = {
    "s3_data_dir": "s3://bucket/data",
    "s3_staging_dir": "s3://bucket/stage",
    "tenant_url": "https://tenant.eu10.hcs.cloud.sap",
    "uri": "/tmp/contract-test",
    "url": "http://localhost:1234",
    "db_path": ":memory:",
    "path": "/tmp/contract-test",
    "bootstrap_servers": "localhost:9092",
}


def _minimal_config(db_type: str) -> dict:
    """Build the smallest config that passes the loader's own validation,
    derived from the registry's required-keys table so the two can't drift."""
    from pipeline.loaders import _REQUIRED_KEYS

    cfg: dict = {}
    for req in _REQUIRED_KEYS.get(db_type, []):
        key = req.split("|")[0]
        cfg[key] = _VALUE_OVERRIDES.get(key, "contract-dummy")
    # Vector loaders read these beyond the required keys
    cfg.setdefault("id_column", "id")
    return cfg


def _patched_has_flags(db_type: str):
    """Context-manager list patching every module-level HAS_* flag on the
    loader's module to True, so __init__ SDK guards pass under mocks."""
    import importlib
    from pipeline.loaders import _LAZY_DISPATCH

    module_path = _LAZY_DISPATCH[db_type][0]
    module = importlib.import_module(module_path)
    flags = [name for name in vars(module) if name.startswith("HAS_")]
    return [patch(f"{module_path}.{name}", True) for name in flags]


def _make_loader(db_type: str, dry_run: bool = False):
    """Resolve through the dispatch (so the column guard is installed) and
    construct with the loader's actual signature."""
    from pipeline.loaders import resolve_loader

    patches = _patched_has_flags(db_type)
    for p in patches:
        p.start()
    try:
        loader_class, needs_db_type, uses_mongo = resolve_loader(db_type)
        if needs_db_type:
            loader = loader_class(MagicMock(), db_type, dry_run=dry_run)
        else:
            loader = loader_class(MagicMock(), dry_run=dry_run)
        return loader, uses_mongo
    finally:
        for p in patches:
            p.stop()


def _call_load(loader, uses_mongo, df, cfg, **kwargs):
    if uses_mongo:
        return loader.load(df, cfg, "contract_table")
    return loader.load(df, cfg, table="contract_table", **kwargs)


def _registry_keys() -> list[str]:
    from pipeline.loaders import _LAZY_DISPATCH
    return sorted(_LAZY_DISPATCH.keys())


class TestLoaderContract(unittest.TestCase):
    """Every registered loader honors the family contract."""

    def test_dry_run_returns_zero(self):
        for db_type in _registry_keys():
            with self.subTest(db_type=db_type):
                patches = _patched_has_flags(db_type)
                for p in patches:
                    p.start()
                try:
                    loader, uses_mongo = _make_loader(db_type, dry_run=True)
                    result = _call_load(loader, uses_mongo, _DF,
                                        _minimal_config(db_type))
                    self.assertEqual(result, 0)
                finally:
                    for p in patches:
                        p.stop()

    # Loaders where if_exists="upsert" is not part of the signature or is
    # legitimately meaningless.  Every entry needs a reason.
    _UPSERT_NOT_APPLICABLE = {
        "mongodb",      # load(df, cfg, collection) — no if_exists kwarg
        "quickbooks",   # QBO semantics: create/update decided per record
        "s3",           # object stores: a write replaces the object
        "gcs",
        "azure_blob",
        "sftp",         # remote file write, no merge concept
        "athena",       # append/replace only; upsert raises its own error
        "parquet",      # file formats have no key-based merge
        "fabric",
        "chroma",       # vector stores upsert by id_column natively
        "pinecone",
        "weaviate",
        "qdrant",
        "milvus",
    }

    def test_upsert_without_natural_keys_raises(self):
        for db_type in _registry_keys():
            if db_type in self._UPSERT_NOT_APPLICABLE:
                continue
            with self.subTest(db_type=db_type):
                patches = _patched_has_flags(db_type)
                for p in patches:
                    p.start()
                try:
                    loader, uses_mongo = _make_loader(db_type)
                    with self.assertRaises(ValueError):
                        _call_load(loader, uses_mongo, _DF,
                                   _minimal_config(db_type),
                                   if_exists="upsert", natural_keys=None)
                finally:
                    for p in patches:
                        p.stop()

    def test_empty_config_raises(self):
        from pipeline.loaders import _REQUIRED_KEYS
        for db_type in _registry_keys():
            if db_type not in _REQUIRED_KEYS:
                continue  # loader documents no hard config requirement
            with self.subTest(db_type=db_type):
                patches = _patched_has_flags(db_type)
                for p in patches:
                    p.start()
                try:
                    loader, uses_mongo = _make_loader(db_type)
                    with self.assertRaises((ValueError, ConfigValidationError, KeyError)):
                        _call_load(loader, uses_mongo, _DF, {})
                finally:
                    for p in patches:
                        p.stop()

    def test_injection_column_name_rejected(self):
        bad_frames = [
            pd.DataFrame({'a"b': [1]}),
            pd.DataFrame({"a`b": [1]}),
        ]
        for db_type in _registry_keys():
            with self.subTest(db_type=db_type):
                patches = _patched_has_flags(db_type)
                for p in patches:
                    p.start()
                try:
                    # dry_run=True: the guard wraps load() and must fire
                    # before the dry-run short-circuit
                    loader, uses_mongo = _make_loader(db_type, dry_run=True)
                    for bad_df in bad_frames:
                        with self.assertRaises(ValueError):
                            _call_load(loader, uses_mongo, bad_df,
                                       _minimal_config(db_type))
                finally:
                    for p in patches:
                        p.stop()


class TestContractSuiteCoversRegistry(unittest.TestCase):
    """The allowlist must shrink, never silently grow stale."""

    def test_upsert_allowlist_entries_exist_in_registry(self):
        from pipeline.loaders import _LAZY_DISPATCH
        stale = TestLoaderContract._UPSERT_NOT_APPLICABLE - set(_LAZY_DISPATCH)
        self.assertEqual(stale, set(),
                         f"allowlist entries no longer in the registry: {stale}")


if __name__ == "__main__":
    unittest.main()
