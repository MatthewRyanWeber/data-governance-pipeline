"""
Multi-tenancy tests for CatalogStore and OpenLineageEmitter.

Validates tenant isolation, default tenant preservation, migration
idempotency, and tenant_id in lineage event facets.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from pipeline.catalog.catalog_store import CatalogStore
from pipeline.lineage.openlineage_emitter import OpenLineageEmitter


_DF = pd.DataFrame({"id": [1, 2], "name": ["alice", "bob"]})


def _gov():
    gov = MagicMock()
    gov.log_dir = Path(tempfile.mkdtemp())
    return gov


class TestDefaultTenant(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._db = Path(self._tmpdir) / "catalog.db"
        self._gov = _gov()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_default_tenant_is_default(self):
        store = CatalogStore(self._gov, db_path=self._db)
        self.assertEqual(store.tenant_id, "default")

    def test_register_and_get_default_tenant(self):
        store = CatalogStore(self._gov, db_path=self._db)
        store.register_dataset(_DF, "customers")
        result = store.get_dataset("customers")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "customers")

    def test_list_datasets_default_tenant(self):
        store = CatalogStore(self._gov, db_path=self._db)
        store.register_dataset(_DF, "ds1")
        store.register_dataset(_DF, "ds2")
        datasets = store.list_datasets()
        self.assertEqual(len(datasets), 2)


class TestTenantIsolation(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._db = Path(self._tmpdir) / "catalog.db"
        self._gov = _gov()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_tenant_a_cannot_see_tenant_b(self):
        store_a = CatalogStore(self._gov, db_path=self._db, tenant_id="tenant_a")
        store_b = CatalogStore(self._gov, db_path=self._db, tenant_id="tenant_b")

        store_a.register_dataset(_DF, "shared_name")
        store_b.register_dataset(_DF, "shared_name")

        result_a = store_a.get_dataset("shared_name")
        result_b = store_b.get_dataset("shared_name")
        self.assertIsNotNone(result_a)
        self.assertIsNotNone(result_b)
        self.assertNotEqual(result_a["dataset_id"], result_b["dataset_id"])

    def test_list_filtered_by_tenant(self):
        store_a = CatalogStore(self._gov, db_path=self._db, tenant_id="alpha")
        store_b = CatalogStore(self._gov, db_path=self._db, tenant_id="beta")

        store_a.register_dataset(_DF, "ds_alpha")
        store_b.register_dataset(_DF, "ds_beta")

        self.assertEqual(len(store_a.list_datasets()), 1)
        self.assertEqual(len(store_b.list_datasets()), 1)
        self.assertEqual(store_a.list_datasets()[0]["name"], "ds_alpha")
        self.assertEqual(store_b.list_datasets()[0]["name"], "ds_beta")

    def test_delete_scoped_to_tenant(self):
        store_a = CatalogStore(self._gov, db_path=self._db, tenant_id="alpha")
        store_b = CatalogStore(self._gov, db_path=self._db, tenant_id="beta")

        store_a.register_dataset(_DF, "shared")
        store_b.register_dataset(_DF, "shared")

        store_a.delete_dataset("shared")
        self.assertIsNone(store_a.get_dataset("shared"))
        self.assertIsNotNone(store_b.get_dataset("shared"))


class TestMigrationIdempotency(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._db = Path(self._tmpdir) / "catalog.db"
        self._gov = _gov()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_migration_runs_twice_without_error(self):
        CatalogStore(self._gov, db_path=self._db)
        CatalogStore(self._gov, db_path=self._db)

    def test_migration_adds_tenant_id_column(self):
        import sqlite3
        CatalogStore(self._gov, db_path=self._db)
        conn = sqlite3.connect(str(self._db))
        cursor = conn.execute("PRAGMA table_info(datasets)")
        columns = [row[1] for row in cursor.fetchall()]
        conn.close()
        self.assertIn("tenant_id", columns)


class TestLineageTenantFacet(unittest.TestCase):

    def test_default_tenant_in_event(self):
        gov = _gov()
        emitter = OpenLineageEmitter(gov, dry_run=True)
        event = emitter.emit_start("test_job")
        self.assertEqual(
            event["run"]["facets"]["tenant"]["tenant_id"], "default"
        )

    def test_custom_tenant_in_event(self):
        gov = _gov()
        emitter = OpenLineageEmitter(gov, dry_run=True, tenant_id="org_42")
        event = emitter.emit_start("test_job")
        self.assertEqual(
            event["run"]["facets"]["tenant"]["tenant_id"], "org_42"
        )

    def test_tenant_facet_preserved_with_other_facets(self):
        gov = _gov()
        emitter = OpenLineageEmitter(gov, dry_run=True, tenant_id="my_org")
        event = emitter.emit_start("test_job", facets={"custom": {"key": "val"}})
        self.assertIn("tenant", event["run"]["facets"])
        self.assertIn("custom", event["run"]["facets"])


if __name__ == "__main__":
    unittest.main()
