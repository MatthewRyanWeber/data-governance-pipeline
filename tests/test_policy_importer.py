"""
Tests for pipeline.catalog.policy_importer.

Covers the JSON export adapter, the Atlan asset->normalized mapping (pure, no
pyatlan), and the PolicyImporter merge into the governance files the preflight
reads — including merge-not-clobber, dry-run, and the exact on-disk shapes
governance_preflight.py expects.

Revision history
────────────────
1.0   2026-06-19   Initial release.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pipeline.catalog.policy_importer import (
    PolicyImporter,
    JsonExportAdapter,
    AtlanCatalogAdapter,
)


class _ListAdapter:
    """Minimal CatalogAdapter returning a fixed policy list."""

    def __init__(self, policies):
        self._policies = policies

    def fetch(self):
        return self._policies


_POLICY = {
    "source_label": "customers",
    "columns": ["id", "email", "ssn"],
    "dtypes": {"id": "int64"},
    "column_purposes": {"email": "contact"},
    "pii_columns": ["ssn"],
    "allowed_columns": ["id", "email"],
    "purpose": "billing",
    "expected_row_count": 1000,
    "null_rates": {"email": 0.02},
}


class TestJsonExportAdapter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, obj):
        path = Path(self.tmp) / "export.json"
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    def test_reads_bare_list(self):
        path = self._write([_POLICY])
        self.assertEqual(JsonExportAdapter(path).fetch(), [_POLICY])

    def test_reads_datasets_wrapper(self):
        path = self._write({"datasets": [_POLICY]})
        self.assertEqual(JsonExportAdapter(path).fetch(), [_POLICY])

    def test_bad_shape_raises(self):
        path = self._write({"nope": 1})
        # dict without "datasets" -> empty list (no datasets), not an error
        self.assertEqual(JsonExportAdapter(path).fetch(), [])
        path2 = self._write(42)
        with self.assertRaises(ValueError):
            JsonExportAdapter(path2).fetch()


class TestAtlanNormalize(unittest.TestCase):
    def test_asset_maps_to_normalized_policy(self):
        adapter = AtlanCatalogAdapter("https://x", "key")
        asset = {
            "name": "orders",
            "purpose": "fulfilment",
            "columns": [
                {"name": "id", "data_type": "int", "purpose": "key"},
                {"name": "card", "is_pii": True},
            ],
        }
        policy = adapter._normalize_asset(asset)
        self.assertEqual(policy["source_label"], "orders")
        self.assertEqual(policy["columns"], ["id", "card"])
        self.assertEqual(policy["dtypes"], {"id": "int"})
        self.assertEqual(policy["column_purposes"], {"id": "key"})
        self.assertEqual(policy["pii_columns"], ["card"])
        self.assertEqual(policy["purpose"], "fulfilment")


class TestPolicyImporter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = Path(self.tmp)
        self.importer = PolicyImporter(config_dir=self.cfg)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _read(self, name):
        return json.loads((self.cfg / name).read_text(encoding="utf-8"))

    def test_writes_all_four_governance_files(self):
        summary = self.importer.import_from(_ListAdapter([_POLICY]))
        self.assertEqual(summary["datasets"], 1)

        schema = self._read("schema_registry.json")
        self.assertEqual(schema["customers"]["columns"], ["id", "email", "ssn"])
        self.assertEqual(schema["customers"]["dtypes"], {"id": "int64"})
        self.assertIn("updated_utc", schema["customers"])

        purposes = self._read("column_purpose.json")
        self.assertEqual(purposes["customers"]["email"], "contact")
        self.assertEqual(purposes["customers"]["ssn"], "PII")  # from pii_columns

        purpose_reg = self._read("purpose_registry.json")
        self.assertEqual(purpose_reg["customers"]["allowed_columns"], ["id", "email"])
        self.assertEqual(purpose_reg["customers"]["purpose"], "billing")

        anomaly = self._read("anomaly_baseline.json")
        self.assertEqual(anomaly["customers"]["expected_row_count"], 1000)
        self.assertEqual(anomaly["customers"]["null_rates"], {"email": 0.02})

    def test_merge_does_not_clobber_other_sources(self):
        # Pre-existing policy for a different source must survive the import.
        (self.cfg).mkdir(parents=True, exist_ok=True)
        (self.cfg / "schema_registry.json").write_text(
            json.dumps({"orders": {"columns": ["x"]}}), encoding="utf-8")
        self.importer.import_from(_ListAdapter([_POLICY]))
        schema = self._read("schema_registry.json")
        self.assertIn("orders", schema)
        self.assertIn("customers", schema)

    def test_column_purpose_merge_keeps_existing_keys(self):
        (self.cfg).mkdir(parents=True, exist_ok=True)
        (self.cfg / "column_purpose.json").write_text(
            json.dumps({"customers": {"phone": "contact"}}), encoding="utf-8")
        self.importer.import_from(_ListAdapter([_POLICY]))
        purposes = self._read("column_purpose.json")
        self.assertEqual(purposes["customers"]["phone"], "contact")  # kept
        self.assertEqual(purposes["customers"]["email"], "contact")  # added

    def test_only_relevant_files_written(self):
        # A schema-only policy must not create the other three files.
        self.importer.import_from(_ListAdapter([{"source_label": "s", "columns": ["a"]}]))
        self.assertTrue((self.cfg / "schema_registry.json").exists())
        self.assertFalse((self.cfg / "column_purpose.json").exists())
        self.assertFalse((self.cfg / "purpose_registry.json").exists())
        self.assertFalse((self.cfg / "anomaly_baseline.json").exists())

    def test_policy_without_source_label_skipped(self):
        summary = self.importer.import_from(_ListAdapter([{"columns": ["a"]}]))
        self.assertEqual(summary["datasets"], 0)

    def test_dry_run_writes_nothing(self):
        importer = PolicyImporter(config_dir=self.cfg, dry_run=True)
        importer.import_from(_ListAdapter([_POLICY]))
        self.assertFalse((self.cfg / "schema_registry.json").exists())


if __name__ == "__main__":
    unittest.main()
