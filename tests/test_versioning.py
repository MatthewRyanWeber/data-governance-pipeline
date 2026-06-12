"""
Tests for pipeline.versioning.snapshot_store.SnapshotStore.

Comprehensive coverage of snapshot creation, checkout (latest and by version),
diff between versions, listing, deletion, dry-run mode, content-addressable
dedup, dataset name sanitization, persistence round-trip, empty-dataset
edge cases, and thread safety.

Revision history
────────────────
1.0   2026-06-09   Initial release: 32 tests across snapshot creation,
                   checkout, diff, listing, deletion, dry-run, dedup,
                   persistence, error handling, and thread safety.
1.1   2026-06-11   Regression tests: snapshot after delete_version must not
                   reuse a version number or overwrite an existing snapshot.
"""

import json
import logging
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from pipeline.versioning.snapshot_store import SnapshotStore

logger = logging.getLogger(__name__)


# ── Helper ────────────────────────────────────────────────────────────────────

def _make_gov():
    """Lightweight stand-in for GovernanceLogger."""
    gov = MagicMock()
    gov.transformation_applied = MagicMock()
    return gov


# ═══════════════════════════════════════════════════════════════════════════════
#  1. Snapshot creation
# ═══════════════════════════════════════════════════════════════════════════════


class TestSnapshot(unittest.TestCase):
    """snapshot() writes immutable CSV files and updates the manifest."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_snapshot_returns_version_one(self):
        df = pd.DataFrame({"name": ["alice", "bob"], "age": [30, 40]})
        version = self.store.snapshot(df, "customers", message="Initial load")
        self.assertEqual(version, 1)

    def test_snapshot_creates_csv_file(self):
        df = pd.DataFrame({"x": [1, 2, 3]})
        self.store.snapshot(df, "numbers")
        csv_path = self.snap_dir / "numbers" / "v1.csv"
        self.assertTrue(csv_path.exists())

    def test_snapshot_creates_manifest(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "tiny")
        manifest_path = self.snap_dir / "tiny" / "manifest.json"
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["versions"]), 1)
        self.assertEqual(manifest["versions"][0]["version"], 1)
        self.assertEqual(manifest["versions"][0]["rows"], 1)

    def test_snapshot_manifest_stores_column_names(self):
        df = pd.DataFrame({"alpha": [1], "beta": [2], "gamma": [3]})
        self.store.snapshot(df, "cols_test")
        manifest_path = self.snap_dir / "cols_test" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["versions"][0]["column_names"], ["alpha", "beta", "gamma"])

    def test_sequential_snapshots_increment_version(self):
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [1, 2]})
        df3 = pd.DataFrame({"x": [1, 2, 3]})
        v1 = self.store.snapshot(df1, "growing")
        v2 = self.store.snapshot(df2, "growing")
        v3 = self.store.snapshot(df3, "growing")
        self.assertEqual(v1, 1)
        self.assertEqual(v2, 2)
        self.assertEqual(v3, 3)

    def test_snapshot_logs_governance_event(self):
        df = pd.DataFrame({"x": [1, 2]})
        self.store.snapshot(df, "governed")
        self.gov.transformation_applied.assert_called_once()
        call_args = self.gov.transformation_applied.call_args
        self.assertEqual(call_args[0][0], "SNAPSHOT_CREATED")
        self.assertEqual(call_args[0][1]["dataset"], "governed")
        self.assertEqual(call_args[0][1]["rows"], 2)

    def test_snapshot_stores_message_and_author(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "annotated", message="First load", author="data-team")
        manifest_path = self.snap_dir / "annotated" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entry = manifest["versions"][0]
        self.assertEqual(entry["message"], "First load")
        self.assertEqual(entry["author"], "data-team")

    def test_snapshot_empty_name_raises(self):
        df = pd.DataFrame({"x": [1]})
        with self.assertRaises(ValueError):
            self.store.snapshot(df, "")

    def test_snapshot_whitespace_name_raises(self):
        df = pd.DataFrame({"x": [1]})
        with self.assertRaises(ValueError):
            self.store.snapshot(df, "   ")


# ═══════════════════════════════════════════════════════════════════════════════
#  2. Content-addressable dedup
# ═══════════════════════════════════════════════════════════════════════════════


class TestDedup(unittest.TestCase):
    """Identical DataFrames produce the same hash and skip re-snapshotting."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_identical_snapshot_returns_same_version(self):
        df = pd.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]})
        v1 = self.store.snapshot(df, "stable")
        v2 = self.store.snapshot(df, "stable")
        self.assertEqual(v1, v2)

    def test_identical_snapshot_does_not_create_second_file(self):
        df = pd.DataFrame({"a": [1, 2]})
        self.store.snapshot(df, "nodupe")
        self.store.snapshot(df, "nodupe")
        csv_files = list((self.snap_dir / "nodupe").glob("v*.csv"))
        self.assertEqual(len(csv_files), 1)

    def test_changed_data_creates_new_version(self):
        df1 = pd.DataFrame({"x": [1, 2]})
        df2 = pd.DataFrame({"x": [1, 2, 3]})
        v1 = self.store.snapshot(df1, "changing")
        v2 = self.store.snapshot(df2, "changing")
        self.assertNotEqual(v1, v2)


# ═══════════════════════════════════════════════════════════════════════════════
#  3. Checkout
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckout(unittest.TestCase):
    """checkout() loads a snapshot by version or defaults to latest."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_checkout_specific_version(self):
        df1 = pd.DataFrame({"x": [10]})
        df2 = pd.DataFrame({"x": [20]})
        self.store.snapshot(df1, "versioned")
        self.store.snapshot(df2, "versioned")
        loaded = self.store.checkout("versioned", version=1)
        self.assertEqual(loaded["x"].iloc[0], 10)

    def test_checkout_latest_by_default(self):
        df1 = pd.DataFrame({"x": [10]})
        df2 = pd.DataFrame({"x": [20]})
        self.store.snapshot(df1, "latest_test")
        self.store.snapshot(df2, "latest_test")
        loaded = self.store.checkout("latest_test")
        self.assertEqual(loaded["x"].iloc[0], 20)

    def test_checkout_preserves_columns_and_rows(self):
        df = pd.DataFrame({"name": ["alice", "bob"], "score": [95, 87]})
        self.store.snapshot(df, "full_check")
        loaded = self.store.checkout("full_check", version=1)
        self.assertEqual(len(loaded), 2)
        self.assertListEqual(list(loaded.columns), ["name", "score"])
        self.assertEqual(loaded["name"].iloc[0], "alice")

    def test_checkout_no_snapshots_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.store.checkout("nonexistent_dataset")

    def test_checkout_invalid_version_raises(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "one_version")
        with self.assertRaises(ValueError) as ctx:
            self.store.checkout("one_version", version=99)
        self.assertIn("99", str(ctx.exception))

    def test_checkout_missing_file_raises(self):
        """If the CSV file was deleted but manifest remains, raise FileNotFoundError."""
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "broken")
        csv_path = self.snap_dir / "broken" / "v1.csv"
        csv_path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.store.checkout("broken", version=1)


# ═══════════════════════════════════════════════════════════════════════════════
#  4. Diff
# ═══════════════════════════════════════════════════════════════════════════════


class TestDiff(unittest.TestCase):
    """diff() compares two versions and reports structural changes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_diff_row_count_change(self):
        df1 = pd.DataFrame({"x": [1, 2]})
        df2 = pd.DataFrame({"x": [1, 2, 3, 4]})
        self.store.snapshot(df1, "growing")
        self.store.snapshot(df2, "growing")
        diff = self.store.diff("growing")
        self.assertEqual(diff["rows_a"], 2)
        self.assertEqual(diff["rows_b"], 4)
        self.assertEqual(diff["row_diff"], 2)

    def test_diff_column_added(self):
        df1 = pd.DataFrame({"name": ["alice"]})
        df2 = pd.DataFrame({"name": ["alice"], "email": ["alice@example.com"]})
        self.store.snapshot(df1, "schema_change")
        self.store.snapshot(df2, "schema_change")
        diff = self.store.diff("schema_change")
        self.assertIn("email", diff["columns_added"])
        self.assertTrue(diff["schema_changed"])

    def test_diff_column_removed(self):
        df1 = pd.DataFrame({"name": ["alice"], "age": [30]})
        df2 = pd.DataFrame({"name": ["alice"]})
        self.store.snapshot(df1, "shrinking")
        self.store.snapshot(df2, "shrinking")
        diff = self.store.diff("shrinking")
        self.assertIn("age", diff["columns_removed"])
        self.assertTrue(diff["schema_changed"])

    def test_diff_no_schema_change(self):
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [2]})
        self.store.snapshot(df1, "same_schema")
        self.store.snapshot(df2, "same_schema")
        diff = self.store.diff("same_schema")
        self.assertFalse(diff["schema_changed"])
        self.assertEqual(diff["columns_added"], [])
        self.assertEqual(diff["columns_removed"], [])

    def test_diff_value_changes_in_column_diffs(self):
        df1 = pd.DataFrame({"status": ["active", "active"]})
        df2 = pd.DataFrame({"status": ["active", "inactive"]})
        self.store.snapshot(df1, "status_ds")
        self.store.snapshot(df2, "status_ds")
        diff = self.store.diff("status_ds")
        self.assertIn("status", diff["column_diffs"])
        self.assertGreater(diff["column_diffs"]["status"]["values_added"], 0)

    def test_diff_explicit_versions(self):
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [2]})
        df3 = pd.DataFrame({"x": [3]})
        self.store.snapshot(df1, "multi")
        self.store.snapshot(df2, "multi")
        self.store.snapshot(df3, "multi")
        diff = self.store.diff("multi", version_a=1, version_b=3)
        self.assertEqual(diff["version_a"], 1)
        self.assertEqual(diff["version_b"], 3)

    def test_diff_single_version_returns_error(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "solo")
        result = self.store.diff("solo")
        self.assertIn("error", result)


# ═══════════════════════════════════════════════════════════════════════════════
#  5. Listing
# ═══════════════════════════════════════════════════════════════════════════════


class TestListing(unittest.TestCase):
    """list_versions and list_datasets enumerate stored snapshots."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_list_versions_returns_all(self):
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [1, 2]})
        self.store.snapshot(df1, "listed")
        self.store.snapshot(df2, "listed")
        versions = self.store.list_versions("listed")
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0]["version"], 1)
        self.assertEqual(versions[1]["version"], 2)

    def test_list_versions_empty_dataset(self):
        versions = self.store.list_versions("never_created")
        self.assertEqual(versions, [])

    def test_list_datasets(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "alpha")
        self.store.snapshot(df.copy(), "beta")
        datasets = self.store.list_datasets()
        self.assertIn("alpha", datasets)
        self.assertIn("beta", datasets)
        self.assertEqual(len(datasets), 2)

    def test_list_datasets_empty_store(self):
        self.assertEqual(self.store.list_datasets(), [])

    def test_list_versions_includes_content_hash(self):
        df = pd.DataFrame({"x": [1, 2, 3]})
        self.store.snapshot(df, "hashed")
        versions = self.store.list_versions("hashed")
        self.assertIn("content_hash", versions[0])
        self.assertEqual(len(versions[0]["content_hash"]), 64)


# ═══════════════════════════════════════════════════════════════════════════════
#  6. Deletion
# ═══════════════════════════════════════════════════════════════════════════════


class TestDeleteVersion(unittest.TestCase):
    """delete_version removes a specific snapshot file and manifest entry."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_delete_existing_version(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "deletable")
        self.assertTrue(self.store.delete_version("deletable", 1))
        csv_path = self.snap_dir / "deletable" / "v1.csv"
        self.assertFalse(csv_path.exists())

    def test_delete_updates_manifest(self):
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [1, 2]})
        self.store.snapshot(df1, "partial_delete")
        self.store.snapshot(df2, "partial_delete")
        self.store.delete_version("partial_delete", 1)
        versions = self.store.list_versions("partial_delete")
        version_nums = [v["version"] for v in versions]
        self.assertNotIn(1, version_nums)
        self.assertIn(2, version_nums)

    def test_delete_nonexistent_version_returns_false(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "one_ver")
        self.assertFalse(self.store.delete_version("one_ver", 99))

    def test_delete_nonexistent_dataset_returns_false(self):
        self.assertFalse(self.store.delete_version("ghost", 1))

    def test_snapshot_after_delete_does_not_reuse_version(self):
        """Regression: len(versions)+1 collided after delete_version and
        overwrote an existing immutable snapshot."""
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [1, 2]})
        df3 = pd.DataFrame({"x": [1, 2, 3]})
        self.store.snapshot(df1, "immutable")
        self.store.snapshot(df2, "immutable")
        self.store.delete_version("immutable", 1)

        new_version = self.store.snapshot(df3, "immutable")
        self.assertEqual(new_version, 3, "version numbers must never be reused")

        # v2 must be untouched by the new snapshot
        v2_df = self.store.checkout("immutable", version=2)
        self.assertEqual(len(v2_df), 2)
        v3_df = self.store.checkout("immutable", version=3)
        self.assertEqual(len(v3_df), 3)

    def test_snapshot_after_mid_delete_preserves_all_existing_files(self):
        """Deleting a middle version then snapshotting twice must never
        touch the surviving snapshot files."""
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [1, 2]})
        df3 = pd.DataFrame({"x": [1, 2, 3]})
        df4 = pd.DataFrame({"x": [1, 2, 3, 4]})
        self.store.snapshot(df1, "mid_delete")
        self.store.snapshot(df2, "mid_delete")
        self.store.snapshot(df3, "mid_delete")
        self.store.delete_version("mid_delete", 2)

        new_version = self.store.snapshot(df4, "mid_delete")
        self.assertEqual(new_version, 4)
        self.assertEqual(len(self.store.checkout("mid_delete", version=1)), 1)
        self.assertEqual(len(self.store.checkout("mid_delete", version=3)), 3)
        self.assertEqual(len(self.store.checkout("mid_delete", version=4)), 4)


# ═══════════════════════════════════════════════════════════════════════════════
#  7. Dry-run mode
# ═══════════════════════════════════════════════════════════════════════════════


class TestDryRun(unittest.TestCase):
    """dry_run=True prevents all file writes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir, dry_run=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dry_run_snapshot_returns_version_but_no_file(self):
        df = pd.DataFrame({"x": [1, 2, 3]})
        version = self.store.snapshot(df, "phantom")
        self.assertEqual(version, 1)
        csv_path = self.snap_dir / "phantom" / "v1.csv"
        self.assertFalse(csv_path.exists())

    def test_dry_run_snapshot_does_not_update_manifest(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "phantom")
        manifest_path = self.snap_dir / "phantom" / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["versions"]), 0)
        # If manifest doesn't exist at all, that's also correct

    def test_dry_run_does_not_call_governance(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "invisible")
        self.gov.transformation_applied.assert_not_called()

    def test_dry_run_delete_returns_true_but_keeps_file(self):
        """Dry-run delete signals success but does not remove files."""
        real_store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir, dry_run=False)
        df = pd.DataFrame({"x": [1]})
        real_store.snapshot(df, "keep_me")
        self.gov.transformation_applied.reset_mock()

        dry_store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir, dry_run=True)
        result = dry_store.delete_version("keep_me", 1)
        self.assertTrue(result)
        csv_path = self.snap_dir / "keep_me" / "v1.csv"
        self.assertTrue(csv_path.exists())


# ═══════════════════════════════════════════════════════════════════════════════
#  8. Dataset name sanitization
# ═══════════════════════════════════════════════════════════════════════════════


class TestSanitization(unittest.TestCase):
    """Special characters in dataset names are sanitized for the filesystem."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_special_chars_sanitized(self):
        df = pd.DataFrame({"x": [1]})
        version = self.store.snapshot(df, "my/dataset:v1")
        self.assertEqual(version, 1)
        # The directory should exist with sanitized name
        datasets = self.store.list_datasets()
        self.assertEqual(len(datasets), 1)

    def test_dots_and_dashes_preserved(self):
        df = pd.DataFrame({"x": [1]})
        self.store.snapshot(df, "my-dataset.v1")
        datasets = self.store.list_datasets()
        self.assertIn("my-dataset.v1", datasets)


# ═══════════════════════════════════════════════════════════════════════════════
#  9. Persistence round-trip
# ═══════════════════════════════════════════════════════════════════════════════


class TestPersistence(unittest.TestCase):
    """A fresh SnapshotStore instance can read snapshots written by another."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_round_trip_checkout(self):
        store1 = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        df = pd.DataFrame({"city": ["new_york", "london"], "pop": [8000000, 9000000]})
        store1.snapshot(df, "cities", message="Census data")

        store2 = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        loaded = store2.checkout("cities", version=1)
        self.assertEqual(len(loaded), 2)
        self.assertIn("city", loaded.columns)

    def test_round_trip_list_versions(self):
        store1 = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [1, 2]})
        store1.snapshot(df1, "persisted")
        store1.snapshot(df2, "persisted")

        store2 = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        versions = store2.list_versions("persisted")
        self.assertEqual(len(versions), 2)

    def test_round_trip_diff(self):
        store1 = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        df1 = pd.DataFrame({"name": ["alice"]})
        df2 = pd.DataFrame({"name": ["alice", "bob"]})
        store1.snapshot(df1, "diffable")
        store1.snapshot(df2, "diffable")

        store2 = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        diff = store2.diff("diffable")
        self.assertEqual(diff["row_diff"], 1)


# ═══════════════════════════════════════════════════════════════════════════════
#  10. Thread safety
# ═══════════════════════════════════════════════════════════════════════════════


class TestThreadSafety(unittest.TestCase):
    """Concurrent snapshot calls must not corrupt the manifest."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap_dir = Path(self.tmp) / "snapshots"
        self.gov = _make_gov()
        self.store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_concurrent_snapshots_different_datasets(self):
        errors = []

        def snap(name, value):
            try:
                df = pd.DataFrame({"val": [value]})
                self.store.snapshot(df, name)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=snap, args=(f"ds_{i}", i))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(self.store.list_datasets()), 10)


if __name__ == "__main__":
    unittest.main()
