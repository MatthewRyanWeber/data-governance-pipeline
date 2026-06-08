"""
Dataset snapshot store — Git-like versioning for DataFrames.

Takes immutable snapshots of datasets with content-addressable storage,
diff between versions, and time-travel queries.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Add dry_run, thread lock, stricter sanitization, atomic
                   manifest writes, input validation.
"""

import hashlib
import json
import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import BASE_DIR
from pipeline.helpers import atomic_json_write

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_SNAPSHOT_DIR = BASE_DIR / "snapshots"


class SnapshotStore:
    """
    Content-addressable snapshot store for DataFrames.

    Quick-start
    -----------
        from pipeline.versioning import SnapshotStore
        store = SnapshotStore(gov)
        version = store.snapshot(df, "customers", message="Initial load")
        old_df = store.checkout("customers", version=1)
        diff = store.diff("customers", version_a=1, version_b=2)
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        snapshot_dir: str | Path | None = None,
        dry_run: bool = False,
    ) -> None:
        self.gov = gov
        self.dry_run = dry_run
        self._lock = threading.Lock()
        self.base_dir = Path(snapshot_dir) if snapshot_dir else _SNAPSHOT_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _dataset_dir(self, dataset: str) -> Path:
        safe = re.sub(r'[^\w\-.]', '_', dataset)
        if not safe:
            raise ValueError("Dataset name produced empty path after sanitization")
        dataset_directory = self.base_dir / safe
        dataset_directory.mkdir(parents=True, exist_ok=True)
        return dataset_directory

    def _manifest_path(self, dataset: str) -> Path:
        return self._dataset_dir(dataset) / "manifest.json"

    def _load_manifest(self, dataset: str) -> dict:
        path = self._manifest_path(dataset)
        if not path.exists():
            return {"dataset": dataset, "versions": []}
        return json.loads(path.read_text(encoding="utf-8"))

    def _save_manifest(self, dataset: str, manifest: dict) -> None:
        path = self._manifest_path(dataset)
        atomic_json_write(path, json.dumps(manifest, indent=2))

    def snapshot(
        self,
        df: "pd.DataFrame",
        dataset: str,
        message: str = "",
        author: str = "",
    ) -> int:
        """
        Take an immutable snapshot of a DataFrame.

        Returns the version number (1-indexed).
        """
        if not dataset or not dataset.strip():
            raise ValueError("Dataset name must not be empty")

        with self._lock:
            manifest = self._load_manifest(dataset)
            version = len(manifest["versions"]) + 1

            csv_data = df.to_csv(index=False, encoding="utf-8")
            content_hash = hashlib.sha256(csv_data.encode("utf-8")).hexdigest()

            if manifest["versions"]:
                last = manifest["versions"][-1]
                if last["content_hash"] == content_hash:
                    logger.info("[SNAPSHOT] '%s' v%d skipped — identical to v%d",
                                dataset, version, last["version"])
                    return last["version"]

            if self.dry_run:
                logger.info("[DRY RUN] Would snapshot '%s' v%d — %d rows, hash=%s",
                            dataset, version, len(df), content_hash[:12])
                return version

            snapshot_file = self._dataset_dir(dataset) / f"v{version}.csv"
            snapshot_file.write_text(csv_data, encoding="utf-8")

            manifest["versions"].append({
                "version": version,
                "content_hash": content_hash,
                "rows": len(df),
                "columns": len(df.columns),
                "column_names": list(df.columns),
                "message": message,
                "author": author,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "file": snapshot_file.name,
            })
            self._save_manifest(dataset, manifest)

            self.gov.transformation_applied("SNAPSHOT_CREATED", {
                "dataset": dataset, "version": version,
                "rows": len(df), "columns": len(df.columns),
                "content_hash": content_hash[:12],
            })
            logger.info("[SNAPSHOT] '%s' v%d — %d rows, hash=%s",
                         dataset, version, len(df), content_hash[:12])
            return version

    def checkout(self, dataset: str, version: int | None = None) -> "pd.DataFrame":
        """
        Load a snapshot by version number. Defaults to latest.
        """
        import pandas as pd

        manifest = self._load_manifest(dataset)
        if not manifest["versions"]:
            raise FileNotFoundError(f"No snapshots for dataset '{dataset}'")

        if version is None:
            entry = manifest["versions"][-1]
        else:
            entries = [v for v in manifest["versions"] if v["version"] == version]
            if not entries:
                raise ValueError(
                    f"Version {version} not found for '{dataset}'. "
                    f"Available: {[v['version'] for v in manifest['versions']]}"
                )
            entry = entries[0]

        path = self._dataset_dir(dataset) / entry["file"]
        if not path.exists():
            raise FileNotFoundError(f"Snapshot file missing: {path}")

        return pd.read_csv(path, encoding="utf-8")

    def diff(
        self,
        dataset: str,
        version_a: int | None = None,
        version_b: int | None = None,
    ) -> dict:
        """
        Compare two versions. Defaults to last two.

        Returns dict with added_rows, removed_rows, modified_columns,
        schema_changes.
        """
        manifest = self._load_manifest(dataset)
        versions = manifest["versions"]

        if len(versions) < 2 and (version_a is None or version_b is None):
            return {"error": "Need at least 2 versions to diff"}

        va = version_a or versions[-2]["version"]
        vb = version_b or versions[-1]["version"]

        df_a = self.checkout(dataset, va)
        df_b = self.checkout(dataset, vb)

        cols_a = set(df_a.columns)
        cols_b = set(df_b.columns)

        result = {
            "dataset": dataset,
            "version_a": va,
            "version_b": vb,
            "rows_a": len(df_a),
            "rows_b": len(df_b),
            "row_diff": len(df_b) - len(df_a),
            "columns_added": sorted(cols_b - cols_a),
            "columns_removed": sorted(cols_a - cols_b),
            "schema_changed": cols_a != cols_b,
        }

        common_cols = sorted(cols_a & cols_b)
        column_diffs = {}
        for col in common_cols:
            a_vals = set(df_a[col].dropna().astype(str))
            b_vals = set(df_b[col].dropna().astype(str))
            if a_vals != b_vals:
                column_diffs[col] = {
                    "values_added": len(b_vals - a_vals),
                    "values_removed": len(a_vals - b_vals),
                    "null_count_a": int(df_a[col].isna().sum()),
                    "null_count_b": int(df_b[col].isna().sum()),
                }
        result["column_diffs"] = column_diffs

        return result

    def list_versions(self, dataset: str) -> list[dict]:
        """List all versions for a dataset."""
        manifest = self._load_manifest(dataset)
        return manifest["versions"]

    def list_datasets(self) -> list[str]:
        """List all datasets that have snapshots."""
        if not self.base_dir.exists():
            return []
        return sorted(
            d.name for d in self.base_dir.iterdir()
            if d.is_dir() and (d / "manifest.json").exists()
        )

    def delete_version(self, dataset: str, version: int) -> bool:
        """Delete a specific version snapshot."""
        with self._lock:
            manifest = self._load_manifest(dataset)
            entry = None
            for v in manifest["versions"]:
                if v["version"] == version:
                    entry = v
                    break
            if not entry:
                return False

            if self.dry_run:
                logger.info("[DRY RUN] Would delete '%s' v%d", dataset, version)
                return True

            path = self._dataset_dir(dataset) / entry["file"]
            if path.exists():
                path.unlink()

            manifest["versions"] = [
                v for v in manifest["versions"] if v["version"] != version
            ]
            self._save_manifest(dataset, manifest)
            logger.info("[SNAPSHOT] Deleted '%s' v%d", dataset, version)
            return True
