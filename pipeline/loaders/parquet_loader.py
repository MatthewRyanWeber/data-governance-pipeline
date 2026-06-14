"""
Parquet loader -- writes governed DataFrames to Parquet files on local disk
or cloud storage (S3, GCS, Azure).

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class ParquetLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   append to an existing single file now reads, concatenates,
                   and rewrites it instead of silently overwriting.
1.3   2026-06-14   single-file append is now crash-safe: write to a sibling
                   temp file then os.replace (atomic), and serialise concurrent
                   writers to the same path with a per-path lock so --parallel
                   workers cannot lose an update.
1.4   2026-06-14   Non-partitioned writes now produce a DIRECTORY of part files
                   (one atomic part per chunk) instead of re-reading and
                   rewriting the whole file every chunk — O(n) per load, not
                   O(n²) over a streaming run. A legacy single-file target is
                   adopted as the first part so append doesn't lose data.
"""

import logging
import os
import threading
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

# Per-path locks serialise dataset-directory preparation (replace-clear and
# legacy-file adoption) for a given output path so two --parallel workers
# targeting it cannot race. Keyed by output path; guarded by _LOCKS_GUARD.
_PATH_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for_path(path: str) -> threading.Lock:
    """Return the shared lock for a given output path, creating it once."""
    with _LOCKS_GUARD:
        lock = _PATH_LOCKS.get(path)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[path] = lock
        return lock


class ParquetLoader(BaseLoader):
    """Write DataFrames to Parquet files with optional partitioning."""

    SUPPORTS_UPSERT = False  # append-only file format, no idempotent merge

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        try:
            import pyarrow as _pa
            _ = _pa  # availability check only
        except ImportError as exc:
            raise RuntimeError(
                "ParquetLoader requires the pyarrow package.\n"
                "Install with:  pip install pyarrow"
            ) from exc

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a Parquet file or partitioned dataset."""
        import pyarrow as pa
        import pyarrow.parquet as pq

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"ParquetLoader: if_exists must be 'append' or 'replace', "
                f"got '{if_exists}'."
            )

        path = cfg.get("path") or (f"{table}.parquet" if table else "")
        if not path:
            raise ValueError(
                "ParquetLoader: supply output path via cfg['path'] or the "
                "table parameter."
            )
        if self._dry_run_guard(path, len(df)):
            return 0

        if df.empty:
            return 0

        compression = cfg.get("compression", "snappy")
        row_group_size = int(cfg.get("row_group_size", 128_000))
        partition_cols = cfg.get("partition_cols")
        storage_opts = cfg.get("storage_options", {})

        arrow_table = pa.Table.from_pandas(df, preserve_index=False)

        if partition_cols:
            # partition_cols is the O(1) streaming path for large loads — each
            # write only adds new fragments, never re-reading prior data.
            pq.write_to_dataset(
                arrow_table,
                root_path=path,
                partition_cols=partition_cols,
                compression=compression,
                existing_data_behavior="overwrite_or_ignore"
                if if_exists == "append" else "delete_matching",
                filesystem=self._filesystem(path, storage_opts),
            )
        else:
            filesystem = self._filesystem(path, storage_opts)
            # Non-partitioned writes go to a DIRECTORY of part files (a standard
            # Parquet dataset): one atomically-written part per load() call.
            # That is O(rows-in-chunk), not the old read-concat-rewrite of the
            # whole file every chunk (which was O(n^2) under streaming), and a
            # crash leaves every completed part intact — exactly what the
            # per-chunk checkpoint/resume model needs. pandas/pyarrow read the
            # directory back as a single table.
            with _lock_for_path(path):
                self._prepare_dataset_dir(path, if_exists, filesystem)
                part_path = self._new_part_path(path, filesystem)
                self._write_table_atomic(
                    pq, arrow_table, part_path, compression,
                    row_group_size, filesystem,
                )

        self.gov._event(
            "LOAD", "PARQUET_WRITE_COMPLETE",
            {
                "path": path,
                "rows": len(df),
                "compression": compression,
                "partitioned": bool(partition_cols),
                "if_exists": if_exists,
            },
        )
        return len(df)

    @staticmethod
    def _write_table_atomic(pq, arrow_table, path, compression,
                            row_group_size, filesystem) -> None:
        """Write the table to a sibling temp file, then atomically replace path.

        A crash during pq.write_table directly over `path` would truncate the
        whole accumulated file and lose every previously-loaded row. Writing a
        temp sibling first and then moving it means `path` is never in a
        partially-written state.
        """
        unique = uuid.uuid4().hex
        tmp_path = f"{path}.tmp-{unique}"
        try:
            pq.write_table(
                arrow_table,
                tmp_path,
                compression=compression,
                row_group_size=row_group_size,
                filesystem=filesystem,
            )
            if filesystem is None:
                # Local disk: os.replace is atomic and overwrites on the same
                # filesystem, the closure for the data-loss bug.
                os.replace(tmp_path, path)
            elif hasattr(filesystem, "mv"):
                # Remote filesystem (s3fs/gcsfs/adlfs): no POSIX rename, but
                # object stores treat a single-key move as atomic at the key
                # level, which is the strongest guarantee available here.
                filesystem.mv(tmp_path, path)
            else:
                # No move primitive available — fall back to a direct write so
                # the load still completes rather than silently dropping data.
                logger.warning(
                    "[PARQUET] filesystem %s has no mv(); writing %s directly "
                    "(non-atomic).", type(filesystem).__name__, path,
                )
                pq.write_table(
                    arrow_table, path, compression=compression,
                    row_group_size=row_group_size, filesystem=filesystem,
                )
        except BaseException:
            ParquetLoader._remove_temp(tmp_path, filesystem)
            raise

    @staticmethod
    def _remove_temp(tmp_path: str, filesystem) -> None:
        """Best-effort removal of a leftover temp file after a failed write."""
        try:
            if filesystem is not None:
                if filesystem.exists(tmp_path):
                    filesystem.rm(tmp_path)
            elif Path(tmp_path).exists():
                Path(tmp_path).unlink()
        except OSError as exc:
            logger.warning(
                "[PARQUET] could not remove temp file %s: %s", tmp_path, exc,
            )

    @staticmethod
    def _new_part_path(path: str, filesystem) -> str:
        """A unique part-file path inside the dataset directory `path`."""
        name = f"part-{uuid.uuid4().hex}.parquet"
        if filesystem is not None:
            return f"{path.rstrip('/')}/{name}"
        return str(Path(path) / name)

    def _prepare_dataset_dir(self, path: str, if_exists: str, filesystem) -> None:
        """Make `path` a dataset directory, honoring replace vs append."""
        if filesystem is not None:
            # Object-store "directories" are key prefixes — nothing to create.
            # For replace, delete any objects already under the prefix.
            if if_exists == "replace" and filesystem.exists(path):
                filesystem.rm(path, recursive=True)
            return
        path_obj = Path(path)
        if if_exists == "replace":
            self._remove_path(path_obj)
        elif path_obj.is_file():
            # A single .parquet FILE written by an older version: adopt its
            # rows as the first part so append doesn't silently lose them.
            self._adopt_legacy_file(path_obj)
        path_obj.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _remove_path(path_obj: Path) -> None:
        """Remove a dataset directory or legacy single file (for replace)."""
        import shutil
        if path_obj.is_dir():
            shutil.rmtree(path_obj)
        elif path_obj.exists():
            path_obj.unlink()

    @staticmethod
    def _adopt_legacy_file(path_obj: Path) -> None:
        """Convert a pre-existing single-file target into a dataset directory."""
        sibling = path_obj.with_name(f"{path_obj.name}.adopt-{uuid.uuid4().hex}")
        os.replace(path_obj, sibling)
        path_obj.mkdir(parents=True, exist_ok=True)
        os.replace(sibling, path_obj / f"part-{uuid.uuid4().hex}.parquet")

    @staticmethod
    def _filesystem(path: str, storage_options: dict):
        """Return the appropriate fsspec filesystem for the given path."""
        if path.startswith("s3://"):
            try:
                import s3fs
                return s3fs.S3FileSystem(**storage_options)
            except ImportError as exc:
                raise RuntimeError(
                    "ParquetLoader: S3 paths require s3fs.\n"
                    "Install with:  pip install s3fs"
                ) from exc
        if path.startswith("gs://"):
            try:
                import gcsfs
                return gcsfs.GCSFileSystem(**storage_options)
            except ImportError as exc:
                raise RuntimeError(
                    "ParquetLoader: GCS paths require gcsfs.\n"
                    "Install with:  pip install gcsfs"
                ) from exc
        if path.startswith(("az://", "abfs://")):
            try:
                import adlfs
                return adlfs.AzureBlobFileSystem(**storage_options)
            except ImportError as exc:
                raise RuntimeError(
                    "ParquetLoader: Azure paths require adlfs.\n"
                    "Install with:  pip install adlfs"
                ) from exc
        return None
