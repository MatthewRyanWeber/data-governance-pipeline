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
1.5   2026-06-14   Layout follows the path so the name never lies: a .parquet
                   /.pq suffix is a single file, anything else a dataset dir
                   (the default). Drops the legacy-file adoption; adds compact()
                   for the dataset small-files trade-off and a one-time warning
                   on O(n²) single-file streaming append.
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

    # Recognized single-file extensions; any other path is a dataset directory.
    _FILE_SUFFIXES = (".parquet", ".pq")

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        self._warned_single_file_append = False
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
        """Write df to a Parquet file or dataset directory.

        The output shape follows the path, so the name never lies:
          * a path ending in ``.parquet`` / ``.pq`` is a SINGLE FILE (atomic
            write; appending re-reads + rewrites it — O(n²) across a streaming
            run, so a one-time warning suggests a directory path instead);
          * any other path is a DATASET DIRECTORY of part files — one atomic
            part per ``load()`` call: O(1) per write, crash-safe, resumable.
            Part files accumulate across runs; ``ParquetLoader.compact()``
            consolidates them (compaction is the consumer's job, as with any
            Parquet dataset).
        The default target (from ``table``) is a dataset directory, so the
        streaming pipeline is O(1) by default.
        """
        import pyarrow as pa
        import pyarrow.parquet as pq

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"ParquetLoader: if_exists must be 'append' or 'replace', "
                f"got '{if_exists}'."
            )

        path = cfg.get("path") or (table if table else "")
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
        filesystem = self._filesystem(path, storage_opts)

        arrow_table = pa.Table.from_pandas(df, preserve_index=False)

        if partition_cols:
            # Partitioned dataset: each write only adds fragments — already O(1).
            pq.write_to_dataset(
                arrow_table,
                root_path=path,
                partition_cols=partition_cols,
                compression=compression,
                existing_data_behavior="overwrite_or_ignore"
                if if_exists == "append" else "delete_matching",
                filesystem=filesystem,
            )
        elif self._is_single_file(path):
            with _lock_for_path(path):
                arrow_table = self._maybe_concat_existing(
                    pq, pa, arrow_table, path, if_exists, filesystem
                )
                self._write_table_atomic(
                    pq, arrow_table, path, compression, row_group_size, filesystem,
                )
        else:
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
                "layout": "partitioned" if partition_cols
                else "file" if self._is_single_file(path) else "dataset",
                "if_exists": if_exists,
            },
        )
        return len(df)

    @classmethod
    def _is_single_file(cls, path: str) -> bool:
        """A path ending in a known file suffix is a single file, else a dataset."""
        return path.lower().endswith(cls._FILE_SUFFIXES)

    def _maybe_concat_existing(self, pq, pa, arrow_table, path, if_exists, filesystem):
        """For single-file append, fold the existing file in (read+concat).

        This is inherently O(file size) per call; warn once so a streaming
        append to a single file points the user at a directory path instead.
        """
        if if_exists == "append" and self._path_exists(path, filesystem):
            if not self._warned_single_file_append:
                logger.warning(
                    "[PARQUET] appending to single file %s re-reads and rewrites "
                    "the whole file each call (O(n²) across a streaming run). "
                    "Use a directory path (no .parquet suffix) for streaming "
                    "loads — it writes one part per chunk.", path,
                )
                self._warned_single_file_append = True
            existing = pq.read_table(path, filesystem=filesystem)
            return pa.concat_tables(
                [existing, arrow_table], promote_options="default"
            )
        return arrow_table

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
        """Make `path` a dataset directory, honoring replace vs append.

        Callers pass if_exists='replace' only for the first write of a run
        (cli._run_chunked downgrades later chunks to append), so replace clears
        the directory exactly once rather than once per chunk.
        """
        if filesystem is not None:
            # Object-store "directories" are key prefixes — nothing to create.
            # For replace, delete any objects already under the prefix.
            if if_exists == "replace" and filesystem.exists(path):
                filesystem.rm(path, recursive=True)
            return
        path_obj = Path(path)
        if if_exists == "replace" and path_obj.exists():
            import shutil
            if path_obj.is_dir():
                shutil.rmtree(path_obj)
            else:
                path_obj.unlink()
        path_obj.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _path_exists(path: str, filesystem) -> bool:
        """Existence check on local disk or the remote filesystem."""
        if filesystem is not None:
            return bool(filesystem.exists(path))
        return Path(path).exists()

    @classmethod
    def compact(cls, path: str, compression: str = "snappy",
                storage_options: dict | None = None) -> int:
        """Consolidate a dataset directory's part files into one part file.

        Dataset mode writes one part per chunk, so parts accumulate across
        runs (the standard Parquet "small files" trade-off). This reads the
        whole dataset and rewrites it as a single part atomically, then drops
        the old parts. Offline use only — do not run while the dataset is
        being written. No-op for a single file or a missing path. Returns the
        number of rows in the compacted dataset.
        """
        import pyarrow.parquet as pq

        filesystem = cls._filesystem(path, storage_options or {})
        if not cls._path_exists(path, filesystem) or cls._is_single_file(path):
            return 0
        table = pq.read_table(path, filesystem=filesystem)
        consolidated = cls._new_part_path(path, filesystem)
        ParquetLoader._write_table_atomic(
            pq, table, consolidated, compression, 128_000, filesystem,
        )
        # Drop every other part now that the consolidated one is durable.
        if filesystem is None:
            for old in Path(path).glob("part-*.parquet"):
                if str(old) != consolidated:
                    old.unlink()
        else:
            for old in filesystem.glob(f"{path.rstrip('/')}/part-*.parquet"):
                if old != consolidated and filesystem.exists(old):
                    filesystem.rm(old)
        logger.info("[PARQUET] compacted %s to a single part (%d rows).",
                    path, table.num_rows)
        return int(table.num_rows)

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
