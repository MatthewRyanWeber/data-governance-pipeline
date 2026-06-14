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

# Per-path locks serialise the read-concat-write of a single Parquet file so
# two --parallel workers targeting the same path cannot clobber each other's
# update. Keyed by output path; guarded by _LOCKS_GUARD for safe creation.
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
            # Serialise same-path writers: the read-concat-write below is a
            # lost-update race under --parallel without this guard.
            with _lock_for_path(path):
                if if_exists == "append" and self._target_exists(path, filesystem):
                    # A single Parquet file cannot be appended to in place:
                    # read + concat + rewrite, otherwise append silently
                    # overwrites the existing data.
                    existing_table = pq.read_table(path, filesystem=filesystem)
                    arrow_table = pa.concat_tables(
                        [existing_table, arrow_table], promote_options="default"
                    )
                    logger.info(
                        "[PARQUET] append: rewriting %s with %d existing + %d "
                        "new rows.", path, existing_table.num_rows, len(df),
                    )
                self._write_table_atomic(
                    pq, arrow_table, path, compression,
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
    def _target_exists(path: str, filesystem) -> bool:
        """Check target existence on local disk or the remote filesystem."""
        if filesystem is not None:
            return bool(filesystem.exists(path))
        return Path(path).exists()

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
