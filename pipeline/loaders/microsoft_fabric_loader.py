"""
Microsoft Fabric loader -- writes governed DataFrames to Microsoft Fabric
via OneLake (ADLS Gen2) as Parquet or Delta Lake files.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class MicrosoftFabricLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   format='delta' raises RuntimeError when deltalake is not
                   installed instead of silently degrading to parquet; parquet
                   append now reads + concatenates + rewrites instead of
                   overwriting the existing file.
1.3   2026-06-16   cfg may carry adlfs storage options (connection_string or a
                   storage_options dict) so the loader can target any ADLS-
                   compatible endpoint — real OneLake or the Azurite emulator
                   used by the integration test. Previously account_name was
                   effectively hardcoded, leaving the write path unconfigurable
                   and unverifiable against a real storage engine.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_FABRIC, HAS_DELTALAKE
from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class MicrosoftFabricLoader(BaseLoader):
    """Write DataFrames to Microsoft Fabric Lakehouse via OneLake."""

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_FABRIC:
            raise RuntimeError(
                "MicrosoftFabricLoader requires adlfs.\n"
                "Install with:  pip install adlfs pyarrow"
            )

    def load(self, df, cfg, table="", if_exists="replace",
             natural_keys=None) -> int:
        """Write df to a Microsoft Fabric Lakehouse via OneLake."""
        import adlfs
        import io
        import pyarrow as pa
        import pyarrow.parquet as pq

        workspace_id = cfg.get("workspace_id")
        lakehouse_id = cfg.get("lakehouse_id")
        path = cfg.get("path", "Files/")
        token = cfg.get("token")
        fmt = cfg.get("format", "parquet").lower()
        account_name = cfg.get("account_name", "onelake")

        if not workspace_id:
            raise ValueError(
                "MicrosoftFabricLoader: cfg must contain 'workspace_id'."
            )
        if not lakehouse_id:
            raise ValueError(
                "MicrosoftFabricLoader: cfg must contain 'lakehouse_id'."
            )
        if self._dry_run_guard(table or "fabric_table", len(df)):
            return 0
        self._validate_config(cfg, ["workspace_id", "lakehouse_id"])

        if df.empty:
            return 0

        file_name = f"{table}.parquet" if table else "data.parquet"
        full_path = (
            f"{workspace_id}/{lakehouse_id}.Lakehouse/"
            f"{path.strip('/')}/{file_name}"
        )

        # adlfs connection options. A caller (or the Azurite integration test)
        # can pass a full connection_string or an explicit storage_options dict
        # to target any ADLS-compatible endpoint; otherwise fall back to the
        # OneLake account_name + bearer token. setdefault lets storage_options
        # win without being clobbered by the defaults.
        fs_kwargs: dict = dict(cfg.get("storage_options") or {})
        connection_string = cfg.get("connection_string")
        if connection_string:
            fs_kwargs.setdefault("connection_string", connection_string)
        else:
            fs_kwargs.setdefault("account_name", account_name)
            if token:
                fs_kwargs.setdefault("credential", token)

        fs = adlfs.AzureBlobFileSystem(**fs_kwargs)

        if fmt == "delta":
            if not HAS_DELTALAKE:
                # Silently degrading to parquet would hand back a Lakehouse
                # file the caller's Delta tooling cannot read.
                raise RuntimeError(
                    "MicrosoftFabricLoader: format='delta' requires the "
                    "deltalake package.\n"
                    "Install with:  pip install deltalake"
                )
            import deltalake
            abfs_path = f"abfs://{full_path.rsplit('/', 1)[0]}"
            # For delta, storage_options are deltalake/object_store keys (a
            # different namespace from adlfs); the caller supplies the right
            # ones for their endpoint, with the bearer token as the default.
            storage_opts = dict(cfg.get("storage_options") or {})
            if token:
                storage_opts.setdefault("bearer_token", token)
            deltalake.write_deltalake(
                abfs_path,
                pa.Table.from_pandas(df, preserve_index=False),
                mode="overwrite" if if_exists == "replace" else "append",
                storage_options=storage_opts,
            )
        else:
            arrow_table = pa.Table.from_pandas(df, preserve_index=False)
            if if_exists == "append" and fs.exists(full_path):
                # A single Parquet file cannot be appended to in place:
                # read + concat + rewrite, otherwise append silently
                # overwrites the existing data.
                with fs.open(full_path, "rb") as existing_file:
                    existing_table = pq.read_table(existing_file)
                arrow_table = pa.concat_tables(
                    [existing_table, arrow_table], promote_options="default"
                )
                logger.info(
                    "[FABRIC] append: rewriting %s with %d existing + %d "
                    "new rows.", full_path, existing_table.num_rows, len(df),
                )
            buf = io.BytesIO()
            pq.write_table(arrow_table, buf)
            buf.seek(0)
            with fs.open(full_path, "wb") as f:
                f.write(buf.getvalue())

        self.gov._event(
            "LOAD", "FABRIC_WRITE_COMPLETE",
            {
                "workspace_id": workspace_id,
                "lakehouse_id": lakehouse_id,
                "path": full_path,
                "rows": len(df),
                "format": fmt,
            },
        )
        return len(df)
