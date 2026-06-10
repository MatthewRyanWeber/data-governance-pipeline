"""
Delta Lake loader -- writes governed DataFrames to Delta Lake tables with
ACID transactions, time travel, and MERGE upsert support.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class DeltaLakeLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_DELTALAKE
from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DeltaLakeLoader(BaseLoader):
    """Delta Lake loader with append, overwrite, and MERGE upsert."""

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_DELTALAKE:
            raise RuntimeError(
                "DeltaLakeLoader requires the deltalake package.\n"
                "Install with:  pip install deltalake pyarrow"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a Delta Lake table."""
        import deltalake
        import pyarrow as pa

        if if_exists not in ("append", "replace", "upsert"):
            raise ValueError(
                f"DeltaLakeLoader: if_exists must be 'append', 'replace', or "
                f"'upsert', got '{if_exists}'."
            )
        path = cfg.get("path")
        if not path:
            raise ValueError("DeltaLakeLoader: cfg must contain 'path'.")
        if self._dry_run_guard(path, len(df)):
            return 0
        self._validate_config(cfg, ["path"])

        if df.empty:
            return 0

        storage_opts = cfg.get("storage_options", {})
        schema_mode = cfg.get("schema_mode", "merge")
        arrow_table = pa.Table.from_pandas(df, preserve_index=False)

        if if_exists == "upsert" and natural_keys:
            missing = [k for k in natural_keys if k not in df.columns]
            if missing:
                raise ValueError(
                    f"DeltaLakeLoader: upsert key(s) not in DataFrame: "
                    f"{missing}"
                )
            predicate = " AND ".join(
                f"t.{k} = s.{k}" for k in natural_keys
            )
            dt = deltalake.DeltaTable(path, storage_options=storage_opts)
            (dt.merge(
                source=arrow_table,
                predicate=predicate,
                source_alias="s",
                target_alias="t",
             )
             .when_matched_update_all()
             .when_not_matched_insert_all()
             .execute())
        else:
            mode = "overwrite" if if_exists == "replace" else "append"
            deltalake.write_deltalake(  # type: ignore[call-overload]
                path,
                arrow_table,
                mode=mode,
                schema_mode=schema_mode,
                storage_options=storage_opts or None,
            )

        self.gov._event(
            "LOAD", "DELTALAKE_WRITE_COMPLETE",
            {
                "path": path,
                "rows": len(df),
                "if_exists": if_exists,
            },
        )
        return len(df)
