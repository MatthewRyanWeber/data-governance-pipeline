"""
Delta Lake loader -- writes governed DataFrames to Delta Lake tables with
ACID transactions, time travel, and MERGE upsert support.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class DeltaLakeLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   First upsert into a non-existent table falls back to a
                   plain write instead of crashing; natural_keys validated
                   as SQL identifiers before interpolation into the merge
                   predicate.
1.3   2026-06-12   Keyless upsert raises via _require_upsert_keys instead of silently appending (loader contract).
1.4   2026-06-14   First-upsert fallback to append now only triggers on a genuine
                   TableNotFoundError; transient catalog/permission/network
                   errors propagate instead of degrading a MERGE into a blind
                   append that duplicates existing rows.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_DELTALAKE
from pipeline.loaders.base import BaseLoader, validate_sql_identifier

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
        self._require_upsert_keys(if_exists, natural_keys)
        self._validate_config(cfg, ["path"])

        if df.empty:
            return 0

        storage_opts = cfg.get("storage_options", {})
        schema_mode = cfg.get("schema_mode", "merge")
        arrow_table = pa.Table.from_pandas(df, preserve_index=False)

        if if_exists == "upsert" and natural_keys:
            for key in natural_keys:
                validate_sql_identifier(key, "natural_key")
            missing = [k for k in natural_keys if k not in df.columns]
            if missing:
                raise ValueError(
                    f"DeltaLakeLoader: upsert key(s) not in DataFrame: "
                    f"{missing}"
                )
            predicate = " AND ".join(
                f"t.{k} = s.{k}" for k in natural_keys
            )
            # Imported here, not at load() top: only the upsert path needs it,
            # and the dry-run/empty/bad-config paths must not touch deltalake's
            # submodules (they run with deltalake mocked out in CI).
            from deltalake.exceptions import TableNotFoundError
            try:
                dt = deltalake.DeltaTable(path, storage_options=storage_opts)
            except TableNotFoundError as exc:
                # Only a genuinely-absent table justifies falling back to a
                # plain write. Transient catalog/permission/network errors must
                # propagate — silently appending here would duplicate every
                # existing row that the MERGE was meant to update in place.
                logger.warning(
                    "DeltaLakeLoader: no Delta table at %s yet (%s) — "
                    "writing initial data instead of merging.", path, exc,
                )
                dt = None
            if dt is None:
                deltalake.write_deltalake(  # type: ignore[call-overload]
                    path,
                    arrow_table,
                    mode="append",
                    schema_mode=schema_mode,
                    storage_options=storage_opts or None,
                )
            else:
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
