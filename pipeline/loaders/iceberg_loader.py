"""
Apache Iceberg loader -- writes governed DataFrames to Iceberg tables via
PyIceberg with support for REST, Glue, Hive, and SQL catalogs.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class IcebergLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_ICEBERG
from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class IcebergLoader(BaseLoader):
    """Apache Iceberg loader with append and overwrite modes."""

    SUPPORTS_UPSERT = False  # append/overwrite only — no row-level merge here

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_ICEBERG:
            raise RuntimeError(
                "IcebergLoader requires the pyiceberg package.\n"
                "Install with:  pip install pyiceberg pyarrow"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to an Iceberg table."""
        import pyarrow as pa

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"IcebergLoader: if_exists must be 'append' or 'replace', "
                f"got '{if_exists}'."
            )

        namespace = cfg.get("namespace")
        table_name = table or cfg.get("table_name")
        if not namespace:
            raise ValueError("IcebergLoader: cfg must contain 'namespace'.")
        if not table_name:
            raise ValueError(
                "IcebergLoader: supply table name via cfg['table_name'] "
                "or the table parameter."
            )
        if self._dry_run_guard(table_name, len(df)):
            return 0
        self._validate_config(cfg, ["namespace"])

        if df.empty:
            return 0

        catalog = self._load_catalog(cfg)
        arrow_table = pa.Table.from_pandas(df, preserve_index=False)

        full_name = f"{namespace}.{table_name}"

        if not catalog.table_exists(full_name):
            catalog.create_namespace_if_not_exists(namespace)
            catalog.create_table(full_name, schema=arrow_table.schema)

        iceberg_table = catalog.load_table(full_name)

        if if_exists == "replace":
            iceberg_table.overwrite(arrow_table)
        else:
            iceberg_table.append(arrow_table)

        self.gov._event(
            "LOAD", "ICEBERG_WRITE_COMPLETE",
            {
                "namespace": namespace,
                "table": table_name,
                "rows": len(df),
                "if_exists": if_exists,
                "catalog": cfg.get("catalog_type", "unknown"),
            },
        )
        return len(df)

    @staticmethod
    def _load_catalog(cfg: dict):
        """Build a PyIceberg catalog from cfg."""
        from pyiceberg.catalog import load_catalog

        catalog_type = cfg.get("catalog_type", "rest")
        catalog_name = cfg.get("catalog_name", "default")
        properties: dict = {"type": catalog_type}

        if cfg.get("warehouse"):
            properties["warehouse"] = cfg["warehouse"]
        if cfg.get("uri"):
            properties["uri"] = cfg["uri"]
        if cfg.get("token"):
            properties["token"] = cfg["token"]
        if cfg.get("region"):
            properties["region"] = cfg["region"]
        if cfg.get("access_key_id"):
            properties["s3.access-key-id"] = cfg["access_key_id"]
            properties["s3.secret-access-key"] = cfg["secret_access_key"]
        if cfg.get("thrift_uri"):
            properties["uri"] = cfg["thrift_uri"]
        if cfg.get("catalog_db"):
            properties["uri"] = cfg["catalog_db"]
            if catalog_type == "sql" and "warehouse" in cfg:
                properties["warehouse"] = cfg["warehouse"]

        return load_catalog(catalog_name, **properties)
