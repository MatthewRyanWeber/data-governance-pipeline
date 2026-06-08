"""
Post-load verification — reconciles row counts between source and destination.

Catches silent data loss: if 10,000 rows went in but only 9,500 landed,
something went wrong during load. This module detects that discrepancy.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class LoadVerifier:
    """
    Verifies that data landed correctly after a load operation.

    Quick-start
    -----------
        from pipeline.load_verifier import LoadVerifier
        verifier = LoadVerifier(gov)
        result = verifier.verify_row_count(source_df, cfg, table="customers")
        if not result["match"]:
            handle_discrepancy(result)
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def verify_row_count(
        self,
        source_df: "pd.DataFrame",
        cfg: dict,
        table: str,
        tolerance: float = 0.0,
    ) -> dict:
        """
        Compare source DataFrame row count against the destination table.

        Args:
            source_df: The DataFrame that was loaded.
            cfg: Loader config dict (connection details).
            table: Destination table name.
            tolerance: Acceptable discrepancy as a fraction (0.01 = 1%).

        Returns:
            Dict with keys: match (bool), source_rows, dest_rows, difference, tolerance.
        """
        source_rows = len(source_df)
        dest_rows = self._count_destination(cfg, table)

        if dest_rows is None:
            logger.warning(
                "[LOAD_VERIFY] Could not count destination rows for '%s' — skipping verification.",
                table,
            )
            return {
                "match": None,
                "source_rows": source_rows,
                "dest_rows": None,
                "difference": None,
                "tolerance": tolerance,
                "table": table,
            }

        difference = dest_rows - source_rows
        within_tolerance = abs(difference) <= source_rows * tolerance if source_rows > 0 else difference == 0

        result = {
            "match": within_tolerance,
            "source_rows": source_rows,
            "dest_rows": dest_rows,
            "difference": difference,
            "tolerance": tolerance,
            "table": table,
        }

        if within_tolerance:
            logger.info(
                "[LOAD_VERIFY] ✓ '%s': source=%d, destination=%d — verified.",
                table, source_rows, dest_rows,
            )
        else:
            logger.warning(
                "[LOAD_VERIFY] ✗ '%s': source=%d, destination=%d — discrepancy of %d rows.",
                table, source_rows, dest_rows, difference,
            )

        self.gov.quality_event("LOAD_VERIFICATION", {
            "table": table,
            "source_rows": source_rows,
            "dest_rows": dest_rows,
            "difference": difference,
            "match": within_tolerance,
        })

        return result

    def verify_column_count(
        self,
        source_df: "pd.DataFrame",
        cfg: dict,
        table: str,
    ) -> dict:
        """Compare source DataFrame column count against the destination table."""
        source_cols = list(source_df.columns)
        dest_cols = self._get_destination_columns(cfg, table)

        if dest_cols is None:
            return {
                "match": None,
                "source_columns": source_cols,
                "dest_columns": None,
                "table": table,
            }

        source_set = set(c.lower() for c in source_cols)
        dest_set = set(c.lower() for c in dest_cols)

        missing_in_dest = source_set - dest_set
        extra_in_dest = dest_set - source_set

        match = not missing_in_dest

        result = {
            "match": match,
            "source_columns": source_cols,
            "dest_columns": dest_cols,
            "missing_in_dest": sorted(missing_in_dest),
            "extra_in_dest": sorted(extra_in_dest),
            "table": table,
        }

        if match:
            logger.info(
                "[LOAD_VERIFY] ✓ '%s': all %d source columns present in destination.",
                table, len(source_cols),
            )
        else:
            logger.warning(
                "[LOAD_VERIFY] ✗ '%s': %d column(s) missing in destination: %s",
                table, len(missing_in_dest), sorted(missing_in_dest),
            )

        return result

    def _count_destination(self, cfg: dict, table: str) -> int | None:
        """Query the destination for a row count."""
        db_type = cfg.get("db_type", "").lower()

        try:
            if db_type in ("mongodb", "mongo"):
                return self._count_mongo(cfg, table)
            if db_type in ("s3", "gcs", "azure_blob", "parquet"):
                return None
            return self._count_sql(cfg, table)
        except Exception as exc:
            logger.warning("[LOAD_VERIFY] Row count query failed for '%s': %s", table, exc)
            return None

    @staticmethod
    def _validate_identifier(name: str) -> str:
        """Validate and quote a SQL identifier to prevent injection."""
        import re
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            raise ValueError(f"Invalid SQL identifier: {name!r}")
        return f'"{name}"'

    def _count_sql(self, cfg: dict, table: str) -> int:
        """Count rows via SQLAlchemy."""
        from sqlalchemy import create_engine, text

        safe_table = self._validate_identifier(table)

        connection_string = cfg.get("connection_string")
        if not connection_string:
            host = cfg.get("host", "localhost")
            db_type = cfg.get("db_type", "postgresql")
            db_name = cfg.get("db_name", "")

            driver_map = {
                "postgresql": "postgresql+psycopg2",
                "postgres": "postgresql+psycopg2",
                "mysql": "mysql+pymysql",
                "mssql": "mssql+pyodbc",
                "sqlite": "sqlite",
            }
            driver = driver_map.get(db_type, db_type)

            if db_type == "sqlite":
                connection_string = f"sqlite:///{db_name}"
            else:
                from urllib.parse import quote_plus
                user = cfg.get("user", "")
                password = cfg.get("password", "")
                port = cfg.get("port", "")
                auth = f"{quote_plus(user)}:{quote_plus(password)}@" if user else ""
                port_part = f":{port}" if port else ""
                connection_string = f"{driver}://{auth}{host}{port_part}/{db_name}"

        engine = create_engine(connection_string)
        try:
            with engine.connect() as conn:
                result = conn.execute(text(f"SELECT COUNT(*) FROM {safe_table}"))
                return result.scalar()
        finally:
            engine.dispose()

    def _count_mongo(self, cfg: dict, table: str) -> int:
        """Count documents in a MongoDB collection."""
        from pymongo import MongoClient

        uri = cfg.get("connection_string") or cfg.get("host", "localhost")
        db_name = cfg.get("db_name", "pipeline")

        with MongoClient(uri) as client:
            db = client[db_name]
            return db[table].count_documents({})

    def _get_destination_columns(self, cfg: dict, table: str) -> list[str] | None:
        """Query the destination for column names."""
        db_type = cfg.get("db_type", "").lower()

        try:
            if db_type in ("mongodb", "mongo", "s3", "gcs", "azure_blob", "parquet"):
                return None
            return self._get_sql_columns(cfg, table)
        except Exception as exc:
            logger.warning("[LOAD_VERIFY] Column query failed for '%s': %s", table, exc)
            return None

    def _get_sql_columns(self, cfg: dict, table: str) -> list[str]:
        """Get column names via SQLAlchemy inspection."""
        from sqlalchemy import create_engine, inspect

        connection_string = cfg.get("connection_string", "")
        if not connection_string:
            return []

        engine = create_engine(connection_string)
        try:
            inspector = inspect(engine)
            columns = inspector.get_columns(table)
            return [c["name"] for c in columns]
        finally:
            engine.dispose()
