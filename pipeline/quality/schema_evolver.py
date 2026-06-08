"""
Schema evolver — detects schema drift and applies safe ALTER TABLE statements.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
"""

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SchemaEvolver:
    """
    Detects schema drift between a stored schema snapshot and the current
    DataFrame, then applies safe ALTER TABLE statements to bring the
    destination table in line with the new schema.

    Handles:
      - New columns added  -> ALTER TABLE ... ADD COLUMN
      - Columns removed    -> logged as warning (not dropped by default)
      - Type widening      -> ALTER TABLE ... ALTER COLUMN (where supported)

    Supports: SQLite, PostgreSQL, MySQL, SQL Server, Snowflake, Redshift

    Quick-start
    -----------
        from pipeline.quality import SchemaEvolver
        evolver = SchemaEvolver(gov, engine)
        evolver.evolve(df, table_name="employees", schema="public")

    Parameters
    ----------
    gov    : GovernanceLogger
    engine : SQLAlchemy engine connected to the target database
    """

    DTYPE_TO_SQL: dict[str, str] = {
        "int64":              "BIGINT",
        "Int64":              "BIGINT",
        "float64":            "DOUBLE PRECISION",
        "bool":               "BOOLEAN",
        "boolean":            "BOOLEAN",
        "datetime64[ns]":     "TIMESTAMP",
        "datetime64[ns, UTC]":"TIMESTAMP",
        "object":             "TEXT",
    }

    def __init__(self, gov: "GovernanceLogger", engine) -> None:
        self.gov    = gov
        self.engine = engine

    def _get_existing_columns(self, table: str, schema: str | None = None) -> dict[str, str]:
        """Return {column_name: data_type} for the existing table."""
        from sqlalchemy import inspect as _sa_inspect  # pylint: disable=import-outside-toplevel
        inspector = _sa_inspect(self.engine)
        try:
            cols = inspector.get_columns(table, schema=schema)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Could not inspect table %s: %s", table, exc)
            return {}
        return {c["name"]: str(c["type"]) for c in cols}

    def evolve(
        self,
        df:           "pd.DataFrame",
        table_name:   str,
        schema:       str | None = None,
        drop_missing: bool       = False,
        engine=None,
    ) -> dict:
        """
        Evolve the target table schema to match the incoming DataFrame.

        The optional ``engine`` kwarg overrides ``self.engine`` for this call only.

        Parameters
        ----------
        df          : pd.DataFrame   Incoming data with the new schema.
        table_name  : str            Target table name.
        schema      : str | None     Database schema / namespace.
        drop_missing: bool           If True, DROP columns absent from df.
                                     Defaults to False (safe — only adds).

        Returns
        -------
        dict  Evolution report: columns_added, columns_dropped, columns_unchanged.
        """
        active_engine = engine if engine is not None else self.engine
        _orig_engine = self.engine
        if engine is not None:
            self.engine = engine
        existing = self._get_existing_columns(table_name, schema)
        incoming = {
            col: self.DTYPE_TO_SQL.get(str(df[col].dtype), "TEXT")
            for col in df.columns
        }

        from sqlalchemy import text  # pylint: disable=import-outside-toplevel

        safe_schema = schema.replace('"', '""') if schema else None
        safe_table = table_name.replace('"', '""')
        qualified = f'"{safe_schema}"."{safe_table}"' if schema else f'"{safe_table}"'
        added    = []
        dropped  = []
        unchanged = []

        with active_engine.begin() as conn:
            # Add new columns
            for col, sql_type in incoming.items():
                if col not in existing:
                    safe_col = col.replace('"', '""')
                    stmt = f'ALTER TABLE {qualified} ADD COLUMN "{safe_col}" {sql_type}'
                    try:
                        conn.execute(text(stmt))
                        added.append(col)
                        self.gov.transformation_applied("SCHEMA_COLUMN_ADDED", {
                            "table": table_name, "column": col, "type": sql_type
                        })
                    except Exception as exc:  # pylint: disable=broad-except
                        self.gov.transformation_applied("SCHEMA_ALTER_FAILED", {
                            "table": table_name, "column": col, "error": str(exc)
                        })
                        logger.warning("ALTER TABLE ADD COLUMN failed for %s.%s: %s",
                                       table_name, col, exc)
                else:
                    unchanged.append(col)

            # Optionally drop removed columns
            if drop_missing:
                for col in existing:
                    if col not in incoming:
                        safe_col = col.replace('"', '""')
                        stmt = f'ALTER TABLE {qualified} DROP COLUMN "{safe_col}"'
                        try:
                            conn.execute(text(stmt))
                            dropped.append(col)
                            self.gov.transformation_applied("SCHEMA_COLUMN_DROPPED", {
                                "table": table_name, "column": col
                            })
                        except Exception as exc:  # pylint: disable=broad-except
                            self.gov.transformation_applied("SCHEMA_DROP_FAILED", {
                                "table": table_name, "column": col, "error": str(exc)
                            })
                            logger.warning("ALTER TABLE DROP COLUMN failed for %s.%s: %s",
                                           table_name, col, exc)
            else:
                # Log missing columns as warnings but don't drop
                for col in existing:
                    if col not in incoming:
                        self.gov.transformation_applied("SCHEMA_COLUMN_MISSING_FROM_SOURCE", {
                            "table": table_name, "column": col,
                            "note":  "Column exists in DB but not in current data — not dropped"
                        })
                        logger.info("Column %s.%s exists in DB but not in source data — skipped",
                                    table_name, col)

        report = {
            "table":               table_name,
            "columns_added":       added,
            "columns_dropped":     dropped,
            "columns_unchanged":   unchanged,
            "generated_utc":       datetime.now(timezone.utc).isoformat(),
        }
        self.gov.transformation_applied("SCHEMA_EVOLUTION_COMPLETE", {
            "added": len(added), "dropped": len(dropped)
        })
        logger.info("[SchemaEvolver] %s: +%d added, -%d dropped, %d unchanged",
                    table_name, len(added), len(dropped), len(unchanged))
        if engine is not None:
            self.engine = _orig_engine
        return report
