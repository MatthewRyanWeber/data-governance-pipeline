"""
PostGIS loader -- writes governed DataFrames with geometry columns to
PostgreSQL with the PostGIS extension enabled.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class PostGISLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.loaders.base import BaseLoader, validate_sql_identifier

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class PostGISLoader(BaseLoader):
    """Write DataFrames with WKT geometry columns to PostGIS."""

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a PostGIS-enabled PostgreSQL table."""
        from sqlalchemy import create_engine, text as sa_text
        from urllib.parse import quote_plus as _qp

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"PostGISLoader: if_exists must be 'append' or 'replace', "
                f"got '{if_exists}'."
            )
        if not table:
            raise ValueError("PostGISLoader: table name is required.")
        if not cfg.get("host"):
            raise ValueError("PostGISLoader: cfg must contain 'host'.")
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._validate_config(cfg, ["host", "user", "password", "db_name"])

        if df.empty:
            return 0

        geom_col = cfg.get("geometry_col", "geometry")
        validate_sql_identifier(geom_col, "geometry_col")
        srid = int(cfg.get("srid", 4326))
        port = cfg.get("port", 5432)
        url = (
            f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
            f"@{cfg['host']}:{port}/{cfg['db_name']}"
        )
        engine = create_engine(url, pool_pre_ping=True)

        with engine.connect() as conn:
            conn.execute(sa_text("CREATE EXTENSION IF NOT EXISTS postgis"))
            conn.commit()

        df_meta = (df.drop(columns=[geom_col]) if geom_col in df.columns
                   else df)
        df_meta.to_sql(table, engine, if_exists=if_exists,
                       index=False, method="multi", chunksize=500)

        if geom_col in df.columns:
            with engine.connect() as conn:
                conn.execute(sa_text(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
                    f"{geom_col} geometry"
                ))
                conn.commit()
                params = [
                    {"wkt": wkt, "srid": srid, "idx": i}
                    for i, wkt in enumerate(df[geom_col])
                    if wkt is not None and wkt != ""
                ]
                if params:
                    conn.execute(
                        sa_text(
                            f"UPDATE {table} SET {geom_col} = "
                            f"ST_GeomFromText(:wkt, :srid) "
                            f"WHERE ctid = (SELECT ctid FROM {table} "
                            f"ORDER BY ctid OFFSET :idx LIMIT 1)"
                        ),
                        params,
                    )
                conn.commit()

        self.gov._event(
            "LOAD", "POSTGIS_WRITE_COMPLETE",
            {
                "host": cfg["host"],
                "table": table,
                "rows": len(df),
                "geom_col": geom_col,
                "srid": srid,
                "if_exists": if_exists,
            },
        )
        return len(df)
