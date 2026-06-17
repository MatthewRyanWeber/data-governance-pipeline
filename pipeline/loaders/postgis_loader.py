"""
PostGIS loader -- writes governed DataFrames with geometry columns to
PostgreSQL with the PostGIS extension enabled.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class PostGISLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   Geometry now written in the same INSERT as the row via
                   ST_GeomFromText, replacing the ctid-offset UPDATE that
                   mismatched geometries on concurrent writes and was O(n²).
1.3   2026-06-17   Byte-aware write chunk size (_adaptive_chunksize) instead of
                   a fixed 500 rows.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.loaders.base import (
    BaseLoader,
    validate_column_names,
    validate_sql_identifier,
)

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
        validate_column_names(df, label="PostGISLoader")
        srid = int(cfg.get("srid", 4326))
        port = cfg.get("port", 5432)
        url = (
            f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
            f"@{cfg['host']}:{port}/{cfg['db_name']}"
        )
        engine = create_engine(url, pool_pre_ping=True)
        try:
            with engine.connect() as conn:
                conn.execute(sa_text("CREATE EXTENSION IF NOT EXISTS postgis"))
                conn.commit()

            if geom_col not in df.columns:
                df.to_sql(table, engine, if_exists=if_exists,
                          index=False, method="multi",
                          chunksize=self._adaptive_chunksize(df, method="multi"))
            else:
                self._load_with_geometry(
                    df, engine, table, if_exists, geom_col, srid
                )
        finally:
            engine.dispose()

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

    @staticmethod
    def _load_with_geometry(df, engine, table, if_exists, geom_col, srid):
        """Insert rows and their geometry atomically in one INSERT per row.

        The geometry is bound into the same statement via ST_GeomFromText,
        so each geometry is guaranteed to land on its own row — matching
        rows back by ctid offset after the fact corrupted spatial data
        whenever another writer touched the table.
        """
        from sqlalchemy import text as sa_text

        attribute_cols = [c for c in df.columns if c != geom_col]

        # to_sql with zero rows creates/replaces the table shape only; the
        # rows themselves go through the geometry-aware INSERT below.
        df[attribute_cols].head(0).to_sql(
            table, engine, if_exists=if_exists, index=False
        )

        quoted_cols = ", ".join(f'"{c}"' for c in attribute_cols)
        value_binds = ", ".join(f":p{i}" for i in range(len(attribute_cols)))
        insert_sql = sa_text(
            f'INSERT INTO "{table}" ({quoted_cols}, "{geom_col}") '
            f"VALUES ({value_binds}, ST_GeomFromText(:wkt, :srid))"
        )

        params = []
        # Object dtype first: .where(notna, None) on numeric columns upcasts
        # None straight back to NaN on some pandas versions.
        clean_df = df.astype(object).where(df.notna(), None)
        for row in clean_df.itertuples(index=False, name=None):
            row_dict = dict(zip(clean_df.columns, row))
            wkt = row_dict.pop(geom_col)
            param = {f"p{i}": row_dict[c]
                     for i, c in enumerate(attribute_cols)}
            # ST_GeomFromText is strict, so a NULL wkt yields a NULL geometry.
            param["wkt"] = wkt if wkt not in (None, "") else None
            param["srid"] = srid
            params.append(param)

        with engine.connect() as conn:
            conn.execute(sa_text(
                f'ALTER TABLE "{table}" ADD COLUMN IF NOT EXISTS '
                f'"{geom_col}" geometry'
            ))
            conn.execute(insert_sql, params)
            conn.commit()
