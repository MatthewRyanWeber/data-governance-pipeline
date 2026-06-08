"""
Snowflake vector loader -- writes DataFrames to Snowflake using the native
VECTOR(FLOAT, N) data type and built-in vector similarity functions.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class SnowflakeVectorLoader).
1.1   2026-06-08   Fixed SQL injection: validate table, vector_col, and
                   select_cols in search() and load().
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_SNOWFLAKE
from pipeline.loaders.base import BaseLoader, validate_sql_identifier, validate_float_vector

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SnowflakeVectorLoader(BaseLoader):
    """
    Snowflake vector loader with VECTOR(FLOAT, N) and similarity search.

    Stores vectors as ARRAY type and casts to VECTOR for similarity
    functions (VECTOR_COSINE_SIMILARITY, VECTOR_L2_DISTANCE,
    VECTOR_INNER_PRODUCT).

    Quick-start
    ───────────
        from pipeline.loaders.vector import SnowflakeVectorLoader
        loader = SnowflakeVectorLoader(gov)
        loader.load(df, cfg, "vectors_table")
    """

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_SNOWFLAKE:
            raise RuntimeError(
                "SnowflakeVectorLoader requires snowflake-sqlalchemy.\n"
                "Install with:  pip install snowflake-sqlalchemy "
                "snowflake-connector-python"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to Snowflake with a VECTOR column."""
        from snowflake.sqlalchemy import URL as _sfurl
        from sqlalchemy import create_engine, text as sa_text
        import numpy as _np

        if if_exists not in ("append", "replace"):
            raise ValueError(
                f"SnowflakeVectorLoader: if_exists must be 'append' or "
                f"'replace', got '{if_exists}'."
            )
        if not table:
            raise ValueError(
                "SnowflakeVectorLoader: table name is required."
            )
        validate_sql_identifier(table, "table")
        if self._dry_run_guard(table, len(df)):
            return 0
        self._validate_config(cfg, ["account", "user", "password", "database", "warehouse"])

        if df.empty:
            return 0

        vector_col = cfg.get("vector_column", "embedding")
        validate_sql_identifier(vector_col, "vector_column")
        embed_cols = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")

        if embed_cols and vector_col not in df.columns:
            df = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if vector_col not in df.columns:
            raise ValueError(
                f"SnowflakeVectorLoader: vector column '{vector_col}' not in "
                "DataFrame."
            )

        if df.empty:
            return 0

        first_vec = df[vector_col].iloc[0]
        if isinstance(first_vec, _np.ndarray):
            first_vec = first_vec.tolist()
        vector_size = cfg.get("vector_size", len(first_vec))

        engine = create_engine(_sfurl(
            account=cfg["account"],
            user=cfg["user"],
            password=cfg["password"],
            database=cfg["database"],
            schema=cfg.get("schema", "PUBLIC"),
            warehouse=cfg["warehouse"],
            role=cfg.get("role", ""),
        ))

        out = df.copy()
        out[vector_col] = out[vector_col].apply(
            lambda v: "[" + ",".join(
                str(x) for x in (v.tolist() if isinstance(v, _np.ndarray)
                                  else v)
            ) + "]"
        )

        out.to_sql(table.lower(), engine, if_exists=if_exists,
                   index=False, method="multi", chunksize=500)

        with engine.connect() as conn:
            try:
                conn.execute(sa_text(
                    f"ALTER TABLE {table} ALTER COLUMN {vector_col} "
                    f"SET DATA TYPE VECTOR(FLOAT, {vector_size})"
                ))
                conn.commit()
            except Exception as exc:
                logger.warning(
                    "SnowflakeVectorLoader: could not set VECTOR type on "
                    "%s.%s: %s", table, vector_col, exc,
                )
                conn.rollback()

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered("snowflake_vector", cfg["database"], table)
        return len(df)

    def search(self, cfg, table, query_vector, vector_col="embedding",
               limit=10, distance="cosine", select_cols=None):
        """Search using Snowflake VECTOR_COSINE_SIMILARITY."""
        from snowflake.sqlalchemy import URL as _sfurl
        from sqlalchemy import create_engine, text as sa_text

        if not query_vector:
            raise ValueError(
                "SnowflakeVectorLoader.search(): query_vector must be "
                "a non-empty list of floats."
            )
        query_vector = validate_float_vector(query_vector, "query_vector")
        validate_sql_identifier(table, "table")
        validate_sql_identifier(vector_col, "vector_col")

        fn_map = {
            "cosine": "VECTOR_COSINE_SIMILARITY",
            "l2": "VECTOR_L2_DISTANCE",
            "inner": "VECTOR_INNER_PRODUCT",
        }
        fn = fn_map.get(distance, "VECTOR_COSINE_SIMILARITY")
        order = "DESC" if distance == "cosine" else "ASC"
        if select_cols:
            for col in select_cols:
                validate_sql_identifier(col, "select_cols element")
            cols = ", ".join(select_cols)
        else:
            cols = "*"
        vec_str = "[" + ",".join(str(v) for v in query_vector) + "]"
        n = len(query_vector)
        sql = (
            f"SELECT {cols}, "
            f"{fn}({vector_col}, '{vec_str}'::VECTOR(FLOAT,{n})) "
            f"AS _similarity "
            f"FROM {table} "
            f"ORDER BY _similarity {order} "
            f"LIMIT {limit}"
        )

        engine = create_engine(_sfurl(
            account=cfg["account"],
            user=cfg["user"],
            password=cfg["password"],
            database=cfg["database"],
            schema=cfg.get("schema", "PUBLIC"),
            warehouse=cfg["warehouse"],
            role=cfg.get("role", ""),
        ))
        with engine.connect() as conn:
            result = pd.read_sql(sa_text(sql), conn)

        logger.info(
            "Snowflake vector search on %s returned %d results.",
            table, len(result),
        )
        return result

    @staticmethod
    def _embed(df, embed_cols, model_name):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "SnowflakeVectorLoader: embed_columns requires "
                "sentence-transformers.\nInstall with: "
                "pip install sentence-transformers"
            ) from exc
        model = SentenceTransformer(model_name)
        texts = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
