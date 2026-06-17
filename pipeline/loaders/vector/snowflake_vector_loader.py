"""
Snowflake vector loader -- writes DataFrames to Snowflake using the native
VECTOR(FLOAT, N) data type and built-in vector similarity functions.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class SnowflakeVectorLoader).
1.1   2026-06-08   Fixed SQL injection: validate table, vector_col, and
                   select_cols in search() and load().
1.2   2026-06-11   Rewrite of load(): Snowflake forbids ALTER VARCHAR->VECTOR,
                   so the loader could never produce a working vector table.
                   The target table is now created up front with the
                   VECTOR(FLOAT, n) column and rows are inserted via
                   INSERT ... SELECT with an explicit conversion from a staged
                   table.  Failures propagate; engines are disposed.
1.3   2026-06-17   Byte-aware, param-capped staging chunk size
                   (_adaptive_chunksize) instead of a fixed 500 rows.
"""

import logging
import re
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

    Creates the target table up front with a native VECTOR(FLOAT, N) column,
    stages rows via to_sql, and inserts with an explicit conversion
    (PARSE_JSON -> ARRAY -> VECTOR) because Snowflake does not allow altering
    a VARCHAR column to VECTOR.  Similarity functions supported:
    VECTOR_COSINE_SIMILARITY, VECTOR_L2_DISTANCE, VECTOR_INNER_PRODUCT.

    Quick-start
    ───────────
        from pipeline.loaders.vector import SnowflakeVectorLoader
        loader = SnowflakeVectorLoader(gov)
        loader.load(df, cfg, "vectors_table")
    """

    # Pandas dtype -> Snowflake column type for the non-vector columns of
    # the explicitly created target table.
    _DTYPE_TO_SQL: dict[str, str] = {
        "int64":               "BIGINT",
        "Int64":               "BIGINT",
        "float64":             "DOUBLE",
        "Float64":             "DOUBLE",
        "bool":                "BOOLEAN",
        "boolean":             "BOOLEAN",
        "datetime64[ns]":      "TIMESTAMP",
        "datetime64[ns, UTC]": "TIMESTAMP",
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_SNOWFLAKE:
            raise RuntimeError(
                "SnowflakeVectorLoader requires snowflake-sqlalchemy.\n"
                "Install with:  pip install snowflake-sqlalchemy "
                "snowflake-connector-python"
            )

    @staticmethod
    def _sf_identifier(name: str) -> str:
        """
        Quote an identifier the same way snowflake-sqlalchemy does, so the
        hand-written INSERT ... SELECT matches the staging table that
        to_sql created: all-lowercase names stay unquoted (Snowflake folds
        them to uppercase), anything else is double-quoted exactly.
        """
        if re.fullmatch(r"[a-z_][a-z0-9_$]*", name):
            return name
        return '"' + name.replace('"', '""') + '"'

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
        vector_size = int(cfg.get("vector_size", len(first_vec)))

        engine = create_engine(_sfurl(
            account=cfg["account"],
            user=cfg["user"],
            password=cfg["password"],
            database=cfg["database"],
            schema=cfg.get("schema", "PUBLIC"),
            warehouse=cfg["warehouse"],
            role=cfg.get("role", ""),
        ))

        # JSON array literals survive the VARCHAR staging table and convert
        # cleanly via PARSE_JSON -> ARRAY -> VECTOR
        out = df.copy()
        out[vector_col] = out[vector_col].apply(
            lambda v: "[" + ",".join(
                str(x) for x in (v.tolist() if isinstance(v, _np.ndarray)
                                  else v)
            ) + "]"
        )

        target = self._sf_identifier(table.lower())
        staging_table = f"{table.lower()}__vector_stage"
        staging = self._sf_identifier(staging_table)

        column_definitions = []
        for col in out.columns:
            identifier = self._sf_identifier(col)
            if col == vector_col:
                column_definitions.append(
                    f"{identifier} VECTOR(FLOAT, {vector_size})"
                )
            else:
                sql_type = self._DTYPE_TO_SQL.get(str(df[col].dtype), "VARCHAR")
                column_definitions.append(f"{identifier} {sql_type}")

        insert_columns = ", ".join(
            self._sf_identifier(c) for c in out.columns
        )
        select_expressions = []
        for col in out.columns:
            identifier = self._sf_identifier(col)
            if col == vector_col:
                # Snowflake forbids ALTER VARCHAR -> VECTOR, so the
                # conversion must happen at insert time
                select_expressions.append(
                    f"PARSE_JSON({identifier})::ARRAY"
                    f"::VECTOR(FLOAT, {vector_size})"
                )
            else:
                select_expressions.append(identifier)

        create_statement = (
            f"CREATE OR REPLACE TABLE {target} "
            if if_exists == "replace"
            else f"CREATE TABLE IF NOT EXISTS {target} "
        ) + "(" + ", ".join(column_definitions) + ")"

        # No exception handling around the SQL: a load that cannot produce
        # the vector table must fail loudly, not report success
        try:
            out.to_sql(staging_table, engine, if_exists="replace",
                       index=False, method="multi",
                       chunksize=self._adaptive_chunksize(out, method="multi"))
            with engine.connect() as conn:
                try:
                    conn.execute(sa_text(create_statement))
                    conn.execute(sa_text(
                        f"INSERT INTO {target} ({insert_columns}) "
                        f"SELECT {', '.join(select_expressions)} "
                        f"FROM {staging}"
                    ))
                    conn.commit()
                finally:
                    conn.execute(sa_text(f"DROP TABLE IF EXISTS {staging}"))
                    conn.commit()
        finally:
            engine.dispose()

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
        limit = int(limit)

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
        try:
            with engine.connect() as conn:
                result = pd.read_sql(sa_text(sql), conn)
        finally:
            engine.dispose()

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
