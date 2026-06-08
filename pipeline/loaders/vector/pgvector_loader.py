"""
pgvector loader -- writes governed DataFrames to PostgreSQL with pgvector
vector columns and provides nearest-neighbour similarity search.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class PgvectorLoader).
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

from pipeline.constants import HAS_PGVECTOR
from pipeline.loaders.base import validate_sql_identifier, validate_float_vector

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class PgvectorLoader:
    """
    PostgreSQL pgvector loader with IVFFlat/HNSW index support.

    Connects via SQLAlchemy + psycopg2, creates the vector extension,
    and supports cosine/l2/inner_product distance metrics.

    Quick-start
    ───────────
        from pipeline.loaders.vector import PgvectorLoader
        loader = PgvectorLoader(gov)
        loader.load(df, cfg, "embeddings_table")
    """

    _DIST_OPS = {"cosine": "<=>", "l2": "<->", "inner": "<#>"}

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_PGVECTOR:
            raise RuntimeError(
                "PgvectorLoader requires the pgvector package.\n"
                "Install with:  pip install pgvector"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """Write df to a PostgreSQL table with a vector column."""
        from sqlalchemy import create_engine, text as sa_text
        import numpy as _np

        if if_exists not in ("append", "replace", "upsert"):
            raise ValueError(
                f"PgvectorLoader: if_exists must be 'append', 'replace', or "
                f"'upsert', got '{if_exists}'."
            )
        if not table:
            raise ValueError("PgvectorLoader: table name is required.")
        if not cfg.get("host"):
            raise ValueError("PgvectorLoader: cfg must contain 'host'.")
        validate_sql_identifier(table, "table")
        validate_sql_identifier(
            cfg.get("vector_column", "embedding"), "vector_column"
        )

        if df.empty:
            return 0

        vector_col = cfg.get("vector_column", "embedding")
        embed_cols = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")

        if embed_cols and vector_col not in df.columns:
            df = self._embed(df, embed_cols, embed_model)
            vector_col = "__embedding__"

        if vector_col not in df.columns:
            raise ValueError(
                f"PgvectorLoader: vector column '{vector_col}' not in "
                "DataFrame. Set cfg['vector_column'] or cfg['embed_columns']."
            )

        first_vec = df[vector_col].iloc[0]
        if isinstance(first_vec, _np.ndarray):
            first_vec = first_vec.tolist()
        vector_size = cfg.get("vector_size", len(first_vec))

        from urllib.parse import quote_plus as _qp
        port = cfg.get("port", 5432)
        url = (f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
               f"@{cfg['host']}:{port}/{cfg['db_name']}")
        engine = create_engine(url, pool_pre_ping=True)

        with engine.connect() as conn:
            conn.execute(sa_text("CREATE EXTENSION IF NOT EXISTS vector"))
            conn.commit()
            try:
                conn.execute(sa_text(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
                    f"{vector_col} vector({vector_size})"
                ))
                conn.commit()
            except Exception as exc:
                logger.warning(
                    "PgvectorLoader: could not alter table %s: %s", table, exc,
                )
                conn.rollback()

        out = df.copy()
        out[vector_col] = out[vector_col].apply(
            lambda v: v.tolist() if isinstance(v, _np.ndarray) else list(v)
        )

        pg_if_exists = "replace" if if_exists == "replace" else "append"
        out.to_sql(table, engine, if_exists=pg_if_exists,
                   index=False, method="multi", chunksize=500)

        index_type = cfg.get("index_type")
        if index_type:
            self.create_index(cfg, table, vector_col,
                              index_type=index_type,
                              distance=cfg.get("distance", "cosine"))

        self.gov.load_complete(len(df), table)
        self.gov.destination_registered("pgvector", cfg["db_name"], table)
        return len(df)

    def create_index(self, cfg, table, vector_col="embedding",
                     index_type="ivfflat", distance="cosine",
                     lists=100, m=16, ef_construction=64):
        """Create an IVFFlat or HNSW ANN index on a pgvector column."""
        from sqlalchemy import create_engine, text as sa_text
        from urllib.parse import quote_plus as _qp

        dist_ops = {"cosine": "vector_cosine_ops",
                    "l2": "vector_l2_ops",
                    "inner": "vector_ip_ops"}
        ops = dist_ops.get(distance, "vector_cosine_ops")
        port = cfg.get("port", 5432)
        url = (f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
               f"@{cfg['host']}:{port}/{cfg['db_name']}")
        engine = create_engine(url)

        idx_name = f"idx_{table}_{vector_col}_{index_type}"

        with engine.connect() as conn:
            row_count = conn.execute(
                sa_text(f"SELECT COUNT(*) FROM {table}")
            ).scalar() or 0
            if row_count == 0:
                logger.warning(
                    "PgvectorLoader.create_index(): table '%s' is empty -- "
                    "load data before creating IVFFlat/HNSW indexes.", table,
                )
                return
            if index_type == "hnsw":
                sql = (f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} "
                       f"USING hnsw ({vector_col} {ops}) "
                       f"WITH (m={m}, ef_construction={ef_construction})")
            else:
                sql = (f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} "
                       f"USING ivfflat ({vector_col} {ops}) "
                       f"WITH (lists={lists})")
            conn.execute(sa_text(sql))
            conn.commit()

        logger.info(
            "pgvector %s index created on %s.%s.", index_type, table, vector_col,
        )

    def search(self, cfg, table, query_vector, vector_col="embedding",
               limit=10, distance="cosine", select_cols=None, where=""):
        """Run a nearest-neighbour vector search using pgvector operators."""
        from sqlalchemy import create_engine, text as sa_text
        from urllib.parse import quote_plus as _qp

        if not query_vector:
            raise ValueError(
                "PgvectorLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )
        query_vector = validate_float_vector(query_vector, "query_vector")
        validate_sql_identifier(table, "table")
        validate_sql_identifier(vector_col, "vector_col")

        op = self._DIST_OPS.get(distance, "<=>")
        if select_cols:
            cols = ", ".join(select_cols)
        else:
            cols = f"* EXCEPT ({vector_col})" if vector_col else "*"
        vec_str = "[" + ",".join(str(v) for v in query_vector) + "]"
        where_clause = f"WHERE {where}" if where else ""
        sql = (
            f"SELECT {cols}, "
            f"{vector_col} {op} '{vec_str}'::vector AS _distance "
            f"FROM {table} "
            f"{where_clause} "
            f"ORDER BY _distance ASC "
            f"LIMIT {limit}"
        )

        port = cfg.get("port", 5432)
        url = (f"postgresql+psycopg2://{_qp(cfg['user'])}:{_qp(cfg['password'])}"
               f"@{cfg['host']}:{port}/{cfg['db_name']}")
        engine = create_engine(url)
        with engine.connect() as conn:
            result = pd.read_sql(sa_text(sql), conn)

        logger.info(
            "pgvector search on %s returned %d results.", table, len(result),
        )
        return result

    @staticmethod
    def _embed(df, embed_cols, model_name):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "PgvectorLoader: embed_columns requires "
                "sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc
        model = SentenceTransformer(model_name)
        texts = df[embed_cols].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
