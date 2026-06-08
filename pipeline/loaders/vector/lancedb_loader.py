"""
LanceDB loader -- writes DataFrames to a LanceDB vector database with
support for pre-computed embeddings, text-to-embedding generation, and
ANN index creation.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class LanceDBLoader).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_LANCEDB

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class LanceDBLoader:
    """
    LanceDB loader with append, overwrite, and merge-insert upsert.

    Serverless embedded vector DB supporting local paths and S3 URIs.
    Chunks writes at 5000 rows to manage memory on large inserts.

    Quick-start
    ───────────
        from pipeline.loaders.vector import LanceDBLoader
        loader = LanceDBLoader(gov)
        loader.load(df, {"uri": "/data/lancedb"}, "my_table")
    """

    _CHUNK = 5_000

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_LANCEDB:
            raise RuntimeError(
                "LanceDBLoader requires the lancedb package.\n"
                "Install with:  pip install lancedb pyarrow"
            )

    def load(self, df, cfg, table, if_exists="append",
             natural_keys=None) -> int:
        """Write df to a LanceDB table."""
        import lancedb

        if if_exists not in ("append", "overwrite", "upsert"):
            raise ValueError(
                f"LanceDBLoader: if_exists must be 'append', 'overwrite', or "
                f"'upsert', got '{if_exists}'."
            )

        uri = cfg.get("uri")
        vector_column = cfg.get("vector_column")
        embed_columns = cfg.get("embed_columns")
        embed_model = cfg.get("embed_model", "all-MiniLM-L6-v2")

        if not uri:
            raise ValueError(
                "LanceDBLoader: cfg must contain 'uri' "
                "(e.g. '/data/lancedb' or 's3://bucket/prefix')."
            )

        if embed_columns:
            df = self._embed(df, embed_columns, embed_model)
            vector_column = "__embedding__"

        total_rows = 0
        db = lancedb.connect(uri)

        if if_exists == "overwrite":
            total_rows = self._write_overwrite(db, table, df, vector_column)
        elif if_exists == "upsert" and natural_keys:
            total_rows = self._write_upsert(db, table, df,
                                            natural_keys, vector_column)
        else:
            total_rows = self._write_append(db, table, df, vector_column)

        self.gov.load_complete(total_rows, table)
        self.gov.destination_registered("lancedb", uri, table)
        return total_rows

    def create_index(self, cfg, table, vector_column, metric="cosine",
                     num_partitions=256, num_sub_vectors=96):
        """Build an IVF-PQ ANN index on a vector column."""
        import lancedb

        uri = cfg.get("uri")
        if not uri:
            raise ValueError("LanceDBLoader: cfg must contain 'uri'.")

        db = lancedb.connect(uri)
        tbl = db.open_table(table)
        tbl.create_index(
            metric=metric,
            num_partitions=num_partitions,
            num_sub_vectors=num_sub_vectors,
            vector_column_name=vector_column,
        )
        logger.info(
            "LanceDB ANN index created on %s.%s (metric=%s).",
            table, vector_column, metric,
        )

    def search(self, cfg, table, query_vector, vector_column,
               limit=10, metric="cosine"):
        """Run a nearest-neighbour vector search."""
        import lancedb

        uri = cfg.get("uri")
        if not uri:
            raise ValueError("LanceDBLoader: cfg must contain 'uri'.")
        if not query_vector:
            raise ValueError(
                "LanceDBLoader.search(): query_vector must be a non-empty "
                "list of floats."
            )

        db = lancedb.connect(uri)
        tbl = db.open_table(table)
        results = (
            tbl.search(query_vector, vector_column_name=vector_column)
               .metric(metric)
               .limit(limit)
               .to_pandas()
        )
        logger.info(
            "LanceDB search on %s returned %d results.", table, len(results),
        )
        return results

    def table_info(self, cfg, table) -> dict:
        """Return row count and schema info for a LanceDB table."""
        import lancedb

        uri = cfg.get("uri")
        if not uri:
            raise ValueError("LanceDBLoader: cfg must contain 'uri'.")

        db = lancedb.connect(uri)
        tbl = db.open_table(table)
        return {
            "table": table,
            "uri": uri,
            "row_count": tbl.count_rows(),
            "schema": str(tbl.schema),
        }

    def list_tables(self, cfg) -> list:
        """Return names of all tables in a LanceDB instance."""
        import lancedb

        uri = cfg.get("uri")
        if not uri:
            raise ValueError("LanceDBLoader: cfg must contain 'uri'.")

        db = lancedb.connect(uri)
        return db.table_names()

    def _write_append(self, db, table, df, vector_column) -> int:
        data = self._to_records(df, vector_column)
        if table in db.table_names():
            tbl = db.open_table(table)
            for chunk in self._chunks(data):
                tbl.add(chunk)
        else:
            db.create_table(table, data=data)
        return len(df)

    def _write_overwrite(self, db, table, df, vector_column) -> int:
        data = self._to_records(df, vector_column)
        db.create_table(table, data=data, mode="overwrite")
        return len(df)

    def _write_upsert(self, db, table, df, natural_keys, vector_column) -> int:
        data = self._to_records(df, vector_column)
        if not data:
            return 0
        if table not in db.table_names():
            db.create_table(table, data=data)
            return len(df)

        tbl = db.open_table(table)
        on_col = natural_keys[0] if len(natural_keys) == 1 else natural_keys
        (
            tbl.merge_insert(on_col)
               .when_matched_update_all()
               .when_not_matched_insert_all()
               .execute(data)
        )
        return len(df)

    @staticmethod
    def _to_records(df, vector_column) -> list:
        """Convert DataFrame to list of dicts compatible with LanceDB."""
        import numpy as np

        out = df.copy()
        if vector_column and vector_column in out.columns:
            out[vector_column] = out[vector_column].apply(
                lambda v: v.tolist() if isinstance(v, np.ndarray) else v
            )
        return out.to_dict(orient="records")

    @staticmethod
    def _chunks(records, size=5_000):
        for i in range(0, len(records), size):
            yield records[i: i + size]

    @staticmethod
    def _embed(df, embed_columns, model_name):
        """Generate sentence-transformer embeddings from text columns."""
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "LanceDBLoader: embed_columns requires sentence-transformers.\n"
                "Install with:  pip install sentence-transformers"
            ) from exc

        model = SentenceTransformer(model_name)
        texts = df[embed_columns].astype(str).agg(" ".join, axis=1).tolist()
        vecs = model.encode(texts, show_progress_bar=False).tolist()
        out = df.copy()
        out["__embedding__"] = vecs
        return out
