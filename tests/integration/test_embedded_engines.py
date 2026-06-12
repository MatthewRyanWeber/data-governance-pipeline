"""
Integration tests for embedded engines — no Docker, no network.

Every test drives the REAL engine through resolve_loader (so the dispatch
column guard is active) and reads the data back through the engine's own
client: sqlite, duckdb, parquet, deltalake, iceberg, chroma, lancedb.

Revision history
────────────────
1.0   2026-06-12   Initial release: append / replace / upsert round-trips
                   for all seven embedded core-tier engines.
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd
import pytest

from pipeline.loaders import resolve_loader


def _df(ids=(1, 2, 3), names=("a", "b", "c")):
    return pd.DataFrame({"id": list(ids), "name": list(names)})


def _loader(db_type: str):
    loader_class, needs_db_type, _ = resolve_loader(db_type)
    if needs_db_type:
        return loader_class(MagicMock(), db_type)
    return loader_class(MagicMock())


class _TmpDirTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


@pytest.mark.integration
class TestSqliteRoundTrip(_TmpDirTest):

    def _cfg(self):
        return {"db_name": str(self.tmpdir / "it.db")}

    def _read(self, table):
        import sqlite3
        with sqlite3.connect(self._cfg()["db_name"]) as conn:
            return pd.read_sql(f"SELECT * FROM {table} ORDER BY id", conn)

    def test_append_then_read_back(self):
        loader = _loader("sqlite")
        rows = loader.load(_df(), self._cfg(), table="people")
        self.assertEqual(rows, 3)
        out = self._read("people")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_replace_clears_previous(self):
        loader = _loader("sqlite")
        loader.load(_df(), self._cfg(), table="people")
        loader.load(_df(ids=(9,), names=("z",)), self._cfg(),
                    table="people", if_exists="replace")
        out = self._read("people")
        self.assertEqual(out["id"].tolist(), [9])

    def test_upsert_updates_and_inserts(self):
        loader = _loader("sqlite")
        loader.load(_df(), self._cfg(), table="people")
        loader.load(_df(ids=(3, 4), names=("c2", "d")), self._cfg(),
                    table="people", if_exists="upsert", natural_keys=["id"])
        out = self._read("people")
        self.assertEqual(out["id"].tolist(), [1, 2, 3, 4])
        self.assertEqual(out.loc[out["id"] == 3, "name"].iloc[0], "c2")


@pytest.mark.integration
class TestDuckDBRoundTrip(_TmpDirTest):

    def _cfg(self):
        return {"db_path": str(self.tmpdir / "it.duckdb")}

    def _read(self, table):
        import duckdb
        conn = duckdb.connect(self._cfg()["db_path"], read_only=True)
        try:
            return conn.execute(f"SELECT * FROM {table} ORDER BY id").df()
        finally:
            conn.close()

    def test_append_then_read_back(self):
        loader = _loader("duckdb")
        rows = loader.load(_df(), self._cfg(), table="people")
        self.assertEqual(rows, 3)
        self.assertEqual(self._read("people")["name"].tolist(), ["a", "b", "c"])

    def test_replace_clears_previous(self):
        loader = _loader("duckdb")
        loader.load(_df(), self._cfg(), table="people")
        loader.load(_df(ids=(9,), names=("z",)), self._cfg(),
                    table="people", if_exists="replace")
        self.assertEqual(self._read("people")["id"].tolist(), [9])

    def test_upsert_updates_and_inserts(self):
        loader = _loader("duckdb")
        loader.load(_df(), self._cfg(), table="people")
        loader.load(_df(ids=(3, 4), names=("c2", "d")), self._cfg(),
                    table="people", if_exists="upsert", natural_keys=["id"])
        out = self._read("people")
        self.assertEqual(out["id"].tolist(), [1, 2, 3, 4])
        self.assertEqual(out.loc[out["id"] == 3, "name"].iloc[0], "c2")


@pytest.mark.integration
class TestParquetRoundTrip(_TmpDirTest):

    def test_write_then_read_back(self):
        path = self.tmpdir / "out.parquet"
        loader = _loader("parquet")
        rows = loader.load(_df(), {"path": str(path)}, table="people")
        self.assertEqual(rows, 3)
        out = pd.read_parquet(path)
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_append_preserves_existing_rows(self):
        path = self.tmpdir / "out.parquet"
        loader = _loader("parquet")
        loader.load(_df(), {"path": str(path)}, table="people")
        loader.load(_df(ids=(4,), names=("d",)), {"path": str(path)},
                    table="people", if_exists="append")
        out = pd.read_parquet(path).sort_values("id")
        self.assertEqual(out["id"].tolist(), [1, 2, 3, 4])

    def test_replace_overwrites(self):
        path = self.tmpdir / "out.parquet"
        loader = _loader("parquet")
        loader.load(_df(), {"path": str(path)}, table="people")
        loader.load(_df(ids=(9,), names=("z",)), {"path": str(path)},
                    table="people", if_exists="replace")
        out = pd.read_parquet(path)
        self.assertEqual(out["id"].tolist(), [9])


@pytest.mark.integration
class TestDeltaLakeRoundTrip(_TmpDirTest):

    def _cfg(self):
        return {"path": str(self.tmpdir / "delta_table")}

    def _read(self):
        import deltalake
        return (deltalake.DeltaTable(self._cfg()["path"])
                .to_pandas().sort_values("id").reset_index(drop=True))

    def test_append_then_read_back(self):
        loader = _loader("deltalake")
        rows = loader.load(_df(), self._cfg(), table="people")
        self.assertEqual(rows, 3)
        self.assertEqual(self._read()["name"].tolist(), ["a", "b", "c"])

    def test_replace_overwrites(self):
        loader = _loader("deltalake")
        loader.load(_df(), self._cfg(), table="people")
        loader.load(_df(ids=(9,), names=("z",)), self._cfg(),
                    table="people", if_exists="replace")
        self.assertEqual(self._read()["id"].tolist(), [9])

    def test_upsert_merges_on_key(self):
        loader = _loader("deltalake")
        loader.load(_df(), self._cfg(), table="people")
        loader.load(_df(ids=(3, 4), names=("c2", "d")), self._cfg(),
                    table="people", if_exists="upsert", natural_keys=["id"])
        out = self._read()
        self.assertEqual(out["id"].tolist(), [1, 2, 3, 4])
        self.assertEqual(out.loc[out["id"] == 3, "name"].iloc[0], "c2")

    def test_first_upsert_creates_table(self):
        loader = _loader("deltalake")
        rows = loader.load(_df(), self._cfg(), table="people",
                           if_exists="upsert", natural_keys=["id"])
        self.assertEqual(rows, 3)
        self.assertEqual(len(self._read()), 3)


@pytest.mark.integration
class TestIcebergRoundTrip(_TmpDirTest):

    def _cfg(self):
        import os
        warehouse = self.tmpdir / "warehouse"
        warehouse.mkdir(exist_ok=True)
        # Relative forward-slash path: pyiceberg parses an absolute
        # Windows path's drive letter ("C:") as a URI scheme, and its
        # file:// handling mangles the drive too.  A relative path has
        # no scheme to misparse, and on Linux CI behaves identically.
        rel_warehouse = os.path.relpath(warehouse).replace("\\", "/")
        return {
            "namespace": "it_ns",
            "catalog_type": "sql",
            "catalog_db": f"sqlite:///{self.tmpdir / 'catalog.db'}",
            "warehouse": rel_warehouse,
        }

    def _read(self, cfg, table):
        from pyiceberg.catalog import load_catalog
        catalog = load_catalog(
            "default",
            type="sql",
            uri=cfg["catalog_db"],
            warehouse=cfg["warehouse"],
        )
        tbl = catalog.load_table(f"{cfg['namespace']}.{table}")
        return (tbl.scan().to_pandas()
                .sort_values("id").reset_index(drop=True))

    def test_append_then_read_back(self):
        loader = _loader("iceberg")
        cfg = self._cfg()
        rows = loader.load(_df(), cfg, table="people")
        self.assertEqual(rows, 3)
        out = self._read(cfg, "people")
        self.assertEqual(out["name"].tolist(), ["a", "b", "c"])

    def test_second_append_accumulates(self):
        loader = _loader("iceberg")
        cfg = self._cfg()
        loader.load(_df(), cfg, table="people")
        loader.load(_df(ids=(4,), names=("d",)), cfg, table="people")
        self.assertEqual(len(self._read(cfg, "people")), 4)


@pytest.mark.integration
class TestChromaRoundTrip(_TmpDirTest):

    def _cfg(self):
        return {
            "path": str(self.tmpdir / "chroma"),
            "id_column": "id",
            "vector_column": "embedding",
        }

    def _vec_df(self, ids=(1, 2, 3)):
        return pd.DataFrame({
            "id": list(ids),
            "name": [f"doc{i}" for i in ids],
            "embedding": [[float(i), 0.5, 0.25] for i in ids],
        })

    def test_append_then_read_back(self):
        import chromadb
        loader = _loader("chroma")
        cfg = self._cfg()
        rows = loader.load(self._vec_df(), cfg, table="docs")
        self.assertEqual(rows, 3)
        client = chromadb.PersistentClient(path=cfg["path"])
        collection = client.get_collection("docs")
        self.assertEqual(collection.count(), 3)


@pytest.mark.integration
class TestLanceDBRoundTrip(_TmpDirTest):

    def _cfg(self):
        return {"uri": str(self.tmpdir / "lance"), "id_column": "id"}

    def _vec_df(self, ids=(1, 2, 3), names=None):
        names = names or [f"doc{i}" for i in ids]
        return pd.DataFrame({
            "id": list(ids),
            "name": names,
            "vector": [[float(i), 0.5] for i in ids],
        })

    def _read(self, cfg, table):
        import lancedb
        db = lancedb.connect(cfg["uri"])
        return (db.open_table(table).to_pandas()
                .sort_values("id").reset_index(drop=True))

    def test_append_then_read_back(self):
        loader = _loader("lancedb")
        cfg = self._cfg()
        rows = loader.load(self._vec_df(), cfg, table="docs")
        self.assertEqual(rows, 3)
        self.assertEqual(len(self._read(cfg, "docs")), 3)

    def test_upsert_merges_on_key(self):
        loader = _loader("lancedb")
        cfg = self._cfg()
        loader.load(self._vec_df(), cfg, table="docs")
        loader.load(self._vec_df(ids=(3, 4), names=["doc3b", "doc4"]),
                    cfg, table="docs", if_exists="upsert",
                    natural_keys=["id"])
        out = self._read(cfg, "docs")
        self.assertEqual(out["id"].tolist(), [1, 2, 3, 4])
        self.assertEqual(out.loc[out["id"] == 3, "name"].iloc[0], "doc3b")


if __name__ == "__main__":
    unittest.main()
