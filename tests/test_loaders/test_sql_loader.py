"""
Concurrency and connection-pooling tests for SQLLoader.

Covers the two bug fixes in sql_loader.py v1.4:
  - upsert staging table names are unique per call (run id + uuid) so parallel
    workers targeting the same destination never clobber a shared staging table;
  - load() reuses one cached engine per connection identity instead of building
    a fresh pool every streaming chunk.

A real in-memory sqlite engine drives the upsert SQL so the staging
create/DELETE/INSERT/DROP path runs for real.

Revision history
────────────────
1.0   2026-06-14   Initial release: unique-staging + engine-cache regression tests.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd
from sqlalchemy import create_engine, inspect, text

from pipeline.loaders.sql_loader import SQLLoader

_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})


def _gov_with_run_id(run_id: str) -> MagicMock:
    gov = MagicMock()
    gov.run_context.pipeline_id = run_id
    return gov


class TestUpsertStagingUniqueness(unittest.TestCase):
    """BUG 1 — staging table name is unique per call and always dropped."""

    def setUp(self):
        # Shared in-memory DB: a single engine reused across the loader so the
        # target table persists between the two upsert calls.
        self.engine = create_engine("sqlite://")
        with self.engine.begin() as conn:
            pd.DataFrame({"id": [1], "name": ["seed"]}).to_sql(
                "events", conn, if_exists="replace", index=False)

    def _capture_staging_names(self, loader):
        """Run an upsert and return the staging table names to_sql saw."""
        seen = []
        real_to_sql = pd.DataFrame.to_sql

        def spy_to_sql(self_df, name, *args, **kwargs):
            if str(name).startswith("_dgp_stg_"):
                seen.append(name)
            return real_to_sql(self_df, name, *args, **kwargs)

        with patch.object(loader, "_engine", return_value=self.engine), \
             patch("pandas.DataFrame.to_sql", spy_to_sql):
            loader.load(_DF, {"db_name": "x"}, "events", natural_keys=["id"])
        return seen

    def test_two_sequential_upserts_use_different_staging_names(self):
        loader = SQLLoader(_gov_with_run_id("run-123"), db_type="sqlite")
        first = self._capture_staging_names(loader)
        second = self._capture_staging_names(loader)
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        # Same run id, but the per-call uuid must make the names differ.
        self.assertNotEqual(first[0], second[0])

    def test_staging_name_carries_run_id(self):
        loader = SQLLoader(_gov_with_run_id("abc-def"), db_type="sqlite")
        names = self._capture_staging_names(loader)
        # Dashes stripped — run token "abcdef" embedded in the identifier.
        self.assertIn("abcdef", names[0])

    def test_staging_table_dropped_after_upsert(self):
        loader = SQLLoader(_gov_with_run_id("run-123"), db_type="sqlite")
        self._capture_staging_names(loader)
        tables = inspect(self.engine).get_table_names()
        leaked = [t for t in tables if t.startswith("_dgp_stg_")]
        self.assertEqual(leaked, [], f"staging table leaked: {leaked}")

    def test_upsert_result_is_correct(self):
        loader = SQLLoader(_gov_with_run_id("run-123"), db_type="sqlite")
        self._capture_staging_names(loader)
        with self.engine.begin() as conn:
            rows = conn.execute(
                text('SELECT id, name FROM "events" ORDER BY id')).fetchall()
        # Seed row id=1 replaced by upsert; id=2 inserted.
        self.assertEqual([tuple(r) for r in rows], [(1, "a"), (2, "b")])

    def test_staging_dropped_even_when_insert_fails(self):
        loader = SQLLoader(_gov_with_run_id("run-123"), db_type="sqlite")

        # Staging df has a column the target table lacks, so the generated
        # INSERT ... SELECT fails at execution — after the staging table was
        # already created.  The finally block must still drop it.
        bad_df = pd.DataFrame({"id": [3], "name": ["c"], "extra": ["x"]})
        with patch.object(loader, "_engine", return_value=self.engine):
            with self.assertRaises(Exception):
                loader.load(bad_df, {"db_name": "x"}, "events",
                            natural_keys=["id"])
        tables = inspect(self.engine).get_table_names()
        leaked = [t for t in tables if t.startswith("_dgp_stg_")]
        self.assertEqual(leaked, [], f"staging table leaked: {leaked}")


class TestEngineCaching(unittest.TestCase):
    """BUG 2 — repeated load() calls reuse one cached engine."""

    def test_engine_built_once_across_chunks(self):
        loader = SQLLoader(MagicMock(), db_type="postgresql")
        engine = MagicMock()
        cfg = {"db_name": "d", "host": "h", "user": "u", "password": "p"}
        with patch.object(loader, "_engine", return_value=engine) as build, \
             patch("pandas.DataFrame.to_sql"):
            for _ in range(5):
                loader.load(_DF, cfg, "events", if_exists="append")
        build.assert_called_once()

    def test_different_targets_get_different_engines(self):
        loader = SQLLoader(MagicMock(), db_type="postgresql")
        with patch.object(loader, "_engine",
                          side_effect=lambda cfg: MagicMock()) as build, \
             patch("pandas.DataFrame.to_sql"):
            loader.load(_DF, {"db_name": "a", "host": "h1"}, "t")
            loader.load(_DF, {"db_name": "b", "host": "h2"}, "t")
        self.assertEqual(build.call_count, 2)

    def test_close_disposes_cached_engines(self):
        loader = SQLLoader(MagicMock(), db_type="postgresql")
        engine = MagicMock()
        cfg = {"db_name": "d", "host": "h"}
        with patch.object(loader, "_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql"):
            loader.load(_DF, cfg, "events")
        loader.close()
        engine.dispose.assert_called_once()
        # Cache cleared — a later load rebuilds.
        with patch.object(loader, "_engine", return_value=engine) as build, \
             patch("pandas.DataFrame.to_sql"):
            loader.load(_DF, cfg, "events")
        build.assert_called_once()

    def test_close_logs_and_continues_when_dispose_fails(self):
        loader = SQLLoader(MagicMock(), db_type="postgresql")
        engine = MagicMock()
        engine.dispose.side_effect = RuntimeError("dispose boom")
        with patch.object(loader, "_engine", return_value=engine), \
             patch("pandas.DataFrame.to_sql"):
            loader.load(_DF, {"db_name": "d", "host": "h"}, "events")
        # Must not raise — disposal is best-effort.
        loader.close()
        self.assertEqual(loader._engine_cache, {})


if __name__ == "__main__":
    unittest.main()
