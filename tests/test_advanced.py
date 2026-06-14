"""
Tests for pipeline.advanced — NLPipelineBuilder, ReversibleLoader,
TableCopier, and DLQReplayer.

Revision history
────────────────
1.0   2026-06-08   Initial release: 18 tests across 4 classes.
1.1   2026-06-14   DLQReplayer: replay/replay_all without a loader must NOT
                   archive the file (data-orphaning regression); replay WITH a
                   loader archives after a successful load.
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.governance_logger import GovernanceLogger
from pipeline.advanced.nl_pipeline_builder import NLPipelineBuilder
from pipeline.advanced.reversible_loader import ReversibleLoader
from pipeline.advanced.table_copier import TableCopier
from pipeline.advanced.dlq_replayer import DLQReplayer


class TestNLPipelineBuilder(unittest.TestCase):
    """NLPipelineBuilder keyword extraction and LLM fallback."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("nlp_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_keyword_csv_to_postgres_with_mask(self):
        builder = NLPipelineBuilder(self.gov)
        config = builder.build("Load customers.csv, mask PII, write to Postgres")
        self.assertEqual(config["source_type"], "csv")
        self.assertEqual(config["destination_type"], "postgresql")
        self.assertIn("mask_pii", config["transforms"])

    def test_keyword_detects_deduplication(self):
        builder = NLPipelineBuilder(self.gov)
        config = builder.build("Read data.json, dedup rows, remove duplicates, save to sqlite")
        self.assertEqual(config["source_type"], "json")
        self.assertIn("deduplicate", config["transforms"])
        self.assertEqual(config["destination_type"], "sqlite")

    def test_keyword_detects_quality_checks(self):
        builder = NLPipelineBuilder(self.gov)
        config = builder.build(
            "Load report.csv, check for null values and PII, write to MySQL"
        )
        self.assertIn("null_check", config["quality_checks"])
        self.assertIn("pii_scan", config["quality_checks"])

    def test_empty_description_raises(self):
        builder = NLPipelineBuilder(self.gov)
        with self.assertRaises(ValueError):
            builder.build("")

    def test_llm_fallback_on_api_error(self):
        builder = NLPipelineBuilder(self.gov, api_key="sk-fake-key-1234")
        with patch.dict("sys.modules", {"requests": MagicMock(
            post=MagicMock(side_effect=ConnectionError("no connection"))
        )}):
            config = builder.build("Load data.csv to snowflake")
        self.assertEqual(config["source_type"], "csv")
        self.assertEqual(config["destination_type"], "snowflake")

    def test_source_path_extracted_from_quotes(self):
        builder = NLPipelineBuilder(self.gov)
        config = builder.build('Load "data/customers.csv" into PostgreSQL')
        self.assertEqual(config["source_path"], "data/customers.csv")


class TestReversibleLoader(unittest.TestCase):
    """ReversibleLoader snapshot, load, and rollback."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("reversible_test", log_dir=self.tmp)
        self.db_path = Path(self.tmp) / "test_rev"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_load_creates_snapshot_and_manifest(self):
        mock_loader = MagicMock()
        rl = ReversibleLoader(
            self.gov, mock_loader, db_type="sqlite",
            snapshot_dir=Path(self.tmp) / "snapshots",
        )

        from sqlalchemy import create_engine
        engine = create_engine(f"sqlite:///{self.db_path}.db")
        df_existing = pd.DataFrame({"name": ["alice", "bob"], "age": [30, 40]})
        with engine.begin() as conn:
            df_existing.to_sql("employees", conn, if_exists="replace", index=False)
        engine.dispose()

        df_new = pd.DataFrame({"name": ["charlie"], "age": [25]})
        cfg = {"db_name": str(self.db_path)}
        run_id = rl.load(df_new, cfg, "employees")

        self.assertIsNotNone(run_id)
        mock_loader.load.assert_called_once()
        snapshots = list((Path(self.tmp) / "snapshots").glob("*.parquet"))
        self.assertEqual(len(snapshots), 1)
        manifest = rl._manifest_records()
        self.assertEqual(len(manifest), 1)
        self.assertEqual(manifest[0]["rows_before"], 2)

    def test_rollback_restores_previous_state(self):
        mock_loader = MagicMock()
        rl = ReversibleLoader(
            self.gov, mock_loader, db_type="sqlite",
            snapshot_dir=Path(self.tmp) / "snapshots",
        )

        from sqlalchemy import create_engine
        engine = create_engine(f"sqlite:///{self.db_path}.db")
        df_original = pd.DataFrame({"val": [1, 2, 3]})
        with engine.begin() as conn:
            df_original.to_sql("data", conn, if_exists="replace", index=False)
        engine.dispose()

        cfg = {"db_name": str(self.db_path)}
        df_new = pd.DataFrame({"val": [99]})
        run_id = rl.load(df_new, cfg, "data")

        rl.rollback("data", run_id, cfg)

        engine = create_engine(f"sqlite:///{self.db_path}.db")
        with engine.connect() as conn:
            restored = pd.read_sql_table("data", conn)
        engine.dispose()
        self.assertEqual(len(restored), 3)

    def test_snapshot_history_returns_entries(self):
        mock_loader = MagicMock()
        rl = ReversibleLoader(
            self.gov, mock_loader, db_type="sqlite",
            snapshot_dir=Path(self.tmp) / "snapshots",
        )
        rl._manifest_append({"run_id": "r1", "table": "t1", "rows_before": 10})
        rl._manifest_append({"run_id": "r2", "table": "t2", "rows_before": 20})
        history = rl.snapshot_history("t1")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["run_id"], "r1")


class TestTableCopier(unittest.TestCase):
    """TableCopier cross-database table copy."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("copier_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_copy_between_sqlite_databases(self):
        from sqlalchemy import create_engine

        src_path = Path(self.tmp) / "src"
        dst_path = Path(self.tmp) / "dst"
        src_engine = create_engine(f"sqlite:///{src_path}.db")
        df = pd.DataFrame({"x": [1, 2, 3], "y": ["a", "b", "c"]})
        with src_engine.begin() as conn:
            df.to_sql("source_table", conn, if_exists="replace", index=False)
        src_engine.dispose()

        copier = TableCopier(self.gov)
        rows = copier.copy(
            src_cfg={"db_name": str(src_path)},
            src_table="source_table",
            dst_cfg={"db_name": str(dst_path)},
            dst_table="dest_table",
            dst_type="sqlite",
        )
        self.assertEqual(rows, 3)

        dst_engine = create_engine(f"sqlite:///{dst_path}.db")
        with dst_engine.connect() as conn:
            result = pd.read_sql_table("dest_table", conn)
        dst_engine.dispose()
        self.assertEqual(len(result), 3)

    def test_dry_run_does_not_write(self):
        from sqlalchemy import create_engine

        src_path = Path(self.tmp) / "dryrun_src"
        dst_path = Path(self.tmp) / "dryrun_dst"
        src_engine = create_engine(f"sqlite:///{src_path}.db")
        df = pd.DataFrame({"col": [10, 20]})
        with src_engine.begin() as conn:
            df.to_sql("t", conn, if_exists="replace", index=False)
        src_engine.dispose()

        copier = TableCopier(self.gov, dry_run=True)
        rows = copier.copy(
            src_cfg={"db_name": str(src_path)},
            src_table="t",
            dst_cfg={"db_name": str(dst_path)},
            dst_table="t_copy",
            dst_type="sqlite",
        )
        self.assertEqual(rows, 2)
        self.assertFalse(Path(f"{dst_path}.db").exists())


class TestDLQReplayer(unittest.TestCase):
    """DLQReplayer file discovery, replay, and archival."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("dlq_test", log_dir=self.tmp)
        self.dlq_dir = Path(self.tmp) / "dlq"
        self.dlq_dir.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_dlq(self, filename: str, rows: list[dict]) -> Path:
        df = pd.DataFrame(rows)
        path = self.dlq_dir / filename
        df.to_csv(path, index=False, encoding="utf-8")
        return path

    def test_list_dlq_files(self):
        self._write_dlq("batch_001.csv", [{"a": 1}])
        self._write_dlq("batch_002.csv", [{"a": 2}])
        replayer = DLQReplayer(self.gov, dlq_dir=self.dlq_dir)
        files = replayer.list_dlq_files()
        self.assertEqual(len(files), 2)

    def test_replay_without_loader_does_not_archive(self):
        # Bug fix: with no loader nothing is re-loaded, so archiving would
        # orphan the rejected rows. The file must be LEFT in place and the
        # honest replayed-row count is 0.
        self._write_dlq("dlq_001.csv", [
            {"name": "alice", "age": 30, "_dlq_reason": "null_pk", "_dlq_pipeline_id": "p1"},
        ])
        replayer = DLQReplayer(self.gov, dlq_dir=self.dlq_dir)
        rows = replayer.replay(self.dlq_dir / "dlq_001.csv")
        self.assertEqual(rows, 0)
        self.assertTrue((self.dlq_dir / "dlq_001.csv").exists())

    def test_replay_with_loader_archives_after_load(self):
        # With a real loader the rows are re-loaded, so archiving is safe and
        # the file is renamed away (no un-replayed .csv remains).
        self._write_dlq("dlq_001b.csv", [
            {"name": "bob", "age": 41, "_dlq_reason": "null_pk", "_dlq_pipeline_id": "p2"},
        ])
        mock_loader = MagicMock()
        replayer = DLQReplayer(self.gov, dlq_dir=self.dlq_dir)
        rows = replayer.replay(
            self.dlq_dir / "dlq_001b.csv",
            loader=mock_loader, cfg={"path": "/tmp/x"}, table="t",
        )
        self.assertEqual(rows, 1)
        mock_loader.load.assert_called_once()
        self.assertFalse((self.dlq_dir / "dlq_001b.csv").exists())
        archived = list(self.dlq_dir.glob("dlq_001b.replayed_*.csv"))
        self.assertEqual(len(archived), 1)

    def test_replay_all_without_loader_leaves_files(self):
        # The CLI replay-dlq path calls replay_all() with no loader; it must
        # not orphan files or report them as replayed.
        self._write_dlq("dlq_a.csv", [{"x": 1, "_dlq_reason": "r"}])
        self._write_dlq("dlq_b.csv", [{"x": 2, "_dlq_reason": "r"}])
        replayer = DLQReplayer(self.gov, dlq_dir=self.dlq_dir)
        summary = replayer.replay_all()
        self.assertEqual(summary["files_replayed"], 0)
        self.assertEqual(summary["total_rows"], 0)
        self.assertTrue((self.dlq_dir / "dlq_a.csv").exists())
        self.assertTrue((self.dlq_dir / "dlq_b.csv").exists())

    def test_replay_with_transformer(self):
        self._write_dlq("dlq_002.csv", [{"val": 10}])
        mock_tx = MagicMock()
        mock_tx.transform.return_value = pd.DataFrame({"val": [10]})
        replayer = DLQReplayer(self.gov, dlq_dir=self.dlq_dir)
        rows = replayer.replay(
            self.dlq_dir / "dlq_002.csv", transformer=mock_tx,
        )
        # No loader supplied, so nothing was re-loaded: honest count is 0
        # and the transformer still ran.
        self.assertEqual(rows, 0)
        mock_tx.transform.assert_called_once()

    def test_dry_run_does_not_archive(self):
        self._write_dlq("dlq_003.csv", [{"x": 1}])
        replayer = DLQReplayer(self.gov, dlq_dir=self.dlq_dir, dry_run=True)
        replayer.replay(self.dlq_dir / "dlq_003.csv")
        self.assertTrue((self.dlq_dir / "dlq_003.csv").exists())

    def test_replay_missing_file_raises(self):
        replayer = DLQReplayer(self.gov, dlq_dir=self.dlq_dir)
        with self.assertRaises(FileNotFoundError):
            replayer.replay(self.dlq_dir / "nonexistent.csv")


if __name__ == "__main__":
    unittest.main()
