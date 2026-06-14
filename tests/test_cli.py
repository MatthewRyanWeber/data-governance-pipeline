"""
Tests for pipeline.cli — argument parsing, subcommand dispatch, and error paths.

Revision history
----------------
1.0   2026-06-08   Initial release: 15 tests across 3 test classes.
1.1   2026-06-11   Regression test: resumed runs carry the previously-loaded
                   row total forward so --verify compares cumulative counts.
"""

import argparse
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.cli import (
    _build_parser,
    _cmd_profile,
    _cmd_validate,
    _load_config,
    _run_chunked,
    _run_single_file,
    main,
)


class TestArgParsing(unittest.TestCase):
    """Validates argument parsing for every subcommand."""

    def setUp(self):
        self.parser = _build_parser()

    def test_run_defaults(self):
        args = self.parser.parse_args(["run", "data.csv", "postgresql"])
        self.assertEqual(args.command, "run")
        self.assertEqual(args.source, "data.csv")
        self.assertEqual(args.destination, "postgresql")
        self.assertFalse(args.dry_run)
        self.assertFalse(args.skip_pii)
        self.assertEqual(args.table, "pipeline_output")
        self.assertEqual(args.chunk_size, 50_000)
        self.assertEqual(args.sla, 0)
        # Reconciliation is on by default — a partial load must not slip by silently.
        self.assertTrue(args.verify)

    def test_no_verify_flag_opts_out(self):
        args = self.parser.parse_args(["run", "data.csv", "postgresql", "--no-verify"])
        self.assertFalse(args.verify)

    def test_run_all_flags(self):
        args = self.parser.parse_args([
            "run", "data.csv", "snowflake",
            "--dry-run", "--skip-pii", "--skip-quality", "--parallel",
            "--table", "users", "--sla", "300", "--verify",
            "--chunk-size", "10000",
            "--config", "cfg.json",
            "--transform-config", "transforms.yaml",
        ])
        self.assertTrue(args.dry_run)
        self.assertTrue(args.skip_pii)
        self.assertTrue(args.skip_quality)
        self.assertTrue(args.parallel)
        self.assertEqual(args.table, "users")
        self.assertEqual(args.sla, 300)
        self.assertTrue(args.verify)
        self.assertEqual(args.chunk_size, 10000)
        self.assertEqual(args.config_path, "cfg.json")
        self.assertEqual(args.transform_config, "transforms.yaml")

    def test_validate_requires_schema_flag(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["validate", "data.csv"])

    def test_validate_parses_source_and_schema(self):
        args = self.parser.parse_args(["validate", "data.csv", "--schema", "s.json"])
        self.assertEqual(args.command, "validate")
        self.assertEqual(args.source, "data.csv")
        self.assertEqual(args.schema, "s.json")

    def test_profile_parses_source(self):
        args = self.parser.parse_args(["profile", "data.csv"])
        self.assertEqual(args.command, "profile")
        self.assertEqual(args.source, "data.csv")

    def test_resume_takes_no_positional_args(self):
        args = self.parser.parse_args(["resume"])
        self.assertEqual(args.command, "resume")

    def test_service_rejects_invalid_action(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["service", "bogus"])

    def test_no_command_yields_none(self):
        args = self.parser.parse_args([])
        self.assertIsNone(args.command)

    def test_version_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            self.parser.parse_args(["--version"])
        self.assertEqual(cm.exception.code, 0)


class TestLoadConfig(unittest.TestCase):
    """Validates config file loading and error paths."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_none_returns_empty_dict(self):
        self.assertEqual(_load_config(None), {})

    def test_json_config_loads(self):
        cfg_path = os.path.join(self.tmpdir, "config.json")
        data = {"host": "localhost", "contact": "alice@example.com"}
        Path(cfg_path).write_text(json.dumps(data), encoding="utf-8")
        result = _load_config(cfg_path)
        self.assertEqual(result["host"], "localhost")
        self.assertEqual(result["contact"], "alice@example.com")

    def test_missing_file_exits_1(self):
        with self.assertRaises(SystemExit) as cm:
            _load_config(os.path.join(self.tmpdir, "nope.json"))
        self.assertEqual(cm.exception.code, 1)


class TestSubcommandHandlers(unittest.TestCase):
    """Tests for _cmd_validate, _cmd_profile, main dispatch, and error flow."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("pipeline.logging_setup.setup_logging")
    def test_main_no_command_exits_zero(self, _):
        with self.assertRaises(SystemExit) as cm:
            main([])
        self.assertEqual(cm.exception.code, 0)

    @patch("pipeline.logging_setup.setup_logging")
    def test_main_handler_exception_exits_one(self, _):
        failing = MagicMock(side_effect=RuntimeError("synthetic"))
        ns = argparse.Namespace(command="explode")
        with patch("pipeline.cli._build_parser") as mock_bp:
            mock_bp.return_value.parse_args.return_value = ns
            with patch("pipeline.cli._COMMAND_DISPATCH", {"explode": failing}):
                with self.assertRaises(SystemExit) as cm:
                    main(["explode"])
                self.assertEqual(cm.exception.code, 1)

    def test_destinations_lists_all_tiers(self):
        import contextlib
        import io
        from pipeline.cli import _cmd_destinations
        from pipeline.loaders import _LAZY_DISPATCH

        buffer = io.StringIO()
        ns = argparse.Namespace(tier=None)
        with contextlib.redirect_stdout(buffer):
            _cmd_destinations(ns)
        output = buffer.getvalue()
        self.assertIn("CORE", output)
        self.assertIn("EMULATOR-VERIFIED", output)
        self.assertIn("CLOUD-CREDENTIAL", output)
        self.assertIn(f"{len(_LAZY_DISPATCH)} destination(s)", output)

    def test_destinations_tier_filter(self):
        import contextlib
        import io
        from pipeline.cli import _cmd_destinations

        buffer = io.StringIO()
        ns = argparse.Namespace(tier="cloud")
        with contextlib.redirect_stdout(buffer):
            _cmd_destinations(ns)
        output = buffer.getvalue()
        self.assertIn("CLOUD-CREDENTIAL", output)
        self.assertNotIn("EMULATOR-VERIFIED", output)
        self.assertIn("redshift", output)

    @patch("pipeline.logging_setup.setup_logging")
    def test_main_run_checks_crash_recovery(self, _):
        mock_crm = MagicMock()
        mock_crm.check_incomplete_runs.return_value = []
        mock_handler = MagicMock()
        with patch("pipeline.crash_recovery.CrashRecoveryManager", return_value=mock_crm):
            with patch.dict("pipeline.cli._COMMAND_DISPATCH", {"run": mock_handler}):
                main(["run", "data.csv", "postgresql"])
        mock_crm.check_incomplete_runs.assert_called_once()
        mock_handler.assert_called_once()

    @patch("pipeline.cli.Extractor", create=True)
    @patch("pipeline.cli.SchemaValidator", create=True)
    @patch("pipeline.cli.GovernanceLogger", create=True)
    def test_cmd_validate_with_synthetic_schema(self, mock_gov_cls, mock_sv_cls, mock_ext_cls):
        schema_path = os.path.join(self.tmpdir, "schema.json")
        schema = {
            "columns": {
                "name": {"type": "string"},
                "email": {"type": "string"},
                "phone": {"type": "string"},
            }
        }
        Path(schema_path).write_text(json.dumps(schema), encoding="utf-8")

        df = pd.DataFrame({
            "name": ["Alice Test"],
            "email": ["alice@example.com"],
            "phone": ["555-0101"],
        })
        mock_ext_cls.return_value.extract.return_value = df
        mock_sv_cls.return_value.validate.return_value = {"valid": True, "errors": []}

        ns = argparse.Namespace(source="data.csv", schema=schema_path)

        with patch("pipeline.cli.GovernanceLogger", mock_gov_cls), \
             patch("pipeline.cli.SchemaValidator", mock_sv_cls), \
             patch("pipeline.cli.Extractor", mock_ext_cls):
            # _cmd_validate uses late imports; patch at the module where they resolve
            with patch("pipeline.governance_logger.GovernanceLogger", mock_gov_cls), \
                 patch("pipeline.schema_validator.SchemaValidator", mock_sv_cls), \
                 patch("pipeline.extract.Extractor", mock_ext_cls):
                _cmd_validate(ns)

        mock_ext_cls.return_value.extract.assert_called_once_with("data.csv")
        mock_sv_cls.return_value.validate.assert_called_once()
        validated_df = mock_sv_cls.return_value.validate.call_args[0][0]
        self.assertEqual(list(validated_df.columns), ["name", "email", "phone"])

    @patch("pipeline.profiler.DataProfiler")
    @patch("pipeline.extract.Extractor")
    @patch("pipeline.governance_logger.GovernanceLogger")
    def test_cmd_profile_returns_report(self, mock_gov_cls, mock_ext_cls, mock_prof_cls):
        df = pd.DataFrame({
            "name": ["Alice Test", "Bob Test"],
            "email": ["alice@example.com", "bob@example.com"],
            "phone": ["555-0101", "555-0102"],
        })
        mock_ext_cls.return_value.extract.return_value = df
        mock_prof_cls.return_value.profile.return_value = {
            "table": {"row_count": 2, "column_count": 3},
            "columns": {},
        }

        ns = argparse.Namespace(source="data.csv")
        _cmd_profile(ns)

        mock_ext_cls.return_value.extract.assert_called_once_with("data.csv")
        mock_prof_cls.return_value.profile.assert_called_once()
        profiled_df = mock_prof_cls.return_value.profile.call_args[0][0]
        self.assertEqual(len(profiled_df), 2)

    @patch("pipeline.cli._run_chunked")
    @patch("pipeline.run_state.RunStateManager")
    def test_run_single_file_calls_chunked_and_marks_complete(self, mock_rsm_cls, mock_chunked):
        mock_rsm = MagicMock()
        mock_rsm_cls.return_value = mock_rsm

        gov = MagicMock()
        gov.run_context.pipeline_id = "test-abc-123"
        metrics = MagicMock()

        ns = argparse.Namespace(
            source="data.csv",
            destination="postgresql",
            table="pipeline_output",
            config_path="",
            dry_run=False,
            skip_pii=False,
            skip_quality=False,
            verify=False,
            transform_config=None,
            chunk_size=50_000,
        )

        _run_single_file("data.csv", ns, {}, gov, metrics)

        mock_rsm.save_start.assert_called_once()
        mock_chunked.assert_called_once()
        # run_id is now per-source (pipeline_id + source hash) so parallel
        # files don't collide on one run-state file.
        mock_rsm.mark_complete.assert_called_once()
        completed_id = mock_rsm.mark_complete.call_args[0][0]
        self.assertTrue(completed_id.startswith("test-abc-123_"))


class TestResumeCarriesRowTotal(unittest.TestCase):
    """Regression: on resume, total_rows restarted at 0 so the --verify
    row-count comparison falsely failed."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        import pipeline.run_state as run_state_module
        self._original_checkpoint_file = run_state_module.CHECKPOINT_FILE
        run_state_module.CHECKPOINT_FILE = Path(self.tmpdir) / "checkpoint.json"

    def tearDown(self):
        import pipeline.run_state as run_state_module
        run_state_module.CHECKPOINT_FILE = self._original_checkpoint_file
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("pipeline.load_verifier.LoadVerifier")
    @patch("pipeline.extract.Extractor")
    @patch("pipeline.cli._make_loader")
    @patch("pipeline.cli._transform_chunk", side_effect=lambda chunk, *a, **kw: chunk)
    def test_verify_sees_cumulative_rows_after_resume(
        self, mock_transform, mock_make_loader, mock_extractor_cls, mock_verifier_cls,
    ):
        from pipeline.run_state import RunStateManager

        gov = MagicMock()
        metrics = MagicMock()
        state_manager = RunStateManager(state_dir=Path(self.tmpdir) / "run_state")

        # Simulate a prior crashed run that loaded chunk 0 with 100 rows.
        state_manager.save_checkpoint(gov, "data.csv", "events", chunk_idx=0, rows=100)

        chunk_one = pd.DataFrame({"a": range(100)})
        chunk_two = pd.DataFrame({"a": range(100)})
        mock_extractor_cls.return_value.chunks.return_value = iter(
            [chunk_one, chunk_two]
        )
        # _make_loader now returns (loader, uses_mongo)
        mock_make_loader.return_value = (MagicMock(), False)
        mock_verifier = mock_verifier_cls.return_value
        mock_verifier.verify_row_count.return_value = {"match": True}

        args = argparse.Namespace(
            source="data.csv",
            destination="postgresql",
            table="events",
            config_path="",
            dry_run=False,
            skip_pii=True,
            verify=True,
            transform_config=None,
            chunk_size=100,
        )

        _run_chunked(
            "data.csv", args, {}, gov, metrics,
            state_manager=state_manager,
        )

        mock_verifier.verify_row_count.assert_called_once()
        verified_df = mock_verifier.verify_row_count.call_args[0][0]
        # Chunk 0 (100 rows, pre-crash) is skipped on resume; chunk 1 adds
        # 100 more. The verify comparison must see 200, not 100.
        self.assertEqual(len(verified_df), 200)


class TestUpsertCapabilityGuard(unittest.TestCase):
    """natural_keys against an append-only destination must fail fast with a
    clear message, not crash mid-first-chunk."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        import pipeline.run_state as run_state_module
        self._orig = run_state_module.CHECKPOINT_FILE
        run_state_module.CHECKPOINT_FILE = Path(self.tmpdir) / "checkpoint.json"

    def tearDown(self):
        import pipeline.run_state as run_state_module
        run_state_module.CHECKPOINT_FILE = self._orig
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("pipeline.cli._make_loader")
    def test_natural_keys_on_append_only_destination_fails_fast(self, mock_make_loader):
        from pipeline.run_state import RunStateManager
        loader = MagicMock()
        loader.SUPPORTS_UPSERT = False
        mock_make_loader.return_value = (loader, False)
        state_manager = RunStateManager(state_dir=Path(self.tmpdir) / "run_state")
        args = argparse.Namespace(
            source="data.parquet", destination="parquet", table="t",
            config_path="", dry_run=False, skip_pii=True, verify=False,
            transform_config=None, chunk_size=100,
        )
        with self.assertRaises(ValueError) as ctx:
            _run_chunked(
                "data.parquet", args, {"natural_keys": ["id"]},
                MagicMock(), MagicMock(), state_manager=state_manager,
            )
        self.assertIn("append-only", str(ctx.exception))


class TestChunkLoadHonorsUpsertKeys(unittest.TestCase):
    """Each chunk must load with the configured if_exists/natural_keys so a
    crash-resume re-run of a chunk is idempotent (exactly-once), not a
    duplicate append."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("pipeline.extract.Extractor")
    @patch("pipeline.cli._make_loader")
    @patch("pipeline.cli._transform_chunk", side_effect=lambda chunk, *a, **kw: chunk)
    def test_natural_keys_become_per_chunk_upsert(
        self, mock_transform, mock_make_loader, mock_extractor_cls,
    ):
        from pipeline.run_state import RunStateManager

        gov = MagicMock()
        metrics = MagicMock()
        state_manager = RunStateManager(state_dir=Path(self.tmpdir) / "rs")

        loader = MagicMock()
        mock_make_loader.return_value = (loader, False)
        mock_extractor_cls.return_value.chunks.return_value = iter(
            [pd.DataFrame({"id": range(10)})]
        )

        args = argparse.Namespace(
            source="data.csv", destination="postgresql", table="events",
            config_path="", dry_run=False, skip_pii=True, verify=False,
            transform_config=None, chunk_size=10,
        )
        config = {"natural_keys": ["id"]}

        _run_chunked("data.csv", args, config, gov, metrics,
                     state_manager=state_manager)

        # The chunk load was issued as an idempotent upsert keyed on id.
        loader.load.assert_called_once()
        _, kwargs = loader.load.call_args
        self.assertEqual(kwargs.get("if_exists"), "upsert")
        self.assertEqual(kwargs.get("natural_keys"), ["id"])


if __name__ == "__main__":
    unittest.main()
