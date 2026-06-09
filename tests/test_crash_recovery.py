"""
Tests for crash recovery and resilience modules:
run_state, crash_recovery, watchdog, and checkpoint.

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from pipeline.run_state import RunState, RunStateManager
from pipeline.crash_recovery import CrashRecoveryManager
from pipeline.watchdog import ProcessWatchdog
from pipeline.checkpoint import CheckpointManager


class MockGov:
    def __getattr__(self, name):
        return lambda *a, **kw: None

    class run_context:
        pipeline_id = "test-run-id"


# ── RunStateManager tests ──────────────────────────────────────────────────


class TestRunStateSaveStart(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.mgr = RunStateManager(state_dir=self.state_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_save_start_creates_file(self):
        state = RunState(
            run_id="run-001",
            source="data.csv",
            destination="postgresql",
            table="customers",
        )
        self.mgr.save_start(state)
        path = self.state_dir / "run-001.json"
        self.assertTrue(path.exists())
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["run_id"], "run-001")
        self.assertEqual(data["status"], "running")


class TestRunStateReadBack(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.mgr = RunStateManager(state_dir=self.state_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_read_back_state(self):
        state = RunState(
            run_id="run-002",
            source="orders.csv",
            destination="snowflake",
            table="orders",
            config_path="/etc/pipeline.yaml",
            args_json='{"dry_run": true}',
        )
        self.mgr.save_start(state)
        read_back = self.mgr._read("run-002")
        self.assertIsNotNone(read_back)
        self.assertEqual(read_back.run_id, "run-002")
        self.assertEqual(read_back.source, "orders.csv")
        self.assertEqual(read_back.destination, "snowflake")
        self.assertEqual(read_back.table, "orders")
        self.assertEqual(read_back.config_path, "/etc/pipeline.yaml")
        self.assertEqual(read_back.status, "running")
        self.assertEqual(read_back.last_chunk_completed, -1)
        self.assertEqual(read_back.total_rows_processed, 0)
        self.assertEqual(read_back.args_json, '{"dry_run": true}')
        self.assertEqual(read_back.error_message, "")


class TestRunStateUpdateChunk(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.mgr = RunStateManager(state_dir=self.state_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_update_chunk_updates_progress(self):
        state = RunState(
            run_id="run-003",
            source="data.csv",
            destination="postgresql",
            table="events",
        )
        self.mgr.save_start(state)
        self.mgr.update_chunk("run-003", chunk_idx=5, rows_so_far=5000)
        updated = self.mgr._read("run-003")
        self.assertEqual(updated.last_chunk_completed, 5)
        self.assertEqual(updated.total_rows_processed, 5000)


class TestRunStateMarkComplete(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.mgr = RunStateManager(state_dir=self.state_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_mark_complete(self):
        state = RunState(
            run_id="run-004",
            source="data.csv",
            destination="postgresql",
            table="events",
        )
        self.mgr.save_start(state)
        self.mgr.mark_complete("run-004")
        completed = self.mgr._read("run-004")
        self.assertEqual(completed.status, "completed")


class TestRunStateMarkFailed(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.mgr = RunStateManager(state_dir=self.state_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_mark_failed(self):
        state = RunState(
            run_id="run-005",
            source="data.csv",
            destination="postgresql",
            table="events",
        )
        self.mgr.save_start(state)
        self.mgr.mark_failed("run-005", "Connection reset by peer")
        failed = self.mgr._read("run-005")
        self.assertEqual(failed.status, "failed")
        self.assertEqual(failed.error_message, "Connection reset by peer")


class TestRunStateGetIncomplete(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.mgr = RunStateManager(state_dir=self.state_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_get_incomplete_runs(self):
        running = RunState(run_id="run-a", source="a.csv",
                           destination="pg", table="t1")
        complete = RunState(run_id="run-b", source="b.csv",
                            destination="pg", table="t2")
        failed = RunState(run_id="run-c", source="c.csv",
                          destination="pg", table="t3")

        self.mgr.save_start(running)
        self.mgr.save_start(complete)
        self.mgr.save_start(failed)

        self.mgr.mark_complete("run-b")
        self.mgr.mark_failed("run-c", "timeout")

        incomplete = self.mgr.get_incomplete_runs()
        self.assertEqual(len(incomplete), 1)
        self.assertEqual(incomplete[0].run_id, "run-a")
        self.assertEqual(incomplete[0].status, "running")

    def test_get_incomplete_runs_empty_dir(self):
        incomplete = self.mgr.get_incomplete_runs()
        self.assertEqual(incomplete, [])


class TestRunStateCleanup(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.mgr = RunStateManager(state_dir=self.state_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_cleanup_old_runs(self):
        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        state = RunState(
            run_id="run-old",
            source="data.csv",
            destination="postgresql",
            table="t",
            started_at=old_time,
        )
        self.mgr.save_start(state)
        self.mgr.mark_complete("run-old")

        removed = self.mgr.cleanup_old_runs(keep_days=7)
        self.assertEqual(removed, 1)
        self.assertIsNone(self.mgr._read("run-old"))

    def test_cleanup_preserves_recent(self):
        recent_time = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        state = RunState(
            run_id="run-recent",
            source="data.csv",
            destination="postgresql",
            table="t",
            started_at=recent_time,
        )
        self.mgr.save_start(state)
        self.mgr.mark_complete("run-recent")

        removed = self.mgr.cleanup_old_runs(keep_days=7)
        self.assertEqual(removed, 0)
        self.assertIsNotNone(self.mgr._read("run-recent"))


# ── CrashRecoveryManager tests ─────────────────────────────────────────────


class TestCrashRecoveryCheckIncomplete(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.state_mgr = RunStateManager(state_dir=self.state_dir)
        self.crm = CrashRecoveryManager(state_manager=self.state_mgr)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_check_incomplete_finds_running(self):
        state = RunState(
            run_id="crash-001",
            source="data.csv",
            destination="postgresql",
            table="events",
        )
        self.state_mgr.save_start(state)
        incomplete = self.crm.check_incomplete_runs()
        self.assertEqual(len(incomplete), 1)
        self.assertEqual(incomplete[0].run_id, "crash-001")

    def test_check_incomplete_ignores_complete(self):
        state = RunState(
            run_id="crash-002",
            source="data.csv",
            destination="postgresql",
            table="events",
        )
        self.state_mgr.save_start(state)
        self.state_mgr.mark_complete("crash-002")
        incomplete = self.crm.check_incomplete_runs()
        self.assertEqual(len(incomplete), 0)

    def test_no_incomplete_runs(self):
        incomplete = self.crm.check_incomplete_runs()
        self.assertEqual(len(incomplete), 0)


class TestCrashRecoveryResume(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = Path(self.tmp) / "run_state"
        self.state_mgr = RunStateManager(state_dir=self.state_dir)
        self.crm = CrashRecoveryManager(state_manager=self.state_mgr)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    @patch("pipeline.crash_recovery.CrashRecoveryManager.resume_run")
    def test_resume_run_calls_chunked(self, mock_resume):
        """Verify resume_run is invoked with the correct RunState."""
        mock_resume.return_value = True
        state = RunState(
            run_id="crash-003",
            source="data.csv",
            destination="postgresql",
            table="events",
            last_chunk_completed=4,
            total_rows_processed=4000,
        )
        self.state_mgr.save_start(state)
        incomplete = self.crm.check_incomplete_runs()
        self.crm.resume_run(incomplete[0])
        mock_resume.assert_called_once()
        call_arg = mock_resume.call_args[0][0]
        self.assertEqual(call_arg.run_id, "crash-003")
        self.assertEqual(call_arg.last_chunk_completed, 4)

    @patch("pipeline.cli._run_chunked")
    @patch("pipeline.crash_recovery.GovernanceLogger", create=True)
    @patch("pipeline.crash_recovery.MetricsCollector", create=True)
    @patch("pipeline.crash_recovery.RunContext", create=True)
    def test_resume_run_marks_complete(self, mock_ctx, mock_metrics,
                                       mock_gov_cls, mock_chunked):
        """After a successful resume, run state becomes 'complete'."""
        mock_chunked.return_value = None
        mock_gov_cls.return_value = MagicMock()
        mock_metrics.return_value = MagicMock()
        mock_ctx.return_value = MagicMock(pipeline_id="test-run-id")

        state = RunState(
            run_id="crash-004",
            source="data.csv",
            destination="postgresql",
            table="events",
            last_chunk_completed=2,
        )
        self.state_mgr.save_start(state)

        with patch.dict("sys.modules", {
            "pipeline.governance_logger": MagicMock(GovernanceLogger=mock_gov_cls),
            "pipeline.monitoring.metrics_collector": MagicMock(MetricsCollector=mock_metrics),
        }), patch("pipeline.constants.RunContext", mock_ctx):
            result = self.crm.resume_run(state)

        self.assertTrue(result)
        final = self.state_mgr._read("crash-004")
        self.assertEqual(final.status, "completed")

    @patch("pipeline.cli._run_chunked", side_effect=RuntimeError("DB connection lost"))
    @patch("pipeline.crash_recovery.GovernanceLogger", create=True)
    @patch("pipeline.crash_recovery.MetricsCollector", create=True)
    @patch("pipeline.crash_recovery.RunContext", create=True)
    def test_resume_run_marks_failed_on_error(self, mock_ctx, mock_metrics,
                                               mock_gov_cls, mock_chunked):
        """If _run_chunked raises, run state becomes 'failed'."""
        mock_gov_cls.return_value = MagicMock()
        mock_metrics.return_value = MagicMock()
        mock_ctx.return_value = MagicMock(pipeline_id="test-run-id")

        state = RunState(
            run_id="crash-005",
            source="data.csv",
            destination="postgresql",
            table="events",
            last_chunk_completed=3,
        )
        self.state_mgr.save_start(state)

        with patch.dict("sys.modules", {
            "pipeline.governance_logger": MagicMock(GovernanceLogger=mock_gov_cls),
            "pipeline.monitoring.metrics_collector": MagicMock(MetricsCollector=mock_metrics),
        }), patch("pipeline.constants.RunContext", mock_ctx):
            result = self.crm.resume_run(state)

        self.assertFalse(result)
        final = self.state_mgr._read("crash-005")
        self.assertEqual(final.status, "failed")
        self.assertIn("DB connection lost", final.error_message)

    @patch("pipeline.cli._run_chunked")
    @patch("pipeline.crash_recovery.GovernanceLogger", create=True)
    @patch("pipeline.crash_recovery.MetricsCollector", create=True)
    @patch("pipeline.crash_recovery.RunContext", create=True)
    def test_auto_resume_all(self, mock_ctx, mock_metrics,
                              mock_gov_cls, mock_chunked):
        """Two incomplete runs both resume successfully, returns 2."""
        mock_chunked.return_value = None
        mock_gov_cls.return_value = MagicMock()
        mock_metrics.return_value = MagicMock()
        mock_ctx.return_value = MagicMock(pipeline_id="test-run-id")

        for rid in ("auto-001", "auto-002"):
            state = RunState(
                run_id=rid,
                source="data.csv",
                destination="postgresql",
                table="t",
                last_chunk_completed=0,
            )
            self.state_mgr.save_start(state)

        with patch.dict("sys.modules", {
            "pipeline.governance_logger": MagicMock(GovernanceLogger=mock_gov_cls),
            "pipeline.monitoring.metrics_collector": MagicMock(MetricsCollector=mock_metrics),
        }), patch("pipeline.constants.RunContext", mock_ctx):
            count = self.crm.auto_resume_all()

        self.assertEqual(count, 2)


# ── ProcessWatchdog tests ──────────────────────────────────────────────────


class _MockPopen:
    """Lightweight Popen stand-in for watchdog tests."""

    def __init__(self, exit_codes):
        self._exit_codes = list(exit_codes)
        self._call_idx = -1
        self.stdout = []
        self._exit_code = None

    def __call__(self, *args, **kwargs):
        self._call_idx += 1
        idx = min(self._call_idx, len(self._exit_codes) - 1)
        self._exit_code = self._exit_codes[idx]
        self.stdout = []
        return self

    def wait(self, timeout=None):
        return self._exit_code

    def poll(self):
        return self._exit_code

    def terminate(self):
        pass

    def kill(self):
        pass


class TestWatchdogCleanExit(unittest.TestCase):

    @patch("pipeline.watchdog.time.sleep")
    @patch("pipeline.watchdog.subprocess.Popen")
    def test_clean_exit_no_restart(self, mock_popen_cls, mock_sleep):
        proc = MagicMock()
        proc.stdout = []
        proc.wait.return_value = 0
        mock_popen_cls.return_value = proc

        wd = ProcessWatchdog(command=["echo", "hello"], max_restarts=3)
        exit_code = wd.watch()

        self.assertEqual(exit_code, 0)
        self.assertEqual(wd._restart_count, 0)
        mock_sleep.assert_not_called()


class TestWatchdogRestart(unittest.TestCase):

    @patch("pipeline.watchdog.time.sleep")
    @patch("pipeline.watchdog.subprocess.Popen")
    def test_restart_on_nonzero_exit(self, mock_popen_cls, mock_sleep):
        """Process exits 1 first, then 0. Should restart once."""
        proc_fail = MagicMock()
        proc_fail.stdout = []
        proc_fail.wait.return_value = 1

        proc_ok = MagicMock()
        proc_ok.stdout = []
        proc_ok.wait.return_value = 0

        mock_popen_cls.side_effect = [proc_fail, proc_ok]

        wd = ProcessWatchdog(
            command=["test"], max_restarts=5,
            initial_delay=0.01, reset_after=999999,
        )
        exit_code = wd.watch()

        self.assertEqual(exit_code, 0)
        self.assertEqual(wd._restart_count, 1)


class TestWatchdogMaxRestarts(unittest.TestCase):

    @patch("pipeline.watchdog.time.sleep")
    @patch("pipeline.watchdog.subprocess.Popen")
    def test_max_restarts_exceeded(self, mock_popen_cls, mock_sleep):
        """Always exits 1 — should stop after max_restarts."""
        proc = MagicMock()
        proc.stdout = []
        proc.wait.return_value = 1
        mock_popen_cls.return_value = proc

        wd = ProcessWatchdog(
            command=["test"], max_restarts=2,
            initial_delay=0.01, reset_after=999999,
        )
        exit_code = wd.watch()

        self.assertEqual(exit_code, 1)
        # restart_count should be 3: attempt 1 fails, restart 1 fails,
        # restart 2 fails, restart 3 would exceed max_restarts=2
        self.assertGreater(wd._restart_count, wd.max_restarts)


class TestWatchdogSigint(unittest.TestCase):

    @patch("pipeline.watchdog.time.sleep")
    @patch("pipeline.watchdog.subprocess.Popen")
    def test_no_restart_on_sigint(self, mock_popen_cls, mock_sleep):
        """Exit code 130 (Ctrl+C) should not trigger restart."""
        proc = MagicMock()
        proc.stdout = []
        proc.wait.return_value = 130
        mock_popen_cls.return_value = proc

        wd = ProcessWatchdog(command=["test"], max_restarts=5)
        exit_code = wd.watch()

        self.assertEqual(exit_code, 130)
        self.assertEqual(wd._restart_count, 0)
        mock_sleep.assert_not_called()


class TestWatchdogBackoff(unittest.TestCase):

    @patch("pipeline.watchdog.time.sleep")
    @patch("pipeline.watchdog.subprocess.Popen")
    def test_backoff_increases(self, mock_popen_cls, mock_sleep):
        """Delay should increase after each restart via backoff_factor."""
        proc = MagicMock()
        proc.stdout = []
        proc.wait.return_value = 1
        mock_popen_cls.return_value = proc

        wd = ProcessWatchdog(
            command=["test"], max_restarts=3,
            initial_delay=1.0, backoff_factor=2.0, max_delay=300.0,
            reset_after=999999,
        )
        wd.watch()

        # Collect the delay values passed to sleep
        delays = [call[0][0] for call in mock_sleep.call_args_list]
        # Each delay should be >= the previous one
        for i in range(1, len(delays)):
            self.assertGreaterEqual(delays[i], delays[i - 1])
        # First delay should be initial_delay
        self.assertAlmostEqual(delays[0], 1.0)

    @patch("pipeline.watchdog.time.sleep")
    @patch("pipeline.watchdog.time.monotonic")
    @patch("pipeline.watchdog.subprocess.Popen")
    def test_backoff_resets_after_long_run(self, mock_popen_cls,
                                            mock_monotonic, mock_sleep):
        """If process runs longer than reset_after, delay resets."""
        proc_long = MagicMock()
        proc_long.stdout = []
        proc_long.wait.return_value = 1

        proc_ok = MagicMock()
        proc_ok.stdout = []
        proc_ok.wait.return_value = 0

        mock_popen_cls.side_effect = [proc_long, proc_ok]

        # Simulate: first spawn at t=0, wait returns at t=700 (>reset_after=600)
        mock_monotonic.side_effect = [0.0, 700.0, 700.0, 700.0]

        wd = ProcessWatchdog(
            command=["test"], max_restarts=5,
            initial_delay=5.0, backoff_factor=2.0,
            reset_after=600.0,
        )
        # Inflate delay first so we can detect the reset
        wd._current_delay = 80.0

        wd.watch()

        # After the long-running fail, delay should have reset to initial
        # then been used for sleep, then multiplied by backoff
        if mock_sleep.call_args_list:
            first_sleep = mock_sleep.call_args_list[0][0][0]
            self.assertAlmostEqual(first_sleep, 5.0)


# ── Checkpoint tests (RunStateManager.{load,save,clear}_checkpoint) ────────


class TestCheckpointSaveAndLoad(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cp_file = Path(self.tmp) / "checkpoint.json"
        self.gov = MockGov()
        self.rsm = RunStateManager(state_dir=Path(self.tmp) / "run_state")
        # Point checkpoint methods at our temp file
        import pipeline.run_state as _mod
        self._orig_cp = _mod.CHECKPOINT_FILE
        _mod.CHECKPOINT_FILE = self.cp_file

    def tearDown(self):
        import pipeline.run_state as _mod
        _mod.CHECKPOINT_FILE = self._orig_cp
        shutil.rmtree(self.tmp)

    def test_save_and_load_checkpoint(self):
        self.rsm.save_checkpoint(self.gov, "data.csv", "customers", chunk_idx=5, rows=5000)
        loaded = self.rsm.load_checkpoint(self.gov, "data.csv", "customers")
        self.assertEqual(loaded, 5)

    def test_load_no_checkpoint_returns_negative_one(self):
        loaded = self.rsm.load_checkpoint(self.gov, "data.csv", "orders")
        self.assertEqual(loaded, -1)

    def test_clear_checkpoint(self):
        self.rsm.save_checkpoint(self.gov, "data.csv", "customers", chunk_idx=3, rows=3000)
        self.rsm.clear_checkpoint("data.csv", "customers")
        loaded = self.rsm.load_checkpoint(self.gov, "data.csv", "customers")
        self.assertEqual(loaded, -1)

    def test_multiple_sources(self):
        self.rsm.save_checkpoint(self.gov, "a.csv", "t1", chunk_idx=2, rows=2000)
        self.rsm.save_checkpoint(self.gov, "b.csv", "t2", chunk_idx=7, rows=7000)

        self.assertEqual(self.rsm.load_checkpoint(self.gov, "a.csv", "t1"), 2)
        self.assertEqual(self.rsm.load_checkpoint(self.gov, "b.csv", "t2"), 7)

    def test_backward_compat_shim(self):
        """CheckpointManager shim delegates to RunStateManager."""
        cp = CheckpointManager(self.gov)
        cp.save_checkpoint("x.csv", "t", chunk_idx=1, rows=100)
        self.assertEqual(cp.load_checkpoint("x.csv", "t"), 1)
        cp.clear_checkpoint("x.csv", "t")
        self.assertEqual(cp.load_checkpoint("x.csv", "t"), -1)


if __name__ == "__main__":
    unittest.main()
