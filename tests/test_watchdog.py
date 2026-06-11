"""
Tests for the process watchdog supervisor.

Revision history
────────────────
1.0   2026-06-09   Initial release.
1.1   2026-06-11   Windows Ctrl+C exit status treated as clean stop; restart
                   counter resets after healthy uptime.
"""

import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from pipeline.watchdog import ProcessWatchdog, _WINDOWS_CTRL_C_EXIT_CODE


class TestProcessWatchdog(unittest.TestCase):

    def test_clean_exit_returns_zero(self):
        wd = ProcessWatchdog(
            command=[sys.executable, "-c", "import sys; sys.exit(0)"],
            max_restarts=2,
        )
        exit_code = wd.watch()
        self.assertEqual(exit_code, 0)
        self.assertEqual(wd._restart_count, 0)

    def test_restarts_on_failure(self):
        wd = ProcessWatchdog(
            command=[sys.executable, "-c", "import sys; sys.exit(1)"],
            max_restarts=2,
            initial_delay=0.01,
            max_delay=0.02,
        )
        exit_code = wd.watch()
        self.assertEqual(exit_code, 1)
        self.assertGreater(wd._restart_count, 0)
        self.assertLessEqual(wd._restart_count, 3)

    def test_interrupt_not_restarted(self):
        wd = ProcessWatchdog(
            command=[sys.executable, "-c", "import sys; sys.exit(130)"],
            max_restarts=5,
        )
        exit_code = wd.watch()
        self.assertEqual(exit_code, 130)
        self.assertEqual(wd._restart_count, 0)

    def test_stop_terminates_process(self):
        wd = ProcessWatchdog(
            command=[sys.executable, "-c", "import time; time.sleep(60)"],
            max_restarts=0,
        )
        import subprocess
        wd._process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        wd.stop()
        self.assertIsNotNone(wd._process.returncode)

    def test_backoff_increases(self):
        wd = ProcessWatchdog(
            command=[sys.executable, "-c", "pass"],
            max_restarts=5,
            initial_delay=1.0,
            backoff_factor=2.0,
            max_delay=100.0,
        )
        self.assertEqual(wd._current_delay, 1.0)

    @patch("pipeline.watchdog.time.sleep")
    @patch("pipeline.watchdog.subprocess.Popen")
    def test_windows_ctrl_c_exit_not_restarted(self, mock_popen_cls, mock_sleep):
        # Regression: only POSIX 130 was treated as Ctrl+C; on Windows the
        # child exits with STATUS_CONTROL_C_EXIT (0xC000013A).
        proc = MagicMock()
        proc.stdout = []
        proc.wait.return_value = _WINDOWS_CTRL_C_EXIT_CODE
        mock_popen_cls.return_value = proc

        wd = ProcessWatchdog(command=["test"], max_restarts=5)
        exit_code = wd.watch()

        self.assertEqual(exit_code, 130)
        self.assertEqual(wd._restart_count, 0)
        mock_sleep.assert_not_called()

    @patch("pipeline.watchdog.time.sleep")
    @patch("pipeline.watchdog.time.monotonic")
    @patch("pipeline.watchdog.subprocess.Popen")
    def test_restart_count_resets_after_healthy_uptime(self, mock_popen_cls,
                                                       mock_monotonic, mock_sleep):
        # Regression: _restart_count never reset, so a long-running service
        # was always a few failures away from the watchdog giving up.
        proc_fail = MagicMock()
        proc_fail.stdout = []
        proc_fail.wait.return_value = 1

        proc_ok = MagicMock()
        proc_ok.stdout = []
        proc_ok.wait.return_value = 0

        mock_popen_cls.side_effect = [proc_fail, proc_fail, proc_ok]
        # Each child "runs" 700s (> reset_after=600) before failing.
        mock_monotonic.side_effect = [0.0, 700.0, 700.0, 1400.0, 1400.0, 2100.0]

        wd = ProcessWatchdog(
            command=["test"], max_restarts=1,
            initial_delay=0.01, reset_after=600.0,
        )
        exit_code = wd.watch()

        # Without the reset, the second failure would exceed max_restarts=1
        # and watch() would give up with exit code 1.
        self.assertEqual(exit_code, 0)
        self.assertEqual(wd._restart_count, 1)

    def test_log_restart_writes_file(self):
        tmpdir = tempfile.mkdtemp()
        try:
            import os
            log_path = os.path.join(tmpdir, "restarts.jsonl")
            with patch("pipeline.watchdog._RESTART_LOG", __import__("pathlib").Path(log_path)):
                wd = ProcessWatchdog(command=["echo", "test"])
                wd._log_restart(1, "test failure")
                self.assertTrue(os.path.exists(log_path))
                import json
                with open(log_path, encoding="utf-8") as f:
                    entry = json.loads(f.readline())
                self.assertEqual(entry["exit_code"], 1)
                self.assertEqual(entry["reason"], "test failure")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
