"""
Tests for the process watchdog supervisor.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import sys
import tempfile
import unittest
from unittest.mock import patch

from pipeline.watchdog import ProcessWatchdog


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
