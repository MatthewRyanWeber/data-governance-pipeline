"""
Process watchdog — monitors and restarts the pipeline on unexpected exit.

A lightweight supervisor that spawns the pipeline as a child process and
restarts it if it dies with a non-zero exit code. Uses exponential backoff
to avoid restart storms.

Layer 6 — standalone supervisor, no internal imports at module level.

Usage
─────
    # Watch a scheduled pipeline:
    python -m pipeline.watchdog schedule data.csv postgresql --cron "*/5 * * * *"

    # Watch a one-shot run:
    python -m pipeline.watchdog run data.csv postgresql --table customers

    # Set max restarts:
    python -m pipeline.watchdog --max-restarts 10 run data.csv snowflake

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-11   Treat the Windows Ctrl+C exit status (0xC000013A) as a clean
                   stop; reset the restart counter after healthy uptime; relay
                   child stdout on a daemon thread so a reader exception cannot
                   deadlock wait() on a full pipe.
"""

import json
import logging
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_RESTART_LOG = Path(__file__).resolve().parent.parent / "config" / "watchdog_restarts.jsonl"

# A Ctrl+C child exits 130 on POSIX but STATUS_CONTROL_C_EXIT on Windows.
_POSIX_CTRL_C_EXIT_CODE = 130
_WINDOWS_CTRL_C_EXIT_CODE = 0xC000013A  # 3221225786


class ProcessWatchdog:
    """
    Monitors a child process and restarts it on unexpected exit.

    Quick-start
    -----------
        from pipeline.watchdog import ProcessWatchdog
        wd = ProcessWatchdog(
            command=[sys.executable, "-m", "pipeline.cli", "run", "data.csv", "postgresql"],
            max_restarts=20,
        )
        wd.watch()  # blocks until max_restarts exceeded or clean exit
    """

    def __init__(
        self,
        command: list[str],
        max_restarts: int = 20,
        initial_delay: float = 5.0,
        max_delay: float = 300.0,
        backoff_factor: float = 2.0,
        reset_after: float = 600.0,
    ) -> None:
        self.command = command
        self.max_restarts = max_restarts
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.reset_after = reset_after

        self._restart_count = 0
        self._current_delay = initial_delay
        self._last_start: float = 0
        self._process: subprocess.Popen | None = None

    def _log_restart(self, exit_code: int, reason: str) -> None:
        """Append a restart event to the watchdog log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "restart_count": self._restart_count,
            "exit_code": exit_code,
            "reason": reason,
            "command": " ".join(self.command),
            "delay_seconds": self._current_delay,
        }
        _RESTART_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(_RESTART_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        logger.warning(
            "[WATCHDOG] Restart #%d (exit_code=%d, reason=%s, delay=%.1fs)",
            self._restart_count, exit_code, reason, self._current_delay,
        )

    def _spawn(self) -> subprocess.Popen:
        """Start the child process."""
        logger.info("[WATCHDOG] Starting: %s", " ".join(self.command))
        self._last_start = time.monotonic()
        return subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            # errors="replace" so undecodable child output cannot crash the
            # relay thread and leave the pipe full.
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

    @staticmethod
    def _relay_child_output(process: subprocess.Popen) -> threading.Thread:
        """Relay child stdout on a daemon thread.

        Reading on the watch thread meant a reader exception stopped draining
        the pipe; once full, the child blocked on write and wait() deadlocked.
        On a daemon thread the pipe keeps draining and wait() always returns.
        """
        def _pump() -> None:
            try:
                for line in process.stdout:  # type: ignore[union-attr]
                    sys.stdout.write(line)
                    sys.stdout.flush()
            except Exception as exc:
                logger.warning("[WATCHDOG] Error relaying child stdout: %s", exc)
                try:
                    # Keep draining (discarding) so the child can never block
                    # on a full pipe even after a relay failure.
                    while process.stdout.read(65_536):  # type: ignore[union-attr]
                        pass
                except Exception as drain_exc:
                    logger.warning(
                        "[WATCHDOG] Could not drain child stdout: %s", drain_exc,
                    )

        pump_thread = threading.Thread(
            target=_pump, daemon=True, name="watchdog-stdout-relay",
        )
        pump_thread.start()
        return pump_thread

    def watch(self) -> int:
        """
        Monitor the child process in a restart loop.

        Returns the final exit code. Blocks until:
        - Child exits cleanly (code 0)
        - Max restarts exceeded
        - KeyboardInterrupt received
        """
        logger.info(
            "[WATCHDOG] Monitoring command with max_restarts=%d",
            self.max_restarts,
        )

        while True:
            self._process = self._spawn()

            relay_thread = self._relay_child_output(self._process)
            exit_code = self._process.wait()
            relay_thread.join(timeout=5)
            uptime = time.monotonic() - self._last_start

            if exit_code == 0:
                logger.info("[WATCHDOG] Process exited cleanly (code 0).")
                return 0

            if exit_code in (_POSIX_CTRL_C_EXIT_CODE, _WINDOWS_CTRL_C_EXIT_CODE):
                logger.info("[WATCHDOG] Process interrupted (Ctrl+C) — not restarting.")
                return _POSIX_CTRL_C_EXIT_CODE

            # Reset backoff and the restart budget after healthy uptime — a
            # service that ran fine for a long stretch should not be a few
            # failures away from the watchdog giving up forever.
            if uptime > self.reset_after:
                self._current_delay = self.initial_delay
                self._restart_count = 0
                logger.info(
                    "[WATCHDOG] Process ran %.0fs before failing — resetting "
                    "backoff and restart count.",
                    uptime,
                )

            self._restart_count += 1
            self._log_restart(exit_code, f"unexpected exit after {uptime:.1f}s")

            if self._restart_count > self.max_restarts:
                logger.error(
                    "[WATCHDOG] Max restarts (%d) exceeded — giving up.",
                    self.max_restarts,
                )
                return exit_code

            logger.info(
                "[WATCHDOG] Waiting %.1fs before restart %d/%d…",
                self._current_delay, self._restart_count, self.max_restarts,
            )
            time.sleep(self._current_delay)
            self._current_delay = min(
                self._current_delay * self.backoff_factor,
                self.max_delay,
            )

    def stop(self) -> None:
        """Terminate the child process if running."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
            logger.info("[WATCHDOG] Child process terminated.")


def main():
    """CLI entry point for the watchdog."""
    from pipeline.logging_setup import setup_logging
    setup_logging()

    args = sys.argv[1:]

    max_restarts = 20
    if "--max-restarts" in args:
        idx = args.index("--max-restarts")
        max_restarts = int(args[idx + 1])
        args = args[:idx] + args[idx + 2:]

    if not args:
        print("Usage: python -m pipeline.watchdog [--max-restarts N] <pipeline args...>")
        print("Example: python -m pipeline.watchdog run data.csv postgresql --table customers")
        sys.exit(1)

    command = [sys.executable, "-m", "pipeline.cli"] + args

    watchdog = ProcessWatchdog(command=command, max_restarts=max_restarts)

    try:
        exit_code = watchdog.watch()
    except KeyboardInterrupt:
        print("\n[WATCHDOG] Interrupted — stopping child process.")
        watchdog.stop()
        exit_code = 130

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
