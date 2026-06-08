"""
Windows Service wrapper — runs the pipeline as an OS-level service.

Registers with the Windows Service Control Manager so the pipeline:
  1. Starts automatically on boot
  2. Restarts automatically after crash or power loss
  3. Can be managed via `sc`, `services.msc`, or `net start/stop`

Layer 6 — imports from everything.

Usage
─────
    # Install the service (run as Administrator):
    python -m pipeline.service install

    # Start:
    python -m pipeline.service start

    # Stop:
    python -m pipeline.service stop

    # Remove:
    python -m pipeline.service remove

    # Debug (runs in foreground):
    python -m pipeline.service debug

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

SERVICE_NAME = "DataGovernancePipeline"
SERVICE_DISPLAY = "Data Governance Pipeline"
SERVICE_DESCRIPTION = (
    "GDPR/CCPA-compliant ETL pipeline with full audit logging. "
    "Processes data on a cron schedule with automatic crash recovery."
)

_CONFIG_FILE = Path(__file__).resolve().parent.parent / "config" / "service_config.json"


def _load_service_config() -> dict:
    """Load service configuration from JSON file."""
    if not _CONFIG_FILE.exists():
        return {
            "mode": "schedule",
            "source": "",
            "destination": "",
            "table": "pipeline_output",
            "config_path": "",
            "cron": "0 * * * *",
            "auto_resume": True,
        }
    with open(_CONFIG_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_service_config(config: dict) -> None:
    """Write service configuration to disk."""
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    logger.info("[SERVICE] Config saved to %s", _CONFIG_FILE)


try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class PipelineWindowsService(win32serviceutil.ServiceFramework):
        """Windows Service that runs the pipeline on a schedule with crash recovery."""

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._running = True

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._running = False
            win32event.SetEvent(self._stop_event)
            logger.info("[SERVICE] Stop signal received.")

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self._main()

        def _main(self):
            from pipeline.logging_setup import setup_logging
            setup_logging()

            logger.info("[SERVICE] Data Governance Pipeline service started.")

            cfg = _load_service_config()

            if cfg.get("auto_resume", True):
                try:
                    from pipeline.crash_recovery import CrashRecoveryManager
                    crm = CrashRecoveryManager()
                    resumed = crm.auto_resume_all()
                    if resumed:
                        logger.info("[SERVICE] Resumed %d interrupted runs.", resumed)
                except Exception as exc:
                    logger.error("[SERVICE] Crash recovery failed: %s", exc)

            mode = cfg.get("mode", "schedule")

            if mode == "schedule" and cfg.get("source") and cfg.get("destination"):
                self._run_scheduled(cfg)
            else:
                logger.info("[SERVICE] No source/destination configured — idle mode.")
                while self._running:
                    rc = win32event.WaitForSingleObject(self._stop_event, 60_000)
                    if rc == win32event.WAIT_OBJECT_0:
                        break

            logger.info("[SERVICE] Service stopped.")

        def _run_scheduled(self, cfg):
            """Run the pipeline on a cron schedule."""
            import argparse
            from pipeline.scheduler import PipelineScheduler

            def _pipeline_run():
                try:
                    from pipeline.cli import _cmd_run
                    args = argparse.Namespace(
                        source=cfg["source"],
                        destination=cfg["destination"],
                        config_path=cfg.get("config_path", ""),
                        dry_run=False,
                        skip_pii=False,
                        skip_quality=False,
                        parallel=False,
                        table=cfg.get("table", "pipeline_output"),
                        sla=0,
                        verify=cfg.get("verify", False),
                        transform_config=cfg.get("transform_config"),
                    )
                    _cmd_run(args)
                except Exception as exc:
                    logger.error("[SERVICE] Scheduled run failed: %s", exc)

            scheduler = PipelineScheduler(
                pipeline_fn=_pipeline_run,
                cron_expr=cfg.get("cron", "0 * * * *"),
            )
            scheduler.start()

            while self._running:
                rc = win32event.WaitForSingleObject(self._stop_event, 5_000)
                if rc == win32event.WAIT_OBJECT_0:
                    break

            scheduler.stop()

    _HAS_WIN32 = True

except ImportError:
    _HAS_WIN32 = False


def configure_service_recovery():
    """Set the service to auto-restart on failure (requires sc.exe)."""
    import subprocess
    try:
        # restart after 10s on 1st failure, 30s on 2nd, 60s on subsequent
        subprocess.run(
            [
                "sc", "failure", SERVICE_NAME,
                "reset=", "86400",
                "actions=", "restart/10000/restart/30000/restart/60000",
            ],
            check=True,
            capture_output=True,
        )
        logger.info("[SERVICE] Recovery options configured: auto-restart on failure.")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        logger.warning("[SERVICE] Could not configure recovery: %s", exc)


def install_service():
    """Install and configure the Windows Service."""
    if not _HAS_WIN32:
        print("ERROR: pywin32 is required. Install with: pip install pywin32")
        sys.exit(1)

    win32serviceutil.InstallService(
        PipelineWindowsService._svc_reg_class_,
        SERVICE_NAME,
        SERVICE_DISPLAY,
        startType=win32service.SERVICE_AUTO_START,
        description=SERVICE_DESCRIPTION,
    )
    configure_service_recovery()
    print(f"Service '{SERVICE_NAME}' installed with auto-start and auto-recovery.")
    print(f"Configure via: {_CONFIG_FILE}")


def main():
    """Entry point for service management commands."""
    if not _HAS_WIN32:
        print("ERROR: pywin32 is required for Windows Service support.")
        print("Install with: pip install pywin32")
        sys.exit(1)

    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(PipelineWindowsService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(PipelineWindowsService)

        if len(sys.argv) > 1 and sys.argv[1].lower() == "install":
            configure_service_recovery()


if __name__ == "__main__":
    main()
