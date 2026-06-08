"""
Crash recovery — detects and resumes incomplete pipeline runs.

On startup, scans the run-state directory for runs stuck in 'running'
status. These are runs that were interrupted by a crash, power loss,
or kill signal. Resumes each from its last checkpoint.

Layer 5 — imports from Layer 0-4 (run_state, checkpoint, extract, transform, loaders).

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import json
import logging

from pipeline.run_state import RunStateManager, RunState

logger = logging.getLogger(__name__)


class CrashRecoveryManager:
    """
    Detects incomplete runs and resumes them from their last checkpoint.

    Quick-start
    -----------
        from pipeline.crash_recovery import CrashRecoveryManager
        crm = CrashRecoveryManager()
        resumed = crm.auto_resume_all()
        print(f"Resumed {resumed} interrupted runs.")
    """

    def __init__(self, state_manager: RunStateManager | None = None) -> None:
        self.state_manager = state_manager or RunStateManager()

    def check_incomplete_runs(self) -> list[RunState]:
        """Return all runs that were interrupted before completion."""
        incomplete = self.state_manager.get_incomplete_runs()
        if incomplete:
            logger.warning(
                "[CRASH_RECOVERY] Found %d incomplete run(s) from previous session.",
                len(incomplete),
            )
            for run in incomplete:
                logger.warning(
                    "[CRASH_RECOVERY]   run_id=%s  source=%s  dest=%s  "
                    "last_chunk=%d  rows=%d  started=%s",
                    run.run_id, run.source, run.destination,
                    run.last_chunk_completed, run.total_rows_processed,
                    run.started_at,
                )
        return incomplete

    def resume_run(self, run_state: RunState) -> bool:
        """
        Resume a single incomplete run from its last checkpoint.

        Returns True if the run completed successfully, False on failure.
        """
        import argparse

        logger.info(
            "[CRASH_RECOVERY] Resuming run %s from chunk %d (%d rows already processed).",
            run_state.run_id, run_state.last_chunk_completed + 1,
            run_state.total_rows_processed,
        )

        try:
            args_dict = json.loads(run_state.args_json)
        except (json.JSONDecodeError, TypeError):
            args_dict = {}

        try:
            args = argparse.Namespace(
                source=run_state.source,
                destination=run_state.destination,
                config_path=args_dict.get("config_path", ""),
                dry_run=args_dict.get("dry_run", False),
                skip_pii=args_dict.get("skip_pii", False),
                skip_quality=args_dict.get("skip_quality", True),
                parallel=False,
                table=run_state.table,
                sla=0,
                verify=args_dict.get("verify", False),
                transform_config=args_dict.get("transform_config"),
            )

            config_path = args.config_path
            config = {}
            if config_path:
                from pathlib import Path
                path = Path(config_path)
                if path.exists():
                    text = path.read_text(encoding="utf-8")
                    if path.suffix in (".yaml", ".yml"):
                        import yaml
                        config = yaml.safe_load(text) or {}
                    else:
                        config = json.loads(text)

            from pipeline.governance_logger import GovernanceLogger
            from pipeline.constants import RunContext
            from pipeline.monitoring.metrics_collector import MetricsCollector

            run_context = RunContext(pipeline_id=run_state.run_id)
            gov = GovernanceLogger(
                source_name=run_state.source,
                run_context=run_context,
                dry_run=args.dry_run,
            )
            gov.pipeline_start({
                "source": run_state.source,
                "destination": run_state.destination,
                "resumed_from_chunk": run_state.last_chunk_completed,
                "crash_recovery": True,
            })

            metrics = MetricsCollector(gov)

            from pipeline.cli import _run_chunked
            _run_chunked(
                run_state.source, args, config, gov, metrics,
                resume_from_chunk=run_state.last_chunk_completed,
                run_state=run_state,
                state_manager=self.state_manager,
            )

            self.state_manager.mark_complete(run_state.run_id)
            gov.pipeline_end({
                "source": run_state.source,
                "crash_recovery": True,
                "resumed_from_chunk": run_state.last_chunk_completed,
            })
            logger.info("[CRASH_RECOVERY] Run %s completed successfully.", run_state.run_id)
            return True

        except Exception as exc:
            logger.error(
                "[CRASH_RECOVERY] Resume of run %s failed: %s",
                run_state.run_id, exc,
            )
            self.state_manager.mark_failed(run_state.run_id, str(exc))
            return False

    def auto_resume_all(self) -> int:
        """Resume all incomplete runs. Returns count of successfully resumed runs."""
        incomplete = self.check_incomplete_runs()
        if not incomplete:
            logger.info("[CRASH_RECOVERY] No incomplete runs found.")
            return 0

        succeeded = 0
        for run_state in incomplete:
            if self.resume_run(run_state):
                succeeded += 1

        logger.info(
            "[CRASH_RECOVERY] Resumed %d/%d incomplete runs.",
            succeeded, len(incomplete),
        )
        return succeeded
