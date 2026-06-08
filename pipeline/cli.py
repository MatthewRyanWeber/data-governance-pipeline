"""
Command-line interface — arg parser and main() orchestrator.

Entry point for running the data-governance pipeline from the terminal.
Supports subcommands: run, validate, profile, replay-dlq, schedule.

Layer 6 — imports from everything.

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-08   Call validate_loader_config() before loader instantiation.
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from pipeline.constants import VERSION, RunContext

logger = logging.getLogger(__name__)


def _load_config(config_path: str | None) -> dict:
    """Load a YAML or JSON config file.  Returns empty dict if no path given."""
    if not config_path:
        return {}

    path = Path(config_path)
    if not path.exists():
        logger.error("Config file not found: %s", path)
        sys.exit(1)

    text = path.read_text(encoding="utf-8")

    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML is required to read YAML configs. pip install pyyaml")
            sys.exit(1)
        return yaml.safe_load(text) or {}

    return json.loads(text)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="data-governance-pipeline",
        description="GDPR/CCPA-compliant ETL with full audit logging (v%s)." % VERSION,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── run ──────────────────────────────────────────────────────────────
    run_parser = subparsers.add_parser("run", help="Execute a pipeline run")
    run_parser.add_argument("source", help="Source file or connection string")
    run_parser.add_argument("destination", help="Destination db_type (e.g. postgresql, snowflake)")
    run_parser.add_argument("--config", dest="config_path", help="Path to YAML/JSON config file")
    run_parser.add_argument("--dry-run", action="store_true", help="Log what would happen without writing")
    run_parser.add_argument("--skip-pii", action="store_true", help="Skip PII detection stage")
    run_parser.add_argument("--skip-quality", action="store_true", help="Skip data quality scoring")
    run_parser.add_argument("--parallel", action="store_true", help="Process source files in parallel")
    run_parser.add_argument("--table", default="pipeline_output", help="Destination table name")
    run_parser.add_argument("--sla", type=int, default=0, help="SLA deadline in seconds (0 = disabled)")

    # ── validate ─────────────────────────────────────────────────────────
    validate_parser = subparsers.add_parser("validate", help="Validate a source file against a schema")
    validate_parser.add_argument("source", help="Source file to validate")
    validate_parser.add_argument("--schema", required=True, help="Path to JSON schema file")

    # ── profile ──────────────────────────────────────────────────────────
    profile_parser = subparsers.add_parser("profile", help="Profile a source file")
    profile_parser.add_argument("source", help="Source file to profile")

    # ── replay-dlq ───────────────────────────────────────────────────────
    dlq_parser = subparsers.add_parser("replay-dlq", help="Replay records from the dead-letter queue")
    dlq_parser.add_argument("--dlq-dir", default="dead_letter_queue", help="DLQ directory")

    # ── schedule ─────────────────────────────────────────────────────────
    sched_parser = subparsers.add_parser("schedule", help="Run the pipeline on a cron schedule")
    sched_parser.add_argument("source", help="Source file or connection string")
    sched_parser.add_argument("destination", help="Destination db_type")
    sched_parser.add_argument("--cron", default="0 * * * *", help="Cron expression (default: hourly)")
    sched_parser.add_argument("--config", dest="config_path", help="Path to YAML/JSON config file")
    sched_parser.add_argument("--table", default="pipeline_output", help="Destination table name")

    return parser


# ── Subcommand handlers ──────────────────────────────────────────────────────

def _cmd_run(args: argparse.Namespace) -> None:
    """Execute a full pipeline run."""
    from pipeline.governance_logger import GovernanceLogger
    from pipeline.monitoring.sla_monitor import SLAMonitor
    from pipeline.monitoring.metrics_collector import MetricsCollector

    config = _load_config(args.config_path)
    run_context = RunContext()

    from pipeline.logging_setup import set_correlation_id
    set_correlation_id(run_context.pipeline_id)

    gov = GovernanceLogger(
        source_name=args.source,
        run_context=run_context,
        dry_run=args.dry_run,
    )
    gov.pipeline_start({"source": args.source, "destination": args.destination})

    metrics = MetricsCollector(gov)
    sla = SLAMonitor(gov, sla_seconds=args.sla)
    sla.start()

    # ── Parallel mode ────────────────────────────────────────────────────
    if args.parallel:
        source_path = Path(args.source)
        if source_path.is_dir():
            files = sorted(source_path.iterdir())
        else:
            files = [source_path]

        if len(files) > 1:
            from pipeline.parallel_runner import run_parallel

            def _single_file_pipeline(file_path):
                _run_single_file(file_path, args, config, gov, metrics)

            results = run_parallel(files, _single_file_pipeline)
            succeeded = sum(1 for r in results if r["success"])
            failed = len(results) - succeeded
            logger.info("Parallel run done — %d succeeded, %d failed.", succeeded, failed)
            gov.pipeline_end({"succeeded": succeeded, "failed": failed})
            metrics.write_report()
            sla.final_check()
            return

    # ── Single-file mode ─────────────────────────────────────────────────
    _run_single_file(args.source, args, config, gov, metrics)

    gov.pipeline_end({"source": args.source})
    metrics.write_report()
    sla.final_check()
    logger.info("Pipeline run complete.")


def _run_single_file(source, args, config, gov, metrics) -> None:
    """Extract, transform, load a single source file."""
    from pipeline.extract import Extractor
    from pipeline.transform import Transformer
    from pipeline.loaders import resolve_loader, validate_loader_config
    from pipeline.profiler import DataProfiler
    from pipeline.logging_setup import timed_operation

    metrics.start_stage("extract")
    extractor = Extractor(gov)
    with timed_operation("extract"):
        df = extractor.extract(str(source))
    metrics.end_stage("extract", rows=len(df))

    if df.empty:
        logger.warning("No data extracted from %s.", source)
        return

    # ── Transform ────────────────────────────────────────────────────
    metrics.start_stage("transform")
    transformer = Transformer(gov)

    if not args.skip_pii:
        from pipeline.helpers import detect_pii
        pii_findings = detect_pii(list(df.columns))
    else:
        pii_findings = []

    with timed_operation("transform"):
        df = transformer.transform(df, pii_findings, "mask", drop_cols=[])
    metrics.end_stage("transform", rows=len(df))

    # ── Profile ──────────────────────────────────────────────────────
    if not args.skip_quality:
        profiler = DataProfiler(gov)
        with timed_operation("profile"):
            profiler.profile(df)

    # ── Load ─────────────────────────────────────────────────────────
    metrics.start_stage("load")
    destination = args.destination
    table_name = args.table

    validate_loader_config(destination, config, table_name)
    loader_class, needs_db_type, uses_mongo = resolve_loader(destination)
    if needs_db_type:
        loader = loader_class(gov, db_type=destination, dry_run=args.dry_run)
    else:
        loader = loader_class(gov, dry_run=args.dry_run)

    with timed_operation(f"load:{destination}"):
        loader.load(df, config, table_name)
    metrics.end_stage("load", rows=len(df))


def _cmd_validate(args: argparse.Namespace) -> None:
    """Validate a source file against a JSON schema."""
    from pipeline.governance_logger import GovernanceLogger
    from pipeline.schema_validator import SchemaValidator

    gov = GovernanceLogger(source_name=args.source)
    validator = SchemaValidator(gov)

    schema_path = Path(args.schema)
    schema_text = schema_path.read_text(encoding="utf-8")
    schema = json.loads(schema_text)

    from pipeline.extract import Extractor

    extractor = Extractor(gov)
    df = extractor.extract(args.source)
    if df.empty:
        logger.warning("No data to validate.")
        return

    result = validator.validate(df, schema)
    print(json.dumps(result, indent=2))


def _cmd_profile(args: argparse.Namespace) -> None:
    """Profile a source file and print the report."""
    from pipeline.governance_logger import GovernanceLogger
    from pipeline.extract import Extractor
    from pipeline.profiler import DataProfiler

    gov = GovernanceLogger(source_name=args.source)
    extractor = Extractor(gov)
    df = extractor.extract(args.source)
    if df.empty:
        logger.warning("No data to profile.")
        return
    profiler = DataProfiler(gov)
    report = profiler.profile(df)
    print(json.dumps(report, indent=2, default=str))


def _cmd_replay_dlq(args: argparse.Namespace) -> None:
    """Replay records from the dead-letter queue."""
    from pipeline.governance_logger import GovernanceLogger
    from pipeline.advanced.dlq_replayer import DLQReplayer

    gov = GovernanceLogger(source_name="dlq-replay")
    replayer = DLQReplayer(gov, dlq_dir=args.dlq_dir)
    summary = replayer.replay_all()
    total = summary["total_rows"]
    logger.info("Replayed %d DLQ records.", total)
    print(f"Replayed {total} records from DLQ.")


def _cmd_schedule(args: argparse.Namespace) -> None:
    """Start the pipeline on a cron schedule (blocks until interrupted)."""
    from pipeline.scheduler import PipelineScheduler

    def _scheduled_run():
        # Re-parse run args into a namespace that _cmd_run expects
        run_ns = argparse.Namespace(
            source=args.source,
            destination=args.destination,
            config_path=args.config_path,
            dry_run=False,
            skip_pii=False,
            skip_quality=False,
            parallel=False,
            table=args.table,
            sla=0,
        )
        _cmd_run(run_ns)

    scheduler = PipelineScheduler(
        pipeline_fn=_scheduled_run,
        cron_expr=args.cron,
    )

    print(f"Scheduler started — cron={args.cron!r}. Press Ctrl+C to stop.")
    scheduler.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        scheduler.stop()
        print("\nScheduler stopped.")


# ── Entry point ──────────────────────────────────────────────────────────────

_COMMAND_DISPATCH = {
    "run": _cmd_run,
    "validate": _cmd_validate,
    "profile": _cmd_profile,
    "replay-dlq": _cmd_replay_dlq,
    "schedule": _cmd_schedule,
}


def main(argv: list[str] | None = None) -> None:
    """Parse arguments and dispatch to the appropriate subcommand."""
    from pipeline.logging_setup import setup_logging
    setup_logging()

    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handler = _COMMAND_DISPATCH.get(args.command)
    if handler is None:
        logger.error("Unknown command: %s", args.command)
        sys.exit(1)

    logger.info("data-governance-pipeline v%s — command=%s", VERSION, args.command)

    start = time.perf_counter()
    try:
        handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except Exception as exc:
        logger.error("Pipeline failed: %s", exc, exc_info=True)
        sys.exit(1)

    elapsed = round(time.perf_counter() - start, 2)
    logger.info("Command '%s' completed in %.2fs.", args.command, elapsed)


if __name__ == "__main__":
    main()
