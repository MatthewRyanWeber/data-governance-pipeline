"""
Command-line interface — arg parser and main() orchestrator.

Entry point for running the data-governance pipeline from the terminal.
Supports subcommands: run, validate, profile, replay-dlq, schedule,
resume, service, destinations.

Layer 6 — imports from everything.

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-08   Call validate_loader_config() before loader instantiation.
1.2   2026-06-08   Add db:/api: source routing, --transform-config, --verify.
1.3   2026-06-08   Chunked processing with checkpoints, crash recovery, resume
                   subcommand, service/watchdog integration.
1.4   2026-06-09   Capture the real exception in run-state on failure instead of
                   the "see logs" placeholder; log full traceback.
1.5   2026-06-11   Resumed runs carry forward the previously-loaded row total so
                   --verify compares the true cumulative count; --skip-pii now
                   passes None so flatten-time PII detection is also skipped.
1.6   2026-06-12   New 'destinations' subcommand: lists every destination with
                   its verification tier (core / emulator / cloud).
1.7   2026-06-13   Per-source run_id so --parallel files no longer collapse
                   onto one run-state file; chunk loads honor configured
                   if_exists/natural_keys (idempotent/exactly-once resume,
                   with an at-least-once warning when keyless); database
                   sources stream via DatabaseExtractor.chunks() instead of
                   loading the whole table into memory.
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

    return json.loads(text)  # type: ignore[no-any-return]


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
    run_parser.add_argument("source", help="Source file, connection string, or 'db:' / 'api:' prefix")
    run_parser.add_argument("destination", help="Destination db_type (e.g. postgresql, snowflake)")
    run_parser.add_argument("--config", dest="config_path", help="Path to YAML/JSON config file")
    run_parser.add_argument("--dry-run", action="store_true", help="Log what would happen without writing")
    run_parser.add_argument("--skip-pii", action="store_true", help="Skip PII detection stage")
    run_parser.add_argument("--skip-quality", action="store_true", help="Skip data quality scoring")
    run_parser.add_argument("--parallel", action="store_true", help="Process source files in parallel")
    run_parser.add_argument("--table", default="pipeline_output", help="Destination table name")
    run_parser.add_argument("--sla", type=int, default=0, help="SLA deadline in seconds (0 = disabled)")
    run_parser.add_argument("--verify", action="store_true", help="Verify row counts after loading")
    run_parser.add_argument("--transform-config", dest="transform_config",
                            help="Path to transform pipeline YAML/JSON config")
    run_parser.add_argument("--chunk-size", type=int, default=50_000,
                            help="Rows per chunk for checkpointed processing (default: 50000)")

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

    # ── resume ────────────────────────────────────────────────────────────
    subparsers.add_parser("resume", help="Resume any interrupted pipeline runs from last checkpoint")

    # ── destinations ─────────────────────────────────────────────────────
    dest_parser = subparsers.add_parser(
        "destinations",
        help="List every supported destination and its verification tier",
    )
    dest_parser.add_argument(
        "--tier", choices=["core", "emulator", "cloud"],
        help="Show only destinations in this tier",
    )

    # ── service ──────────────────────────────────────────────────────────
    svc_parser = subparsers.add_parser("service", help="Manage the Windows Service")
    svc_parser.add_argument("action", choices=["install", "remove", "start", "stop", "status"],
                            help="Service action to perform")

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

            results = run_parallel(files, _single_file_pipeline)  # type: ignore[arg-type]
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


def _extract_source(source, config, gov):
    """Route extraction based on source type: file, database, or REST API."""
    from pipeline.logging_setup import timed_operation

    source_str = str(source)

    if source_str.startswith("db:") or config.get("source_type") == "database":
        from pipeline.extractors import DatabaseExtractor
        db_ext = DatabaseExtractor(gov)
        db_cfg = config.get("source", config)
        query = db_cfg.get("query") or config.get("query")
        table = db_cfg.get("table") or source_str.removeprefix("db:")
        with timed_operation("extract:database"):
            df = db_ext.extract(db_cfg, query=query, table=table if not query else None)

    elif source_str.startswith("api:") or config.get("source_type") == "rest_api":
        from pipeline.extractors import RESTExtractor
        rest_ext = RESTExtractor(gov)
        api_cfg = config.get("source", config)
        if not api_cfg.get("url"):
            api_cfg["url"] = source_str.removeprefix("api:")
        with timed_operation("extract:rest_api"):
            df = rest_ext.extract(api_cfg)

    else:
        from pipeline.extract import Extractor
        extractor = Extractor(gov)
        with timed_operation("extract:file"):
            df = extractor.extract(source_str)

    return df


def _iter_source_chunks(source, config, gov, chunk_size):
    """Yield source data in chunks, streaming for every source type.

    - database  → DatabaseExtractor.chunks() (server-side pagination, never
      materializes the whole table)
    - file      → Extractor.chunks() (native chunked reader)
    - REST API  → a single in-memory batch (REST has no streaming
      abstraction here; responses are expected to be bounded)
    """
    from pipeline.logging_setup import timed_operation
    source_str = str(source)

    if source_str.startswith("db:") or config.get("source_type") == "database":
        from pipeline.extractors import DatabaseExtractor
        db_ext = DatabaseExtractor(gov)
        db_cfg = config.get("source", config)
        query = db_cfg.get("query") or config.get("query")
        table = db_cfg.get("table") or source_str.removeprefix("db:")
        schema = db_cfg.get("schema")
        with timed_operation("extract:database:stream"):
            yield from db_ext.chunks(
                db_cfg, query=query,
                table=table if not query else None,
                schema=schema, chunk_size=chunk_size,
            )

    elif source_str.startswith("api:") or config.get("source_type") == "rest_api":
        df = _extract_source(source, config, gov)
        if not df.empty:
            yield df

    else:
        from pipeline.extract import Extractor
        extractor = Extractor(gov)
        yield from extractor.chunks(source_str, chunk_size=chunk_size)


_transform_config_cache: dict | None = None


def _transform_chunk(chunk, args, config, gov):
    """Apply transformation to a single chunk."""
    global _transform_config_cache
    from pipeline.transform import Transformer
    from pipeline.logging_setup import timed_operation

    transform_config_path = getattr(args, "transform_config", None)
    if transform_config_path:
        from pipeline.transform_pipeline import TransformPipeline
        if _transform_config_cache is None:
            _transform_config_cache = _load_config(transform_config_path)
        tp = TransformPipeline(gov)
        with timed_operation("transform:pipeline"):
            return tp.run(chunk, _transform_config_cache)
    else:
        transformer = Transformer(gov)
        if not args.skip_pii:
            from pipeline.helpers import detect_pii
            pii_findings = detect_pii(list(chunk.columns))
        else:
            # None (not []) tells the transformer the PII stage is disabled,
            # so it also skips supplemental detection on flattened columns.
            pii_findings = None
        with timed_operation("transform"):
            return transformer.transform(chunk, pii_findings, "mask", drop_cols=[])


def _make_loader(args, config, gov):
    """Instantiate the destination loader.

    Returns (loader, uses_mongo) — the Mongo loader has a
    ``load(df, cfg, collection)`` signature with no if_exists/natural_keys.
    """
    from pipeline.loaders import resolve_loader, validate_loader_config

    destination = args.destination
    table_name = args.table
    validate_loader_config(destination, config, table_name)
    loader_class, needs_db_type, uses_mongo = resolve_loader(destination)
    if needs_db_type:
        loader = loader_class(gov, db_type=destination, dry_run=args.dry_run)
    else:
        loader = loader_class(gov, dry_run=args.dry_run)
    return loader, uses_mongo


def _run_chunked(
    source, args, config, gov, metrics,
    resume_from_chunk: int = -1,
    run_state=None,
    state_manager=None,
) -> None:
    """Process source in chunks: extract → transform → load → checkpoint per chunk."""
    from pipeline.logging_setup import timed_operation

    chunk_size = getattr(args, "chunk_size", 50_000)
    destination = args.destination
    table_name = args.table

    if state_manager is None:
        from pipeline.run_state import RunStateManager
        state_manager = RunStateManager()

    if resume_from_chunk < 0:
        resume_from_chunk = state_manager.load_checkpoint(gov, str(source), table_name)

    # On resume, rows loaded before the crash must seed the running total —
    # restarting at 0 made the --verify row-count comparison falsely fail.
    rows_already_loaded = 0
    if resume_from_chunk >= 0:
        rows_already_loaded = state_manager.load_checkpoint_rows(str(source), table_name)
        if rows_already_loaded == 0 and run_state is not None:
            rows_already_loaded = run_state.total_rows_processed
        if rows_already_loaded:
            logger.info(
                "[CHECKPOINT] Carrying forward %d rows already loaded before resume.",
                rows_already_loaded,
            )

    loader, uses_mongo = _make_loader(args, config, gov)

    # Honor upsert keys from config so each chunk load is idempotent: a
    # crash between load and checkpoint re-runs that chunk on resume, and
    # without keys (plain append) the re-run DUPLICATES rows. With
    # natural_keys the per-chunk upsert makes resume exactly-once.
    if_exists = config.get("if_exists", "append")
    natural_keys = config.get("natural_keys")
    if natural_keys and if_exists == "append":
        if_exists = "upsert"

    def _load_chunk(chunk_df):
        if uses_mongo:
            # Mongo signature: load(df, cfg, collection) — no if_exists.
            loader.load(chunk_df, config, table_name)
        else:
            loader.load(chunk_df, config, table_name,
                        if_exists=if_exists, natural_keys=natural_keys)

    if resume_from_chunk >= 0 and not natural_keys and \
            if_exists == "append" and not uses_mongo:
        logger.warning(
            "[CHECKPOINT] Resuming an append-mode load with no natural_keys: "
            "the chunk interrupted by the crash will be re-loaded, which can "
            "DUPLICATE its rows (at-least-once). Configure 'natural_keys' for "
            "exactly-once resume."
        )

    # One streaming loop for every source type — never load the whole
    # dataset into memory.  Database sources stream via
    # DatabaseExtractor.chunks() (previously they loaded the entire table
    # then sliced in memory, OOMing on large tables and violating the
    # streaming guarantee); file sources via Extractor.chunks(); REST APIs
    # yield a single in-memory batch (no streaming pagination abstraction).
    total_rows = rows_already_loaded
    chunk_idx = 0

    metrics.start_stage("extract")
    for chunk in _iter_source_chunks(source, config, gov, chunk_size):
        if chunk_idx <= resume_from_chunk:
            logger.info("[CHECKPOINT] Skipping chunk %d (already processed).", chunk_idx)
            chunk_idx += 1
            continue

        metrics.end_stage("extract", rows=len(chunk))

        chunk = _transform_chunk(chunk, args, config, gov)

        with timed_operation(f"load:{destination}:chunk_{chunk_idx}"):
            _load_chunk(chunk)

        total_rows += len(chunk)
        state_manager.save_checkpoint(gov, str(source), table_name, chunk_idx, total_rows)

        if state_manager and run_state:
            state_manager.update_chunk(run_state.run_id, chunk_idx, total_rows)

        logger.info(
            "[PIPELINE] Chunk %d loaded — %d rows total.",
            chunk_idx + 1, total_rows,
        )
        chunk_idx += 1
        metrics.start_stage("extract")

    state_manager.clear_checkpoint(str(source), table_name)
    logger.info("[PIPELINE] All chunks loaded — %d rows total.", total_rows)

    if getattr(args, "verify", False) and not args.dry_run:
        from pipeline.load_verifier import LoadVerifier
        verifier = LoadVerifier(gov)
        verify_cfg = dict(config)
        verify_cfg["db_type"] = destination
        with timed_operation("verify"):
            import pandas as pd
            dummy = pd.DataFrame(index=range(total_rows))
            result = verifier.verify_row_count(dummy, verify_cfg, table_name)
        if result.get("match") is False:
            logger.warning(
                "Load verification FAILED: %d source rows vs %d destination rows.",
                result["source_rows"], result["dest_rows"],
            )


def _run_single_file(source, args, config, gov, metrics) -> None:
    """Extract, transform, load with chunk-level checkpointing and crash recovery."""
    from pipeline.run_state import RunStateManager, RunState

    state_manager = RunStateManager()
    # Per-source run_id: in --parallel mode every worker shares one gov
    # (one pipeline_id), so keying the run-state file on pipeline_id alone
    # made all files write the same {run_id}.json — racing and leaving
    # every file but one unrecoverable on crash. A deterministic per-source
    # suffix gives each file its own resumable run-state.
    import hashlib
    source_tag = hashlib.sha1(str(source).encode("utf-8")).hexdigest()[:8]
    per_source_run_id = f"{gov.run_context.pipeline_id}_{source_tag}"
    run_state = RunState(
        run_id=per_source_run_id,
        source=str(source),
        destination=args.destination,
        table=args.table,
        config_path=getattr(args, "config_path", "") or "",
        args_json=json.dumps({
            "config_path": getattr(args, "config_path", ""),
            "dry_run": args.dry_run,
            "skip_pii": args.skip_pii,
            "skip_quality": getattr(args, "skip_quality", False),
            "verify": getattr(args, "verify", False),
            "transform_config": getattr(args, "transform_config", None),
            "chunk_size": getattr(args, "chunk_size", 50_000),
        }),
    )
    state_manager.save_start(run_state)

    try:
        _run_chunked(
            source, args, config, gov, metrics,
            run_state=run_state,
            state_manager=state_manager,
        )
        state_manager.mark_complete(run_state.run_id)
    except Exception as exc:
        # Persist the real exception so `resume`/status reporting is actionable —
        # the prior "see logs" placeholder was useless when logs had rotated away.
        logger.error("Run %s failed: %s", run_state.run_id, exc, exc_info=True)
        state_manager.mark_failed(run_state.run_id, f"{type(exc).__name__}: {exc}")
        raise


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


def _cmd_resume(args: argparse.Namespace) -> None:
    """Resume any interrupted pipeline runs from their last checkpoint."""
    from pipeline.crash_recovery import CrashRecoveryManager
    crm = CrashRecoveryManager()
    incomplete = crm.check_incomplete_runs()
    if not incomplete:
        print("No interrupted runs found.")
        return
    print(f"Found {len(incomplete)} interrupted run(s). Resuming…")
    resumed = crm.auto_resume_all()
    print(f"Resumed {resumed}/{len(incomplete)} runs successfully.")


def _cmd_service(args: argparse.Namespace) -> None:
    """Manage the Windows Service."""
    action = args.action.lower()

    if action == "install":
        from pipeline.service import install_service
        install_service()
    elif action == "remove":
        from pipeline.service import main as svc_main
        saved_argv = sys.argv[:]
        try:
            sys.argv = [sys.argv[0], "remove"]
            svc_main()
        finally:
            sys.argv = saved_argv
    elif action == "start":
        import subprocess
        subprocess.run(["sc", "start", "DataGovernancePipeline"], check=True)
        print("Service started.")
    elif action == "stop":
        import subprocess
        subprocess.run(["sc", "stop", "DataGovernancePipeline"], check=True)
        print("Service stopped.")
    elif action == "status":
        import subprocess
        result = subprocess.run(
            ["sc", "query", "DataGovernancePipeline"],
            capture_output=True, text=True,
        )
        print(result.stdout or result.stderr)


def _cmd_destinations(args: argparse.Namespace) -> None:
    """List every supported destination grouped by verification tier."""
    from pipeline.loaders import destination_catalog

    tier_headlines = {
        "core": "CORE — tested against a real engine in CI on every push",
        "emulator": "EMULATOR-VERIFIED — mechanics proven against an emulator; "
                    "vendor-specific behaviour is not covered",
        "cloud": "CLOUD-CREDENTIAL — verified against the live service only "
                 "when credentials are configured",
    }

    entries = destination_catalog()
    if args.tier:
        entries = [e for e in entries if e["tier"] == args.tier]

    current_tier = None
    for entry in entries:
        if entry["tier"] != current_tier:
            current_tier = entry["tier"]
            print(f"\n{tier_headlines[current_tier]}")
            print("-" * 72)
        print(f"  {entry['db_type']:<20} {entry['loader_class']}")
    print(f"\n{len(entries)} destination(s).")


# ── Entry point ──────────────────────────────────────────────────────────────

_COMMAND_DISPATCH = {
    "run": _cmd_run,
    "validate": _cmd_validate,
    "profile": _cmd_profile,
    "replay-dlq": _cmd_replay_dlq,
    "schedule": _cmd_schedule,
    "resume": _cmd_resume,
    "service": _cmd_service,
    "destinations": _cmd_destinations,
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

    # ── Auto-detect interrupted runs on any 'run' command ────────────
    if args.command == "run":
        from pipeline.crash_recovery import CrashRecoveryManager
        crm = CrashRecoveryManager()
        incomplete = crm.check_incomplete_runs()
        if incomplete:
            logger.warning(
                "Found %d interrupted run(s) from a previous session. "
                "Run 'pipeline resume' to recover them, or they will be "
                "skipped for this run.",
                len(incomplete),
            )

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
