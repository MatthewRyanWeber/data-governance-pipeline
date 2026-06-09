"""
Full end-to-end integration tests for the data-governance pipeline.

Exercises the complete pipeline flow: config -> extract -> transform ->
validate -> load, using only core dependencies (pandas, SQLAlchemy, sqlite).
No Docker, no external services, no network calls.

Each test creates synthetic data, runs it through real pipeline modules
(Extractor, Transformer, SQLLoader, GovernanceLogger, DataProfiler,
LoadVerifier), and verifies the output in a temporary SQLite database.

Revision history
----------------
1.0   2026-06-09   Initial release: 8 end-to-end scenarios covering CSV,
                   JSON, dry-run, governance audit, replace/append, upsert,
                   empty-frame, and gzip-compressed extraction.
1.1   2026-06-09   Added TestFullStackPipeline: MetricsCollector, SLAMonitor,
                   DataObserver, checkpoint recovery, metrics report.
"""

import gzip
import json
import logging
import os
import shutil
import tempfile
import unittest

import pandas as pd
from sqlalchemy import create_engine

from pipeline.checkpoint import CheckpointManager
from pipeline.constants import RunContext, CHECKPOINT_FILE
from pipeline.extract import Extractor
from pipeline.governance_logger import GovernanceLogger
from pipeline.helpers import detect_pii
from pipeline.load_verifier import LoadVerifier
from pipeline.loaders.sql_loader import SQLLoader
from pipeline.monitoring.metrics_collector import MetricsCollector
from pipeline.monitoring.observability import DataObserver
from pipeline.monitoring.sla_monitor import SLAMonitor
from pipeline.profiler import DataProfiler
from pipeline.transform import Transformer

logger = logging.getLogger(__name__)


# ── Synthetic data factories ────────────────────────────────────────────────

def _sample_rows() -> list[dict]:
    """7 rows of synthetic PII-bearing data for integration testing."""
    return [
        {"id": 1, "full_name": "Alice Smith",   "email": "alice@example.com",   "phone": "555-0101", "age": 30, "balance": 1200.50},
        {"id": 2, "full_name": "Bob Johnson",    "email": "bob@example.com",     "phone": "555-0102", "age": 25, "balance": 850.00},
        {"id": 3, "full_name": "Carol Williams", "email": "carol@example.com",   "phone": "555-0103", "age": 45, "balance": 3200.75},
        {"id": 4, "full_name": "Dave Brown",     "email": "dave@example.com",    "phone": "555-0104", "age": 35, "balance": 0.00},
        {"id": 5, "full_name": "Eve Davis",      "email": "eve@example.com",     "phone": "555-0105", "age": 28, "balance": 540.20},
        {"id": 6, "full_name": "Frank Miller",   "email": "frank@example.com",   "phone": "555-0106", "age": 52, "balance": 9100.00},
        {"id": 7, "full_name": "Grace Wilson",   "email": "grace@example.com",   "phone": "555-0107", "age": 38, "balance": 2750.10},
    ]


def _sample_df() -> pd.DataFrame:
    return pd.DataFrame(_sample_rows())


def _write_csv(path: str, rows: list[dict] | None = None) -> str:
    """Write synthetic rows to a CSV file and return the path."""
    df = pd.DataFrame(rows or _sample_rows())
    df.to_csv(path, index=False, encoding="utf-8")
    return path


def _write_json(path: str, rows: list[dict] | None = None) -> str:
    """Write synthetic rows to a JSON file and return the path."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows or _sample_rows(), f)
    return path


def _sqlite_engine(db_path: str):
    """Create a SQLAlchemy engine for a SQLite file (with .db appended by loader)."""
    return create_engine(f"sqlite:///{db_path}.db")


def _read_table(db_path: str, table: str) -> pd.DataFrame:
    """Read an entire SQLite table back into a DataFrame for assertions."""
    engine = _sqlite_engine(db_path)
    try:
        return pd.read_sql(f'SELECT * FROM "{table}"', engine)
    finally:
        engine.dispose()


# ── Full pipeline helper ────────────────────────────────────────────────────

def _run_pipeline(
    source_path: str,
    db_path: str,
    table: str = "pipeline_output",
    if_exists: str = "replace",
    natural_keys: list[str] | None = None,
    dry_run: bool = False,
    skip_pii: bool = False,
    pii_strategy: str = "mask",
) -> tuple[GovernanceLogger, pd.DataFrame]:
    """
    Run extract -> transform -> load through real pipeline modules.

    Returns (gov, transformed_df) so callers can inspect audit events and
    the DataFrame that was loaded.
    """
    run_context = RunContext()
    gov = GovernanceLogger(
        source_name=os.path.basename(source_path),
        log_dir=os.path.join(os.path.dirname(db_path), "gov_logs"),
        run_context=run_context,
        dry_run=dry_run,
    )
    gov.pipeline_start({"source": source_path, "destination": "sqlite"})

    # Extract
    extractor = Extractor(gov)
    df = extractor.extract(source_path)

    if df.empty:
        gov.pipeline_end({"rows": 0})
        return gov, df

    # Transform
    transformer = Transformer(gov, run_context=run_context)
    if skip_pii:
        pii_findings = []
    else:
        pii_findings = detect_pii(list(df.columns))
    df = transformer.transform(df, pii_findings, pii_strategy, drop_cols=[])

    # Load
    loader = SQLLoader(gov, db_type="sqlite", dry_run=dry_run)
    cfg = {"db_name": db_path}
    loader.load(df, cfg, table, if_exists=if_exists, natural_keys=natural_keys)

    gov.pipeline_end({"rows": len(df)})
    return gov, df


# ═══════════════════════════════════════════════════════════════════════════════
# Test cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestCsvToSqliteFullPipeline(unittest.TestCase):
    """End-to-end: CSV source -> extract -> transform (fill_nulls, mask PII) -> SQLite."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_csv_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_csv_to_sqlite_full_pipeline(self):
        """Synthetic CSV with PII flows through the entire pipeline to SQLite."""
        csv_path = os.path.join(self.tmpdir, "customers.csv")
        db_path = os.path.join(self.tmpdir, "output")
        _write_csv(csv_path)

        gov, df = _run_pipeline(csv_path, db_path, table="customers")

        # Data must have landed in SQLite
        result = _read_table(db_path, "customers")
        self.assertEqual(len(result), 7)

        # PII columns (email, phone, full_name) must be masked
        for col in result.columns:
            col_lower = col.lower()
            if "email" in col_lower or "phone" in col_lower or "full_name" in col_lower:
                for val in result[col].dropna():
                    self.assertTrue(
                        str(val).startswith("MASKED_"),
                        f"Column '{col}' value '{val}' was not masked",
                    )

        # Pipeline metadata columns must be present
        self.assertIn("_pipeline_id", result.columns)
        self.assertIn("_loaded_at_utc", result.columns)

        # Numeric columns must survive transformation
        self.assertTrue(all(result["age"] > 0))


class TestJsonToSqliteFullPipeline(unittest.TestCase):
    """End-to-end: JSON source -> extract -> transform -> SQLite."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_json_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_json_to_sqlite_full_pipeline(self):
        """Synthetic JSON array with PII flows through to SQLite."""
        json_path = os.path.join(self.tmpdir, "customers.json")
        db_path = os.path.join(self.tmpdir, "output")
        _write_json(json_path)

        gov, df = _run_pipeline(json_path, db_path, table="customers")

        result = _read_table(db_path, "customers")
        self.assertEqual(len(result), 7)

        # Verify PII masking happened
        for val in result["email"].dropna():
            self.assertTrue(str(val).startswith("MASKED_"))

        # Verify non-PII data survived intact
        ages = sorted(result["age"].tolist())
        self.assertEqual(ages, [25, 28, 30, 35, 38, 45, 52])


class TestDryRunPipeline(unittest.TestCase):
    """End-to-end: dry_run=True must not write anything to the database."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_dry_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_dry_run_pipeline(self):
        """With dry_run=True the SQLite file must not be created."""
        csv_path = os.path.join(self.tmpdir, "customers.csv")
        db_path = os.path.join(self.tmpdir, "output")
        _write_csv(csv_path)

        gov, df = _run_pipeline(csv_path, db_path, table="customers", dry_run=True)

        # The loader should not have created the database file
        db_file = db_path + ".db"
        self.assertFalse(
            os.path.exists(db_file),
            f"Database file '{db_file}' should not exist after dry run",
        )

        # Transform should still have produced a DataFrame
        self.assertGreater(len(df), 0)

        # Governance logger should still have recorded events
        self.assertGreater(len(gov.ledger_entries), 0)


class TestPipelineWithGovernanceAudit(unittest.TestCase):
    """Verify GovernanceLogger captured events throughout the pipeline run."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_audit_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pipeline_with_governance_audit(self):
        """The audit ledger must contain extract, transformation, and load events."""
        csv_path = os.path.join(self.tmpdir, "audit_test.csv")
        db_path = os.path.join(self.tmpdir, "output")
        _write_csv(csv_path)

        gov, df = _run_pipeline(csv_path, db_path, table="audit_target")

        actions = [e["action"] for e in gov.ledger_entries]

        # Lifecycle bookends
        self.assertIn("PIPELINE_STARTED", actions)
        self.assertIn("PIPELINE_COMPLETED", actions)

        # Extract events
        self.assertIn("EXTRACT_START", actions)
        self.assertIn("EXTRACT_COMPLETE", actions)

        # Transformation events (the transformer logs several)
        self.assertIn("TRANSFORM_COMPLETE", actions)
        self.assertIn("DEDUPLICATION", actions)
        self.assertIn("NULL_HANDLING", actions)
        self.assertIn("COLUMN_SANITIZATION", actions)

        # PII masking events
        pii_actions = [a for a in actions if a.startswith("PII_")]
        self.assertGreater(len(pii_actions), 0, "Expected PII action events")

        # Load event
        self.assertIn("LOAD_COMPLETE", actions)

        # Chained-hash integrity
        self.assertTrue(gov.verify_ledger(), "Ledger integrity check failed")

        # Every event must have a pipeline_id
        for entry in gov.ledger_entries:
            self.assertEqual(entry["pipeline_id"], gov.run_context.pipeline_id)


class TestPipelineReplaceVsAppend(unittest.TestCase):
    """Load data twice with replace then append, verify row counts."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_replace_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pipeline_replace_vs_append(self):
        """Replace resets the table; append adds to it."""
        csv_path = os.path.join(self.tmpdir, "data.csv")
        db_path = os.path.join(self.tmpdir, "output")
        _write_csv(csv_path)

        # First load with replace
        _run_pipeline(csv_path, db_path, table="rva_test", if_exists="replace")
        result_1 = _read_table(db_path, "rva_test")
        self.assertEqual(len(result_1), 7)

        # Second load with append (same 7 rows -> 14 total)
        _run_pipeline(csv_path, db_path, table="rva_test", if_exists="append")
        result_2 = _read_table(db_path, "rva_test")
        self.assertEqual(len(result_2), 14)

        # Third load with replace (back to 7)
        _run_pipeline(csv_path, db_path, table="rva_test", if_exists="replace")
        result_3 = _read_table(db_path, "rva_test")
        self.assertEqual(len(result_3), 7)


class TestPipelineWithNaturalKeysUpsert(unittest.TestCase):
    """Load data with natural_keys to exercise upsert (delete+insert) behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_upsert_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pipeline_with_natural_keys_upsert(self):
        """Upsert updates existing rows and inserts new ones."""
        db_path = os.path.join(self.tmpdir, "output")

        # Initial load: 7 rows, skip PII masking so 'id' stays numeric
        csv_path_1 = os.path.join(self.tmpdir, "initial.csv")
        _write_csv(csv_path_1)
        _run_pipeline(
            csv_path_1, db_path, table="upsert_test",
            if_exists="replace", skip_pii=True,
        )
        initial = _read_table(db_path, "upsert_test")
        self.assertEqual(len(initial), 7)

        # Upsert: update id=2 (new balance), insert id=99 (new row)
        upsert_rows = [
            {"id": 2, "full_name": "Bob Updated",  "email": "bob2@example.com",  "phone": "555-0202", "age": 26, "balance": 999.99},
            {"id": 99, "full_name": "New Person",   "email": "new@example.com",   "phone": "555-0199", "age": 40, "balance": 100.00},
        ]
        csv_path_2 = os.path.join(self.tmpdir, "upsert.csv")
        _write_csv(csv_path_2, upsert_rows)
        _run_pipeline(
            csv_path_2, db_path, table="upsert_test",
            natural_keys=["id"], skip_pii=True,
        )

        result = _read_table(db_path, "upsert_test")

        # Original 7 minus the 1 that matched (id=2) + 2 from the upsert batch = 8
        self.assertEqual(len(result), 8)

        # id=99 must be present (inserted)
        self.assertIn(99, result["id"].tolist())

        # id=2 must have the updated balance
        row_2 = result[result["id"] == 2].iloc[0]
        self.assertAlmostEqual(row_2["balance"], 999.99, places=2)


class TestPipelineHandlesEmptyDataframe(unittest.TestCase):
    """Extract from an empty CSV, verify graceful handling without errors."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_empty_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pipeline_handles_empty_dataframe(self):
        """An empty CSV (headers only) must not crash and must not create a table."""
        csv_path = os.path.join(self.tmpdir, "empty.csv")
        # Headers only, no data rows
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("id,name,email\n")

        db_path = os.path.join(self.tmpdir, "output")
        gov, df = _run_pipeline(csv_path, db_path, table="empty_test")

        self.assertEqual(len(df), 0)

        # The database file should not exist (no rows to write)
        db_file = db_path + ".db"
        self.assertFalse(
            os.path.exists(db_file),
            "Database file should not be created for an empty DataFrame",
        )

        # Governance logger should still have lifecycle events
        actions = [e["action"] for e in gov.ledger_entries]
        self.assertIn("PIPELINE_STARTED", actions)
        self.assertIn("PIPELINE_COMPLETED", actions)


class TestPipelineWithCompression(unittest.TestCase):
    """Create a gzip-compressed CSV, verify the pipeline can extract through it."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_gzip_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pipeline_with_compression(self):
        """A .csv.gz file must decompress transparently and load correctly."""
        # Write a plain CSV then gzip it
        plain_csv = os.path.join(self.tmpdir, "data.csv")
        _write_csv(plain_csv)

        gz_path = os.path.join(self.tmpdir, "data.csv.gz")
        with open(plain_csv, "rb") as f_in:
            with gzip.open(gz_path, "wb") as f_out:
                f_out.write(f_in.read())

        db_path = os.path.join(self.tmpdir, "output")
        gov, df = _run_pipeline(gz_path, db_path, table="gz_test")

        result = _read_table(db_path, "gz_test")
        self.assertEqual(len(result), 7)

        # PII must still be masked even through compression
        for val in result["email"].dropna():
            self.assertTrue(str(val).startswith("MASKED_"))

        # Extract events should reference the compressed source
        extract_events = [
            e for e in gov.ledger_entries if e["action"] == "EXTRACT_START"
        ]
        self.assertGreater(len(extract_events), 0)
        self.assertIn(".gz", extract_events[0]["detail"]["source"])


class TestPipelineProfilerIntegration(unittest.TestCase):
    """Verify DataProfiler produces a valid report when run alongside the pipeline."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_profile_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_profiler_on_extracted_data(self):
        """Profile the raw extracted DataFrame and verify report structure."""
        csv_path = os.path.join(self.tmpdir, "profile_test.csv")
        _write_csv(csv_path)

        run_context = RunContext()
        gov = GovernanceLogger(
            source_name="profile_test",
            log_dir=os.path.join(self.tmpdir, "gov_logs"),
            run_context=run_context,
        )

        extractor = Extractor(gov)
        df = extractor.extract(csv_path)

        profiler = DataProfiler(gov)
        report = profiler.profile(df)

        # Table-level stats
        self.assertEqual(report["table"]["row_count"], 7)
        self.assertEqual(report["table"]["column_count"], 6)
        self.assertEqual(report["table"]["duplicate_row_count"], 0)

        # Column-level stats
        self.assertIn("age", report["columns"])
        age_profile = report["columns"]["age"]
        self.assertEqual(age_profile["null_count"], 0)
        self.assertIn("min", age_profile)
        self.assertIn("max", age_profile)
        self.assertEqual(age_profile["min"], 25.0)
        self.assertEqual(age_profile["max"], 52.0)

        # String column
        self.assertIn("email", report["columns"])
        email_profile = report["columns"]["email"]
        self.assertIn("min_length", email_profile)
        self.assertGreater(email_profile["min_length"], 0)


class TestPipelineLoadVerifier(unittest.TestCase):
    """Verify LoadVerifier can reconcile row counts against the SQLite destination."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_verify_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_load_verifier_matches(self):
        """After a successful load, row counts must match."""
        csv_path = os.path.join(self.tmpdir, "verify_test.csv")
        db_path = os.path.join(self.tmpdir, "output")
        _write_csv(csv_path)

        gov, df = _run_pipeline(csv_path, db_path, table="verify_tbl", skip_pii=True)

        verifier = LoadVerifier(gov)
        verify_cfg = {
            "db_type": "sqlite",
            "connection_string": f"sqlite:///{db_path}.db",
        }
        result = verifier.verify_row_count(df, verify_cfg, "verify_tbl")

        self.assertTrue(result["match"])
        self.assertEqual(result["source_rows"], 7)
        self.assertEqual(result["dest_rows"], 7)
        self.assertEqual(result["difference"], 0)

    def test_load_verifier_detects_mismatch(self):
        """LoadVerifier detects when source and destination row counts differ."""
        csv_path = os.path.join(self.tmpdir, "verify_test.csv")
        db_path = os.path.join(self.tmpdir, "output")
        _write_csv(csv_path)

        gov, df = _run_pipeline(csv_path, db_path, table="verify_mm", skip_pii=True)

        # Fabricate a source_df with more rows than what was loaded
        bigger_df = pd.DataFrame({"x": range(100)})

        verifier = LoadVerifier(gov)
        verify_cfg = {
            "db_type": "sqlite",
            "connection_string": f"sqlite:///{db_path}.db",
        }
        result = verifier.verify_row_count(bigger_df, verify_cfg, "verify_mm")

        self.assertFalse(result["match"])
        self.assertEqual(result["source_rows"], 100)
        self.assertEqual(result["dest_rows"], 7)


class TestFullStackPipeline(unittest.TestCase):
    """Exercise the complete pipeline stack including monitoring, observability,
    and checkpoint recovery — the stages that simpler E2E tests skip."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="e2e_fullstack_")
        self._checkpoint_backup = None
        if CHECKPOINT_FILE.exists():
            self._checkpoint_backup = CHECKPOINT_FILE.read_text(encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        if self._checkpoint_backup is not None:
            CHECKPOINT_FILE.write_text(self._checkpoint_backup, encoding="utf-8")
        elif CHECKPOINT_FILE.exists():
            CHECKPOINT_FILE.unlink()

    def test_full_stack_csv_all_stages(self):
        """Extract -> PII -> transform -> profile -> observe -> SLA -> load ->
        verify -> metrics.  Assert governance ledger has events from ALL stages."""
        csv_path = os.path.join(self.tmpdir, "fullstack.csv")
        db_path = os.path.join(self.tmpdir, "output")
        gov_dir = os.path.join(self.tmpdir, "gov_logs")
        _write_csv(csv_path)

        run_context = RunContext()
        gov = GovernanceLogger(
            source_name="fullstack.csv",
            log_dir=gov_dir,
            run_context=run_context,
        )
        gov.pipeline_start({"source": csv_path, "destination": "sqlite"})

        metrics = MetricsCollector(gov)
        sla = SLAMonitor(gov, sla_seconds=600)
        sla.start()

        # Extract
        metrics.start_stage("extract")
        extractor = Extractor(gov)
        df = extractor.extract(csv_path)
        metrics.end_stage("extract", rows=len(df))
        metrics.rows_in = len(df)

        # PII + Transform
        metrics.start_stage("transform")
        pii_findings = detect_pii(list(df.columns))
        transformer = Transformer(gov, run_context=run_context)
        df = transformer.transform(df, pii_findings, "mask", drop_cols=[])
        metrics.end_stage("transform", rows=len(df))

        # Profile
        profiler = DataProfiler(gov)
        profile_report = profiler.profile(df)

        # Observe
        observer = DataObserver(gov, history_file=os.path.join(gov_dir, "obs.jsonl"))
        obs_report = observer.observe(df, dataset="fullstack")

        # SLA mid-check
        sla.check("after transform")

        # Load
        metrics.start_stage("load")
        loader = SQLLoader(gov, db_type="sqlite")
        loader.load(df, {"db_name": db_path}, "fullstack_out", if_exists="replace")
        metrics.end_stage("load", rows=len(df))
        metrics.rows_out = len(df)

        # Verify
        verifier = LoadVerifier(gov)
        verify_result = verifier.verify_row_count(
            df, {"db_type": "sqlite", "connection_string": f"sqlite:///{db_path}.db"},
            "fullstack_out",
        )

        # Final SLA + metrics
        sla.final_check()
        metrics.write_report()
        gov.pipeline_end({"rows": len(df)})

        # ── Assertions ──

        # Data landed correctly
        result = _read_table(db_path, "fullstack_out")
        self.assertEqual(len(result), 7)

        # Verify row count match
        self.assertTrue(verify_result["match"])

        # Profile has expected structure
        self.assertEqual(profile_report["table"]["row_count"], 7)
        self.assertIn("columns", profile_report)

        # Observability report returned
        self.assertEqual(obs_report["row_count"], 7)
        self.assertEqual(obs_report["dataset"], "fullstack")

        # SLA not breached
        self.assertFalse(sla.breached)

        # Governance ledger covers ALL stages
        actions = [e["action"] for e in gov.ledger_entries]
        self.assertIn("PIPELINE_STARTED", actions)
        self.assertIn("PIPELINE_COMPLETED", actions)
        self.assertIn("EXTRACT_START", actions)
        self.assertIn("EXTRACT_COMPLETE", actions)
        self.assertIn("TRANSFORM_COMPLETE", actions)
        self.assertIn("LOAD_COMPLETE", actions)
        self.assertIn("PROFILE_GENERATED", actions)

        # Metrics were recorded
        metrics_events = [a for a in actions if "METRICS" in a]
        self.assertGreater(len(metrics_events), 0)

        # PII masking happened
        pii_actions = [a for a in actions if a.startswith("PII_")]
        self.assertGreater(len(pii_actions), 0)

        # Ledger integrity
        self.assertTrue(gov.verify_ledger())

    def test_checkpoint_recovery(self):
        """Simulate crash after chunk 1: save checkpoint, verify resume skips
        already-completed chunks."""
        csv_path = os.path.join(self.tmpdir, "checkpoint_test.csv")
        _write_csv(csv_path)

        run_context = RunContext()
        gov = GovernanceLogger(
            source_name="checkpoint_test.csv",
            log_dir=os.path.join(self.tmpdir, "gov_logs"),
            run_context=run_context,
        )

        source_key = "checkpoint_test.csv"
        table_key = "ckpt_table"

        ckpt = CheckpointManager(gov)

        # No checkpoint should exist initially
        last = ckpt.load_checkpoint(source_key, table_key)
        self.assertEqual(last, -1)

        # Simulate: chunk 0 loaded successfully, then crash
        ckpt.save_checkpoint(source_key, table_key, chunk_idx=0, rows=100)

        # Simulate: chunk 1 loaded successfully, then crash
        ckpt.save_checkpoint(source_key, table_key, chunk_idx=1, rows=200)

        # "Restart" — load checkpoint should return 1 (last completed chunk)
        gov2 = GovernanceLogger(
            source_name="checkpoint_test.csv",
            log_dir=os.path.join(self.tmpdir, "gov_logs"),
            run_context=RunContext(),
        )
        ckpt2 = CheckpointManager(gov2)
        resumed_from = ckpt2.load_checkpoint(source_key, table_key)
        self.assertEqual(resumed_from, 1)

        # Governance should have checkpoint events
        actions = [e["action"] for e in gov.ledger_entries]
        checkpoint_actions = [a for a in actions if "CHECKPOINT" in a]
        self.assertGreater(len(checkpoint_actions), 0)

        # Clean up
        ckpt2.clear_checkpoint(source_key, table_key)
        final = ckpt2.load_checkpoint(source_key, table_key)
        self.assertEqual(final, -1)

    def test_metrics_report_contents(self):
        """Verify MetricsCollector report has all expected fields."""
        csv_path = os.path.join(self.tmpdir, "metrics_test.csv")
        _write_csv(csv_path)

        run_context = RunContext()
        gov = GovernanceLogger(
            source_name="metrics_test.csv",
            log_dir=os.path.join(self.tmpdir, "gov_logs"),
            run_context=run_context,
        )

        mc = MetricsCollector(gov)

        mc.start_stage("extract")
        mc.end_stage("extract", rows=7)
        mc.rows_in = 7

        mc.start_stage("transform")
        mc.end_stage("transform", rows=7)

        mc.start_stage("load")
        mc.end_stage("load", rows=7)
        mc.rows_out = 7

        mc.write_report()

        # Find the METRICS_RECORDED event in the ledger
        metrics_events = [
            e for e in gov.ledger_entries if e["action"] == "METRICS_RECORDED"
        ]
        self.assertEqual(len(metrics_events), 1)

        detail = metrics_events[0]["detail"]
        self.assertIn("total_duration_sec", detail)
        self.assertIn("rows_input", detail)
        self.assertIn("rows_output", detail)
        self.assertIn("rows_dlq", detail)
        self.assertIn("error_rate", detail)
        self.assertIn("overall_rows_per_sec", detail)
        self.assertIn("stages", detail)

        self.assertEqual(detail["rows_input"], 7)
        self.assertEqual(detail["rows_output"], 7)
        self.assertEqual(detail["rows_dlq"], 0)

        stages = detail["stages"]
        self.assertIn("extract", stages)
        self.assertIn("transform", stages)
        self.assertIn("load", stages)

        for stage_name in ("extract", "transform", "load"):
            self.assertIn("duration_sec", stages[stage_name])
            self.assertIn("rows", stages[stage_name])
            self.assertIn("rows_per_sec", stages[stage_name])


if __name__ == "__main__":
    unittest.main()
