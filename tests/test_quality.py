"""
Tests for the quality sub-package modules.

Covers: DataQualityScorer, DataContractEnforcer, DataDiffReporter,
QualityAnomalyAlerter, SchemaEvolver, SyntheticDataGenerator, ColumnProfiler.

Revision history
────────────────
1.0   2026-06-08   Initial release — 37 tests across 7 quality modules.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd


# ── MockGov helper ────────────────────────────────────────────────────────────
# Lightweight stand-in for GovernanceLogger; records transformation_applied
# calls so tests can assert on governance events without disk I/O.


def _make_gov(tmpdir: str) -> MagicMock:
    gov = MagicMock()
    gov.log_dir = Path(tmpdir)
    gov.transformation_applied = MagicMock()
    gov.quality_log_file = str(Path(tmpdir) / "quality_history.jsonl")
    gov.error = MagicMock()
    return gov


# ═══════════════════════════════════════════════════════════════════════════════
#  1. DataQualityScorer
# ═══════════════════════════════════════════════════════════════════════════════


class TestDataQualityScorer(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_composite_score_in_range(self):
        """Composite score is between 0 and 100."""
        from pipeline.quality.data_quality_scorer import DataQualityScorer
        scorer = DataQualityScorer(self.gov, history_file=Path(self.tmpdir) / "h.jsonl")
        df = pd.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]})
        result = scorer.score(df)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_perfect_dataframe_scores_high(self):
        """A clean, complete DataFrame with no nulls or dupes scores >= 90."""
        from pipeline.quality.data_quality_scorer import DataQualityScorer
        scorer = DataQualityScorer(self.gov, history_file=Path(self.tmpdir) / "h.jsonl")
        df = pd.DataFrame({"id": range(100), "val": range(100, 200)})
        result = scorer.score(df)
        self.assertGreaterEqual(result["score"], 90)
        self.assertEqual(result["grade"], "A")

    def test_all_null_dataframe_scores_low_completeness(self):
        """A fully-null DataFrame gets 0 for completeness."""
        from pipeline.quality.data_quality_scorer import DataQualityScorer
        scorer = DataQualityScorer(self.gov, history_file=Path(self.tmpdir) / "h.jsonl")
        df = pd.DataFrame({"a": [None, None, None], "b": [None, None, None]})
        result = scorer.score(df)
        self.assertEqual(result["dimensions"]["completeness"], 0.0)
        self.assertLess(result["score"], 80)

    def test_weight_overrides_change_score(self):
        """Custom weights shift the composite score."""
        from pipeline.quality.data_quality_scorer import DataQualityScorer
        df = pd.DataFrame({"a": [None, None, None], "b": [1, 2, 3]})

        # Default weights
        scorer_default = DataQualityScorer(
            self.gov, history_file=Path(self.tmpdir) / "h1.jsonl"
        )
        score_default = scorer_default.score(df)["score"]

        # Heavily weight completeness (where this df is weak)
        scorer_custom = DataQualityScorer(
            self.gov,
            history_file=Path(self.tmpdir) / "h2.jsonl",
            weights={"completeness": 0.90, "uniqueness": 0.025,
                     "validity": 0.025, "consistency": 0.025, "timeliness": 0.025},
        )
        score_custom = scorer_custom.score(df)["score"]
        self.assertNotEqual(score_default, score_custom)

    def test_score_includes_expected_keys(self):
        """Score report dict has all documented keys."""
        from pipeline.quality.data_quality_scorer import DataQualityScorer
        scorer = DataQualityScorer(self.gov, history_file=Path(self.tmpdir) / "h.jsonl")
        df = pd.DataFrame({"a": [1]})
        result = scorer.score(df, run_label="test-run")
        for key in ("score", "grade", "dimensions", "rows", "columns",
                     "run_label", "generated_utc"):
            self.assertIn(key, result)

    def test_dry_run_does_not_write_history(self):
        """dry_run=True skips the history file write."""
        from pipeline.quality.data_quality_scorer import DataQualityScorer
        hfile = Path(self.tmpdir) / "h.jsonl"
        scorer = DataQualityScorer(self.gov, history_file=hfile, dry_run=True)
        scorer.score(pd.DataFrame({"a": [1]}))
        self.assertFalse(hfile.exists())

    def test_trend_returns_history(self):
        """trend() reads back persisted score records."""
        from pipeline.quality.data_quality_scorer import DataQualityScorer
        hfile = Path(self.tmpdir) / "h.jsonl"
        scorer = DataQualityScorer(self.gov, history_file=hfile)
        scorer.score(pd.DataFrame({"a": [1, 2]}))
        scorer.score(pd.DataFrame({"a": [3, 4]}))
        records = scorer.trend(n=10)
        self.assertEqual(len(records), 2)


# ═══════════════════════════════════════════════════════════════════════════════
#  2. DataContractEnforcer
# ═══════════════════════════════════════════════════════════════════════════════


class TestDataContractEnforcer(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_contract(self, content: dict) -> Path:
        import yaml
        path = Path(self.tmpdir) / "contract.yaml"
        path.write_text(yaml.dump(content), encoding="utf-8")
        return path

    def test_required_columns_pass(self):
        """No violations when all required columns are present."""
        from pipeline.quality.data_contract_enforcer import DataContractEnforcer
        contract = {"schema": {"require_columns": ["id", "name"]}}
        path = self._write_contract(contract)
        enforcer = DataContractEnforcer(
            self.gov, path,
            violation_log=Path(self.tmpdir) / "v.jsonl",
        )
        df = pd.DataFrame({"id": [1], "name": ["alice"]})
        viols = enforcer.check(df)
        schema_viols = [v for v in viols if v["rule"] == "require_columns"]
        self.assertEqual(len(schema_viols), 0)

    def test_missing_required_column_violation(self):
        """Missing a required column produces a CRITICAL violation."""
        from pipeline.quality.data_contract_enforcer import DataContractEnforcer
        contract = {"schema": {"require_columns": ["id", "name", "email"]}}
        path = self._write_contract(contract)
        enforcer = DataContractEnforcer(
            self.gov, path,
            violation_log=Path(self.tmpdir) / "v.jsonl",
        )
        df = pd.DataFrame({"id": [1], "name": ["alice"]})
        viols = enforcer.check(df)
        missing = [v for v in viols if v["rule"] == "require_columns"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["column"], "email")
        self.assertEqual(missing[0]["severity"], "CRITICAL")

    def test_column_dtype_mismatch_violation(self):
        """Wrong dtype triggers an ERROR violation."""
        from pipeline.quality.data_contract_enforcer import DataContractEnforcer
        contract = {
            "schema": {
                "columns": {
                    "age": {"dtype": "int64"},
                },
            },
        }
        path = self._write_contract(contract)
        enforcer = DataContractEnforcer(
            self.gov, path,
            violation_log=Path(self.tmpdir) / "v.jsonl",
        )
        df = pd.DataFrame({"age": ["thirty", "forty"]})
        viols = enforcer.check(df)
        dtype_viols = [v for v in viols if v["rule"] == "dtype"]
        self.assertTrue(len(dtype_viols) >= 1)
        self.assertEqual(dtype_viols[0]["severity"], "ERROR")

    def test_enforce_raises_on_critical(self):
        """enforce() raises ContractViolationError for CRITICAL violations."""
        from pipeline.exceptions import ContractViolationError
        from pipeline.quality.data_contract_enforcer import DataContractEnforcer
        contract = {"schema": {"require_columns": ["missing_col"]}}
        path = self._write_contract(contract)
        enforcer = DataContractEnforcer(
            self.gov, path,
            violation_log=Path(self.tmpdir) / "v.jsonl",
        )
        df = pd.DataFrame({"other": [1]})
        with self.assertRaises(ContractViolationError):
            enforcer.enforce(df)

    def test_warn_only_does_not_raise(self):
        """warn_only=True logs violations but does not raise."""
        from pipeline.quality.data_contract_enforcer import DataContractEnforcer
        contract = {"schema": {"require_columns": ["missing_col"]}}
        path = self._write_contract(contract)
        enforcer = DataContractEnforcer(
            self.gov, path,
            violation_log=Path(self.tmpdir) / "v.jsonl",
            warn_only=True,
        )
        df = pd.DataFrame({"other": [1]})
        warnings = enforcer.enforce(df)
        self.assertIsInstance(warnings, list)

    def test_sla_min_rows_violation(self):
        """Too few rows triggers a CRITICAL SLA violation."""
        from pipeline.quality.data_contract_enforcer import DataContractEnforcer
        contract = {"sla": {"min_rows": 100}}
        path = self._write_contract(contract)
        enforcer = DataContractEnforcer(
            self.gov, path,
            violation_log=Path(self.tmpdir) / "v.jsonl",
            warn_only=True,
        )
        df = pd.DataFrame({"a": [1, 2, 3]})
        viols = enforcer.check(df)
        sla_viols = [v for v in viols if v["rule"] == "min_rows"]
        self.assertEqual(len(sla_viols), 1)
        self.assertEqual(sla_viols[0]["severity"], "CRITICAL")


# ═══════════════════════════════════════════════════════════════════════════════
#  3. DataDiffReporter
# ═══════════════════════════════════════════════════════════════════════════════


class TestDataDiffReporter(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_identical_dataframes_no_diffs(self):
        """Identical DataFrames produce zero adds, deletes, or changes."""
        from pipeline.quality.data_diff_reporter import DataDiffReporter
        reporter = DataDiffReporter(self.gov)
        df = pd.DataFrame({"id": [1, 2, 3], "val": ["a", "b", "c"]})
        diff = reporter.compare(df, df, key_columns=["id"])
        self.assertEqual(diff["rows_added"], 0)
        self.assertEqual(diff["rows_deleted"], 0)
        self.assertEqual(diff["rows_changed"], 0)

    def test_added_rows_detected(self):
        """New rows in df_new are reported as additions."""
        from pipeline.quality.data_diff_reporter import DataDiffReporter
        reporter = DataDiffReporter(self.gov)
        df_old = pd.DataFrame({"id": [1, 2], "val": ["a", "b"]})
        df_new = pd.DataFrame({"id": [1, 2, 3], "val": ["a", "b", "c"]})
        diff = reporter.compare(df_old, df_new, key_columns=["id"])
        self.assertEqual(diff["rows_added"], 1)
        self.assertIn("3", diff["added_keys"])

    def test_removed_rows_detected(self):
        """Rows missing from df_new are reported as deletions."""
        from pipeline.quality.data_diff_reporter import DataDiffReporter
        reporter = DataDiffReporter(self.gov)
        df_old = pd.DataFrame({"id": [1, 2, 3], "val": ["a", "b", "c"]})
        df_new = pd.DataFrame({"id": [1, 3], "val": ["a", "c"]})
        diff = reporter.compare(df_old, df_new, key_columns=["id"])
        self.assertEqual(diff["rows_deleted"], 1)
        self.assertIn("2", diff["deleted_keys"])

    def test_changed_values_detected(self):
        """Modified cell values are reported as changed rows."""
        from pipeline.quality.data_diff_reporter import DataDiffReporter
        reporter = DataDiffReporter(self.gov)
        df_old = pd.DataFrame({"id": [1, 2], "val": ["a", "b"]})
        df_new = pd.DataFrame({"id": [1, 2], "val": ["a", "CHANGED"]})
        diff = reporter.compare(df_old, df_new, key_columns=["id"])
        self.assertEqual(diff["rows_changed"], 1)
        changed = diff["changed_rows"][0]
        self.assertIn("val", changed["changes"])

    def test_save_writes_json_file(self):
        """save() persists the diff report as a JSON file."""
        from pipeline.quality.data_diff_reporter import DataDiffReporter
        reporter = DataDiffReporter(self.gov)
        df = pd.DataFrame({"id": [1]})
        diff = reporter.compare(df, df, key_columns=["id"])
        path = reporter.save(diff)
        self.assertTrue(path.exists())
        content = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("rows_added", content)


# ═══════════════════════════════════════════════════════════════════════════════
#  4. QualityAnomalyAlerter
# ═══════════════════════════════════════════════════════════════════════════════


class TestQualityAnomalyAlerter(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_history(self, records: list[dict]) -> Path:
        hfile = Path(self.tmpdir) / "quality_history.jsonl"
        with open(hfile, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        return hfile

    def test_score_drop_triggers_alert(self):
        """A drop exceeding the threshold fires a THRESHOLD_DROP alert."""
        from pipeline.quality.quality_anomaly_alerter import QualityAnomalyAlerter
        hfile = self._write_history([
            {"score": 90, "dimensions": {}},
            {"score": 70, "dimensions": {}},
        ])
        alerter = QualityAnomalyAlerter(
            gov=self.gov,
            drop_threshold=10.0,
            history_file=hfile,
            alert_log_file=Path(self.tmpdir) / "alerts.jsonl",
        )
        # current_report is the latest; previous is second-to-last in history
        current = {"score": 70, "dimensions": {}}
        alerts = alerter.check(current)
        types = [a["type"] for a in alerts]
        self.assertIn("THRESHOLD_DROP", types)

    def test_stable_scores_no_alert(self):
        """Stable scores with no decline produce zero alerts."""
        from pipeline.quality.quality_anomaly_alerter import QualityAnomalyAlerter
        hfile = self._write_history([
            {"score": 95, "dimensions": {}},
            {"score": 95, "dimensions": {}},
        ])
        alerter = QualityAnomalyAlerter(
            gov=self.gov,
            drop_threshold=10.0,
            history_file=hfile,
            alert_log_file=Path(self.tmpdir) / "alerts.jsonl",
        )
        current = {"score": 95, "dimensions": {}}
        alerts = alerter.check(current)
        self.assertEqual(len(alerts), 0)

    def test_floor_breach_alert(self):
        """Score below the absolute floor fires FLOOR_BREACH."""
        from pipeline.quality.quality_anomaly_alerter import QualityAnomalyAlerter
        hfile = self._write_history([])
        alerter = QualityAnomalyAlerter(
            gov=self.gov,
            absolute_floor=60.0,
            history_file=hfile,
            alert_log_file=Path(self.tmpdir) / "alerts.jsonl",
        )
        current = {"score": 45, "dimensions": {}}
        alerts = alerter.check(current)
        types = [a["type"] for a in alerts]
        self.assertIn("FLOOR_BREACH", types)

    def test_dimension_spike_alert(self):
        """A single dimension dropping beyond threshold fires DIMENSION_SPIKE."""
        from pipeline.quality.quality_anomaly_alerter import QualityAnomalyAlerter
        hfile = self._write_history([
            {"score": 85, "dimensions": {"completeness": 95}},
            {"score": 82, "dimensions": {"completeness": 70}},
        ])
        alerter = QualityAnomalyAlerter(
            gov=self.gov,
            dimension_threshold=15.0,
            history_file=hfile,
            alert_log_file=Path(self.tmpdir) / "alerts.jsonl",
        )
        current = {"score": 82, "dimensions": {"completeness": 70}}
        alerts = alerter.check(current)
        types = [a["type"] for a in alerts]
        self.assertIn("DIMENSION_SPIKE", types)

    def test_slack_webhook_called(self):
        """When slack_webhook is set, _alert_slack is invoked on alert."""
        from pipeline.quality.quality_anomaly_alerter import QualityAnomalyAlerter
        hfile = self._write_history([])
        alerter = QualityAnomalyAlerter(
            gov=self.gov,
            absolute_floor=80.0,
            slack_webhook="https://hooks.example.com/test",
            history_file=hfile,
            alert_log_file=Path(self.tmpdir) / "alerts.jsonl",
        )
        with patch.object(alerter, "_alert_slack") as mock_slack:
            alerter.check({"score": 50, "dimensions": {}})
            mock_slack.assert_called()

    def test_webhook_url_called(self):
        """When webhook_url is set, _alert_webhook is invoked on alert."""
        from pipeline.quality.quality_anomaly_alerter import QualityAnomalyAlerter
        hfile = self._write_history([])
        alerter = QualityAnomalyAlerter(
            gov=self.gov,
            absolute_floor=80.0,
            webhook_url="https://webhook.example.com/test",
            history_file=hfile,
            alert_log_file=Path(self.tmpdir) / "alerts.jsonl",
        )
        with patch.object(alerter, "_alert_webhook") as mock_hook:
            alerter.check({"score": 50, "dimensions": {}})
            mock_hook.assert_called()


# ═══════════════════════════════════════════════════════════════════════════════
#  5. SchemaEvolver
# ═══════════════════════════════════════════════════════════════════════════════


class TestSchemaEvolver(unittest.TestCase):
    """Uses an in-memory SQLite database via sqlalchemy for isolation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

        from sqlalchemy import create_engine, text
        self.engine = create_engine("sqlite:///:memory:")
        with self.engine.begin() as conn:
            conn.execute(text(
                'CREATE TABLE employees ("id" INTEGER, "name" TEXT, "salary" REAL)'
            ))

    def tearDown(self):
        self.engine.dispose()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_new_column_detected_and_added(self):
        """A column present in the DataFrame but not in the table is added."""
        from pipeline.quality.schema_evolver import SchemaEvolver
        evolver = SchemaEvolver(self.gov, self.engine)
        df = pd.DataFrame({
            "id": [1], "name": ["alice"], "salary": [50000.0], "department": ["eng"],
        })
        report = evolver.evolve(df, table_name="employees")
        self.assertIn("department", report["columns_added"])

    def test_dropped_column_detected(self):
        """A column in the table but missing from the DataFrame is dropped when requested."""
        from pipeline.quality.schema_evolver import SchemaEvolver
        evolver = SchemaEvolver(self.gov, self.engine)
        # DataFrame lacks the 'salary' column
        df = pd.DataFrame({"id": [1], "name": ["alice"]})
        report = evolver.evolve(df, table_name="employees", drop_missing=True)
        self.assertIn("salary", report["columns_dropped"])

    def test_type_change_logged_as_missing_from_source(self):
        """When drop_missing=False, missing columns are logged but not dropped."""
        from pipeline.quality.schema_evolver import SchemaEvolver
        evolver = SchemaEvolver(self.gov, self.engine)
        df = pd.DataFrame({"id": [1], "name": ["alice"]})
        report = evolver.evolve(df, table_name="employees", drop_missing=False)
        self.assertEqual(len(report["columns_dropped"]), 0)
        # Governance logger should have been called for the missing column
        calls = [
            c for c in self.gov.transformation_applied.call_args_list
            if c[0][0] == "SCHEMA_COLUMN_MISSING_FROM_SOURCE"
        ]
        self.assertTrue(len(calls) >= 1)

    def test_unchanged_columns_tracked(self):
        """Columns that exist in both table and DataFrame appear as unchanged."""
        from pipeline.quality.schema_evolver import SchemaEvolver
        evolver = SchemaEvolver(self.gov, self.engine)
        df = pd.DataFrame({"id": [1], "name": ["alice"], "salary": [50000.0]})
        report = evolver.evolve(df, table_name="employees")
        self.assertEqual(len(report["columns_added"]), 0)
        self.assertIn("id", report["columns_unchanged"])
        self.assertIn("name", report["columns_unchanged"])


# ═══════════════════════════════════════════════════════════════════════════════
#  6. SyntheticDataGenerator
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyntheticDataGenerator(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generates_correct_column_count(self):
        """Output DataFrame has the same columns as the source."""
        from pipeline.quality.synthetic_data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(self.gov)
        source = pd.DataFrame({"id": [1, 2], "name": ["alice", "bob"], "score": [88, 92]})
        result = gen.generate(source, n_rows=5)
        self.assertEqual(list(result.columns), list(source.columns))

    def test_generates_requested_row_count(self):
        """Output DataFrame has the exact number of rows requested."""
        from pipeline.quality.synthetic_data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(self.gov)
        source = pd.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]})
        result = gen.generate(source, n_rows=50)
        self.assertEqual(len(result), 50)

    def test_output_is_dataframe(self):
        """Output is a valid pandas DataFrame."""
        from pipeline.quality.synthetic_data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(self.gov)
        source = pd.DataFrame({"val": [10, 20, 30]})
        result = gen.generate(source, n_rows=10)
        self.assertIsInstance(result, pd.DataFrame)

    def test_save_csv(self):
        """save() writes a valid CSV file to disk."""
        from pipeline.quality.synthetic_data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(self.gov)
        source = pd.DataFrame({"a": [1], "b": ["x"]})
        fake = gen.generate(source, n_rows=5)
        out_path = str(Path(self.tmpdir) / "synthetic.csv")
        gen.save(fake, out_path, fmt="csv")
        loaded = pd.read_csv(out_path)
        self.assertEqual(len(loaded), 5)

    def test_pii_column_uses_faker(self):
        """Columns named 'email' produce string values (Faker-generated)."""
        from pipeline.quality.synthetic_data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(self.gov)
        source = pd.DataFrame({"email": ["alice@example.com", "bob@example.com"]})
        result = gen.generate(source, n_rows=3)
        for val in result["email"]:
            self.assertIsInstance(val, str)
            self.assertIn("@", val)


# ═══════════════════════════════════════════════════════════════════════════════
#  7. ColumnProfiler
# ═══════════════════════════════════════════════════════════════════════════════


class TestColumnProfiler(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_numeric_min_max_mean(self):
        """Numeric column profile contains correct min, max, mean."""
        from pipeline.quality.column_profiler import ColumnProfiler
        profiler = ColumnProfiler(self.gov, history_file=Path(self.tmpdir) / "p.jsonl")
        df = pd.DataFrame({"score": [10, 20, 30, 40, 50]})
        report = profiler.profile(df, dataset_name="test")
        col = report["columns"][0]
        self.assertEqual(col["min"], 10.0)
        self.assertEqual(col["max"], 50.0)
        self.assertEqual(col["mean"], 30.0)

    def test_string_min_max_length(self):
        """String column profile has correct min_length and max_length."""
        from pipeline.quality.column_profiler import ColumnProfiler
        profiler = ColumnProfiler(self.gov, history_file=Path(self.tmpdir) / "p.jsonl")
        df = pd.DataFrame({"tag": ["ab", "abcde", "abc"]})
        report = profiler.profile(df, dataset_name="test")
        col = report["columns"][0]
        self.assertEqual(col["min_length"], 2)
        self.assertEqual(col["max_length"], 5)

    def test_null_counts_correct(self):
        """Null count and null rate are computed correctly."""
        from pipeline.quality.column_profiler import ColumnProfiler
        profiler = ColumnProfiler(self.gov, history_file=Path(self.tmpdir) / "p.jsonl")
        df = pd.DataFrame({"val": [1, None, 3, None, 5]})
        report = profiler.profile(df, dataset_name="test")
        col = report["columns"][0]
        self.assertEqual(col["null_count"], 2)
        self.assertAlmostEqual(col["null_rate"], 0.4, places=2)

    def test_empty_dataframe_returns_minimal_profile(self):
        """An empty DataFrame returns a profile with row_count=0."""
        from pipeline.quality.column_profiler import ColumnProfiler
        profiler = ColumnProfiler(self.gov, history_file=Path(self.tmpdir) / "p.jsonl")
        df = pd.DataFrame({"a": pd.Series([], dtype="int64")})
        report = profiler.profile(df, dataset_name="empty")
        self.assertEqual(report["row_count"], 0)
        self.assertEqual(report["columns"], [])

    def test_dry_run_skips_history_write(self):
        """dry_run=True does not write to the history file."""
        from pipeline.quality.column_profiler import ColumnProfiler
        hfile = Path(self.tmpdir) / "p.jsonl"
        profiler = ColumnProfiler(self.gov, history_file=hfile, dry_run=True)
        profiler.profile(pd.DataFrame({"a": [1, 2]}), dataset_name="test")
        self.assertFalse(hfile.exists())

    def test_profile_report_structure(self):
        """Profile report contains all documented top-level keys."""
        from pipeline.quality.column_profiler import ColumnProfiler
        profiler = ColumnProfiler(self.gov, history_file=Path(self.tmpdir) / "p.jsonl")
        df = pd.DataFrame({"x": [1, 2, 3]})
        report = profiler.profile(df, dataset_name="test")
        for key in ("dataset_name", "row_count", "column_count",
                     "generated_utc", "columns"):
            self.assertIn(key, report)


if __name__ == "__main__":
    unittest.main()
