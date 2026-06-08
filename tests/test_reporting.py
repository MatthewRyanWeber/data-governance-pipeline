"""
Tests for pipeline.reporting — ReportWriter, HTMLReportGenerator,
CostEstimator, and LineageGraphGenerator.

Revision history
────────────────
1.0   2026-06-08   Initial release: 17 tests across 4 classes.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pipeline.governance_logger import GovernanceLogger
from pipeline.reporting.report_writer import ReportWriter
from pipeline.reporting.html_report_generator import HTMLReportGenerator
from pipeline.reporting.cost_estimator import CostEstimator
from pipeline.reporting.lineage_graph_generator import LineageGraphGenerator


class TestReportWriter(unittest.TestCase):
    """ReportWriter writes structured JSON governance reports."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("report_test", log_dir=self.tmp)
        self.writer = ReportWriter(self.gov)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_pii_report_creates_file(self):
        self.gov.pii_findings.append({
            "field": "email", "pattern": "email", "special_category": False,
        })
        self.writer.write_pii_report()
        self.assertTrue(self.gov.pii_report_file.exists())
        report = json.loads(self.gov.pii_report_file.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["total_pii_fields"], 1)

    def test_write_validation_report_creates_file(self):
        self.gov.validation_results.append({"name": "not_null", "success": True})
        self.gov.validation_results.append({"name": "range_check", "success": False})
        self.writer.write_validation_report()
        self.assertTrue(self.gov.validation_rpt_file.exists())
        report = json.loads(self.gov.validation_rpt_file.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["summary"]["failed"], 1)

    def test_write_profile_report_creates_file(self):
        profile = {"columns": {"age": {"min": 18, "max": 99}}}
        self.writer.write_profile_report(profile)
        self.assertTrue(self.gov.profile_rpt_file.exists())

    def test_write_metrics_report_creates_file(self):
        metrics = {"total_duration_sec": 5.2, "rows_output": 100}
        self.writer.write_metrics_report(metrics)
        self.assertTrue(self.gov.metrics_rpt_file.exists())

    def test_write_classification_report_creates_file(self):
        self.gov.classification_tags.append({"level": "CONFIDENTIAL"})
        self.writer.write_classification_report()
        self.assertTrue(self.gov.classification_file.exists())

    def test_write_transfer_log_creates_file(self):
        self.gov.transfer_events.append({"dest": "EU", "type": "INTRA_EU"})
        self.writer.write_transfer_log()
        self.assertTrue(self.gov.transfer_log_file.exists())

    def test_dry_run_does_not_create_files(self):
        dry_gov = GovernanceLogger("dry_rpt", log_dir=self.tmp, dry_run=True)
        writer = ReportWriter(dry_gov)
        writer.write_pii_report()
        self.assertFalse(dry_gov.pii_report_file.exists())


class TestHTMLReportGenerator(unittest.TestCase):
    """HTMLReportGenerator produces valid HTML."""

    def setUp(self):
        import pandas as pd
        self.pd = pd
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("html_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_generate_creates_html_file(self):
        df = self.pd.DataFrame({"name": ["alice", "bob"], "age": [30, 40]})
        gen = HTMLReportGenerator(self.gov)
        path = gen.generate(df, run_meta={"source": "synth.csv", "destination": "sqlite"})
        self.assertTrue(Path(path).exists())
        content = Path(path).read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("Pipeline Run Report", content)

    def test_generate_includes_quality_score(self):
        df = self.pd.DataFrame({"value": [1, 2, 3]})
        gen = HTMLReportGenerator(self.gov)
        quality = {"score": 85, "dimensions": {"completeness": 90, "accuracy": 80}}
        path = gen.generate(
            df, run_meta={"source": "x.csv", "destination": "sqlite"},
            quality=quality,
        )
        content = Path(path).read_text(encoding="utf-8")
        self.assertIn("85", content)

    def test_generate_with_diff_report(self):
        df = self.pd.DataFrame({"x": [1]})
        gen = HTMLReportGenerator(self.gov)
        diff = {
            "rows_changed": 5, "rows_added": 2, "rows_deleted": 1,
            "column_change_counts": {"x": 3, "y": 2},
        }
        path = gen.generate(
            df, run_meta={"source": "x.csv", "destination": "sqlite"},
            diff=diff,
        )
        content = Path(path).read_text(encoding="utf-8")
        self.assertIn("5", content)


class TestCostEstimator(unittest.TestCase):
    """CostEstimator computes per-run cost breakdowns."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("cost_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_snowflake_estimate(self):
        est = CostEstimator(self.gov, cost_log=Path(self.tmp) / "cost.jsonl")
        report = est.estimate(
            db_type="snowflake", elapsed_seconds=120, rows_processed=1000,
            bytes_processed=1_000_000, bytes_written=500_000,
            warehouse_size="Small",
        )
        self.assertGreater(report["total_usd"], 0)
        self.assertEqual(report["breakdown"]["platform"], "snowflake")
        self.assertEqual(report["breakdown"]["warehouse_size"], "Small")

    def test_bigquery_estimate(self):
        est = CostEstimator(self.gov, cost_log=Path(self.tmp) / "cost.jsonl")
        report = est.estimate(
            db_type="bigquery", elapsed_seconds=60, rows_processed=5000,
            bytes_processed=10_000_000_000, bytes_written=1_000_000_000,
        )
        self.assertEqual(report["breakdown"]["platform"], "bigquery")
        self.assertGreater(report["total_usd"], 0)

    def test_redshift_estimate(self):
        est = CostEstimator(self.gov, cost_log=Path(self.tmp) / "cost.jsonl")
        report = est.estimate(
            db_type="redshift", elapsed_seconds=300, rows_processed=10000,
            bytes_written=5_000_000_000,
            node_type="ra3.xlplus", num_nodes=2,
        )
        self.assertEqual(report["breakdown"]["platform"], "redshift")
        self.assertEqual(report["breakdown"]["num_nodes"], 2)

    def test_generic_estimate_for_unknown_platform(self):
        est = CostEstimator(self.gov, cost_log=Path(self.tmp) / "cost.jsonl")
        report = est.estimate(
            db_type="mysql", elapsed_seconds=30, rows_processed=500,
            bytes_processed=100_000,
        )
        self.assertEqual(report["breakdown"]["platform"], "generic")

    def test_budget_warning(self):
        est = CostEstimator(
            self.gov, cost_log=Path(self.tmp) / "cost.jsonl",
            warn_budget=0.001,
        )
        est.estimate(
            db_type="snowflake", elapsed_seconds=3600, rows_processed=1_000_000,
            bytes_processed=10_000_000_000, bytes_written=5_000_000_000,
            warehouse_size="X-Large",
        )
        events = self.gov.ledger_entries
        budget_events = [
            e for e in events if "COST_BUDGET_EXCEEDED" in str(e.get("action", ""))
        ]
        self.assertGreater(len(budget_events), 0)

    def test_history_and_cumulative(self):
        cost_log = Path(self.tmp) / "cost.jsonl"
        est = CostEstimator(self.gov, cost_log=cost_log)
        est.estimate(db_type="snowflake", elapsed_seconds=60, rows_processed=100)
        est.estimate(db_type="bigquery", elapsed_seconds=30, rows_processed=200)
        history = est.history()
        self.assertEqual(len(history), 2)
        cumulative = est.cumulative_cost()
        self.assertEqual(cumulative["run_count"], 2)
        self.assertGreater(cumulative["total_usd"], 0)


class TestLineageGraphGenerator(unittest.TestCase):
    """LineageGraphGenerator builds lineage graph from ledger events."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("lineage_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_ledger_generates_html(self):
        gen = LineageGraphGenerator(self.gov)
        path = gen.generate(output_path=str(Path(self.tmp) / "lineage.html"))
        self.assertTrue(Path(path).exists())
        content = Path(path).read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("Data Lineage", content)

    def test_build_graph_returns_nodes_and_edges(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        self.gov.transformation_applied("SOURCE_REGISTERED", {
            "source_path": "synth.csv", "file_type": "csv",
            "row_count": 100, "col_count": 3, "sha256": "abc123",
        })
        gen = LineageGraphGenerator(self.gov)
        nodes, edges = gen._build_graph()
        source_nodes = [n for n in nodes if n["type"] == "source"]
        self.assertEqual(len(source_nodes), 1)


if __name__ == "__main__":
    unittest.main()
