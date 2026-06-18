"""
Tests for pipeline.monitoring.metrics_exporter.DataQualityMetricsExporter.

Covers Prometheus text-exposition rendering (labels, escaping, conditional
families), the run-summary aggregation, atomic/dry-run file writes, and the
end-to-end DataObserver.export_metrics path driven from observation history.

Revision history
────────────────
1.0   2026-06-18   Initial release.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from pipeline.governance_logger import GovernanceLogger
from pipeline.monitoring.metrics_exporter import DataQualityMetricsExporter
from pipeline.monitoring.observability import DataObserver


_REPORTS = [
    {
        "dataset": "orders",
        "row_count": 1000,
        "column_count": 5,
        "alert_count": 2,
        "alerts": [{"type": "VOLUME"}, {"type": "NULL_SPIKE"}],
        "duplicate_key_rate": 0.02,
        "column_stats": [
            {"name": "id", "null_rate": 0.0},
            {"name": "email", "null_rate": 0.1},
        ],
    },
    {
        "dataset": "customers",
        "row_count": 50,
        "column_count": 3,
        "alert_count": 0,
        "alerts": [],
        "column_stats": [{"name": "name", "null_rate": 0.0}],
    },
]


class TestRenderPrometheus(unittest.TestCase):
    def setUp(self):
        self.exporter = DataQualityMetricsExporter()

    def test_emits_help_and_type_once_per_family(self):
        text = self.exporter.render_prometheus(_REPORTS)
        self.assertEqual(text.count("# TYPE dgp_observed_rows gauge"), 1)
        self.assertEqual(text.count("# HELP dgp_observed_rows"), 1)

    def test_row_and_column_gauges_present(self):
        text = self.exporter.render_prometheus(_REPORTS)
        self.assertIn('dgp_observed_rows{dataset="orders"} 1000', text)
        self.assertIn('dgp_observed_columns{dataset="customers"} 3', text)

    def test_alerts_broken_out_by_type(self):
        text = self.exporter.render_prometheus(_REPORTS)
        self.assertIn('dgp_alerts_by_type{dataset="orders",type="VOLUME"} 1', text)
        self.assertIn('dgp_alerts_by_type{dataset="orders",type="NULL_SPIKE"} 1', text)

    def test_duplicate_key_rate_only_when_present(self):
        text = self.exporter.render_prometheus(_REPORTS)
        self.assertIn('dgp_duplicate_key_rate{dataset="orders"}', text)
        # customers has no duplicate_key_rate key → no series for it
        self.assertNotIn('dgp_duplicate_key_rate{dataset="customers"}', text)

    def test_column_null_rate_series(self):
        text = self.exporter.render_prometheus(_REPORTS)
        self.assertIn('dgp_column_null_rate{dataset="orders",column="email"} 0.1', text)

    def test_empty_reports_render_empty(self):
        self.assertEqual(self.exporter.render_prometheus([]), "")

    def test_label_values_escaped(self):
        reports = [{"dataset": 'we"ird\\name', "row_count": 1, "column_count": 1}]
        text = self.exporter.render_prometheus(reports)
        self.assertIn(r'dataset="we\"ird\\name"', text)


class TestSummarize(unittest.TestCase):
    def test_summary_aggregates(self):
        summary = DataQualityMetricsExporter().summarize(_REPORTS)
        self.assertEqual(summary["datasets_observed"], 2)
        self.assertEqual(summary["total_rows"], 1050)
        self.assertEqual(summary["total_alerts"], 2)
        self.assertEqual(summary["alerts_by_type"], {"VOLUME": 1, "NULL_SPIKE": 1})
        self.assertEqual(summary["datasets_with_alerts"], ["orders"])


class TestFileWrites(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_textfile_creates_prom(self):
        path = Path(self.tmp) / "metrics" / "dgp.prom"
        DataQualityMetricsExporter().write_textfile(path, _REPORTS)
        self.assertTrue(path.exists())
        self.assertIn("dgp_observed_rows", path.read_text(encoding="utf-8"))

    def test_dry_run_writes_nothing(self):
        path = Path(self.tmp) / "dgp.prom"
        DataQualityMetricsExporter(dry_run=True).write_textfile(path, _REPORTS)
        self.assertFalse(path.exists())

    def test_write_summary_json(self):
        path = Path(self.tmp) / "summary.json"
        DataQualityMetricsExporter().write_summary_json(path, _REPORTS)
        loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["total_rows"], 1050)


class TestExportFromHistory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("metrics_export_test", log_dir=self.tmp)
        self.observer = DataObserver(self.gov)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_latest_reports_dedup_by_dataset_newest_first(self):
        # Two observations of the same dataset: the latest (newest) wins.
        self.observer.observe(pd.DataFrame({"id": [1, 2, 3]}), dataset="orders")
        self.observer.observe(pd.DataFrame({"id": [1, 2]}), dataset="orders")
        reports = DataQualityMetricsExporter().latest_reports_from_history(self.observer)
        orders = [r for r in reports if r["dataset"] == "orders"]
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0]["row_count"], 2)

    def test_export_metrics_writes_prom_and_summary(self):
        self.observer.observe(pd.DataFrame({"id": [1, 2, 3]}), dataset="orders")
        prom = Path(self.tmp) / "dgp.prom"
        summary = Path(self.tmp) / "summary.json"
        result = self.observer.export_metrics(prom, summary_path=summary)
        self.assertTrue(prom.exists())
        self.assertIn('dgp_observed_rows{dataset="orders"} 3', prom.read_text(encoding="utf-8"))
        self.assertEqual(result["datasets_observed"], 1)

    def test_export_metrics_empty_history(self):
        # No observations recorded → empty (but valid) output, no crash.
        prom = Path(self.tmp) / "dgp.prom"
        result = self.observer.export_metrics(prom)
        self.assertEqual(result["datasets_observed"], 0)


if __name__ == "__main__":
    unittest.main()
