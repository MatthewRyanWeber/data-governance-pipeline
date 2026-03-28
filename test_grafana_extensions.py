#!/usr/bin/env python3
"""
test_grafana_extensions.py  —  Unit tests for grafana_extensions.py

Covers all three Grafana integration classes:
    MetricsSink, PrometheusExporter, GrafanaDashboardGenerator

Run with:  python3 test_grafana_extensions.py  (or pytest)
"""
import json
import pathlib
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from grafana_extensions import (
    MetricsSink,
    PrometheusExporter,
    GrafanaDashboardGenerator,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_gov(tmp_dir: str) -> MagicMock:
    gov = MagicMock()
    gov.log_dir = tmp_dir
    gov._event  = MagicMock()
    return gov


class _TmpMixin(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.gov  = _make_gov(self._tmp)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)


# ═════════════════════════════════════════════════════════════════════════════
#  MetricsSink
# ═════════════════════════════════════════════════════════════════════════════

class TestMetricsSink(_TmpMixin):

    def _sink(self, **kw):
        return MetricsSink(self.gov, **kw)

    def _run_kwargs(self, **overrides):
        base = dict(
            run_id="run_001", source="employees.csv",
            destination="snowflake", rows_extracted=1000,
            rows_loaded=998, rows_failed=2,
            duration_sec=12.5, status="success", pii_columns=3,
        )
        base.update(overrides)
        return base

    # ── Database setup ────────────────────────────────────────────────────────

    def test_db_created_on_init(self):
        self.assertTrue(self._sink().db_path().exists())

    def test_all_tables_created(self):
        sink = self._sink()
        conn = sqlite3.connect(str(sink.db_path()))
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        for tbl in ("pipeline_runs", "stage_metrics",
                    "compliance_controls", "audit_summary"):
            self.assertIn(tbl, tables, f"Table {tbl} missing from metrics DB")

    def test_custom_db_path(self):
        custom = pathlib.Path(self._tmp) / "custom" / "metrics.db"
        MetricsSink(self.gov, db_path=custom)
        self.assertTrue(custom.exists())

    # ── record_run ────────────────────────────────────────────────────────────

    def test_record_run_inserts_row(self):
        sink = self._sink()
        sink.record_run(**self._run_kwargs())
        conn  = sqlite3.connect(str(sink.db_path()))
        count = conn.execute("SELECT COUNT(*) FROM pipeline_runs").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_record_run_values_correct(self):
        sink = self._sink()
        sink.record_run(**self._run_kwargs())
        conn = sqlite3.connect(str(sink.db_path()))
        row  = conn.execute(
            "SELECT run_id, source, destination, rows_extracted, "
            "rows_loaded, rows_failed, duration_sec, status, pii_columns "
            "FROM pipeline_runs"
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], "run_001")
        self.assertEqual(row[1], "employees.csv")
        self.assertEqual(row[2], "snowflake")
        self.assertEqual(row[3], 1000)
        self.assertEqual(row[4], 998)
        self.assertEqual(row[5], 2)
        self.assertAlmostEqual(row[6], 12.5, places=1)
        self.assertEqual(row[7], "success")
        self.assertEqual(row[8], 3)

    def test_record_run_multiple_rows(self):
        sink = self._sink()
        for i in range(5):
            sink.record_run(**self._run_kwargs(run_id=f"run_{i:03d}"))
        conn  = sqlite3.connect(str(sink.db_path()))
        count = conn.execute("SELECT COUNT(*) FROM pipeline_runs").fetchone()[0]
        conn.close()
        self.assertEqual(count, 5)

    def test_record_run_invalid_status_raises(self):
        sink = self._sink()
        with self.assertRaises(ValueError) as ctx:
            sink.record_run(**self._run_kwargs(status="unknown"))
        self.assertIn("status", str(ctx.exception))

    def test_record_run_with_stage_metrics(self):
        sink = self._sink()
        stages = {
            "extract":   {"rows": 1000, "elapsed": 3.2},
            "transform": {"rows": 998,  "elapsed": 1.1},
            "load":      {"rows": 998,  "elapsed": 8.2},
        }
        sink.record_run(**self._run_kwargs(stage_metrics=stages))
        conn  = sqlite3.connect(str(sink.db_path()))
        count = conn.execute("SELECT COUNT(*) FROM stage_metrics").fetchone()[0]
        conn.close()
        self.assertEqual(count, 3)

    def test_stage_rows_per_sec_calculated(self):
        sink = self._sink()
        sink.record_run(**self._run_kwargs(stage_metrics={
            "load": {"rows": 1000, "elapsed": 5.0},
        }))
        conn = sqlite3.connect(str(sink.db_path()))
        rps  = conn.execute(
            "SELECT rows_per_sec FROM stage_metrics WHERE stage='load'"
        ).fetchone()[0]
        conn.close()
        self.assertAlmostEqual(rps, 200.0, places=1)

    def test_record_run_fires_governance_event(self):
        sink = self._sink()
        sink.record_run(**self._run_kwargs())
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("RUN_RECORDED" in c for c in calls))

    def test_dry_run_does_not_write_db(self):
        sink = self._sink(dry_run=True)
        sink.record_run(**self._run_kwargs())
        conn  = sqlite3.connect(str(sink.db_path()))
        count = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 0)

    def test_warning_status_accepted(self):
        sink = self._sink()
        sink.record_run(**self._run_kwargs(status="warning"))
        conn = sqlite3.connect(str(sink.db_path()))
        row  = conn.execute("SELECT status FROM pipeline_runs").fetchone()
        conn.close()
        self.assertEqual(row[0], "warning")

    def test_error_status_with_message(self):
        sink = self._sink()
        sink.record_run(**self._run_kwargs(
            status="error", error_message="Connection refused"
        ))
        conn = sqlite3.connect(str(sink.db_path()))
        row  = conn.execute(
            "SELECT status, error_message FROM pipeline_runs"
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], "error")
        self.assertEqual(row[1], "Connection refused")

    # ── record_run_from_collector ─────────────────────────────────────────────

    def test_record_run_from_collector(self):
        sink = self._sink()
        mc   = MagicMock()
        mc._stages    = {
            "extract": {"rows": 500, "elapsed": 2.0},
            "load":    {"rows": 495, "elapsed": 5.0},
        }
        mc.rows_in    = 500
        mc.rows_out   = 495
        mc._run_start = time.monotonic() - 7.0

        sink.record_run_from_collector(
            mc, run_id="run_mc", source="test.csv", destination="sqlite"
        )
        conn = sqlite3.connect(str(sink.db_path()))
        row  = conn.execute(
            "SELECT rows_extracted, rows_loaded FROM pipeline_runs"
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], 500)
        self.assertEqual(row[1], 495)

    # ── record_controls ───────────────────────────────────────────────────────

    def test_record_controls_inserts_rows(self):
        sink    = self._sink()
        results = [
            {"control_id": "LOG_DIR_WRITABLE",   "status": "OK",
             "detail": "Writable", "checked_at": "2024-01-01T00:00:00"},
            {"control_id": "AUDIT_LEDGER_INTACT", "status": "WARN",
             "detail": "No files", "checked_at": "2024-01-01T00:00:00"},
            {"control_id": "BAA_REGISTRY_CURRENT","status": "FAIL",
             "detail": "Expired",  "checked_at": "2024-01-01T00:00:00"},
        ]
        sink.record_controls(results)
        conn  = sqlite3.connect(str(sink.db_path()))
        count = conn.execute(
            "SELECT COUNT(*) FROM compliance_controls"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 3)

    def test_record_controls_values_correct(self):
        sink = self._sink()
        sink.record_controls([{
            "control_id": "TEST_CTRL",
            "status":     "FAIL",
            "detail":     "Something broke",
            "checked_at": "2024-06-01T12:00:00",
        }])
        conn = sqlite3.connect(str(sink.db_path()))
        row  = conn.execute(
            "SELECT control_id, status, detail FROM compliance_controls"
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], "TEST_CTRL")
        self.assertEqual(row[1], "FAIL")
        self.assertEqual(row[2], "Something broke")

    def test_record_controls_dry_run(self):
        sink = self._sink(dry_run=True)
        sink.record_controls([{
            "control_id": "X", "status": "OK",
            "detail": "", "checked_at": "2024-01-01T00:00:00"
        }])
        conn  = sqlite3.connect(str(sink.db_path()))
        count = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 0)

    # ── summarise_ledger ──────────────────────────────────────────────────────

    def test_summarise_ledger_no_files_returns_empty(self):
        sink   = self._sink()
        result = sink.summarise_ledger()
        self.assertEqual(result, {})

    def test_summarise_ledger_counts_categories(self):
        ledger = pathlib.Path(self._tmp) / "audit_ledger_test.jsonl"
        events = [
            {"category": "EXTRACT",    "action": "A",
             "timestamp_utc": "2024-01-01T00:00:00+00:00", "level": "INFO"},
            {"category": "PRIVACY",    "action": "B",
             "timestamp_utc": "2024-01-01T01:00:00+00:00", "level": "INFO"},
            {"category": "COMPLIANCE", "action": "C",
             "timestamp_utc": "2024-01-01T02:00:00+00:00", "level": "ERROR"},
            {"category": "LOAD",       "action": "D",
             "timestamp_utc": "2024-01-01T03:00:00+00:00", "level": "INFO"},
        ]
        with ledger.open("w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        sink   = self._sink()
        result = sink.summarise_ledger()

        self.assertEqual(result["total_events"],      4)
        self.assertEqual(result["extract_events"],    1)
        self.assertEqual(result["privacy_events"],    1)
        self.assertEqual(result["compliance_events"], 1)
        self.assertEqual(result["load_events"],       1)
        self.assertEqual(result["error_events"],      1)

    def test_summarise_ledger_writes_to_db(self):
        ledger = pathlib.Path(self._tmp) / "audit_ledger_test.jsonl"
        ledger.write_text(
            json.dumps({
                "category": "EXTRACT", "action": "A",
                "timestamp_utc": "2024-06-01T00:00:00+00:00", "level": "INFO"
            }) + "\n",
            encoding="utf-8",
        )
        sink = self._sink()
        sink.summarise_ledger()
        conn  = sqlite3.connect(str(sink.db_path()))
        count = conn.execute(
            "SELECT COUNT(*) FROM audit_summary"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_summarise_ledger_date_range(self):
        ledger = pathlib.Path(self._tmp) / "audit_ledger_test.jsonl"
        events = [
            {"category": "EXTRACT", "action": "A",
             "timestamp_utc": "2024-01-01T00:00:00+00:00", "level": "INFO"},
            {"category": "LOAD",    "action": "B",
             "timestamp_utc": "2024-06-30T00:00:00+00:00", "level": "INFO"},
        ]
        with ledger.open("w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        result = self._sink().summarise_ledger()
        self.assertIn("2024-01-01", result["period_start"])
        self.assertIn("2024-06-30", result["period_end"])

    # ── recent_runs ───────────────────────────────────────────────────────────

    def test_recent_runs_returns_list(self):
        sink = self._sink()
        for i in range(3):
            sink.record_run(**self._run_kwargs(run_id=f"run_{i}"))
        runs = sink.recent_runs(n=10)
        self.assertEqual(len(runs), 3)

    def test_recent_runs_empty_db(self):
        runs = self._sink().recent_runs()
        self.assertEqual(runs, [])

    def test_recent_runs_respects_n_limit(self):
        sink = self._sink()
        for i in range(10):
            sink.record_run(**self._run_kwargs(run_id=f"run_{i:02d}"))
        runs = sink.recent_runs(n=3)
        self.assertEqual(len(runs), 3)

    def test_recent_runs_returns_dicts(self):
        sink = self._sink()
        sink.record_run(**self._run_kwargs())
        runs = sink.recent_runs()
        self.assertIsInstance(runs[0], dict)
        self.assertIn("run_id", runs[0])
        self.assertIn("rows_loaded", runs[0])


# ═════════════════════════════════════════════════════════════════════════════
#  PrometheusExporter
# ═════════════════════════════════════════════════════════════════════════════

class TestPrometheusExporter(_TmpMixin):

    def _exporter(self, **kw):
        # Always use dry_run=True in tests — no real HTTP server
        return PrometheusExporter(self.gov, port=19999, dry_run=True, **kw)

    def test_initial_counters_zero(self):
        exp = self._exporter()
        self.assertEqual(exp._counters["pipeline_runs_total"],           0)
        self.assertEqual(exp._counters["pipeline_rows_loaded_total"],    0)
        self.assertEqual(exp._counters["pipeline_rows_extracted_total"], 0)
        self.assertEqual(exp._counters["pipeline_rows_failed_total"],    0)

    def test_update_run_increments_counters(self):
        exp = self._exporter()
        exp.update_run(
            rows_extracted=1000, rows_loaded=995,
            rows_failed=5, duration_sec=10.0, status="success"
        )
        self.assertEqual(exp._counters["pipeline_runs_total"],           1)
        self.assertEqual(exp._counters["pipeline_rows_extracted_total"], 1000)
        self.assertEqual(exp._counters["pipeline_rows_loaded_total"],    995)
        self.assertEqual(exp._counters["pipeline_rows_failed_total"],    5)

    def test_update_run_multiple_accumulates(self):
        exp = self._exporter()
        for _ in range(3):
            exp.update_run(rows_extracted=100, rows_loaded=100)
        self.assertEqual(exp._counters["pipeline_runs_total"],        3)
        self.assertEqual(exp._counters["pipeline_rows_loaded_total"], 300)

    def test_update_run_status_success_gauge(self):
        exp = self._exporter()
        exp.update_run(status="success")
        self.assertEqual(exp._gauges["pipeline_last_status"], 1.0)

    def test_update_run_status_warning_gauge(self):
        exp = self._exporter()
        exp.update_run(status="warning")
        self.assertEqual(exp._gauges["pipeline_last_status"], 0.5)

    def test_update_run_status_error_gauge(self):
        exp = self._exporter()
        exp.update_run(status="error")
        self.assertEqual(exp._gauges["pipeline_last_status"], 0.0)

    def test_update_run_duration_gauge(self):
        exp = self._exporter()
        exp.update_run(duration_sec=42.7)
        self.assertAlmostEqual(
            exp._gauges["pipeline_last_duration_seconds"], 42.7, places=1
        )

    def test_update_run_pii_columns_gauge(self):
        exp = self._exporter()
        exp.update_run(pii_columns=5)
        self.assertEqual(exp._gauges["pipeline_pii_columns_detected"], 5)

    def test_update_controls_sets_gauges(self):
        exp = self._exporter()
        exp.update_controls([
            {"control_id": "LOG_DIR_WRITABLE",    "status": "OK"},
            {"control_id": "AUDIT_LEDGER_INTACT",  "status": "WARN"},
            {"control_id": "BAA_REGISTRY_CURRENT", "status": "FAIL"},
        ])
        self.assertEqual(exp._control_gauges["LOG_DIR_WRITABLE"],    1.0)
        self.assertEqual(exp._control_gauges["AUDIT_LEDGER_INTACT"],  0.5)
        self.assertEqual(exp._control_gauges["BAA_REGISTRY_CURRENT"], 0.0)

    def test_update_audit_count(self):
        exp = self._exporter()
        exp.update_audit_count(12345)
        self.assertEqual(
            exp._counters["pipeline_audit_events_total"], 12345
        )

    def test_render_metrics_contains_counter_names(self):
        exp = self._exporter()
        exp.update_run(rows_loaded=500, status="success")
        output = exp._render_metrics()
        self.assertIn("pipeline_runs_total",        output)
        self.assertIn("pipeline_rows_loaded_total", output)
        self.assertIn("pipeline_last_status",       output)

    def test_render_metrics_contains_control_labels(self):
        exp = self._exporter()
        exp.update_controls([
            {"control_id": "MY_CONTROL", "status": "OK"}
        ])
        output = exp._render_metrics()
        self.assertIn("MY_CONTROL",                      output)
        self.assertIn("compliance_control_status",       output)

    def test_render_metrics_prometheus_format(self):
        exp    = self._exporter()
        output = exp._render_metrics()
        self.assertIn("# HELP",  output)
        self.assertIn("# TYPE",  output)
        self.assertTrue(output.endswith("\n"))

    def test_dry_run_server_not_started(self):
        exp = PrometheusExporter(self.gov, port=19998, dry_run=True)
        exp.start()
        self.assertFalse(exp.is_running())

    def test_is_running_false_before_start(self):
        exp = self._exporter()
        self.assertFalse(exp.is_running())

    def test_thread_safe_update(self):
        """Concurrent updates must not corrupt counter state."""
        import threading
        exp     = self._exporter()
        threads = []
        for _ in range(10):
            t = threading.Thread(
                target=exp.update_run,
                kwargs={"rows_loaded": 100, "status": "success"}
            )
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(exp._counters["pipeline_runs_total"],        10)
        self.assertEqual(exp._counters["pipeline_rows_loaded_total"], 1000)


# ═════════════════════════════════════════════════════════════════════════════
#  GrafanaDashboardGenerator
# ═════════════════════════════════════════════════════════════════════════════

class TestGrafanaDashboardGenerator(_TmpMixin):

    def _gen(self, ds_type="sqlite", **kw):
        return GrafanaDashboardGenerator(
            title="Test Dashboard",
            datasource_name="Test DS",
            datasource_type=ds_type,
            **kw,
        )

    # ── Validation ────────────────────────────────────────────────────────────

    def test_invalid_datasource_type_raises(self):
        with self.assertRaises(ValueError) as ctx:
            GrafanaDashboardGenerator(datasource_type="mysql")
        self.assertIn("datasource_type", str(ctx.exception))

    # ── generate() ───────────────────────────────────────────────────────────

    def test_generate_creates_file(self):
        gen = self._gen()
        out = pathlib.Path(self._tmp) / "dashboard.json"
        gen.generate(out)
        self.assertTrue(out.exists())

    def test_generate_valid_json(self):
        gen = self._gen()
        out = pathlib.Path(self._tmp) / "dashboard.json"
        gen.generate(out)
        data = json.loads(out.read_text())
        self.assertIsInstance(data, dict)

    def test_generate_prometheus_variant(self):
        gen = self._gen(ds_type="prometheus")
        out = pathlib.Path(self._tmp) / "dashboard_prom.json"
        gen.generate(out)
        data = json.loads(out.read_text())
        self.assertIsInstance(data, dict)

    # ── Dashboard structure ───────────────────────────────────────────────────

    def test_dashboard_has_required_keys(self):
        data = self._gen().as_dict()
        for key in ("title", "uid", "panels", "schemaVersion",
                    "refresh", "time", "templating"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_dashboard_title_includes_org_name(self):
        data = GrafanaDashboardGenerator(
            title="Pipeline", org_name="Acme Corp",
            datasource_type="sqlite",
        ).as_dict()
        self.assertIn("Acme Corp", data["title"])

    def test_dashboard_has_panels(self):
        data = self._gen().as_dict()
        self.assertIsInstance(data["panels"], list)
        self.assertGreater(len(data["panels"]), 0)

    def test_dashboard_has_stat_panels(self):
        data   = self._gen().as_dict()
        types  = {p["type"] for p in data["panels"]}
        self.assertIn("stat", types)

    def test_dashboard_has_timeseries_panels(self):
        data  = self._gen().as_dict()
        types = {p["type"] for p in data["panels"]}
        self.assertIn("timeseries", types)

    def test_dashboard_has_table_panel(self):
        data  = self._gen().as_dict()
        types = {p["type"] for p in data["panels"]}
        self.assertIn("table", types)

    def test_dashboard_panel_ids_unique(self):
        data = self._gen().as_dict()
        ids  = [p["id"] for p in data["panels"]]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate panel IDs found")

    def test_dashboard_refresh_interval(self):
        gen  = self._gen(refresh_interval="5m")
        data = gen.as_dict()
        self.assertEqual(data["refresh"], "5m")

    def test_dashboard_tags_include_type(self):
        data = self._gen(ds_type="prometheus").as_dict()
        self.assertIn("prometheus", data["tags"])

    def test_dashboard_targets_reference_datasource(self):
        data    = self._gen().as_dict()
        targets = []
        for panel in data["panels"]:
            targets.extend(panel.get("targets", []))
        self.assertGreater(len(targets), 0)
        for t in targets:
            self.assertIn("datasource", t)

    def test_sqlite_targets_have_raw_sql(self):
        data    = self._gen(ds_type="sqlite").as_dict()
        targets = []
        for panel in data["panels"]:
            targets.extend(panel.get("targets", []))
        sql_targets = [t for t in targets if "rawSql" in t]
        self.assertGreater(len(sql_targets), 0)

    def test_prometheus_targets_have_expr(self):
        data    = self._gen(ds_type="prometheus").as_dict()
        targets = []
        for panel in data["panels"]:
            targets.extend(panel.get("targets", []))
        prom_targets = [t for t in targets if "expr" in t]
        self.assertGreater(len(prom_targets), 0)

    def test_sql_targets_reference_correct_tables(self):
        data = self._gen(ds_type="sqlite").as_dict()
        all_sql = " ".join(
            t.get("rawSql", "")
            for panel in data["panels"]
            for t in panel.get("targets", [])
        )
        for table in ("pipeline_runs", "compliance_controls", "audit_summary"):
            self.assertIn(table, all_sql,
                          f"Table '{table}' not referenced in any SQL target")

    def test_as_dict_returns_dict(self):
        data = self._gen().as_dict()
        self.assertIsInstance(data, dict)

    def test_generate_and_as_dict_produce_same_content(self):
        gen  = self._gen()
        out  = pathlib.Path(self._tmp) / "dashboard.json"
        gen.generate(out)
        from_file = json.loads(out.read_text())
        from_dict = gen.as_dict()
        # Title and panel count should match
        self.assertEqual(from_file["title"],          from_dict["title"])
        self.assertEqual(len(from_file["panels"]),    len(from_dict["panels"]))


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in (
        TestMetricsSink,
        TestPrometheusExporter,
        TestGrafanaDashboardGenerator,
    ):
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
