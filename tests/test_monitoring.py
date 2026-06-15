"""
Tests for pipeline.monitoring — MetricsCollector, SLAMonitor, DataObserver,
and Notifier.

Revision history
────────────────
1.0   2026-06-08   Initial release: 22 tests across 4 classes.
"""

import json
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from pipeline.governance_logger import GovernanceLogger
from pipeline.monitoring.metrics_collector import MetricsCollector
from pipeline.monitoring.sla_monitor import SLAMonitor
from pipeline.monitoring.observability import DataObserver
from pipeline.monitoring.notifier import Notifier


class TestMetricsCollector(unittest.TestCase):
    """MetricsCollector stage timing, row counting, and report generation."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("metrics_test", log_dir=self.tmp)
        self.mc = MetricsCollector(self.gov)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_start_and_end_stage_records_duration(self):
        self.mc.start_stage("extract")
        time.sleep(0.02)
        dur = self.mc.end_stage("extract", rows=100)
        self.assertGreater(dur, 0)
        self.assertEqual(self.mc._stages["extract"]["rows"], 100)
        self.assertIsNotNone(self.mc._stages["extract"]["duration_sec"])

    def test_end_stage_without_start_records_zero(self):
        dur = self.mc.end_stage("orphan", rows=50)
        self.assertEqual(dur, 0.0)
        self.assertIn("orphan", self.mc._stages)
        self.assertEqual(self.mc._stages["orphan"]["rows"], 50)

    def test_record_extract_populates_stage(self):
        self.mc.record_extract(rows=500, elapsed=1.23)
        self.assertEqual(self.mc._stages["extract"]["rows"], 500)
        self.assertEqual(self.mc._stages["extract"]["elapsed"], 1.23)

    def test_record_transform_populates_stage(self):
        self.mc.record_transform(rows=450, elapsed=0.8)
        self.assertEqual(self.mc._stages["transform"]["rows"], 450)

    def test_record_load_populates_stage(self):
        self.mc.record_load(rows=440, elapsed=2.1)
        self.assertEqual(self.mc._stages["load"]["rows"], 440)

    def test_record_validate_populates_stage(self):
        self.mc.record_validate(rows_total=500, rows_failed=5, elapsed=0.3)
        self.assertEqual(self.mc._stages["validate"]["rows"], 500)

    def test_record_custom_metric(self):
        self.mc.record("cache_hit_rate", 0.95, stage="custom_stage")
        self.assertEqual(self.mc._stages["custom_stage"]["cache_hit_rate"], 0.95)

    def test_rows_per_sec_calculated(self):
        self.mc.start_stage("fast")
        time.sleep(0.01)
        self.mc.end_stage("fast", rows=1000)
        self.assertGreater(self.mc._stages["fast"]["rows_per_sec"], 0)

    def test_write_report_logs_metrics(self):
        self.mc.rows_in = 100
        self.mc.rows_out = 95
        self.mc.write_report(dlq_rows=5)
        events = self.gov.ledger_entries
        actions = [e["action"] for e in events]
        self.assertIn("METRICS_RECORDED", actions)

    def test_report_returns_stages_dict(self):
        self.mc.record_extract(rows=100, elapsed=0.5)
        result = self.mc.report()
        self.assertIn("extract", result)


class TestSLAMonitor(unittest.TestCase):
    """SLAMonitor wall-clock tracking and breach detection."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("sla_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_check_before_start_returns_zero(self):
        sla = SLAMonitor(self.gov, sla_seconds=100)
        self.assertEqual(sla.check(), 0.0)

    def test_no_breach_within_sla(self):
        sla = SLAMonitor(self.gov, sla_seconds=100)
        sla.start()
        elapsed = sla.check()
        self.assertFalse(sla.breached)
        self.assertGreater(elapsed, 0)

    def test_breach_fires_event(self):
        sla = SLAMonitor(self.gov, sla_seconds=0.001)
        sla.start()
        time.sleep(0.01)
        sla.check()
        self.assertTrue(sla.breached)
        events = self.gov.ledger_entries
        breach_events = [e for e in events if e.get("action") == "SLA_BREACH"]
        self.assertGreater(len(breach_events), 0)

    def test_warning_at_80_percent(self):
        sla = SLAMonitor(self.gov, sla_seconds=0.01)
        sla.start()
        time.sleep(0.009)
        sla.check()
        events = self.gov.ledger_entries
        warning_events = [
            e for e in events
            if e.get("action") in ("SLA_WARNING", "SLA_BREACH")
        ]
        self.assertGreater(len(warning_events), 0)

    def test_final_check_fires_ok_when_within_sla(self):
        sla = SLAMonitor(self.gov, sla_seconds=100)
        sla.start()
        elapsed = sla.final_check()
        self.assertGreater(elapsed, 0)
        self.assertFalse(sla.breached)
        events = self.gov.ledger_entries
        ok_events = [e for e in events if e.get("action") == "SLA_OK"]
        self.assertGreater(len(ok_events), 0)

    def test_no_sla_configured_skips_checks(self):
        sla = SLAMonitor(self.gov, sla_seconds=0)
        sla.start()
        elapsed = sla.check()
        self.assertGreater(elapsed, 0)
        self.assertFalse(sla.breached)


class TestDataObserver(unittest.TestCase):
    """DataObserver freshness, volume, and drift checks."""

    def setUp(self):
        import pandas as pd
        self.pd = pd
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("observer_test", log_dir=self.tmp)
        self.history_file = Path(self.tmp) / "obs_history.jsonl"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_dataframe_returns_zero_rows(self):
        obs = DataObserver(self.gov, history_file=self.history_file)
        df = self.pd.DataFrame()
        report = obs.observe(df, dataset="empty_test")
        self.assertEqual(report["row_count"], 0)
        self.assertEqual(report["alert_count"], 0)

    def test_fresh_data_no_freshness_alert(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file,
            freshness_threshold_hours=24.0,
        )
        now = datetime.now(timezone.utc)
        df = self.pd.DataFrame({
            "updated_at": self.pd.to_datetime([now, now - timedelta(hours=1)]),
            "value": [10, 20],
        })
        report = obs.observe(df, dataset="fresh_test")
        freshness_alerts = [a for a in report["alerts"] if a["type"] == "FRESHNESS"]
        self.assertEqual(len(freshness_alerts), 0)

    def test_stale_data_triggers_freshness_alert(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file,
            freshness_threshold_hours=1.0,
        )
        old_ts = datetime.now(timezone.utc) - timedelta(hours=48)
        df = self.pd.DataFrame({
            "updated_at": self.pd.to_datetime([old_ts]),
            "value": [10],
        })
        report = obs.observe(df, dataset="stale_test", timestamp_col="updated_at")
        freshness_alerts = [a for a in report["alerts"] if a["type"] == "FRESHNESS"]
        self.assertEqual(len(freshness_alerts), 1)
        self.assertGreater(freshness_alerts[0]["age_hours"], 1.0)

    def test_volume_anomaly_detected(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file,
            volume_change_threshold=0.5,
        )
        for i in range(5):
            record = {
                "dataset": "vol_test",
                "row_count": 100,
                "column_count": 2,
                "alerts": [],
                "alert_count": 0,
                "observed_utc": datetime.now(timezone.utc).isoformat(),
                "column_stats": [],
            }
            with open(self.history_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")

        df = self.pd.DataFrame({"a": range(200)})
        report = obs.observe(df, dataset="vol_test")
        volume_alerts = [a for a in report["alerts"] if a["type"] == "VOLUME"]
        self.assertEqual(len(volume_alerts), 1)

    def test_drift_detected_on_mean_shift(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file,
            drift_threshold=0.1,
        )
        prev = {
            "dataset": "drift_test",
            "row_count": 100,
            "column_count": 1,
            "alerts": [],
            "alert_count": 0,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "column_stats": [{"name": "score", "mean": 50.0, "std": 5.0}],
        }
        with open(self.history_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(prev) + "\n")

        df = self.pd.DataFrame({"score": [200.0] * 100})
        report = obs.observe(df, dataset="drift_test")
        drift_alerts = [a for a in report["alerts"] if a["type"] == "DRIFT"]
        self.assertGreater(len(drift_alerts), 0)

    def test_dry_run_does_not_write_history(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file, dry_run=True,
        )
        df = self.pd.DataFrame({"x": [1, 2, 3]})
        obs.observe(df, dataset="dryrun_test")
        self.assertFalse(self.history_file.exists())

    def test_column_stats_in_report(self):
        obs = DataObserver(self.gov, history_file=self.history_file)
        df = self.pd.DataFrame({"price": [10.0, 20.0, 30.0]})
        report = obs.observe(df, dataset="stats_test")
        self.assertIn("column_stats", report)
        self.assertEqual(len(report["column_stats"]), 1)
        self.assertEqual(report["column_stats"][0]["name"], "price")

    def test_column_stats_track_null_rate(self):
        obs = DataObserver(self.gov, history_file=self.history_file)
        df = self.pd.DataFrame({"email": ["a@x.com", None, "c@x.com", None]})
        report = obs.observe(df, dataset="nr_test")
        stat = report["column_stats"][0]
        self.assertEqual(stat["name"], "email")
        self.assertEqual(stat["null_rate"], 0.5)

    def test_null_spike_detected_vs_baseline(self):
        obs = DataObserver(self.gov, history_file=self.history_file)
        prev = {
            "dataset": "spike_test",
            "row_count": 4,
            "column_count": 1,
            "alerts": [],
            "alert_count": 0,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "column_stats": [{"name": "email", "null_rate": 0.0}],
        }
        with open(self.history_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(prev) + "\n")
        # Same field is now 75% null — a silent spike vs the 0% baseline.
        df = self.pd.DataFrame({"email": ["a@x.com", None, None, None]})
        report = obs.observe(df, dataset="spike_test")
        null_alerts = [a for a in report["alerts"] if a["type"] == "NULL_SPIKE"]
        self.assertEqual(len(null_alerts), 1)
        self.assertEqual(null_alerts[0]["column"], "email")

    def test_no_null_spike_when_rate_stable(self):
        obs = DataObserver(self.gov, history_file=self.history_file)
        prev = {
            "dataset": "stable_null",
            "row_count": 4,
            "column_count": 1,
            "alerts": [],
            "alert_count": 0,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "column_stats": [{"name": "email", "null_rate": 0.5}],
        }
        with open(self.history_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(prev) + "\n")
        df = self.pd.DataFrame({"email": ["a@x.com", None, "c@x.com", None]})
        report = obs.observe(df, dataset="stable_null")
        null_alerts = [a for a in report["alerts"] if a["type"] == "NULL_SPIKE"]
        self.assertEqual(len(null_alerts), 0)

    def test_critical_field_floor_breach_on_first_run(self):
        # No baseline exists, but a declared-critical field is mostly null.
        obs = DataObserver(
            self.gov, history_file=self.history_file,
            critical_fields=["ssn"], null_absolute_floor=0.5,
        )
        df = self.pd.DataFrame({"ssn": [None, None, None, "x"]})
        report = obs.observe(df, dataset="floor_test")
        floor_alerts = [a for a in report["alerts"] if a["type"] == "NULL_FLOOR"]
        self.assertEqual(len(floor_alerts), 1)

    def test_missing_critical_field_alerts(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file, critical_fields=["ssn"],
        )
        df = self.pd.DataFrame({"name": ["a", "b"]})
        report = obs.observe(df, dataset="missing_test")
        floor_alerts = [a for a in report["alerts"] if a["type"] == "NULL_FLOOR"]
        self.assertEqual(len(floor_alerts), 1)
        self.assertEqual(floor_alerts[0]["column"], "ssn")

    def test_duplicate_columns_do_not_crash(self):
        obs = DataObserver(self.gov, history_file=self.history_file)
        df = self.pd.DataFrame([[1, None, 3]], columns=["a", "a", "b"])
        report = obs.observe(df, dataset="dup_test")  # must not raise
        # First of each duplicate label is kept: a, b.
        names = [s["name"] for s in report["column_stats"]]
        self.assertEqual(names, ["a", "b"])

    def test_volume_tolerates_record_without_row_count(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file, volume_change_threshold=0.5,
        )
        with open(self.history_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"dataset": "novc", "observed_utc": "x"}) + "\n")
        df = self.pd.DataFrame({"a": range(10)})
        report = obs.observe(df, dataset="novc")  # must not raise KeyError
        self.assertEqual(report["row_count"], 10)

    def test_critical_field_spike_over_floor_is_high(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file,
            critical_fields=["email"], null_spike_threshold=0.2,
            null_absolute_floor=0.5,
        )
        prev = {
            "dataset": "sev", "row_count": 10, "column_count": 1, "alerts": [],
            "alert_count": 0,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "column_stats": [{"name": "email", "null_rate": 0.4}],
        }
        with open(self.history_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(prev) + "\n")
        # 0.4 -> 0.7: jump 0.3 (not > 0.4, so MEDIUM by jump alone) but
        # curr 0.7 > floor 0.5 for a critical field -> must escalate to HIGH.
        df = self.pd.DataFrame({"email": ["x"] * 3 + [None] * 7})
        report = obs.observe(df, dataset="sev")
        spikes = [a for a in report["alerts"] if a["type"] == "NULL_SPIKE"]
        self.assertEqual(len(spikes), 1)
        self.assertEqual(spikes[0]["severity"], "HIGH")

    def test_duplicate_business_key_detected(self):
        # Same business key, DIFFERENT timestamp -> not a full-row dup, row
        # count unchanged, but a business-key violation that must be caught.
        obs = DataObserver(
            self.gov, history_file=self.history_file, business_keys=["order_id"],
        )
        df = self.pd.DataFrame({
            "order_id": [1, 2, 2, 3],
            "ts": ["t1", "t2", "t2b", "t3"],  # row 3 dupes order_id 2
        })
        report = obs.observe(df, dataset="dup_test")
        dups = [a for a in report["alerts"] if a["type"] == "DUPLICATE_KEYS"]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]["duplicate_count"], 1)
        self.assertEqual(report["duplicate_key_rate"], 0.25)

    def test_no_duplicate_alert_when_keys_unique(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file, business_keys=["order_id"],
        )
        df = self.pd.DataFrame({"order_id": [1, 2, 3], "ts": ["a", "b", "c"]})
        report = obs.observe(df, dataset="uniq_test")
        dups = [a for a in report["alerts"] if a["type"] == "DUPLICATE_KEYS"]
        self.assertEqual(len(dups), 0)
        self.assertEqual(report["duplicate_key_rate"], 0.0)

    def test_rising_duplicate_rate_escalates_to_high(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file,
            business_keys=["order_id"], duplicate_key_spike=0.01,
        )
        prev = {
            "dataset": "rise", "row_count": 4, "column_count": 1, "alerts": [],
            "alert_count": 0,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "duplicate_key_rate": 0.0,
        }
        with open(self.history_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(prev) + "\n")
        # A source that just started duplicating: 0% -> 50%.
        df = self.pd.DataFrame({"order_id": [1, 1, 2, 2]})
        report = obs.observe(df, dataset="rise")
        dups = [a for a in report["alerts"] if a["type"] == "DUPLICATE_KEYS"]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]["severity"], "HIGH")

    def test_missing_business_key_alerts(self):
        obs = DataObserver(
            self.gov, history_file=self.history_file, business_keys=["order_id"],
        )
        df = self.pd.DataFrame({"name": ["a", "b"]})
        report = obs.observe(df, dataset="missing_bk")
        dups = [a for a in report["alerts"] if a["type"] == "DUPLICATE_KEYS"]
        self.assertEqual(len(dups), 1)
        self.assertIn("order_id", dups[0]["missing"])

    def test_observer_config_keys_match_constructor(self):
        # The CLI forwards config via OBSERVER_CONFIG_KEYS; if a constructor
        # parameter is renamed, this pins the drift to a CI failure instead
        # of a silently dropped config value.
        import inspect
        from pipeline.monitoring.observability import OBSERVER_CONFIG_KEYS
        params = set(inspect.signature(DataObserver.__init__).parameters)
        for key in OBSERVER_CONFIG_KEYS:
            self.assertIn(key, params, f"{key} is not a DataObserver parameter")


class TestNotifier(unittest.TestCase):
    """Notifier email and Slack dispatch."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("notify_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_build_subject_success(self):
        notifier = Notifier(self.gov)
        subject = notifier._build_subject(True)
        self.assertIn("SUCCESS", subject)
        self.assertIn("Pipeline v4", subject)

    def test_build_subject_failure(self):
        notifier = Notifier(self.gov)
        subject = notifier._build_subject(False)
        self.assertIn("FAILED", subject)

    def test_build_html_contains_status(self):
        notifier = Notifier(self.gov)
        html = notifier._build_html(True, {"rows": 100, "duration": "5s"})
        self.assertIn("COMPLETED SUCCESSFULLY", html)
        self.assertIn("100", html)

    @patch("pipeline.monitoring.notifier.smtplib.SMTP")
    def test_send_email_calls_smtp(self, mock_smtp_cls):
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        email_cfg = {
            "from_addr": "pipeline@example.com",
            "to_addrs": ["team@example.com"],
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "smtp_user": "pipeline@example.com",
            "smtp_password": "synth-pass-1234",
        }
        notifier = Notifier(self.gov, email_cfg=email_cfg)
        notifier.send(success=True, stats={"rows": 50})
        mock_smtp_cls.assert_called_once()

    @patch("pipeline.monitoring.notifier.HAS_REQUESTS", False)
    def test_slack_skipped_without_requests(self):
        notifier = Notifier(
            self.gov,
            slack_cfg={"webhook_url": "https://hooks.slack.example.com/test"},
        )
        notifier.send(success=True, stats={"rows": 50})
        events = self.gov.ledger_entries
        slack_events = [
            e for e in events
            if "SLACK" in str(e.get("action", ""))
        ]
        self.assertGreater(len(slack_events), 0)


if __name__ == "__main__":
    unittest.main()
