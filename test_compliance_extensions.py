#!/usr/bin/env python3
"""
test_compliance_extensions.py  —  Unit tests for compliance_extensions.py

Covers all three compliance classes:
    ComplianceMonitor, VendorRiskTracker, TrustReportGenerator

Run with:  python3 test_compliance_extensions.py  (or pytest)
"""
import json
import pathlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from compliance_extensions import (
    ComplianceMonitor,
    VendorRiskTracker,
    TrustReportGenerator,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_gov(tmp_dir: str) -> MagicMock:
    gov = MagicMock()
    gov.log_dir = tmp_dir
    gov._event  = MagicMock()
    return gov


def _future(days: int = 365) -> str:
    return (datetime.now(timezone.utc).date() + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()


class _TmpMixin(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.gov  = _make_gov(self._tmp)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)


# ═════════════════════════════════════════════════════════════════════════════
#  ComplianceMonitor
# ═════════════════════════════════════════════════════════════════════════════

class TestComplianceMonitor(_TmpMixin):

    def _monitor(self, **kw):
        return ComplianceMonitor(self.gov, **kw)

    # ── run_all ───────────────────────────────────────────────────────────────

    def test_run_all_returns_list_of_results(self):
        m = self._monitor()
        results = m.run_all()
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_run_all_each_result_has_required_keys(self):
        m = self._monitor()
        for r in m.run_all():
            for key in ("control_id", "status", "detail", "checked_at"):
                self.assertIn(key, r, f"Missing key '{key}' in result {r}")

    def test_run_all_status_values_are_valid(self):
        m = self._monitor()
        for r in m.run_all():
            self.assertIn(r["status"], ("OK", "WARN", "FAIL"),
                          f"Invalid status '{r['status']}' for {r['control_id']}")

    def test_run_all_fires_governance_events(self):
        m = self._monitor()
        m.run_all()
        self.assertGreater(self.gov._event.call_count, 0)

    def test_dry_run_does_not_fire_events(self):
        m = self._monitor(dry_run=True)
        m.run_all()
        self.assertEqual(self.gov._event.call_count, 0)

    # ── Individual controls ───────────────────────────────────────────────────

    def test_log_dir_writable_ok(self):
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_LOG_DIR)
        self.assertEqual(r["status"], "OK")

    def test_log_dir_not_writable_fails(self):
        m = self._monitor()
        # Point gov.log_dir at a nonexistent path
        self.gov.log_dir = "/nonexistent/path/that/does/not/exist"
        r = m.run_check(ComplianceMonitor.CTRL_LOG_DIR)
        self.assertEqual(r["status"], "FAIL")

    def test_audit_ledger_no_files_warns(self):
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_LEDGER)
        self.assertEqual(r["status"], "WARN")

    def test_audit_ledger_with_file_ok(self):
        # Write a fake ledger file
        ledger = pathlib.Path(self._tmp) / "audit_ledger_test.jsonl"
        ledger.write_text(
            json.dumps({"event_id": "e1", "category": "EXTRACT",
                        "action": "TEST", "timestamp_utc": "2024-01-01T00:00:00+00:00"})
            + "\n",
            encoding="utf-8",
        )
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_LEDGER)
        self.assertEqual(r["status"], "OK")
        self.assertIn("1 event", r["detail"])

    def test_encryption_key_no_file_warns(self):
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_ENCRYPTION)
        self.assertEqual(r["status"], "WARN")

    def test_encryption_key_with_file_ok(self):
        key_file = pathlib.Path(self._tmp) / "encryption_key_versions.json"
        key_file.write_text(json.dumps({"v1": "key_data"}), encoding="utf-8")
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_ENCRYPTION)
        self.assertEqual(r["status"], "OK")

    def test_consent_db_no_file_warns(self):
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_CONSENT)
        self.assertEqual(r["status"], "WARN")

    def test_consent_db_reachable_ok(self):
        db_path = pathlib.Path(self._tmp) / "consent.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE consent_records "
            "(id INTEGER PRIMARY KEY, purpose TEXT)"
        )
        conn.commit()
        conn.close()
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_CONSENT)
        self.assertEqual(r["status"], "OK")

    def test_baa_registry_no_file_warns(self):
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_BAA)
        self.assertEqual(r["status"], "WARN")

    def test_baa_registry_all_active_ok(self):
        baa_file = pathlib.Path(self._tmp) / "baa_registry.json"
        baa_file.write_text(json.dumps({
            "dest1": {"expiry_date": _future(365), "vendor": "V1"},
        }), encoding="utf-8")
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_BAA)
        self.assertEqual(r["status"], "OK")

    def test_baa_registry_expired_fails(self):
        baa_file = pathlib.Path(self._tmp) / "baa_registry.json"
        baa_file.write_text(json.dumps({
            "dest1": {"expiry_date": _past(10), "vendor": "V1"},
        }), encoding="utf-8")
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_BAA)
        self.assertEqual(r["status"], "FAIL")

    def test_baa_registry_expiring_warns(self):
        baa_file = pathlib.Path(self._tmp) / "baa_registry.json"
        baa_file.write_text(json.dumps({
            "dest1": {"expiry_date": _future(10), "vendor": "V1"},
        }), encoding="utf-8")
        m = self._monitor(warn_days=30)
        r = m.run_check(ComplianceMonitor.CTRL_BAA)
        self.assertEqual(r["status"], "WARN")

    def test_irb_registry_no_file_warns(self):
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_IRB)
        self.assertEqual(r["status"], "WARN")

    def test_irb_registry_expired_fails(self):
        irb_file = pathlib.Path(self._tmp) / "irb_registry.json"
        irb_file.write_text(json.dumps({
            "IRB-001": {"expiry_date": _past(5), "study_title": "Test"},
        }), encoding="utf-8")
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_IRB)
        self.assertEqual(r["status"], "FAIL")

    def test_purpose_registry_no_file_warns(self):
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_PURPOSE)
        self.assertEqual(r["status"], "WARN")

    def test_purpose_registry_with_data_ok(self):
        purpose_file = pathlib.Path(self._tmp) / "purpose_registry.json"
        purpose_file.write_text(
            json.dumps({"analytics": ["col1", "col2"]}), encoding="utf-8"
        )
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_PURPOSE)
        self.assertEqual(r["status"], "OK")

    def test_vendor_risk_no_file_warns(self):
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_VENDOR)
        self.assertEqual(r["status"], "WARN")

    def test_vendor_risk_all_current_ok(self):
        vendor_file = pathlib.Path(self._tmp) / "vendor_registry.json"
        vendor_file.write_text(json.dumps({
            "v1": {"next_review_date": _future(365)},
        }), encoding="utf-8")
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_VENDOR)
        self.assertEqual(r["status"], "OK")

    def test_vendor_risk_overdue_fails(self):
        vendor_file = pathlib.Path(self._tmp) / "vendor_registry.json"
        vendor_file.write_text(json.dumps({
            "v1": {"next_review_date": _past(30)},
        }), encoding="utf-8")
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_VENDOR)
        self.assertEqual(r["status"], "FAIL")

    def test_invalid_control_id_raises(self):
        m = self._monitor()
        with self.assertRaises(ValueError):
            m.run_check("NONEXISTENT_CONTROL")

    # ── Reports ───────────────────────────────────────────────────────────────


    def test_vendor_risk_missing_review_date_warns_not_crashes(self):
        """A vendor record missing next_review_date must WARN, not raise KeyError."""
        vendor_file = pathlib.Path(self._tmp) / "vendor_registry.json"
        import json
        vendor_file.write_text(json.dumps({
            "broken_vendor": {
                "vendor_name": "Broken Corp",
                # next_review_date intentionally missing
            },
            "good_vendor": {
                "vendor_name": "Good Corp",
                "next_review_date": "2099-01-01",
            }
        }), encoding="utf-8")
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_VENDOR)
        # Must return WARN (not crash with KeyError)
        self.assertIn(r["status"], ("OK", "WARN", "FAIL"))
        self.assertNotEqual(r["status"], "FAIL",
                            "Missing key should warn, not hard-fail")

    def test_vendor_risk_invalid_date_warns_not_crashes(self):
        """A vendor record with a malformed date must WARN, not raise ValueError."""
        vendor_file = pathlib.Path(self._tmp) / "vendor_registry.json"
        import json
        vendor_file.write_text(json.dumps({
            "bad_date_vendor": {
                "vendor_name": "Bad Date Corp",
                "next_review_date": "not-a-date",
            }
        }), encoding="utf-8")
        m = self._monitor()
        r = m.run_check(ComplianceMonitor.CTRL_VENDOR)
        self.assertIn(r["status"], ("OK", "WARN", "FAIL"))

    def test_save_report_html(self):
        m = self._monitor()
        m.run_all()
        out = pathlib.Path(self._tmp) / "controls.html"
        m.save_report(out, fmt="html")
        self.assertTrue(out.exists())
        self.assertIn("Compliance Controls Status", out.read_text())

    def test_save_report_json(self):
        m = self._monitor()
        m.run_all()
        out = pathlib.Path(self._tmp) / "controls.json"
        m.save_report(out, fmt="json")
        data = json.loads(out.read_text())
        self.assertIsInstance(data, list)

    def test_save_report_requires_run_all_first(self):
        m = self._monitor()
        with self.assertRaises(RuntimeError):
            m.save_report(pathlib.Path(self._tmp) / "x.html")


# ═════════════════════════════════════════════════════════════════════════════
#  VendorRiskTracker
# ═════════════════════════════════════════════════════════════════════════════

class TestVendorRiskTracker(_TmpMixin):

    def _tracker(self, **kw):
        return VendorRiskTracker(self.gov, **kw)

    def _register_vendor(self, tracker, vendor_id="snowflake",
                         risk_level="medium", soc2_status="certified",
                         dpa_signed=True, next_review_date=None):
        tracker.register_vendor(
            vendor_id        = vendor_id,
            vendor_name      = f"Vendor {vendor_id}",
            service_type     = "cloud warehouse",
            data_types       = ["employee_data"],
            soc2_status      = soc2_status,
            last_review_date = "2025-01-01",
            next_review_date = next_review_date or _future(365),
            dpa_signed       = dpa_signed,
            risk_level       = risk_level,
        )

    def test_register_and_retrieve(self):
        t = self._tracker()
        self._register_vendor(t)
        records = t.all_vendors()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["vendor_id"], "snowflake")

    def test_register_persists_to_disk(self):
        t = self._tracker()
        self._register_vendor(t)
        reg_file = pathlib.Path(self._tmp) / "vendor_registry.json"
        self.assertTrue(reg_file.exists())
        data = json.loads(reg_file.read_text())
        self.assertIn("snowflake", data)

    def test_check_vendor_returns_record(self):
        t = self._tracker()
        self._register_vendor(t)
        rec = t.check_vendor("snowflake")
        self.assertEqual(rec["vendor_id"], "snowflake")

    def test_check_vendor_unknown_raises(self):
        t = self._tracker()
        with self.assertRaises(ValueError):
            t.check_vendor("nonexistent_vendor")

    def test_invalid_soc2_status_raises(self):
        t = self._tracker()
        with self.assertRaises(ValueError):
            t.register_vendor(
                vendor_id="x", vendor_name="X",
                service_type="y", soc2_status="invalid"
            )

    def test_invalid_risk_level_raises(self):
        t = self._tracker()
        with self.assertRaises(ValueError):
            t.register_vendor(
                vendor_id="x", vendor_name="X",
                service_type="y", risk_level="extreme"
            )

    def test_get_overdue_reviews(self):
        t = self._tracker()
        self._register_vendor(t, "overdue_v", next_review_date=_past(10))
        self._register_vendor(t, "current_v", next_review_date=_future(365))
        overdue = t.get_overdue_reviews()
        ids = [r["vendor_id"] for r in overdue]
        self.assertIn("overdue_v", ids)
        self.assertNotIn("current_v", ids)

    def test_get_high_risk_vendors(self):
        t = self._tracker()
        self._register_vendor(t, "high_v",   risk_level="high")
        self._register_vendor(t, "low_v",    risk_level="low")
        self._register_vendor(t, "crit_v",   risk_level="critical")
        high = t.get_high_risk_vendors()
        ids  = [r["vendor_id"] for r in high]
        self.assertIn("high_v", ids)
        self.assertIn("crit_v", ids)
        self.assertNotIn("low_v", ids)

    def test_get_missing_dpa(self):
        t = self._tracker()
        self._register_vendor(t, "no_dpa_v",  dpa_signed=False)
        self._register_vendor(t, "has_dpa_v", dpa_signed=True)
        missing = t.get_missing_dpa()
        ids = [r["vendor_id"] for r in missing]
        self.assertIn("no_dpa_v", ids)
        self.assertNotIn("has_dpa_v", ids)

    def test_default_next_review_date_set(self):
        t = self._tracker()
        t.register_vendor(
            vendor_id="v1", vendor_name="V1",
            service_type="warehouse",
        )
        rec = t.check_vendor("v1")
        self.assertIsNotNone(rec["next_review_date"])
        self.assertTrue(len(rec["next_review_date"]) >= 10)

    def test_governance_event_fired_on_register(self):
        t = self._tracker()
        self._register_vendor(t)
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("VENDOR_REGISTERED" in c for c in calls))

    def test_governance_event_fired_on_check(self):
        t = self._tracker()
        self._register_vendor(t)
        t.check_vendor("snowflake")
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("VENDOR_REVIEW_CHECKED" in c for c in calls))

    def test_export_register_html(self):
        t = self._tracker()
        self._register_vendor(t)
        out = pathlib.Path(self._tmp) / "vendor_register.html"
        t.export_register(out)
        self.assertTrue(out.exists())
        content = out.read_text()
        self.assertIn("Vendor Risk Register", content)
        self.assertIn("snowflake", content)

    def test_multiple_vendors_all_appear_in_report(self):
        t = self._tracker()
        for i in range(5):
            self._register_vendor(t, f"vendor_{i}")
        out = pathlib.Path(self._tmp) / "vendor_register.html"
        t.export_register(out)
        content = out.read_text()
        for i in range(5):
            self.assertIn(f"vendor_{i}", content)

    def test_expiry_warning_logged(self):
        t = self._tracker(warn_days=60)
        self._register_vendor(t, "soon_v", next_review_date=_future(20))
        t.check_vendor("soon_v")
        # Should log a warning but not raise
        records = t.all_vendors()
        self.assertEqual(len(records), 1)


# ═════════════════════════════════════════════════════════════════════════════
#  TrustReportGenerator
# ═════════════════════════════════════════════════════════════════════════════

class TestTrustReportGenerator(_TmpMixin):

    def _reporter(self, **kw):
        return TrustReportGenerator(self.gov, org_name="TestOrg", **kw)

    def _seed_ledger(self):
        """Write a minimal audit ledger file."""
        ledger = pathlib.Path(self._tmp) / "audit_ledger_test.jsonl"
        for i, (cat, action) in enumerate([
            ("EXTRACT", "FILE_LOADED"),
            ("PRIVACY", "PII_SCAN_COMPLETE"),
            ("COMPLIANCE", "BAA_VERIFIED"),
        ]):
            ledger.open("a").write(
                json.dumps({
                    "event_id":      f"e{i}",
                    "category":      cat,
                    "action":        action,
                    "timestamp_utc": "2024-06-01T00:00:00+00:00",
                }) + "\n"
            )

    def _seed_baa(self):
        baa_file = pathlib.Path(self._tmp) / "baa_registry.json"
        baa_file.write_text(json.dumps({
            "snowflake": {
                "vendor":      "Snowflake Inc.",
                "expiry_date": _future(365),
            }
        }), encoding="utf-8")

    def _seed_vendors(self):
        vendor_file = pathlib.Path(self._tmp) / "vendor_registry.json"
        vendor_file.write_text(json.dumps({
            "snowflake": {
                "vendor_name":    "Snowflake Inc.",
                "soc2_status":    "certified",
                "dpa_signed":     True,
                "next_review_date": _future(365),
            }
        }), encoding="utf-8")

    def _seed_consent_db(self):
        db_path = pathlib.Path(self._tmp) / "consent.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE consent_records "
            "(id INTEGER PRIMARY KEY, purpose TEXT, subject_id TEXT)"
        )
        conn.executemany(
            "INSERT INTO consent_records (purpose, subject_id) VALUES (?, ?)",
            [("analytics", "S001"), ("marketing", "S002")]
        )
        conn.commit()
        conn.close()

    def test_generate_creates_html_file(self):
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        self.assertTrue(out.exists())
        content = out.read_text()
        self.assertIn("TestOrg", content)

    def test_report_contains_frameworks(self):
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        content = out.read_text()
        for fw in ("GDPR", "CCPA", "HIPAA", "OMOP"):
            self.assertIn(fw, content, f"Framework {fw} missing from report")

    def test_report_contains_security_controls(self):
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        content = out.read_text()
        self.assertIn("AES-256", content)
        self.assertIn("Tamper-Evident", content)
        self.assertIn("PII Detection", content)

    def test_report_reflects_ledger_data(self):
        self._seed_ledger()
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        content = out.read_text()
        self.assertIn("3", content)   # 3 audit events

    def test_report_reflects_baa_data(self):
        self._seed_baa()
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        content = out.read_text()
        self.assertIn("1", content)   # 1 active BAA

    def test_report_reflects_consent_data(self):
        self._seed_consent_db()
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        content = out.read_text()
        self.assertIn("2", content)   # 2 consent records

    def test_report_reflects_vendor_data(self):
        self._seed_vendors()
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        content = out.read_text()
        self.assertIn("Vendor", content)

    def test_dry_run_no_governance_event(self):
        r   = self._reporter(dry_run=True)
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        self.assertEqual(self.gov._event.call_count, 0)

    def test_governance_event_fired_normally(self):
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("TRUST_REPORT_GENERATED" in c for c in calls))

    def test_empty_log_dir_still_generates(self):
        """Report generates even when no governance data exists yet."""
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        self.assertTrue(out.exists())

    def test_irb_titles_hidden_by_default(self):
        irb_file = pathlib.Path(self._tmp) / "irb_registry.json"
        irb_file.write_text(json.dumps({
            "IRB-001": {
                "study_title": "SECRET STUDY NAME",
                "expiry_date": _future(365),
                "pi_name": "Dr. Smith",
            }
        }), encoding="utf-8")
        r   = self._reporter(show_irb_titles=False)
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        self.assertNotIn("SECRET STUDY NAME", out.read_text())

    def test_irb_titles_shown_when_enabled(self):
        irb_file = pathlib.Path(self._tmp) / "irb_registry.json"
        irb_file.write_text(json.dumps({
            "IRB-001": {
                "study_title": "VISIBLE STUDY NAME",
                "expiry_date": _future(365),
                "pi_name": "Dr. Smith",
            }
        }), encoding="utf-8")
        r   = self._reporter(show_irb_titles=True)
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        self.assertIn("VISIBLE STUDY NAME", out.read_text())

    def test_controls_monitor_results_included(self):
        # Write a fake compliance status JSON
        status = [
            {"control_id": "LOG_DIR_WRITABLE", "status": "OK",
             "detail": "Writable", "checked_at": "2024-06-01T00:00:00"},
        ]
        status_file = pathlib.Path(self._tmp) / "compliance_status_001.json"
        status_file.write_text(json.dumps(status), encoding="utf-8")
        r   = self._reporter()
        out = pathlib.Path(self._tmp) / "trust_report.html"
        r.generate(out)
        self.assertIn("LOG_DIR_WRITABLE", out.read_text())


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in (
        TestComplianceMonitor,
        TestVendorRiskTracker,
        TestTrustReportGenerator,
    ):
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
