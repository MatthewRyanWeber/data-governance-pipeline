# test_governance_extensions.py  —  Test suite for governance_extensions.py
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import json, logging, pathlib, shutil, sqlite3
import sys, tempfile, time, unittest
from datetime import datetime, timedelta

logging.disable(logging.CRITICAL)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import pandas as pd
from pipeline_v3 import GovernanceLogger
from governance_extensions import (
    RoPAGenerator, RetentionEnforcer, DSARResponder,
    BreachDetector, ConsentManager, ConsentRequiredError, ConsentExpiredError,
    DifferentialPrivacyTransformer, BudgetExhaustedError,
    PurposeLimitationEnforcer, PurposeLimitationViolation,
    PseudonymVault, _now_utc,
)

# ─────────────────────────────────────────────────────────────────────────────
def _gov(name="test.csv"):
    g = GovernanceLogger(name)
    g.pipeline_start({"source": name})
    return g

def _gov_in_dir(tmpdir, name="vault_test.csv"):
    """Like _gov() but writes logs into an explicit temp directory so tests
    that need isolated DB paths don't share the fixed stem-based log_dir."""
    g = GovernanceLogger(name, log_dir=tmpdir)
    g.pipeline_start({"source": name})
    return g

def _df():
    return pd.DataFrame({
        "id":     [1, 2, 3],
        "email":  ["a@b.com", "c@d.com", "e@f.com"],
        "salary": [50000, 60000, 70000],
        "dept":   ["Eng", "HR", "Sales"],
        "_loaded_at_utc": [
            _now_utc().isoformat(),
            (_now_utc() - timedelta(days=40)).isoformat(),
            (_now_utc() - timedelta(days=10)).isoformat(),
        ],
    })

# ═════════════════════════════════════════════════════════════════════════════
class TestRoPAGenerator(unittest.TestCase):

    def setUp(self):
        self.gov = _gov("ropa_test.csv")
        self.ropa = RoPAGenerator(
            self.gov,
            controller_name="Test Corp",
            dpo_contact="dpo@test.com",
        )

    def tearDown(self):
        shutil.rmtree(self.gov.log_dir, ignore_errors=True)

    def test_add_activity_and_write(self):
        self.ropa.add_activity(
            name="Test activity",
            purpose="Testing",
            legal_basis="Art. 6(1)(b) — Contract",
            data_subjects=["employees"],
            data_categories=["email", "salary"],
            retention="1_year",
        )
        path = self.ropa.write()
        self.assertTrue(path.exists())
        html = path.read_text()
        self.assertIn("Test activity", html)
        self.assertIn("Art. 6(1)(b)", html)

    def test_write_empty_report(self):
        path = self.ropa.write()
        html = path.read_text()
        self.assertIn("No processing activities", html)

    def test_ingest_from_ledger(self):
        self.gov.destination_registered("sqlite", "/tmp/x", "orders")
        self.gov.consent_recorded("analytics", "Art. 6(1)(f)", confirmed=True)
        self.ropa.ingest_from_ledger()
        self.assertGreater(len(self.ropa._activities), 0)

    def test_multiple_activities(self):
        for i in range(5):
            self.ropa.add_activity(
                name=f"Activity {i}",
                purpose=f"Purpose {i}",
                legal_basis="Art. 6(1)(f) — Legitimate interests",
                data_subjects=["users"],
                data_categories=["id"],
            )
        self.assertEqual(len(self.ropa._activities), 5)
        path = self.ropa.write()
        html = path.read_text()
        for i in range(5):
            self.assertIn(f"Activity {i}", html)

    def test_third_country_transfer_shown(self):
        self.ropa.add_activity(
            name="US Transfer",
            purpose="Cloud storage",
            legal_basis="Art. 6(1)(f) — Legitimate interests",
            data_subjects=["customers"],
            data_categories=["email"],
            third_country_transfers=[{"destination_country": "US",
                                       "transfer_mechanism": "SCCs",
                                       "db_type": "snowflake"}],
        )
        path = self.ropa.write()
        html = path.read_text()
        self.assertIn("Third-country transfer", html)
        self.assertIn("US", html)

    def test_retention_days_calculated(self):
        self.ropa.add_activity(
            name="Billing", purpose="X", legal_basis="Art. 6(1)(b) — Contract",
            data_subjects=["customers"], data_categories=["amount"],
            retention="3_years",
        )
        act = self.ropa._activities[0]
        self.assertEqual(act["retention_days"], 365 * 3)

    def test_add_activity_returns_self(self):
        result = self.ropa.add_activity(
            name="Chain", purpose="X", legal_basis="Art. 6(1)(b) — Contract",
            data_subjects=["X"], data_categories=["X"],
        )
        self.assertIs(result, self.ropa)


# ═════════════════════════════════════════════════════════════════════════════
class TestRetentionEnforcer(unittest.TestCase):

    def setUp(self):
        self.gov = _gov("retention_test.csv")
        self.tmp = tempfile.mkdtemp()
        self.db  = str(pathlib.Path(self.tmp) / "db")
        from sqlalchemy import create_engine
        self.engine = create_engine(f"sqlite:///{self.db}.db")
        _df().to_sql("customers", self.engine, if_exists="replace", index=False)
        self.enforcer = RetentionEnforcer(self.gov, db_type="sqlite")

    def tearDown(self):
        shutil.rmtree(self.gov.log_dir, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_enforce_delete_removes_old_rows(self):
        from sqlalchemy import text as sat
        result = self.enforcer.enforce(
            {"db_name": self.db}, "customers", "30_days",
            timestamp_column="_loaded_at_utc", action="delete",
        )
        self.assertEqual(result["rows_acted"], 1)   # 1 row is 40 days old
        with self.engine.connect() as conn:
            count = conn.execute(sat("SELECT COUNT(*) FROM customers")).scalar()
        self.assertEqual(count, 2)

    def test_enforce_dry_run_does_not_delete(self):
        from sqlalchemy import text as sat
        self.enforcer.enforce(
            {"db_name": self.db}, "customers", "30_days",
            timestamp_column="_loaded_at_utc", action="delete", dry_run=True,
        )
        with self.engine.connect() as conn:
            count = conn.execute(sat("SELECT COUNT(*) FROM customers")).scalar()
        self.assertEqual(count, 3)   # nothing deleted

    def test_enforce_archive_creates_parquet(self):
        self.enforcer.enforce(
            {"db_name": self.db}, "customers", "30_days",
            timestamp_column="_loaded_at_utc", action="archive",
        )
        archives = list(self.enforcer.archive_dir.glob("*.parquet"))
        self.assertEqual(len(archives), 1)
        archived = pd.read_parquet(archives[0])
        self.assertEqual(len(archived), 1)

    def test_indefinite_policy_skips(self):
        result = self.enforcer.enforce(
            {"db_name": self.db}, "customers", "indefinite",
            timestamp_column="_loaded_at_utc",
        )
        self.assertEqual(result["rows_acted"], 0)

    def test_missing_timestamp_column_skips_gracefully(self):
        result = self.enforcer.enforce(
            {"db_name": self.db}, "customers", "30_days",
            timestamp_column="nonexistent_col",
        )
        self.assertEqual(result["rows_acted"], 0)

    def test_enforce_dataframe_drops_old_rows(self):
        df = _df()
        filtered = self.enforcer.enforce_dataframe(df, "30_days",
                                                    timestamp_column="_loaded_at_utc")
        self.assertEqual(len(filtered), 2)

    def test_scan_all_tables(self):
        results = self.enforcer.scan_all_tables(
            {"db_name": self.db},
            {"customers": "30_days"},
            timestamp_column="_loaded_at_utc",
            action="delete",
        )
        self.assertIn("customers", results)
        self.assertEqual(results["customers"]["rows_acted"], 1)


# ═════════════════════════════════════════════════════════════════════════════
class TestDSARResponder(unittest.TestCase):

    def setUp(self):
        self.gov = _gov("dsar_test.csv")
        self.tmp = tempfile.mkdtemp()
        self.db  = str(pathlib.Path(self.tmp) / "dsar_db")
        from sqlalchemy import create_engine
        df = _df()
        create_engine(f"sqlite:///{self.db}.db")
        df.to_sql("users", create_engine(f"sqlite:///{self.db}.db"),
                  if_exists="replace", index=False)
        self.responder = DSARResponder(self.gov)
        self.responder.add_sql_source(
            "sqlite", {"db_name": self.db},
            tables=["users"], subject_column="email",
        )

    def tearDown(self):
        shutil.rmtree(self.gov.log_dir, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_respond_finds_matching_subject(self):
        response = self.responder.respond("a@b.com")
        matching = [r for r in response.records if "_source_error" not in r]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["email"], "a@b.com")

    def test_respond_no_match_returns_empty(self):
        response = self.responder.respond("nobody@nowhere.com")
        matching = [r for r in response.records if "_source_error" not in r]
        self.assertEqual(len(matching), 0)

    def test_write_creates_html_and_export(self):
        response = self.responder.respond("a@b.com")
        paths = response.write()
        self.assertTrue(paths["html"].exists())
        self.assertTrue(paths["export"].exists())

    def test_write_json_export_valid(self):
        response = self.responder.respond("a@b.com")
        paths = response.write()
        data = json.loads(paths["export"].read_text())
        self.assertIsInstance(data, list)

    def test_write_csv_export(self):
        response = self.responder.respond("a@b.com", export_format="csv")
        paths = response.write()
        self.assertTrue(paths["export"].name.endswith(".csv"))

    def test_add_dataframe_source(self):
        self.responder.add_dataframe(_df(), "test_df", subject_column="email")
        response = self.responder.respond("c@d.com")
        matching = [r for r in response.records
                    if r.get("_source") == "test_df"]
        self.assertGreater(len(matching), 0)

    def test_request_id_auto_generated(self):
        r = self.responder.respond("a@b.com")
        self.assertTrue(r.request_id.startswith("DSAR-"))

    def test_html_report_contains_request_id(self):
        response = self.responder.respond("a@b.com", request_id="DSAR-TEST-001")
        paths = response.write()
        html = paths["html"].read_text()
        self.assertIn("DSAR-TEST-001", html)


# ═════════════════════════════════════════════════════════════════════════════
class TestBreachDetector(unittest.TestCase):

    def setUp(self):
        self.gov      = _gov("breach_test.csv")
        self.detector = BreachDetector(self.gov, normal_row_max=2,
                                        quality_collapse_threshold=50.0,
                                        max_erasure_single_run=100)

    def tearDown(self):
        shutil.rmtree(self.gov.log_dir, ignore_errors=True)

    def test_bulk_load_alert(self):
        alerts = self.detector.check_load(_df(), "sqlite:users")
        bulk = [a for a in alerts if a["event_type"] == "BULK_LOAD"]
        self.assertEqual(len(bulk), 1)
        self.assertEqual(bulk[0]["severity"], "MEDIUM")

    def test_new_pii_table_alert(self):
        alerts = self.detector.check_load(_df(), "sqlite:patients",
                                           pii_fields=["email"])
        pii = [a for a in alerts if a["event_type"] == "NEW_PII_TABLE"]
        self.assertEqual(len(pii), 1)

    def test_second_load_no_new_pii_alert(self):
        self.detector.check_load(_df(), "sqlite:known",
                                  pii_fields=["email"])
        alerts2 = self.detector.check_load(_df(), "sqlite:known",
                                            pii_fields=["email"])
        pii = [a for a in alerts2 if a["event_type"] == "NEW_PII_TABLE"]
        self.assertEqual(len(pii), 0)

    def test_column_disappearance_alert(self):
        df1 = _df()
        df2 = _df().drop(columns=["salary"])
        self.detector.check_load(df1, "sqlite:orders")
        alerts2 = self.detector.check_load(df2, "sqlite:orders")
        disappeared = [a for a in alerts2 if a["event_type"] == "COLUMN_DISAPPEARANCE"]
        self.assertEqual(len(disappeared), 1)
        self.assertEqual(disappeared[0]["severity"], "HIGH")
        self.assertIn("salary", disappeared[0]["detail"]["disappeared"])

    def test_quality_collapse_alert(self):
        alert = self.detector.check_quality_score(25.0, "patients")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "HIGH")
        self.assertIsNotNone(alert["art33_deadline"])

    def test_bulk_erasure_alert(self):
        alert = self.detector.check_erasure(500, "users")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "HIGH")

    def test_normal_erasure_no_alert(self):
        alert = self.detector.check_erasure(10, "users")
        self.assertIsNone(alert)

    def test_new_transfer_country_alert(self):
        alert = self.detector.check_transfer("RU", "SCCs")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["event_type"], "NEW_TRANSFER_COUNTRY")

    def test_known_country_no_alert(self):
        self.detector.check_transfer("US", "SCCs")
        alert2 = self.detector.check_transfer("US", "SCCs")
        self.assertIsNone(alert2)

    def test_art33_deadline_72h(self):
        alert = self.detector.check_erasure(10_000, "big_table")
        deadline = datetime.fromisoformat(alert["art33_deadline"])
        diff = (deadline - _now_utc()).total_seconds()
        self.assertAlmostEqual(diff, 72 * 3600, delta=10)

    def test_report_writes_html(self):
        self.detector.check_load(_df(), "t", pii_fields=["email"])
        path = self.detector.report()
        self.assertTrue(path.exists())
        self.assertIn("Breach", path.read_text())

    def test_state_persists_across_instances(self):
        self.detector.check_load(_df(), "persist_table", pii_fields=["email"])
        d2 = BreachDetector(self.gov, normal_row_max=2)
        alerts = d2.check_load(_df(), "persist_table", pii_fields=["email"])
        pii_alerts = [a for a in alerts if a["event_type"] == "NEW_PII_TABLE"]
        self.assertEqual(len(pii_alerts), 0, "State should persist — table already known")


# ═════════════════════════════════════════════════════════════════════════════
class TestConsentManager(unittest.TestCase):

    def setUp(self):
        self.gov = _gov("consent_test.csv")
        self.cm  = ConsentManager(self.gov)

    def tearDown(self):
        shutil.rmtree(self.gov.log_dir, ignore_errors=True)

    def test_record_and_check_active(self):
        self.cm.record("alice@example.com", "analytics")
        self.assertTrue(self.cm.check("alice@example.com", "analytics"))

    def test_no_consent_returns_false(self):
        self.assertFalse(self.cm.check("nobody@example.com", "analytics"))

    def test_raise_on_missing(self):
        with self.assertRaises(ConsentRequiredError):
            self.cm.check("nobody@example.com", "analytics", raise_on_missing=True)

    def test_withdraw_single_purpose(self):
        self.cm.record("bob@example.com", "analytics")
        self.cm.record("bob@example.com", "marketing")
        self.cm.withdraw("bob@example.com", purpose="analytics")
        self.assertFalse(self.cm.check("bob@example.com", "analytics"))
        self.assertTrue(self.cm.check("bob@example.com", "marketing"))

    def test_withdraw_all_purposes(self):
        self.cm.record("carol@example.com", "analytics")
        self.cm.record("carol@example.com", "marketing")
        self.cm.withdraw("carol@example.com")
        self.assertFalse(self.cm.check("carol@example.com", "analytics"))
        self.assertFalse(self.cm.check("carol@example.com", "marketing"))

    def test_expired_consent_returns_false(self):
        # Record consent that expires immediately
        self.cm.record("dave@example.com", "analytics", expires_days=0)
        time.sleep(0.01)
        self.assertFalse(self.cm.check("dave@example.com", "analytics"))

    def test_raise_on_expired(self):
        self.cm.record("eve@example.com", "analytics", expires_days=0)
        time.sleep(0.01)
        with self.assertRaises(ConsentExpiredError):
            self.cm.check("eve@example.com", "analytics", raise_on_missing=True)

    def test_re_record_overwrites_previous(self):
        self.cm.record("frank@example.com", "analytics", legal_basis="Art. 6(1)(a)")
        self.cm.record("frank@example.com", "analytics", legal_basis="Art. 6(1)(b)")
        self.assertTrue(self.cm.check("frank@example.com", "analytics"))
        # Only one active record should exist
        with sqlite3.connect(str(self.cm.db_path)) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM consent WHERE subject_hash=? "
                "AND purpose='analytics' AND withdrawn_utc IS NULL",
                (self.cm._hash("frank@example.com"),),
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_get_subjects_without_consent(self):
        self.cm.record("a@b.com", "analytics")
        df = _df()
        no_consent = self.cm.get_subjects_without_consent(df, "email", "analytics")
        # c@d.com and e@f.com have no consent
        self.assertEqual(len(no_consent), 2)
        self.assertNotIn("a@b.com", no_consent["email"].tolist())

    def test_export_consent_register(self):
        self.cm.record("x@y.com", "analytics")
        path = self.cm.export_consent_register()
        self.assertTrue(path.exists())
        html = path.read_text()
        self.assertIn("Consent Register", html)


# ═════════════════════════════════════════════════════════════════════════════
class TestDifferentialPrivacyTransformer(unittest.TestCase):

    def setUp(self):
        self.gov = _gov("dp_test.csv")
        self.dp  = DifferentialPrivacyTransformer(self.gov, epsilon=1.0, budget_cap=10.0)

    def tearDown(self):
        shutil.rmtree(self.gov.log_dir, ignore_errors=True)

    def test_apply_returns_dataframe(self):
        noisy = self.dp.apply(_df(), columns=["salary"], sensitivity=10000.0)
        self.assertIsInstance(noisy, pd.DataFrame)
        self.assertIn("salary", noisy.columns)

    def test_original_not_modified(self):
        df = _df()
        orig = df["salary"].tolist()
        self.dp.apply(df, columns=["salary"], sensitivity=1000.0)
        self.assertEqual(df["salary"].tolist(), orig)

    def test_noise_actually_added(self):
        df = _df()
        # With high sensitivity (relative to epsilon), noise should be large
        noisy = self.dp.apply(df, columns=["salary"], sensitivity=1_000_000.0)
        diffs = (df["salary"] - noisy["salary"]).abs()
        self.assertGreater(diffs.sum(), 0, "Zero noise added — check RNG")

    def test_non_numeric_column_skipped(self):
        df = _df()
        noisy = self.dp.apply(df, columns=["email"], sensitivity=1.0)
        pd.testing.assert_series_equal(df["email"], noisy["email"])

    def test_budget_accumulates(self):
        budget_before = self.dp._total_spent
        self.dp.apply(_df(), columns=["salary"], sensitivity=1000.0)
        self.assertAlmostEqual(self.dp._total_spent, budget_before + 1.0, places=6)

    def test_budget_exhausted_raises(self):
        dp = DifferentialPrivacyTransformer(self.gov, epsilon=3.0, budget_cap=5.0)
        dp.apply(_df(), columns=["salary"], sensitivity=1.0)  # uses 3.0
        with self.assertRaises(BudgetExhaustedError):
            dp.apply(_df(), columns=["salary"], sensitivity=1.0)  # would need 3.0 more

    def test_gaussian_mechanism(self):
        noisy = self.dp.apply(_df(), columns=["salary"], sensitivity=1000.0,
                               mechanism="gaussian")
        self.assertIsInstance(noisy, pd.DataFrame)

    def test_remaining_budget(self):
        self.dp.apply(_df(), columns=["salary"], sensitivity=1.0)
        self.assertAlmostEqual(self.dp.remaining_budget(), 9.0, places=4)

    def test_no_budget_cap_infinite_remaining(self):
        dp = DifferentialPrivacyTransformer(self.gov, epsilon=1.0)
        self.assertEqual(dp.remaining_budget(), float("inf"))

    def test_apply_aggregates(self):
        df = _df()
        result = self.dp.apply_aggregates(
            df, group_by=["dept"], agg_columns=["salary"],
            agg_func="sum", sensitivity=10000.0,
        )
        self.assertIn("dept", result.columns)
        self.assertIn("salary", result.columns)

    def test_clip_to_range_respected(self):
        df = _df()
        orig_min = float(df["salary"].min())
        orig_max = float(df["salary"].max())
        # Use enormous sensitivity to force large noise, then confirm clipping works
        noisy = self.dp.apply(df, columns=["salary"],
                               sensitivity=1_000_000.0, clip_to_range=True)
        self.assertGreaterEqual(float(noisy["salary"].min()), orig_min - 1)
        self.assertLessEqual(float(noisy["salary"].max()), orig_max + 1)

    def test_invalid_epsilon_raises(self):
        with self.assertRaises(ValueError):
            DifferentialPrivacyTransformer(self.gov, epsilon=0.0)


# ═════════════════════════════════════════════════════════════════════════════
class TestPurposeLimitationEnforcer(unittest.TestCase):

    def setUp(self):
        self.gov = _gov("ple_test.csv")
        self.ple = PurposeLimitationEnforcer(self.gov, strict=False)
        self.ple.register_purpose(
            "analytics",
            allowed_columns=["id", "dept", "salary"],
            description="Internal HR analytics",
            legal_basis="Art. 6(1)(f)",
        )

    def tearDown(self):
        shutil.rmtree(self.gov.log_dir, ignore_errors=True)

    def test_enforce_drops_out_of_scope(self):
        df = _df()
        clean = self.ple.enforce(df, "analytics")
        self.assertNotIn("email", clean.columns)
        self.assertNotIn("_loaded_at_utc", clean.columns)
        self.assertIn("salary", clean.columns)

    def test_enforce_strict_raises(self):
        ple_strict = PurposeLimitationEnforcer(self.gov, strict=True)
        ple_strict.register_purpose("analytics",
                                     allowed_columns=["id", "dept"])
        with self.assertRaises(PurposeLimitationViolation):
            ple_strict.enforce(_df(), "analytics")

    def test_check_returns_out_of_scope_list(self):
        violations = self.ple.check(_df(), "analytics")
        self.assertIn("email", violations)
        self.assertIn("_loaded_at_utc", violations)

    def test_all_allowed_columns_no_drop(self):
        df = pd.DataFrame({"id": [1], "dept": ["Eng"], "salary": [50000]})
        clean = self.ple.enforce(df, "analytics")
        self.assertEqual(list(clean.columns), list(df.columns))

    def test_unknown_purpose_non_strict_passthrough(self):
        df = _df()
        result = self.ple.enforce(df, "unknown_purpose")
        # Non-strict: returns df unchanged with a warning
        self.assertEqual(len(result), len(df))

    def test_unknown_purpose_strict_raises(self):
        ple_strict = PurposeLimitationEnforcer(self.gov, strict=True)
        with self.assertRaises(PurposeLimitationViolation):
            ple_strict.enforce(_df(), "nonexistent_purpose")

    def test_list_purposes(self):
        self.assertIn("analytics", self.ple.list_purposes())

    def test_write_registry_report(self):
        path = self.ple.write_registry_report()
        self.assertTrue(path.exists())
        html = path.read_text()
        self.assertIn("analytics", html)
        self.assertIn("salary", html)

    def test_register_purpose_returns_self(self):
        result = self.ple.register_purpose("x", allowed_columns=["a"])
        self.assertIs(result, self.ple)

    def test_registry_persists_to_json(self):
        self.assertTrue(self.ple._registry_path.exists())
        data = json.loads(self.ple._registry_path.read_text())
        self.assertIn("analytics", data)


# ═════════════════════════════════════════════════════════════════════════════
class TestPseudonymVault(unittest.TestCase):

    def setUp(self):
        # Use a unique temp directory per test so consecutive tests never share
        # the same vault.db path.  The fixed stem ("vault_test LOGS") caused
        # "database is locked" errors: tearDown deleted the dir while SQLite WAL
        # files were still being flushed, and the next setUp immediately reopened
        # the same path, racing the OS flush.
        self._tmpdir = tempfile.mkdtemp()
        self.gov     = _gov_in_dir(self._tmpdir)
        self.vault   = PseudonymVault(self.gov)

    def tearDown(self):
        # Close the logging FileHandler that GovernanceLogger adds to the root
        # logger via logging.basicConfig().  Without this, the root logger holds
        # an open file handle into the deleted temp directory, causing
        # ResourceWarning noise and preventing clean dir removal on some OSes.
        for h in logging.root.handlers[:]:
            try:
                h.close()
            except Exception:
                pass
            logging.root.removeHandler(h)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_pseudonym_is_consistent(self):
        p1 = self.vault.pseudonymise("alice@example.com", context="email")
        p2 = self.vault.pseudonymise("alice@example.com", context="email")
        self.assertEqual(p1, p2)

    def test_different_values_different_pseudonyms(self):
        p1 = self.vault.pseudonymise("alice@example.com", context="email")
        p2 = self.vault.pseudonymise("bob@example.com",   context="email")
        self.assertNotEqual(p1, p2)

    def test_different_contexts_different_pseudonyms(self):
        p1 = self.vault.pseudonymise("alice@example.com", context="email")
        p2 = self.vault.pseudonymise("alice@example.com", context="phone")
        self.assertNotEqual(p1, p2)

    def test_pseudonym_has_prefix(self):
        p = self.vault.pseudonymise("test@example.com")
        self.assertTrue(p.startswith("pseu_"))

    def test_reverse_returns_original(self):
        original = "alice@example.com"
        pseudo   = self.vault.pseudonymise(original, context="email")
        reversed_val = self.vault.reverse(pseudo)
        self.assertEqual(reversed_val, original)

    def test_reverse_unknown_returns_none(self):
        self.assertIsNone(self.vault.reverse("pseu_doesnotexist"))

    def test_pseudonymise_column(self):
        df = _df()
        result = self.vault.pseudonymise_column(df, "email")
        self.assertEqual(len(result), len(df))
        self.assertTrue(all(str(v).startswith("pseu_") for v in result))

    def test_pseudonymise_column_does_not_modify_original(self):
        df = _df()
        orig = df["email"].tolist()
        self.vault.pseudonymise_column(df, "email")
        self.assertEqual(df["email"].tolist(), orig)

    def test_pseudonymise_columns_multiple(self):
        df = _df()
        out = self.vault.pseudonymise_columns(df, ["email"], inplace=False)
        self.assertTrue(all(str(v).startswith("pseu_") for v in out["email"]))
        # Original unchanged
        self.assertFalse(all(str(v).startswith("pseu_") for v in df["email"]))

    def test_vault_stats(self):
        self.vault.pseudonymise("a@b.com", context="email")
        self.vault.pseudonymise("c@d.com", context="email")
        stats = self.vault.vault_stats()
        self.assertEqual(stats["total_entries"], 2)
        self.assertIn("email", stats["by_context"])
        self.assertEqual(stats["by_context"]["email"], 2)

    def test_empty_value_passthrough(self):
        result = self.vault.pseudonymise("", context="email")
        self.assertEqual(result, "")

    def test_none_value_passthrough(self):
        result = self.vault.pseudonymise("None", context="email")
        # "None" as string — should still be pseudonymised (non-empty)
        self.assertTrue(result.startswith("pseu_"))

    def test_key_file_created(self):
        self.assertTrue(self.vault.key_path.exists())

    def test_vault_db_created(self):
        self.assertTrue(self.vault.vault_path.exists())

    def test_key_rotation(self):
        original = "rotate_test@example.com"
        pseudo   = self.vault.pseudonymise(original, context="email")
        new_key  = self.vault.rotate_key()
        self.assertTrue(new_key.exists())
        # After rotation, reverse should still work
        reversed_val = self.vault.reverse(pseudo)
        self.assertEqual(reversed_val, original)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
