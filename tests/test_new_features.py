"""
Tests for the 10 new features added to the data governance pipeline.

1. Data Catalog                    6. Business Glossary
2. Automated Column Profiling      7. Automated Test Generation
3. RBAC / Access Policies          8. NLP PII Detection
4. Data Observability              9. Data Versioning
5. OpenLineage Emitter            10. ML Model Governance

Revision history
────────────────
1.0   2026-06-08   Initial test suite for all 10 features.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd


def _make_gov(tmpdir):
    gov = MagicMock()
    gov.log_dir = Path(tmpdir)
    gov.dlq_file = str(Path(tmpdir) / "dlq.csv")
    gov.transformation_applied = MagicMock()
    gov.error = MagicMock()
    return gov


class TestCatalogStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)
        self.db_path = Path(self.tmpdir) / "catalog.db"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_register_and_get_dataset(self):
        from pipeline.catalog.catalog_store import CatalogStore
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"name": ["Alice", "Bob"], "age": [30, 25]})
        ds_id = cat.register_dataset(df, "customers", owner="data-team", domain="CRM")
        self.assertIsInstance(ds_id, str)
        result = cat.get_dataset("customers")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "customers")
        self.assertEqual(result["row_count"], 2)
        self.assertEqual(result["col_count"], 2)
        self.assertEqual(result["owner"], "data-team")

    def test_list_datasets(self):
        from pipeline.catalog.catalog_store import CatalogStore
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df1 = pd.DataFrame({"a": [1]})
        df2 = pd.DataFrame({"b": [2]})
        cat.register_dataset(df1, "ds1", domain="sales")
        cat.register_dataset(df2, "ds2", domain="sales")
        all_ds = cat.list_datasets()
        self.assertEqual(len(all_ds), 2)
        sales_ds = cat.list_datasets(domain="sales")
        self.assertEqual(len(sales_ds), 2)

    def test_tag_column(self):
        from pipeline.catalog.catalog_store import CatalogStore
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"email": ["a@b.com"], "name": ["Alice"]})
        cat.register_dataset(df, "users")
        cat.tag_column("users", "email", pii=True, description="User email")
        result = cat.get_dataset("users")
        email_col = [c for c in result["columns"] if c["name"] == "email"][0]
        self.assertEqual(email_col["pii"], 1)

    def test_delete_dataset(self):
        from pipeline.catalog.catalog_store import CatalogStore
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"x": [1]})
        cat.register_dataset(df, "temp")
        self.assertTrue(cat.delete_dataset("temp"))
        self.assertIsNone(cat.get_dataset("temp"))


class TestCatalogSearch(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)
        self.db_path = Path(self.tmpdir) / "catalog.db"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_search_by_name(self):
        from pipeline.catalog.catalog_store import CatalogStore
        from pipeline.catalog.catalog_search import CatalogSearch
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"revenue": [100]})
        cat.register_dataset(df, "quarterly_revenue", domain="finance")
        search = CatalogSearch(self.gov, db_path=self.db_path)
        results = search.search("revenue")
        self.assertGreaterEqual(len(results), 1)

    def test_search_columns(self):
        from pipeline.catalog.catalog_store import CatalogStore
        from pipeline.catalog.catalog_search import CatalogSearch
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"customer_email": ["a@b.com"]})
        cat.register_dataset(df, "users")
        search = CatalogSearch(self.gov, db_path=self.db_path)
        results = search.search_columns("email")
        self.assertGreaterEqual(len(results), 1)


class TestBusinessGlossary(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)
        self.glossary_file = Path(self.tmpdir) / "glossary.json"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_add_and_get_term(self):
        from pipeline.catalog.glossary import BusinessGlossary
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Customer LTV", "Lifetime value in USD",
                    domain="Finance", columns=["customers.ltv_usd"])
        result = g.get_term("Customer LTV")
        self.assertIsNotNone(result)
        self.assertEqual(result["definition"], "Lifetime value in USD")

    def test_search_terms(self):
        from pipeline.catalog.glossary import BusinessGlossary
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Monthly Revenue", "Total revenue per month", domain="Finance")
        g.add_term("Churn Rate", "Rate of customer attrition", domain="Product")
        results = g.search("revenue")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["term"], "Monthly Revenue")

    def test_terms_for_column(self):
        from pipeline.catalog.glossary import BusinessGlossary
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("LTV", "Lifetime value", columns=["customers.ltv"])
        matches = g.terms_for_column("customers.ltv")
        self.assertEqual(len(matches), 1)

    def test_remove_term(self):
        from pipeline.catalog.glossary import BusinessGlossary
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Temp", "Temporary term")
        self.assertTrue(g.remove_term("Temp"))
        self.assertIsNone(g.get_term("Temp"))


class TestColumnProfiler(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_profile_basic(self):
        from pipeline.quality.column_profiler import ColumnProfiler
        profiler = ColumnProfiler(self.gov)
        df = pd.DataFrame({
            "id": [1, 2, 3, 4, 5],
            "name": ["Alice", "Bob", "Charlie", None, "Eve"],
            "score": [85.5, 92.0, 78.3, 95.1, 88.0],
        })
        result = profiler.profile(df, dataset_name="test")
        self.assertEqual(result["row_count"], 5)
        self.assertEqual(result["column_count"], 3)
        cols = {c["name"]: c for c in result["columns"]}
        self.assertEqual(cols["name"]["null_count"], 1)
        self.assertIn("mean", cols["score"])

    def test_profile_history(self):
        from pipeline.quality.column_profiler import ColumnProfiler
        profiler = ColumnProfiler(self.gov)
        df = pd.DataFrame({"x": [1, 2, 3]})
        profiler.profile(df, dataset_name="ds1")
        profiler.profile(df, dataset_name="ds1")
        history = profiler.history("ds1")
        self.assertEqual(len(history), 2)


class TestAccessPolicy(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)
        self.policy_file = Path(self.tmpdir) / "policies.json"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_role_and_enforce(self):
        from pipeline.security.access_policy import AccessPolicy
        pol = AccessPolicy(self.gov, policy_file=self.policy_file)
        pol.add_role("analyst", denied_columns=["ssn", "salary"])
        df = pd.DataFrame({"name": ["Alice"], "ssn": ["123"], "salary": [100000], "dept": ["Eng"]})
        result = pol.enforce(df, role="analyst")
        self.assertNotIn("ssn", result.columns)
        self.assertNotIn("salary", result.columns)
        self.assertIn("name", result.columns)
        self.assertIn("dept", result.columns)

    def test_allowed_columns_whitelist(self):
        from pipeline.security.access_policy import AccessPolicy
        pol = AccessPolicy(self.gov, policy_file=self.policy_file)
        pol.add_role("viewer", allowed_columns=["name", "dept"])
        df = pd.DataFrame({"name": ["Alice"], "ssn": ["123"], "dept": ["Eng"]})
        result = pol.enforce(df, role="viewer")
        self.assertEqual(set(result.columns), {"name", "dept"})

    def test_assign_role_to_user(self):
        from pipeline.security.access_policy import AccessPolicy
        pol = AccessPolicy(self.gov, policy_file=self.policy_file)
        pol.add_role("admin")
        pol.assign_role("alice", "admin")
        self.assertEqual(pol.user_roles("alice"), ["admin"])

    def test_row_filter(self):
        from pipeline.security.access_policy import AccessPolicy
        pol = AccessPolicy(self.gov, policy_file=self.policy_file)
        pol.add_role("us_only", row_filter="country == 'US'")
        df = pd.DataFrame({"name": ["Alice", "Bob"], "country": ["US", "UK"]})
        result = pol.enforce(df, role="us_only")
        self.assertEqual(len(result), 1)
        self.assertEqual(result.iloc[0]["name"], "Alice")

    def test_missing_role_raises(self):
        from pipeline.security.access_policy import AccessPolicy
        pol = AccessPolicy(self.gov, policy_file=self.policy_file)
        df = pd.DataFrame({"x": [1]})
        with self.assertRaises(ValueError):
            pol.enforce(df, role="nonexistent_role")

    def test_row_filter_injection_blocked(self):
        from pipeline.security.access_policy import AccessPolicy
        pol = AccessPolicy(self.gov, policy_file=self.policy_file)
        pol.add_role("evil", row_filter="__import__('os').system('echo pwned')")
        df = pd.DataFrame({"x": [1]})
        with self.assertRaises(ValueError):
            pol.enforce(df, role="evil")


class TestDataObserver(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_observe_basic(self):
        from pipeline.monitoring.observability import DataObserver
        obs = DataObserver(self.gov)
        df = pd.DataFrame({"x": [1, 2, 3], "y": ["a", "b", "c"]})
        report = obs.observe(df, dataset="test")
        self.assertEqual(report["row_count"], 3)
        self.assertIn("alerts", report)

    def test_freshness_alert(self):
        from pipeline.monitoring.observability import DataObserver
        obs = DataObserver(self.gov, freshness_threshold_hours=1.0)
        old_date = pd.Timestamp("2020-01-01")
        df = pd.DataFrame({"ts": [old_date], "val": [1]})
        report = obs.observe(df, dataset="stale", timestamp_col="ts")
        freshness_alerts = [a for a in report["alerts"] if a["type"] == "FRESHNESS"]
        self.assertGreater(len(freshness_alerts), 0)

    def test_column_stats_persisted_for_drift(self):
        import json as _json
        from pipeline.monitoring.observability import DataObserver
        obs = DataObserver(self.gov)
        df = pd.DataFrame({"metric": [10.0, 20.0, 30.0]})
        obs.observe(df, dataset="drift_test")
        lines = obs.history_file.read_text(encoding="utf-8").strip().splitlines()
        record = _json.loads(lines[-1])
        self.assertIn("column_stats", record)
        self.assertEqual(len(record["column_stats"]), 1)
        self.assertAlmostEqual(record["column_stats"][0]["mean"], 20.0, places=2)


class TestOpenLineageEmitter(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_emit_start_complete(self):
        from pipeline.lineage.openlineage_emitter import OpenLineageEmitter
        emitter = OpenLineageEmitter(self.gov, namespace="test")
        start = emitter.emit_start("extract", inputs=["s3://bucket/raw.csv"])
        self.assertEqual(start["eventType"], "START")
        self.assertEqual(len(start["inputs"]), 1)
        complete = emitter.emit_complete("extract", outputs=["postgres://db/staging"])
        self.assertEqual(complete["eventType"], "COMPLETE")

    def test_emit_fail(self):
        from pipeline.lineage.openlineage_emitter import OpenLineageEmitter
        emitter = OpenLineageEmitter(self.gov, namespace="test")
        fail = emitter.emit_fail("load", error_message="Connection refused")
        self.assertEqual(fail["eventType"], "FAIL")
        self.assertIn("errorMessage", fail["run"]["facets"])

    def test_events_written_to_file(self):
        from pipeline.lineage.openlineage_emitter import OpenLineageEmitter
        out = Path(self.tmpdir) / "ol.jsonl"
        emitter = OpenLineageEmitter(self.gov, namespace="test", output_file=out)
        emitter.emit_start("job1")
        emitter.emit_complete("job1")
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)


class TestTestGenerator(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generate_from_profile(self):
        from pipeline.quality.column_profiler import ColumnProfiler
        from pipeline.quality.test_generator import TestGenerator
        profiler = ColumnProfiler(self.gov)
        df = pd.DataFrame({
            "id": [1, 2, 3, 4, 5],
            "name": ["Alice", "Bob", "Charlie", "Diana", "Eve"],
            "score": [85.0, 92.0, 78.0, 95.0, 88.0],
        })
        profile = profiler.profile(df, dataset_name="test")
        gen = TestGenerator(self.gov)
        expectations = gen.generate(profile)
        self.assertGreater(len(expectations), 0)
        types = {e["expectation_type"] for e in expectations}
        self.assertIn("expect_table_row_count_to_be_between", types)

    def test_save_suite(self):
        from pipeline.quality.test_generator import TestGenerator
        gen = TestGenerator(self.gov)
        expectations = [{
            "expectation_type": "expect_column_values_to_not_be_null",
            "kwargs": {"column": "id"},
            "meta": {"source": "test"},
        }]
        path = Path(self.tmpdir) / "suite.json"
        gen.save_suite(expectations, path)
        self.assertTrue(path.exists())
        suite = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(suite["expectations"]), 1)


class TestNLPPIIDetector(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_regex_detection(self):
        from pipeline.privacy.nlp_pii_detector import NLPPIIDetector
        detector = NLPPIIDetector(self.gov, confidence_threshold=0.01)
        df = pd.DataFrame({
            "notes": [
                "Contact alice@example.com for details",
                "Call 555-123-4567",
                "SSN: 123-45-6789",
                "Normal text here",
            ]
        })
        findings = detector.scan(df, text_columns=["notes"], include_regex=True)
        types = {f["entity_type"] for f in findings}
        self.assertIn("EMAIL", types)
        self.assertIn("PHONE", types)
        self.assertIn("SSN", types)

    def test_scan_and_classify(self):
        from pipeline.privacy.nlp_pii_detector import NLPPIIDetector
        detector = NLPPIIDetector(self.gov, confidence_threshold=0.01)
        df = pd.DataFrame({"email_field": ["test@example.com"] * 5})
        classification = detector.scan_and_classify(df, text_columns=["email_field"])
        self.assertIn("email_field", classification)


class TestSnapshotStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)
        self.snap_dir = Path(self.tmpdir) / "snapshots"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_snapshot_and_checkout(self):
        from pipeline.versioning.snapshot_store import SnapshotStore
        store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        df = pd.DataFrame({"name": ["Alice", "Bob"], "age": [30, 25]})
        v = store.snapshot(df, "customers", message="Initial")
        self.assertEqual(v, 1)
        loaded = store.checkout("customers", version=1)
        self.assertEqual(len(loaded), 2)
        self.assertIn("name", loaded.columns)

    def test_skip_identical_snapshot(self):
        from pipeline.versioning.snapshot_store import SnapshotStore
        store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        df = pd.DataFrame({"x": [1, 2, 3]})
        v1 = store.snapshot(df, "ds")
        v2 = store.snapshot(df, "ds")
        self.assertEqual(v1, v2)

    def test_diff(self):
        from pipeline.versioning.snapshot_store import SnapshotStore
        store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        df1 = pd.DataFrame({"name": ["Alice"], "age": [30]})
        df2 = pd.DataFrame({"name": ["Alice", "Bob"], "age": [30, 25], "email": ["a@b.com", "b@c.com"]})
        store.snapshot(df1, "users", message="v1")
        store.snapshot(df2, "users", message="v2")
        diff = store.diff("users")
        self.assertEqual(diff["row_diff"], 1)
        self.assertIn("email", diff["columns_added"])

    def test_list_versions(self):
        from pipeline.versioning.snapshot_store import SnapshotStore
        store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        df1 = pd.DataFrame({"x": [1]})
        df2 = pd.DataFrame({"x": [1, 2]})
        store.snapshot(df1, "ds")
        store.snapshot(df2, "ds")
        versions = store.list_versions("ds")
        self.assertEqual(len(versions), 2)

    def test_delete_version(self):
        from pipeline.versioning.snapshot_store import SnapshotStore
        store = SnapshotStore(self.gov, snapshot_dir=self.snap_dir)
        df = pd.DataFrame({"x": [1]})
        store.snapshot(df, "ds")
        self.assertTrue(store.delete_version("ds", 1))


class TestModelRegistry(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = _make_gov(self.tmpdir)
        self.reg_file = Path(self.tmpdir) / "models.json"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_register_and_list(self):
        from pipeline.ml_governance.model_registry import ModelRegistry
        reg = ModelRegistry(self.gov, registry_file=self.reg_file)
        reg.register_model("churn", framework="sklearn",
                           datasets=["customers", "transactions"])
        models = reg.list_models()
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["model_name"], "churn")

    def test_log_training_run(self):
        from pipeline.ml_governance.model_registry import ModelRegistry
        reg = ModelRegistry(self.gov, registry_file=self.reg_file)
        reg.register_model("churn", framework="sklearn")
        v = reg.log_training_run("churn", metrics={"accuracy": 0.92, "f1": 0.88})
        self.assertEqual(v, 1)
        lineage = reg.training_lineage("churn")
        self.assertEqual(lineage["total_versions"], 1)
        self.assertEqual(lineage["versions"][0]["metrics"]["accuracy"], 0.92)

    def test_impact_analysis(self):
        from pipeline.ml_governance.model_registry import ModelRegistry
        reg = ModelRegistry(self.gov, registry_file=self.reg_file)
        reg.register_model("model_a", datasets=["customers"])
        reg.register_model("model_b", datasets=["customers", "orders"])
        reg.register_model("model_c", datasets=["orders"])
        affected = reg.impact_analysis("customers")
        names = {m["model_name"] for m in affected}
        self.assertEqual(names, {"model_a", "model_b"})

    def test_compare_versions(self):
        from pipeline.ml_governance.model_registry import ModelRegistry
        reg = ModelRegistry(self.gov, registry_file=self.reg_file)
        reg.register_model("churn")
        reg.log_training_run("churn", metrics={"accuracy": 0.85})
        reg.log_training_run("churn", metrics={"accuracy": 0.92})
        diff = reg.compare_versions("churn", 1, 2)
        self.assertAlmostEqual(diff["metric_diff"]["accuracy"]["diff"], 0.07, places=2)

    def test_delete_model(self):
        from pipeline.ml_governance.model_registry import ModelRegistry
        reg = ModelRegistry(self.gov, registry_file=self.reg_file)
        reg.register_model("temp")
        self.assertTrue(reg.delete_model("temp"))
        self.assertEqual(len(reg.list_models()), 0)


if __name__ == "__main__":
    unittest.main()
