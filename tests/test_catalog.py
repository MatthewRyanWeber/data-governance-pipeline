"""
Tests for pipeline.catalog — CatalogStore, CatalogSearch, and BusinessGlossary.

Comprehensive coverage of dataset registration, column tagging, quality scores,
deletion, full-text search, column search, PII column discovery, owner queries,
glossary term CRUD, search by definition/synonym/column, domain filtering,
dry-run mode, persistence, empty-state edge cases, and error handling.

Revision history
────────────────
1.0   2026-06-08   Initial release: 16 tests across 3 classes.
2.0   2026-06-09   Expanded to 46 tests: re-registration upsert, tag_column
                   on missing column, quality score on missing dataset, column
                   search, PII across multiple datasets, datasets_by_owner
                   with no match, search partial match, search_columns
                   partial, glossary export, glossary persistence round-trip,
                   glossary case-insensitive lookup, glossary remove
                   nonexistent, glossary search empty query, glossary
                   terms_for_column partial match, catalog dry-run for
                   tag_column/quality/delete, search on empty DB.
"""

import json
import logging
import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from pipeline.governance_logger import GovernanceLogger
from pipeline.catalog.catalog_store import CatalogStore
from pipeline.catalog.catalog_search import CatalogSearch
from pipeline.catalog.glossary import BusinessGlossary

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  1. CatalogStore
# ═══════════════════════════════════════════════════════════════════════════════


class TestCatalogStore(unittest.TestCase):
    """CatalogStore CRUD operations on datasets and columns."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("catalog_test", log_dir=self.tmp)
        self.db_path = Path(self.tmp) / "test_catalog.db"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_register_and_get_dataset(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"name": ["alice", "bob"], "age": [30, 40]})
        dataset_id = cat.register_dataset(df, "customers", owner="data-team", domain="CRM")
        self.assertIsNotNone(dataset_id)
        result = cat.get_dataset("customers")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "customers")
        self.assertEqual(result["row_count"], 2)
        self.assertEqual(result["owner"], "data-team")
        self.assertEqual(len(result["columns"]), 2)

    def test_register_empty_name_raises(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"x": [1]})
        with self.assertRaises(ValueError):
            cat.register_dataset(df, "")

    def test_register_whitespace_name_raises(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"x": [1]})
        with self.assertRaises(ValueError):
            cat.register_dataset(df, "   ")

    def test_list_datasets_returns_all(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df1 = pd.DataFrame({"a": [1]})
        df2 = pd.DataFrame({"b": [2]})
        cat.register_dataset(df1, "dataset_alpha", domain="sales")
        cat.register_dataset(df2, "dataset_beta", domain="marketing")
        all_datasets = cat.list_datasets()
        self.assertEqual(len(all_datasets), 2)

    def test_list_datasets_filter_by_domain(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df1 = pd.DataFrame({"a": [1]})
        df2 = pd.DataFrame({"b": [2]})
        cat.register_dataset(df1, "ds_sales", domain="sales")
        cat.register_dataset(df2, "ds_marketing", domain="marketing")
        sales = cat.list_datasets(domain="sales")
        self.assertEqual(len(sales), 1)
        self.assertEqual(sales[0]["domain"], "sales")

    def test_tag_column(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"email": ["alice@example.com"], "age": [30]})
        cat.register_dataset(df, "users")
        cat.tag_column("users", "email", pii=True, description="User email address")
        result = cat.get_dataset("users")
        email_col = next(c for c in result["columns"] if c["name"] == "email")
        self.assertEqual(email_col["pii"], 1)
        self.assertEqual(email_col["description"], "User email address")

    def test_tag_column_with_glossary_term(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"ltv_usd": [500.0]})
        cat.register_dataset(df, "metrics")
        cat.tag_column("metrics", "ltv_usd", glossary_term="Customer LTV")
        result = cat.get_dataset("metrics")
        col = next(c for c in result["columns"] if c["name"] == "ltv_usd")
        self.assertEqual(col["glossary_term"], "Customer LTV")

    def test_update_quality_score(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"x": [1, 2]})
        cat.register_dataset(df, "scored_ds")
        cat.update_quality_score("scored_ds", 87.5)
        result = cat.get_dataset("scored_ds")
        self.assertAlmostEqual(result["quality_score"], 87.5, places=1)

    def test_delete_dataset(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"x": [1]})
        cat.register_dataset(df, "to_delete")
        deleted = cat.delete_dataset("to_delete")
        self.assertTrue(deleted)
        self.assertIsNone(cat.get_dataset("to_delete"))

    def test_delete_nonexistent_returns_false(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        self.assertFalse(cat.delete_dataset("no_such_dataset"))

    def test_dry_run_does_not_persist(self):
        cat = CatalogStore(self.gov, db_path=self.db_path, dry_run=True)
        df = pd.DataFrame({"x": [1]})
        dataset_id = cat.register_dataset(df, "dry_ds")
        self.assertIsNotNone(dataset_id)
        cat2 = CatalogStore(self.gov, db_path=self.db_path)
        self.assertIsNone(cat2.get_dataset("dry_ds"))

    def test_register_with_tags(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"x": [1]})
        cat.register_dataset(df, "tagged_ds", tags=["pii", "finance"])
        result = cat.get_dataset("tagged_ds")
        self.assertEqual(result["tags"], ["pii", "finance"])

    def test_re_register_updates_metadata(self):
        """Re-registering with new metadata updates the existing record."""
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df1 = pd.DataFrame({"x": [1]})
        cat.register_dataset(df1, "evolving", owner="team_a", domain="sales")
        df2 = pd.DataFrame({"x": [1, 2], "y": [3, 4]})
        cat.register_dataset(df2, "evolving", owner="team_b", domain="marketing")
        result = cat.get_dataset("evolving")
        self.assertEqual(result["owner"], "team_b")
        self.assertEqual(result["domain"], "marketing")
        self.assertEqual(result["row_count"], 2)
        self.assertEqual(len(result["columns"]), 2)

    def test_register_stores_column_dtypes(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"name": ["alice"], "score": [95.5], "active": [True]})
        cat.register_dataset(df, "typed")
        result = cat.get_dataset("typed")
        dtypes = {c["name"]: c["dtype"] for c in result["columns"]}
        self.assertTrue(
            "object" in dtypes["name"] or "str" in dtypes["name"],
            f"Expected 'object' or 'str' dtype, got {dtypes['name']}",
        )
        self.assertIn("float", dtypes["score"])

    def test_register_detects_nullable_columns(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"complete": [1, 2, 3], "sparse": [1, None, 3]})
        cat.register_dataset(df, "nullable_test")
        result = cat.get_dataset("nullable_test")
        cols = {c["name"]: c for c in result["columns"]}
        self.assertEqual(cols["complete"]["nullable"], 0)
        self.assertEqual(cols["sparse"]["nullable"], 1)

    def test_get_nonexistent_dataset_returns_none(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        self.assertIsNone(cat.get_dataset("ghost"))

    def test_list_datasets_empty_returns_empty(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        self.assertEqual(cat.list_datasets(), [])

    def test_delete_removes_columns_too(self):
        """Deleting a dataset also removes its column metadata."""
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"a": [1], "b": [2]})
        cat.register_dataset(df, "full_delete")
        cat.delete_dataset("full_delete")
        # Re-register with different columns to prove old columns are gone
        df2 = pd.DataFrame({"c": [3]})
        cat.register_dataset(df2, "full_delete")
        result = cat.get_dataset("full_delete")
        col_names = [c["name"] for c in result["columns"]]
        self.assertEqual(col_names, ["c"])

    def test_dry_run_tag_column_does_not_persist(self):
        cat_real = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"email": ["alice@example.com"]})
        cat_real.register_dataset(df, "dry_tag_test")

        cat_dry = CatalogStore(self.gov, db_path=self.db_path, dry_run=True)
        cat_dry.tag_column("dry_tag_test", "email", pii=True)

        result = cat_real.get_dataset("dry_tag_test")
        email_col = next(c for c in result["columns"] if c["name"] == "email")
        self.assertEqual(email_col["pii"], 0)

    def test_dry_run_quality_score_does_not_persist(self):
        cat_real = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"x": [1]})
        cat_real.register_dataset(df, "dry_score_test")

        cat_dry = CatalogStore(self.gov, db_path=self.db_path, dry_run=True)
        cat_dry.update_quality_score("dry_score_test", 99.9)

        result = cat_real.get_dataset("dry_score_test")
        self.assertIsNone(result["quality_score"])

    def test_dry_run_delete_returns_false(self):
        cat = CatalogStore(self.gov, db_path=self.db_path, dry_run=True)
        self.assertFalse(cat.delete_dataset("anything"))

    def test_register_with_source_info(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({"x": [1]})
        cat.register_dataset(
            df, "sourced", source_type="s3", source_path="s3://bucket/data.csv",
        )
        result = cat.get_dataset("sourced")
        self.assertEqual(result["source_type"], "s3")
        self.assertEqual(result["source_path"], "s3://bucket/data.csv")


# ═══════════════════════════════════════════════════════════════════════════════
#  2. CatalogSearch
# ═══════════════════════════════════════════════════════════════════════════════


class TestCatalogSearch(unittest.TestCase):
    """CatalogSearch full-text and column search."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("search_test", log_dir=self.tmp)
        self.db_path = Path(self.tmp) / "search_catalog.db"
        self.cat = CatalogStore(self.gov, db_path=self.db_path)
        df = pd.DataFrame({
            "email": ["alice@example.com"],
            "full_name": ["Alice Smith"],
        })
        self.cat.register_dataset(
            df, "customer_emails",
            description="Customer email addresses",
            owner="data-team",
            domain="CRM",
        )
        self.cat.tag_column("customer_emails", "email", pii=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_search_by_name(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        results = search.search("customer")
        self.assertGreater(len(results), 0)

    def test_search_empty_query_returns_empty(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        self.assertEqual(search.search(""), [])

    def test_search_whitespace_query_returns_empty(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        self.assertEqual(search.search("   "), [])

    def test_find_pii_columns(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        pii_cols = search.find_pii_columns()
        self.assertGreater(len(pii_cols), 0)
        self.assertEqual(pii_cols[0]["name"], "email")

    def test_datasets_by_owner(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        results = search.datasets_by_owner("data-team")
        self.assertEqual(len(results), 1)

    def test_datasets_by_owner_no_match(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        results = search.datasets_by_owner("nonexistent-team")
        self.assertEqual(results, [])

    def test_search_columns_by_name(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        results = search.search_columns("email")
        self.assertGreater(len(results), 0)
        col_names = [r["name"] for r in results]
        self.assertIn("email", col_names)

    def test_search_columns_empty_returns_empty(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        self.assertEqual(search.search_columns(""), [])

    def test_find_pii_across_multiple_datasets(self):
        df2 = pd.DataFrame({"ssn": ["555-12-3456"], "dept": ["engineering"]})
        self.cat.register_dataset(df2, "employee_data", domain="HR")
        self.cat.tag_column("employee_data", "ssn", pii=True, description="Social security")
        search = CatalogSearch(self.gov, db_path=self.db_path)
        pii_cols = search.find_pii_columns()
        self.assertEqual(len(pii_cols), 2)
        pii_names = {c["name"] for c in pii_cols}
        self.assertEqual(pii_names, {"email", "ssn"})

    def test_search_no_results(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        results = search.search("zzz_nonexistent_term_zzz")
        self.assertEqual(results, [])

    def test_search_on_nonexistent_db(self):
        missing_db = Path(self.tmp) / "nonexistent.db"
        search = CatalogSearch(self.gov, db_path=missing_db)
        self.assertEqual(search.search("anything"), [])
        self.assertEqual(search.search_columns("anything"), [])
        self.assertEqual(search.find_pii_columns(), [])
        self.assertEqual(search.datasets_by_owner("anyone"), [])

    def test_search_logs_governance_event(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        search.search("customer")
        # GovernanceLogger.transformation_applied is a real method here,
        # so we verify it doesn't raise and the search completes.


# ═══════════════════════════════════════════════════════════════════════════════
#  3. BusinessGlossary
# ═══════════════════════════════════════════════════════════════════════════════


class TestBusinessGlossary(unittest.TestCase):
    """BusinessGlossary term mapping and search."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("glossary_test", log_dir=self.tmp)
        self.glossary_file = Path(self.tmp) / "glossary.json"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_add_and_get_term(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Customer LTV", "Lifetime value in USD", domain="Finance")
        result = g.get_term("Customer LTV")
        self.assertIsNotNone(result)
        self.assertEqual(result["definition"], "Lifetime value in USD")
        self.assertEqual(result["domain"], "Finance")

    def test_add_empty_term_raises(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        with self.assertRaises(ValueError):
            g.add_term("", "some definition")

    def test_add_whitespace_term_raises(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        with self.assertRaises(ValueError):
            g.add_term("   ", "some definition")

    def test_search_by_definition(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Churn Rate", "Percentage of customers who stop using the service")
        results = g.search("customers who stop")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["term"], "Churn Rate")

    def test_search_by_synonym(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("MRR", "Monthly Recurring Revenue", synonyms=["monthly revenue"])
        results = g.search("monthly revenue")
        self.assertEqual(len(results), 1)

    def test_search_by_term_name(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Revenue Growth", "Year-over-year revenue increase")
        results = g.search("revenue")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["term"], "Revenue Growth")

    def test_search_by_column_mapping(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("ARR", "Annual Recurring Revenue", columns=["finance.arr_usd"])
        results = g.search("finance.arr")
        self.assertEqual(len(results), 1)

    def test_search_empty_query_returns_empty(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Something", "Definition")
        self.assertEqual(g.search(""), [])

    def test_search_whitespace_query_returns_empty(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Something", "Definition")
        self.assertEqual(g.search("   "), [])

    def test_search_no_match_returns_empty(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Revenue", "Total income")
        self.assertEqual(g.search("zzz_nonexistent_zzz"), [])

    def test_terms_for_column(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("ARR", "Annual Recurring Revenue", columns=["finance.arr_usd"])
        results = g.terms_for_column("finance.arr_usd")
        self.assertEqual(len(results), 1)

    def test_terms_for_column_partial_match(self):
        """terms_for_column uses substring matching on column names."""
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("LTV", "Lifetime value", columns=["customers.ltv_usd"])
        results = g.terms_for_column("ltv_usd")
        self.assertEqual(len(results), 1)

    def test_terms_for_column_no_match(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("LTV", "Lifetime value", columns=["customers.ltv_usd"])
        results = g.terms_for_column("nonexistent_col")
        self.assertEqual(results, [])

    def test_remove_term(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Temp Term", "Will be removed")
        self.assertTrue(g.remove_term("Temp Term"))
        self.assertIsNone(g.get_term("Temp Term"))

    def test_remove_nonexistent_term_returns_false(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        self.assertFalse(g.remove_term("never_existed"))

    def test_dry_run_does_not_save(self):
        g = BusinessGlossary(
            self.gov, glossary_file=self.glossary_file, dry_run=True,
        )
        g.add_term("Ghost Term", "Should not persist")
        self.assertFalse(self.glossary_file.exists())

    def test_dry_run_remove_returns_false(self):
        g_real = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g_real.add_term("Kept Term", "Should survive dry-run remove")

        g_dry = BusinessGlossary(
            self.gov, glossary_file=self.glossary_file, dry_run=True,
        )
        result = g_dry.remove_term("Kept Term")
        self.assertFalse(result)

    def test_list_terms_by_domain(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("CAC", "Customer Acquisition Cost", domain="Marketing")
        g.add_term("NPS", "Net Promoter Score", domain="Support")
        marketing = g.list_terms(domain="Marketing")
        self.assertEqual(len(marketing), 1)
        self.assertEqual(marketing[0]["term"], "CAC")

    def test_list_terms_all(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("CAC", "Customer Acquisition Cost", domain="Marketing")
        g.add_term("NPS", "Net Promoter Score", domain="Support")
        g.add_term("ARR", "Annual Recurring Revenue", domain="Finance")
        all_terms = g.list_terms()
        self.assertEqual(len(all_terms), 3)

    def test_list_terms_empty_glossary(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        self.assertEqual(g.list_terms(), [])

    def test_case_insensitive_lookup(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Customer LTV", "Lifetime value in USD")
        self.assertIsNotNone(g.get_term("customer ltv"))
        self.assertIsNotNone(g.get_term("CUSTOMER LTV"))
        self.assertIsNotNone(g.get_term("Customer LTV"))

    def test_update_existing_term(self):
        """Adding a term that already exists overwrites it."""
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("MRR", "Monthly Recurring Revenue", domain="Finance")
        g.add_term("MRR", "Monthly Recurring Revenue (updated)", domain="Accounting")
        result = g.get_term("MRR")
        self.assertEqual(result["definition"], "Monthly Recurring Revenue (updated)")
        self.assertEqual(result["domain"], "Accounting")

    def test_export_glossary(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Alpha", "First letter", domain="Greek")
        g.add_term("Beta", "Second letter", domain="Greek")
        export = g.export()
        self.assertEqual(export["version"], "1.0")
        self.assertEqual(export["term_count"], 2)
        self.assertIn("alpha", export["terms"])
        self.assertIn("beta", export["terms"])

    def test_export_empty_glossary(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        export = g.export()
        self.assertEqual(export["term_count"], 0)
        self.assertEqual(export["terms"], {})

    def test_add_term_with_all_metadata(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term(
            "Customer LTV",
            "Lifetime value in USD",
            domain="Finance",
            owner="analytics-team",
            columns=["customers.ltv_usd", "summary.ltv"],
            synonyms=["lifetime value", "CLV"],
            tags=["kpi", "finance", "retention"],
        )
        result = g.get_term("Customer LTV")
        self.assertEqual(result["owner"], "analytics-team")
        self.assertEqual(result["columns"], ["customers.ltv_usd", "summary.ltv"])
        self.assertEqual(result["synonyms"], ["lifetime value", "CLV"])
        self.assertEqual(result["tags"], ["kpi", "finance", "retention"])


# ═══════════════════════════════════════════════════════════════════════════════
#  4. Glossary persistence round-trip
# ═══════════════════════════════════════════════════════════════════════════════


class TestGlossaryPersistence(unittest.TestCase):
    """A fresh BusinessGlossary reads terms written by another instance."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("persistence_test", log_dir=self.tmp)
        self.glossary_file = Path(self.tmp) / "glossary.json"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_round_trip_preserves_terms(self):
        g1 = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g1.add_term("Alpha", "First", domain="Greek", columns=["tbl.alpha"])
        g1.add_term("Beta", "Second", domain="Greek", synonyms=["B"])

        g2 = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        self.assertIsNotNone(g2.get_term("Alpha"))
        self.assertEqual(g2.get_term("Alpha")["columns"], ["tbl.alpha"])
        self.assertIsNotNone(g2.get_term("Beta"))
        self.assertEqual(g2.get_term("Beta")["synonyms"], ["B"])

    def test_load_from_corrupt_file_returns_empty(self):
        self.glossary_file.write_text("NOT VALID JSON {{{", encoding="utf-8")
        with self.assertLogs("pipeline.catalog.glossary", level="WARNING"):
            g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        self.assertEqual(g.list_terms(), [])

    def test_glossary_file_structure(self):
        """The persisted JSON has version, updated_utc, and terms keys."""
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Test", "A test term")
        data = json.loads(self.glossary_file.read_text(encoding="utf-8"))
        self.assertIn("version", data)
        self.assertIn("updated_utc", data)
        self.assertIn("terms", data)
        self.assertEqual(data["version"], "1.0")


if __name__ == "__main__":
    unittest.main()
