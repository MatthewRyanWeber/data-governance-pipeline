"""
Tests for pipeline.catalog — CatalogStore, CatalogSearch, and BusinessGlossary.

Revision history
────────────────
1.0   2026-06-08   Initial release: 16 tests across 3 classes.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from pipeline.governance_logger import GovernanceLogger
from pipeline.catalog.catalog_store import CatalogStore
from pipeline.catalog.catalog_search import CatalogSearch
from pipeline.catalog.glossary import BusinessGlossary


class TestCatalogStore(unittest.TestCase):
    """CatalogStore CRUD operations on datasets and columns."""

    def setUp(self):
        import pandas as pd
        self.pd = pd
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("catalog_test", log_dir=self.tmp)
        self.db_path = Path(self.tmp) / "test_catalog.db"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_register_and_get_dataset(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = self.pd.DataFrame({"name": ["alice", "bob"], "age": [30, 40]})
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
        df = self.pd.DataFrame({"x": [1]})
        with self.assertRaises(ValueError):
            cat.register_dataset(df, "")

    def test_list_datasets_returns_all(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df1 = self.pd.DataFrame({"a": [1]})
        df2 = self.pd.DataFrame({"b": [2]})
        cat.register_dataset(df1, "dataset_alpha", domain="sales")
        cat.register_dataset(df2, "dataset_beta", domain="marketing")
        all_datasets = cat.list_datasets()
        self.assertEqual(len(all_datasets), 2)

    def test_list_datasets_filter_by_domain(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df1 = self.pd.DataFrame({"a": [1]})
        df2 = self.pd.DataFrame({"b": [2]})
        cat.register_dataset(df1, "ds_sales", domain="sales")
        cat.register_dataset(df2, "ds_marketing", domain="marketing")
        sales = cat.list_datasets(domain="sales")
        self.assertEqual(len(sales), 1)
        self.assertEqual(sales[0]["domain"], "sales")

    def test_tag_column(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = self.pd.DataFrame({"email": ["alice@example.com"], "age": [30]})
        cat.register_dataset(df, "users")
        cat.tag_column("users", "email", pii=True, description="User email address")
        result = cat.get_dataset("users")
        email_col = next(c for c in result["columns"] if c["name"] == "email")
        self.assertEqual(email_col["pii"], 1)
        self.assertEqual(email_col["description"], "User email address")

    def test_update_quality_score(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = self.pd.DataFrame({"x": [1, 2]})
        cat.register_dataset(df, "scored_ds")
        cat.update_quality_score("scored_ds", 87.5)
        result = cat.get_dataset("scored_ds")
        self.assertAlmostEqual(result["quality_score"], 87.5, places=1)

    def test_delete_dataset(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = self.pd.DataFrame({"x": [1]})
        cat.register_dataset(df, "to_delete")
        deleted = cat.delete_dataset("to_delete")
        self.assertTrue(deleted)
        self.assertIsNone(cat.get_dataset("to_delete"))

    def test_delete_nonexistent_returns_false(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        self.assertFalse(cat.delete_dataset("no_such_dataset"))

    def test_dry_run_does_not_persist(self):
        cat = CatalogStore(self.gov, db_path=self.db_path, dry_run=True)
        df = self.pd.DataFrame({"x": [1]})
        dataset_id = cat.register_dataset(df, "dry_ds")
        self.assertIsNotNone(dataset_id)
        cat2 = CatalogStore(self.gov, db_path=self.db_path)
        self.assertIsNone(cat2.get_dataset("dry_ds"))

    def test_register_with_tags(self):
        cat = CatalogStore(self.gov, db_path=self.db_path)
        df = self.pd.DataFrame({"x": [1]})
        cat.register_dataset(df, "tagged_ds", tags=["pii", "finance"])
        result = cat.get_dataset("tagged_ds")
        self.assertEqual(result["tags"], ["pii", "finance"])


class TestCatalogSearch(unittest.TestCase):
    """CatalogSearch full-text and column search."""

    def setUp(self):
        import pandas as pd
        self.pd = pd
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("search_test", log_dir=self.tmp)
        self.db_path = Path(self.tmp) / "search_catalog.db"
        self.cat = CatalogStore(self.gov, db_path=self.db_path)
        df = self.pd.DataFrame({
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

    def test_find_pii_columns(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        pii_cols = search.find_pii_columns()
        self.assertGreater(len(pii_cols), 0)
        self.assertEqual(pii_cols[0]["name"], "email")

    def test_datasets_by_owner(self):
        search = CatalogSearch(self.gov, db_path=self.db_path)
        results = search.datasets_by_owner("data-team")
        self.assertEqual(len(results), 1)


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

    def test_terms_for_column(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("ARR", "Annual Recurring Revenue", columns=["finance.arr_usd"])
        results = g.terms_for_column("finance.arr_usd")
        self.assertEqual(len(results), 1)

    def test_remove_term(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("Temp Term", "Will be removed")
        self.assertTrue(g.remove_term("Temp Term"))
        self.assertIsNone(g.get_term("Temp Term"))

    def test_dry_run_does_not_save(self):
        g = BusinessGlossary(
            self.gov, glossary_file=self.glossary_file, dry_run=True,
        )
        g.add_term("Ghost Term", "Should not persist")
        self.assertFalse(self.glossary_file.exists())

    def test_list_terms_by_domain(self):
        g = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        g.add_term("CAC", "Customer Acquisition Cost", domain="Marketing")
        g.add_term("NPS", "Net Promoter Score", domain="Support")
        marketing = g.list_terms(domain="Marketing")
        self.assertEqual(len(marketing), 1)
        self.assertEqual(marketing[0]["term"], "CAC")


if __name__ == "__main__":
    unittest.main()
