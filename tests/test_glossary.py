"""
Tests for the business glossary.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pipeline.catalog.glossary import BusinessGlossary


class TestBusinessGlossary(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.glossary_file = Path(self.tmpdir) / "glossary.json"
        self.gov = MagicMock()
        self.glossary = BusinessGlossary(
            self.gov, glossary_file=self.glossary_file,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_add_and_get_term(self):
        self.glossary.add_term("Customer LTV", "Lifetime value in USD", domain="Finance")
        result = self.glossary.get_term("Customer LTV")
        self.assertIsNotNone(result)
        self.assertEqual(result["term"], "Customer LTV")
        self.assertEqual(result["definition"], "Lifetime value in USD")

    def test_search_by_name(self):
        self.glossary.add_term("Revenue", "Total income")
        results = self.glossary.search("revenue")
        self.assertEqual(len(results), 1)

    def test_search_by_definition(self):
        self.glossary.add_term("ARR", "Annual recurring revenue")
        results = self.glossary.search("recurring")
        self.assertEqual(len(results), 1)

    def test_search_by_synonym(self):
        self.glossary.add_term("Churn", "Customer attrition",
                               synonyms=["attrition", "turnover"])
        results = self.glossary.search("turnover")
        self.assertEqual(len(results), 1)

    def test_search_by_column(self):
        self.glossary.add_term("MRR", "Monthly recurring revenue",
                               columns=["billing.mrr_usd"])
        results = self.glossary.search("mrr_usd")
        self.assertEqual(len(results), 1)

    def test_search_empty_query(self):
        self.glossary.add_term("Test", "def")
        results = self.glossary.search("")
        self.assertEqual(results, [])

    def test_terms_for_column(self):
        self.glossary.add_term("Email", "Customer email",
                               columns=["customers.email"])
        results = self.glossary.terms_for_column("customers.email")
        self.assertEqual(len(results), 1)

    def test_list_terms(self):
        self.glossary.add_term("T1", "Def1", domain="Sales")
        self.glossary.add_term("T2", "Def2", domain="Eng")
        all_terms = self.glossary.list_terms()
        self.assertEqual(len(all_terms), 2)

    def test_list_terms_by_domain(self):
        self.glossary.add_term("T1", "Def1", domain="Sales")
        self.glossary.add_term("T2", "Def2", domain="Eng")
        sales = self.glossary.list_terms(domain="Sales")
        self.assertEqual(len(sales), 1)
        self.assertEqual(sales[0]["domain"], "Sales")

    def test_remove_term(self):
        self.glossary.add_term("Temp", "Temporary term")
        removed = self.glossary.remove_term("Temp")
        self.assertTrue(removed)
        self.assertIsNone(self.glossary.get_term("Temp"))

    def test_remove_nonexistent(self):
        self.assertFalse(self.glossary.remove_term("nope"))

    def test_empty_term_raises(self):
        with self.assertRaises(ValueError):
            self.glossary.add_term("", "def")

    def test_dry_run_no_write(self):
        glossary = BusinessGlossary(self.gov, glossary_file=self.glossary_file, dry_run=True)
        glossary.add_term("Dry", "Run")
        self.assertIsNone(glossary.get_term("Dry"))

    def test_persistence(self):
        self.glossary.add_term("Persistent", "Should survive reload")
        reloaded = BusinessGlossary(self.gov, glossary_file=self.glossary_file)
        result = reloaded.get_term("Persistent")
        self.assertIsNotNone(result)

    def test_export(self):
        self.glossary.add_term("X", "Y")
        export = self.glossary.export()
        self.assertEqual(export["term_count"], 1)
        self.assertIn("terms", export)

    def test_governance_event(self):
        self.glossary.add_term("Test", "Def", domain="D", columns=["a.b"])
        self.gov.transformation_applied.assert_called_once()
        args = self.gov.transformation_applied.call_args[0]
        self.assertEqual(args[0], "GLOSSARY_TERM_ADDED")


if __name__ == "__main__":
    unittest.main()
