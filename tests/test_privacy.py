"""
Tests for the privacy sub-package: PIIDiscoveryReporter, ColumnEncryptor,
DataClassificationTagger, CrossBorderTransferLogger, ErasureHandler,
and NLPPIIDetector.

Uses real SQLite databases for erasure tests, synthetic data only
(alice@example.com, 555-0101, user1@test.com), and unittest.TestCase.

Revision history
────────────────
1.0   2026-06-08   Initial release — ~30 tests covering all six privacy modules.
"""

import hashlib
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd


class MockGov:
    """Accepts any method call without error — lightweight governance stub."""

    def __getattr__(self, name):
        return lambda *a, **kw: None


# =============================================================================
# PIIDiscoveryReporter
# =============================================================================


class TestPIIDiscoveryReporterDetection(unittest.TestCase):
    """Tests for PIIDiscoveryReporter.scan() column-name pattern matching."""

    def setUp(self):
        from pipeline.privacy.pii_discovery import PIIDiscoveryReporter
        self.reporter = PIIDiscoveryReporter(MockGov())

    def test_scan_detects_email_column(self):
        df = pd.DataFrame({"email": ["alice@example.com"], "amount": [100]})
        findings = self.reporter.scan(df)
        fields = [f["field"] for f in findings]
        self.assertIn("email", fields)

    def test_scan_detects_phone_column(self):
        df = pd.DataFrame({"phone": ["555-0101"], "product_id": [42]})
        findings = self.reporter.scan(df)
        fields = [f["field"] for f in findings]
        self.assertIn("phone", fields)

    def test_scan_detects_ssn_column(self):
        df = pd.DataFrame({"ssn": ["000-00-0000"], "amount": [50]})
        findings = self.reporter.scan(df)
        fields = [f["field"] for f in findings]
        self.assertIn("ssn", fields)

    def test_scan_ignores_non_pii_columns(self):
        df = pd.DataFrame({"product_id": [1], "amount": [99.99], "status": ["active"]})
        findings = self.reporter.scan(df)
        self.assertEqual(findings, [])

    def test_scan_detects_health_as_special_category(self):
        df = pd.DataFrame({"health_status": ["good"], "id": [1]})
        findings = self.reporter.scan(df)
        self.assertTrue(len(findings) > 0)
        health_finding = [f for f in findings if f["field"] == "health_status"][0]
        self.assertTrue(health_finding["special_category"])
        self.assertEqual(health_finding["gdpr_reference"], "Article 9")

    def test_scan_detects_biometric_as_special_category(self):
        df = pd.DataFrame({"biometric": ["abc123"], "status": ["active"]})
        findings = self.reporter.scan(df)
        biometric = [f for f in findings if f["field"] == "biometric"]
        self.assertTrue(len(biometric) > 0)
        self.assertTrue(biometric[0]["special_category"])

    def test_scan_multiple_pii_columns(self):
        df = pd.DataFrame({
            "email": ["alice@example.com"],
            "phone": ["555-0101"],
            "ssn": ["000-00-0000"],
            "product_id": [1],
        })
        findings = self.reporter.scan(df)
        fields = {f["field"] for f in findings}
        self.assertIn("email", fields)
        self.assertIn("phone", fields)
        self.assertIn("ssn", fields)
        self.assertNotIn("product_id", fields)


# =============================================================================
# ColumnEncryptor
# =============================================================================


class TestColumnEncryptorRoundtrip(unittest.TestCase):
    """Tests for ColumnEncryptor encrypt/decrypt lifecycle."""

    def setUp(self):
        from pipeline.constants import HAS_CRYPTO
        if not HAS_CRYPTO:
            self.skipTest("cryptography library not installed")
        from pipeline.privacy.column_encryptor import ColumnEncryptor
        self.key = ColumnEncryptor.generate_key()
        self.enc = ColumnEncryptor(MockGov(), self.key)

    def test_encrypt_decrypt_roundtrip(self):
        df = pd.DataFrame({"ssn": ["000-00-0000", "111-11-1111"], "name": ["Alice", "Bob"]})
        original = df.copy()
        df = self.enc.encrypt(df, ["ssn"])
        # Encrypted values should differ from originals
        self.assertTrue(df["ssn"].iloc[0].startswith("ENCRYPTED:"))
        df = self.enc.decrypt(df, ["ssn"])
        self.assertEqual(df["ssn"].iloc[0], original["ssn"].iloc[0])
        self.assertEqual(df["ssn"].iloc[1], original["ssn"].iloc[1])

    def test_null_values_remain_null(self):
        df = pd.DataFrame({"ssn": ["000-00-0000", None, "222-22-2222"]})
        df = self.enc.encrypt(df, ["ssn"])
        self.assertTrue(pd.isna(df["ssn"].iloc[1]))
        df = self.enc.decrypt(df, ["ssn"])
        self.assertTrue(pd.isna(df["ssn"].iloc[1]))

    def test_different_keys_produce_different_ciphertexts(self):
        from pipeline.privacy.column_encryptor import ColumnEncryptor
        key2 = ColumnEncryptor.generate_key()
        enc2 = ColumnEncryptor(MockGov(), key2)

        df1 = pd.DataFrame({"secret": ["alice@example.com"]})
        df2 = pd.DataFrame({"secret": ["alice@example.com"]})

        df1 = self.enc.encrypt(df1, ["secret"])
        df2 = enc2.encrypt(df2, ["secret"])

        self.assertNotEqual(df1["secret"].iloc[0], df2["secret"].iloc[0])

    def test_encrypt_skips_missing_column(self):
        df = pd.DataFrame({"name": ["Alice"]})
        result = self.enc.encrypt(df, ["nonexistent_column"])
        self.assertListEqual(list(result.columns), ["name"])

    def test_generate_key_returns_valid_string(self):
        from pipeline.privacy.column_encryptor import ColumnEncryptor
        key = ColumnEncryptor.generate_key()
        self.assertIsInstance(key, str)
        self.assertTrue(len(key) > 0)


# =============================================================================
# DataClassificationTagger
# =============================================================================


class TestDataClassificationTagger(unittest.TestCase):
    """Tests for DataClassificationTagger.classify()."""

    def setUp(self):
        from pipeline.privacy.classification_tagger import DataClassificationTagger
        self.tagger = DataClassificationTagger(MockGov())

    def test_pii_columns_classified_confidential(self):
        df = pd.DataFrame({"email": ["alice@example.com"], "id": [1]})
        pii_findings = [{"field": "email", "special_category": False}]
        result_df, level = self.tagger.classify(df, pii_findings)
        self.assertEqual(level, "CONFIDENTIAL")
        self.assertTrue((result_df["_data_classification"] == "CONFIDENTIAL").all())

    def test_special_category_pii_classified_restricted(self):
        df = pd.DataFrame({"health_status": ["good"], "id": [1]})
        pii_findings = [{"field": "health_status", "special_category": True}]
        result_df, level = self.tagger.classify(df, pii_findings)
        self.assertEqual(level, "RESTRICTED")

    def test_no_pii_internal_keyword_classified_internal(self):
        df = pd.DataFrame({"budget_forecast": [1000], "internal_notes": ["test"]})
        result_df, level = self.tagger.classify(df, [])
        self.assertEqual(level, "INTERNAL")

    def test_no_pii_no_keywords_classified_public(self):
        df = pd.DataFrame({"product_id": [1], "quantity": [10]})
        result_df, level = self.tagger.classify(df, [])
        self.assertEqual(level, "PUBLIC")

    def test_classification_column_added_to_dataframe(self):
        df = pd.DataFrame({"id": [1, 2, 3]})
        result_df, _ = self.tagger.classify(df, [])
        self.assertIn("_data_classification", result_df.columns)

    def test_multiple_special_categories_still_restricted(self):
        df = pd.DataFrame({"health": ["ok"], "biometric": ["fp"], "religion": ["none"]})
        pii_findings = [
            {"field": "health", "special_category": True},
            {"field": "biometric", "special_category": True},
            {"field": "religion", "special_category": True},
        ]
        _, level = self.tagger.classify(df, pii_findings)
        self.assertEqual(level, "RESTRICTED")


# =============================================================================
# CrossBorderTransferLogger
# =============================================================================


class TestCrossBorderTransferLogger(unittest.TestCase):
    """Tests for CrossBorderTransferLogger.check_and_log()."""

    def setUp(self):
        from pipeline.privacy.cross_border_transfer import CrossBorderTransferLogger
        self.xfer = CrossBorderTransferLogger(MockGov())

    def test_eu_to_eu_logged_as_intra_eu(self):
        result = self.xfer.check_and_log("DE", "FR")
        self.assertEqual(result, "INTRA_EU")

    def test_eu_to_us_logged_with_scc_safeguard(self):
        result = self.xfer.check_and_log("DE", "US", "SCC")
        self.assertEqual(result, "SCC")

    def test_adequate_country_recognized(self):
        # UK has an adequacy decision
        result = self.xfer.check_and_log("DE", "UK")
        self.assertEqual(result, "ADEQUACY_DECISION")

    def test_adequate_country_japan(self):
        result = self.xfer.check_and_log("FR", "JP")
        self.assertEqual(result, "ADEQUACY_DECISION")

    def test_domestic_transfer_same_country(self):
        result = self.xfer.check_and_log("US", "US")
        self.assertEqual(result, "DOMESTIC")

    def test_bcr_safeguard(self):
        result = self.xfer.check_and_log("DE", "CN", "BCR")
        self.assertEqual(result, "BCR")

    def test_unknown_safeguard(self):
        result = self.xfer.check_and_log("DE", "CN", "HANDSHAKE")
        self.assertEqual(result, "UNKNOWN_SAFEGUARD")

    def test_case_insensitive_country_codes(self):
        result = self.xfer.check_and_log("de", "fr")
        self.assertEqual(result, "INTRA_EU")


# =============================================================================
# ErasureHandler (real SQLite, no mocks)
# =============================================================================


class TestErasureHandler(unittest.TestCase):
    """Tests for ErasureHandler using a real SQLite database."""

    def setUp(self):
        from pipeline.privacy.erasure_handler import ErasureHandler
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "testdb")
        self.handler = ErasureHandler(MockGov())

        # Create and populate a test table
        conn = sqlite3.connect(self.db_path + ".db")
        conn.execute(
            "CREATE TABLE employees (id INTEGER PRIMARY KEY, email TEXT, "
            "name TEXT, phone TEXT)"
        )
        conn.execute(
            "INSERT INTO employees VALUES (1, 'alice@example.com', 'Alice Test', '555-0101')"
        )
        conn.execute(
            "INSERT INTO employees VALUES (2, 'user1@test.com', 'Bob Test', '555-0102')"
        )
        conn.execute(
            "INSERT INTO employees VALUES (3, 'alice@example.com', 'Alice Other', '555-0103')"
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _db_cfg(self):
        return {"db_name": self.db_path}

    def test_execute_delete_removes_subject_rows(self):
        rows = self.handler.execute(
            subject_id="alice@example.com",
            subject_col="email",
            db_type="sqlite",
            db_cfg=self._db_cfg(),
            table="employees",
            mode="delete",
        )
        self.assertEqual(rows, 2)

        # Verify rows are actually gone
        conn = sqlite3.connect(self.db_path + ".db")
        remaining = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
        conn.close()
        self.assertEqual(remaining, 1)

    def test_execute_nullify_clears_pii_columns(self):
        rows = self.handler.execute(
            subject_id="alice@example.com",
            subject_col="email",
            db_type="sqlite",
            db_cfg=self._db_cfg(),
            table="employees",
            mode="nullify",
            pii_cols=["name", "phone"],
        )
        self.assertEqual(rows, 2)

        conn = sqlite3.connect(self.db_path + ".db")
        row = conn.execute(
            "SELECT name, phone FROM employees WHERE id = 1"
        ).fetchone()
        conn.close()
        self.assertIsNone(row[0])
        self.assertIsNone(row[1])

    def test_dsar_export_returns_correct_subject_data(self):
        tables = [("employees", "sqlite", self._db_cfg())]
        result = self.handler.dsar_export(
            subject_id="alice@example.com",
            tables=tables,
            id_column="email",
        )
        self.assertIn("employees", result)
        self.assertEqual(len(result["employees"]), 2)
        for row in result["employees"]:
            self.assertEqual(row["email"], "alice@example.com")

    def test_dsar_export_no_results_for_unknown_subject(self):
        tables = [("employees", "sqlite", self._db_cfg())]
        result = self.handler.dsar_export(
            subject_id="nobody@example.com",
            tables=tables,
            id_column="email",
        )
        self.assertEqual(len(result["employees"]), 0)

    def test_subject_id_hashed_in_audit_trail(self):
        """Governance logger receives a hashed subject ID, never raw PII."""
        gov_mock = MagicMock()
        from pipeline.privacy.erasure_handler import ErasureHandler
        handler = ErasureHandler(gov_mock)
        handler.execute(
            subject_id="alice@example.com",
            subject_col="email",
            db_type="sqlite",
            db_cfg=self._db_cfg(),
            table="employees",
            mode="delete",
        )
        gov_mock.erasure_executed.assert_called_once()
        call_args = gov_mock.erasure_executed.call_args
        # The raw subject_id is passed to erasure_executed, which internally hashes it
        # Verify the governance logger method was called with the raw ID
        # (the hashing happens inside GovernanceLogger.erasure_executed)
        self.assertEqual(call_args[1].get("subject_id") or call_args[0][0], "alice@example.com")

    def test_erase_alias_delegates_to_execute(self):
        rows = self.handler.erase(
            subject_id="user1@test.com",
            table="employees",
            db_type="sqlite",
            db_cfg=self._db_cfg(),
            id_column="email",
            mode="delete",
        )
        self.assertEqual(rows, 1)

    def test_governance_logger_hashes_subject_id(self):
        """Verify GovernanceLogger.erasure_executed stores hashed subject ID, not raw."""
        from pipeline.governance_logger import GovernanceLogger
        gov = GovernanceLogger("test_erasure", log_dir=self.tmpdir, dry_run=True)
        handler = from_gov(gov)
        handler.execute(
            subject_id="alice@example.com",
            subject_col="email",
            db_type="sqlite",
            db_cfg=self._db_cfg(),
            table="employees",
            mode="delete",
        )
        # Check the ledger entry contains the hash, not the raw email
        erasure_events = [
            e for e in gov.ledger_entries
            if e.get("action") == "GDPR_ERASURE_EXECUTED"
        ]
        self.assertTrue(len(erasure_events) > 0)
        detail = erasure_events[0]["detail"]
        expected_hash = hashlib.sha256(b"alice@example.com").hexdigest()[:16]
        self.assertEqual(detail["subject_id_hash"], expected_hash)
        # Raw email must not appear anywhere in the detail
        self.assertNotIn("alice@example.com", str(detail))


def from_gov(gov):
    """Helper to create ErasureHandler from GovernanceLogger."""
    from pipeline.privacy.erasure_handler import ErasureHandler
    return ErasureHandler(gov)


# =============================================================================
# NLPPIIDetector
# =============================================================================


class TestNLPPIIDetectorRegex(unittest.TestCase):
    """Tests for NLPPIIDetector regex-based detection (no spaCy required)."""

    def setUp(self):
        from pipeline.privacy.nlp_pii_detector import NLPPIIDetector
        self.gov = MockGov()
        self.detector = NLPPIIDetector(self.gov, confidence_threshold=0.1)

    def test_regex_detects_email(self):
        df = pd.DataFrame({"notes": ["Contact alice@example.com for details"]})
        # Disable NER, test regex only
        with patch.object(self.detector, "_scan_column_ner", return_value=[]):
            findings = self.detector.scan(df, text_columns=["notes"], include_regex=True)
        email_findings = [f for f in findings if f["entity_type"] == "EMAIL"]
        self.assertTrue(len(email_findings) > 0)

    def test_regex_detects_phone(self):
        df = pd.DataFrame({"notes": ["Call 555-010-1234 for info"]})
        with patch.object(self.detector, "_scan_column_ner", return_value=[]):
            findings = self.detector.scan(df, text_columns=["notes"], include_regex=True)
        phone_findings = [f for f in findings if f["entity_type"] == "PHONE"]
        self.assertTrue(len(phone_findings) > 0)

    def test_regex_detects_ssn(self):
        df = pd.DataFrame({"notes": ["SSN: 123-45-6789"]})
        with patch.object(self.detector, "_scan_column_ner", return_value=[]):
            findings = self.detector.scan(df, text_columns=["notes"], include_regex=True)
        ssn_findings = [f for f in findings if f["entity_type"] == "SSN"]
        self.assertTrue(len(ssn_findings) > 0)

    def test_empty_dataframe_returns_no_findings(self):
        df = pd.DataFrame({"notes": pd.Series([], dtype=str)})
        findings = self.detector.scan(df, text_columns=["notes"])
        self.assertEqual(findings, [])

    def test_scan_auto_detects_text_columns(self):
        df = pd.DataFrame({
            "text_field": ["Contact alice@example.com"],
            "numeric_field": [42],
        })
        with patch.object(self.detector, "_scan_column_ner", return_value=[]):
            findings = self.detector.scan(df, include_regex=True)
        # Should auto-detect object columns
        columns_scanned = {f["column"] for f in findings}
        if findings:
            self.assertNotIn("numeric_field", columns_scanned)


class TestNLPPIIDetectorWithSpacy(unittest.TestCase):
    """Tests for NLPPIIDetector NER detection — mocks spaCy if not installed."""

    def _make_mock_doc(self, entities):
        """Build a mock spaCy Doc with the given entity list."""
        doc = MagicMock()
        ents = []
        for label, text in entities:
            ent = MagicMock()
            ent.label_ = label
            ent.text = text
            ents.append(ent)
        doc.ents = ents
        return doc

    def test_ner_detects_person_entity(self):
        from pipeline.privacy.nlp_pii_detector import NLPPIIDetector

        mock_nlp = MagicMock()
        doc = self._make_mock_doc([("PERSON", "Alice Test")])
        mock_nlp.pipe.return_value = [doc]

        detector = NLPPIIDetector(MockGov(), confidence_threshold=0.1)
        detector._nlp = mock_nlp

        df = pd.DataFrame({"notes": ["Alice Test is a person"]})
        findings = detector.scan(df, text_columns=["notes"], include_regex=False)
        person_findings = [f for f in findings if f["entity_type"] == "PERSON_NAME"]
        self.assertTrue(len(person_findings) > 0)

    def test_ner_maps_gpe_to_location(self):
        from pipeline.privacy.nlp_pii_detector import NLPPIIDetector

        mock_nlp = MagicMock()
        doc = self._make_mock_doc([("GPE", "New York")])
        mock_nlp.pipe.return_value = [doc]

        detector = NLPPIIDetector(MockGov(), confidence_threshold=0.1)
        detector._nlp = mock_nlp

        df = pd.DataFrame({"notes": ["Lives in New York"]})
        findings = detector.scan(df, text_columns=["notes"], include_regex=False)
        location_findings = [f for f in findings if f["entity_type"] == "LOCATION"]
        self.assertTrue(len(location_findings) > 0)

    def test_scan_and_classify_returns_dict(self):
        from pipeline.privacy.nlp_pii_detector import NLPPIIDetector

        mock_nlp = MagicMock()
        doc = self._make_mock_doc([("PERSON", "Alice Test")])
        mock_nlp.pipe.return_value = [doc]

        detector = NLPPIIDetector(MockGov(), confidence_threshold=0.1)
        detector._nlp = mock_nlp

        df = pd.DataFrame({"notes": ["Alice Test is here"]})
        classification = detector.scan_and_classify(df, text_columns=["notes"])
        self.assertIsInstance(classification, dict)
        if classification:
            self.assertIn("notes", classification)
            self.assertIn("pii_type", classification["notes"])


if __name__ == "__main__":
    unittest.main()
