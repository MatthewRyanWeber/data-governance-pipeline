#!/usr/bin/env python3
"""
test_epic_extensions.py  —  Unit tests for epic_extensions.py

Covers all six Epic / HIPAA governance classes:
    HIPAASafeHarborFilter, ClarityExtractor, BAATracker,
    IRBApprovalGate, OMOPTransformer, PHIKAnonymityChecker

Run with:  python3 test_epic_extensions.py  (or pytest)
"""
import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from epic_extensions import (
    HIPAASafeHarborFilter,
    BAATracker,
    IRBApprovalGate,
    OMOPTransformer,
    PHIKAnonymityChecker,
    PHIAnonymityError,
)
# ClarityExtractor requires live SQL Server; tested separately below


# ── Shared helpers ────────────────────────────────────────────────────────

def _make_gov(tmp_dir: str) -> MagicMock:
    """Create a minimal GovernanceLogger mock."""
    gov = MagicMock()
    gov.log_dir = tmp_dir
    gov._event  = MagicMock()
    return gov


class _TmpMixin(unittest.TestCase):
    """TestCase mixin that creates and destroys an isolated temp directory."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.gov  = _make_gov(self._tmp)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)


# ═════════════════════════════════════════════════════════════════════════════
#  HIPAASafeHarborFilter
# ═════════════════════════════════════════════════════════════════════════════

class TestHIPAASafeHarborFilter(_TmpMixin):

    def _filt(self, **kw):
        return HIPAASafeHarborFilter(self.gov, **kw)

    def _df(self):
        return pd.DataFrame({
            "PAT_ID":          ["P001", "P002", "P003"],
            "PAT_MRN_ID":      ["MRN001", "MRN002", "MRN003"],
            "PAT_NAME":        ["Alice Smith", "Bob Jones", "Carol Wu"],
            "PAT_HOME_PHONE":  ["212-555-0001", "212-555-0002", "212-555-0003"],
            "PAT_EMAIL":       ["a@x.com", "b@x.com", "c@x.com"],
            "BIRTH_DATE":      ["1980-06-15", "1995-01-22", "1928-03-07"],
            "AGE":             [44, 29, 95],
            "ZIP":             ["10036", "59201", "10001"],
            "ADMIT_DATE":      ["2024-01-10", "2024-03-21", "2024-06-05"],
            "DIAGNOSIS":       ["E11", "J18", "Z00"],     # non-PHI
            "DEPARTMENT_ID":   [101, 102, 103],           # non-PHI
        })

    def test_scan_identifies_phi_columns(self):
        filt   = self._filt()
        report = filt.scan(self._df(), source_label="test")
        phi_cols = {f["column"] for f in report["findings"]}
        # All of these should be detected
        for col in ("PAT_NAME", "PAT_HOME_PHONE", "PAT_EMAIL",
                    "BIRTH_DATE", "AGE", "ZIP", "ADMIT_DATE",
                    "PAT_MRN_ID"):
            self.assertIn(col, phi_cols,
                          f"{col} should be detected as PHI")

    def test_scan_does_not_flag_non_phi(self):
        filt   = self._filt()
        report = filt.scan(self._df())
        phi_cols = {f["column"] for f in report["findings"]}
        for col in ("DIAGNOSIS", "DEPARTMENT_ID"):
            self.assertNotIn(col, phi_cols,
                             f"{col} should NOT be detected as PHI")

    def test_apply_drops_name_phone_email(self):
        filt  = self._filt()
        clean = filt.apply(self._df())
        for col in ("PAT_NAME", "PAT_HOME_PHONE", "PAT_EMAIL"):
            self.assertNotIn(col, clean.columns)

    def test_apply_hashes_mrn_and_pat_id(self):
        filt  = self._filt(hash_identifiers=True)
        clean = filt.apply(self._df())
        # MRN should still exist but values should be hashed (16 hex chars)
        self.assertIn("PAT_MRN_ID", clean.columns)
        for val in clean["PAT_MRN_ID"]:
            self.assertEqual(len(val), 16,
                             f"Hashed MRN should be 16 chars, got '{val}'")

    def test_apply_drops_mrn_when_hash_false(self):
        filt  = self._filt(hash_identifiers=False)
        clean = filt.apply(self._df())
        self.assertNotIn("PAT_MRN_ID", clean.columns)

    def test_zip_transforms_to_3_digits(self):
        filt  = self._filt()
        clean = filt.apply(self._df())
        self.assertIn("ZIP", clean.columns)
        # 10036 → first 3 digits = 103 (not restricted)
        non_restricted = clean.loc[clean.index[0], "ZIP"]
        self.assertEqual(non_restricted, "100")

    def test_zip_restricts_small_population_prefix(self):
        filt  = self._filt()
        clean = filt.apply(self._df())
        # 59201 → prefix 592 — NOT in restricted set, so stays as 592
        # 036xx → would be "000"; use a direct test
        df2 = pd.DataFrame({"ZIP": ["03601", "10001"]})
        filt2 = self._filt()
        filt2.scan(df2)
        out = filt2.apply(df2)
        self.assertEqual(out.loc[0, "ZIP"], "000",
                         "ZIP prefix 036 is restricted; should be '000'")
        self.assertEqual(out.loc[1, "ZIP"], "100")

    def test_age_cap_applied(self):
        filt  = self._filt(age_cap=90, age_cap_label="90+")
        clean = filt.apply(self._df())
        self.assertIn("AGE", clean.columns)
        # Age 95 → "90+", age 44 and 29 → unchanged
        ages = list(clean["AGE"])
        self.assertIn("90+", ages)
        self.assertIn(44, ages)
        self.assertIn(29, ages)

    def test_date_reduces_to_year_only(self):
        filt  = self._filt()
        clean = filt.apply(self._df())
        self.assertIn("ADMIT_DATE", clean.columns)
        for val in clean["ADMIT_DATE"].dropna():
            # All values should be 4-digit year strings
            self.assertRegex(str(val), r"^\d{4}$",
                             f"ADMIT_DATE should be year only, got '{val}'")

    def test_birth_date_year_only(self):
        filt  = self._filt()
        clean = filt.apply(self._df())
        self.assertIn("BIRTH_DATE", clean.columns)
        for val in clean["BIRTH_DATE"].dropna():
            self.assertRegex(str(val), r"^\d{4}$")

    def test_dry_run_does_not_modify_df(self):
        filt  = self._filt(dry_run=True)
        df    = self._df()
        clean = filt.apply(df)
        # Original columns must all be present
        self.assertIn("PAT_NAME", clean.columns)
        self.assertIn("PAT_HOME_PHONE", clean.columns)

    def test_save_report_html(self):
        filt = self._filt()
        filt.scan(self._df())
        out  = pathlib.Path(self._tmp) / "phi_report.html"
        filt.save_report(out, fmt="html")
        self.assertTrue(out.exists())
        self.assertIn("HIPAA", out.read_text())

    def test_save_report_json(self):
        filt = self._filt()
        filt.scan(self._df())
        out  = pathlib.Path(self._tmp) / "phi_report.json"
        filt.save_report(out, fmt="json")
        data = json.loads(out.read_text())
        self.assertIn("findings", data)

    def test_save_report_requires_prior_scan(self):
        filt = self._filt()
        with self.assertRaises(RuntimeError):
            filt.save_report(pathlib.Path(self._tmp) / "x.html")

    def test_governance_event_fired(self):
        filt = self._filt()
        filt.scan(self._df(), source_label="mytest")
        # _event should have been called with PHI_SCAN_COMPLETE
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("PHI_SCAN_COMPLETE" in c for c in calls))

    def test_additional_columns_override(self):
        filt = self._filt(additional_columns={"CUSTOM_SECRET": "drop"})
        df   = pd.DataFrame({"CUSTOM_SECRET": ["a", "b"],
                              "SAFE_COL": [1, 2]})
        filt.scan(df)
        clean = filt.apply(df)
        self.assertNotIn("CUSTOM_SECRET", clean.columns)
        self.assertIn("SAFE_COL", clean.columns)

    def test_null_zip_handled_gracefully(self):
        filt = self._filt()
        df   = pd.DataFrame({"ZIP": [None, "10001", ""]})
        filt.scan(df)
        out  = filt.apply(df)
        self.assertIn("ZIP", out.columns)

    def test_null_age_passes_through(self):
        filt = self._filt()
        df   = pd.DataFrame({"AGE": [None, 45, 95]})
        filt.scan(df)
        out  = filt.apply(df)
        self.assertTrue(pd.isna(out.loc[0, "AGE"]))


# ═════════════════════════════════════════════════════════════════════════════
#  BAATracker
# ═════════════════════════════════════════════════════════════════════════════

class TestBAATracker(_TmpMixin):

    def _tracker(self, **kw):
        return BAATracker(self.gov, **kw)

    def _future(self, days: int = 365) -> str:
        return (datetime.now(timezone.utc).date()
                + timedelta(days=days)).isoformat()

    def _past(self, days: int = 1) -> str:
        return (datetime.now(timezone.utc).date()
                - timedelta(days=days)).isoformat()

    def test_register_and_check_valid_baa(self):
        t = self._tracker()
        t.register_baa(
            destination_id="snowflake_prod",
            vendor="Snowflake Inc.",
            signed_date="2024-01-01",
            expiry_date=self._future(365),
        )
        result = t.check_phi_load("snowflake_prod")
        self.assertTrue(result)

    def test_check_missing_baa_raises(self):
        t = self._tracker()
        with self.assertRaises(RuntimeError) as ctx:
            t.check_phi_load("nonexistent_dest")
        self.assertIn("no BAA", str(ctx.exception))

    def test_check_expired_baa_raises(self):
        t = self._tracker()
        t.register_baa(
            destination_id="old_dest",
            vendor="Acme",
            signed_date="2020-01-01",
            expiry_date=self._past(10),
        )
        with self.assertRaises(RuntimeError) as ctx:
            t.check_phi_load("old_dest")
        self.assertIn("expired", str(ctx.exception))

    def test_dry_run_missing_returns_false(self):
        t = self._tracker(dry_run=True)
        result = t.check_phi_load("missing_dest")
        self.assertFalse(result)

    def test_dry_run_expired_returns_false(self):
        t = self._tracker(dry_run=True)
        t.register_baa(
            destination_id="x",
            vendor="Y",
            signed_date="2020-01-01",
            expiry_date=self._past(5),
        )
        result = t.check_phi_load("x")
        self.assertFalse(result)

    def test_get_expiring_returns_near_expiry(self):
        t = self._tracker(warn_days=60)
        t.register_baa("dest_a", "VendorA", "2024-01-01",
                        self._future(20))   # expires in 20 days — within window
        t.register_baa("dest_b", "VendorB", "2024-01-01",
                        self._future(200))  # expires in 200 days — outside window
        expiring = t.get_expiring(within_days=60)
        ids = [r["destination_id"] for r in expiring]
        self.assertIn("dest_a", ids)
        self.assertNotIn("dest_b", ids)

    def test_registry_persists_to_disk(self):
        t = self._tracker()
        t.register_baa("dest1", "VendorX", "2024-01-01", self._future())
        reg_file = pathlib.Path(self._tmp) / "baa_registry.json"
        self.assertTrue(reg_file.exists())
        data = json.loads(reg_file.read_text())
        self.assertIn("dest1", data)

    def test_export_register_html(self):
        t = self._tracker()
        t.register_baa("dest1", "VendorX", "2024-01-01", self._future())
        out = pathlib.Path(self._tmp) / "baa_register.html"
        t.export_register(out)
        self.assertTrue(out.exists())
        self.assertIn("VendorX", out.read_text())

    def test_baa_verified_event_fired(self):
        t = self._tracker()
        t.register_baa("d", "V", "2024-01-01", self._future())
        t.check_phi_load("d")
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("BAA_VERIFIED" in c for c in calls))

    def test_phi_type_coverage_warning(self):
        t = self._tracker()
        t.register_baa(
            destination_id="partial_dest",
            vendor="V",
            signed_date="2024-01-01",
            expiry_date=self._future(),
            phi_types=["demographics"],
        )
        # Requesting a type not in the BAA should log a warning but not raise
        result = t.check_phi_load("partial_dest",
                                  phi_types=["lab_results"])
        self.assertTrue(result)
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("PHI_TYPE_NOT_COVERED" in c for c in calls))

    def test_all_records_returns_list(self):
        t = self._tracker()
        t.register_baa("d1", "V1", "2024-01-01", self._future())
        t.register_baa("d2", "V2", "2024-01-01", self._future())
        records = t.all_records()
        self.assertEqual(len(records), 2)


# ═════════════════════════════════════════════════════════════════════════════
#  IRBApprovalGate
# ═════════════════════════════════════════════════════════════════════════════

class TestIRBApprovalGate(_TmpMixin):

    def _gate(self, **kw):
        return IRBApprovalGate(self.gov, **kw)

    def _future(self, days: int = 365) -> str:
        return (datetime.now(timezone.utc).date()
                + timedelta(days=days)).isoformat()

    def _past(self, days: int = 1) -> str:
        return (datetime.now(timezone.utc).date()
                - timedelta(days=days)).isoformat()

    def _df(self):
        return pd.DataFrame({
            "PAT_ENC_CSN_ID":       ["C001", "C002", "C003"],
            "CONTACT_DATE":         ["2024-01-01", "2024-01-02", "2024-01-03"],
            "CURRENT_ICD10_LIST":   ["E11", "J18", "Z00"],
            "PAT_NAME":             ["Alice", "Bob", "Carol"],  # unapproved
            "HOME_PHONE":           ["555-1111", "555-2222", "555-3333"],  # unapproved
        })

    def test_register_and_check_valid_protocol(self):
        g = self._gate()
        g.register_protocol(
            protocol_id   = "IRB-2024-001",
            study_title   = "Test study",
            pi_name       = "Dr. X",
            approved_date = "2024-01-01",
            expiry_date   = self._future(),
        )
        rec = g.check_protocol("IRB-2024-001")
        self.assertEqual(rec["protocol_id"], "IRB-2024-001")

    def test_check_missing_protocol_raises(self):
        g = self._gate()
        with self.assertRaises(RuntimeError) as ctx:
            g.check_protocol("NONEXISTENT")
        self.assertIn("no IRB protocol", str(ctx.exception))

    def test_check_expired_protocol_raises(self):
        g = self._gate()
        g.register_protocol("IRB-OLD", "Old study", "Dr. Y",
                             "2020-01-01", self._past(5))
        with self.assertRaises(RuntimeError) as ctx:
            g.check_protocol("IRB-OLD")
        self.assertIn("expired", str(ctx.exception))

    def test_gate_dataframe_drops_unapproved_columns(self):
        g = self._gate()
        g.register_protocol(
            protocol_id      = "IRB-2024-002",
            study_title      = "Dx study",
            pi_name          = "Dr. Z",
            approved_date    = "2024-01-01",
            expiry_date      = self._future(),
            approved_columns = ["PAT_ENC_CSN_ID", "CONTACT_DATE",
                                 "CURRENT_ICD10_LIST"],
        )
        df    = self._df()
        clean = g.gate_dataframe(df, protocol_id="IRB-2024-002")
        self.assertNotIn("PAT_NAME", clean.columns)
        self.assertNotIn("HOME_PHONE", clean.columns)
        self.assertIn("PAT_ENC_CSN_ID", clean.columns)
        self.assertIn("CURRENT_ICD10_LIST", clean.columns)

    def test_gate_dataframe_empty_approved_list_allows_all(self):
        g = self._gate()
        g.register_protocol(
            protocol_id      = "IRB-2024-003",
            study_title      = "Broad study",
            pi_name          = "Dr. W",
            approved_date    = "2024-01-01",
            expiry_date      = self._future(),
            approved_columns = [],   # empty = all columns allowed
        )
        df    = self._df()
        clean = g.gate_dataframe(df, protocol_id="IRB-2024-003")
        self.assertEqual(set(clean.columns), set(df.columns))

    def test_usage_log_written(self):
        g = self._gate()
        g.register_protocol("IRB-2024-004", "Study", "PI",
                             "2024-01-01", self._future(),
                             approved_columns=["PAT_ENC_CSN_ID"])
        g.gate_dataframe(self._df(), protocol_id="IRB-2024-004")
        log_path = pathlib.Path(self._tmp) / "irb_usage_log.jsonl"
        self.assertTrue(log_path.exists())
        entries = [json.loads(l) for l in log_path.read_text().splitlines() if l]
        self.assertTrue(len(entries) >= 1)

    def test_dry_run_missing_protocol_returns_original(self):
        g = self._gate(dry_run=True)
        df    = self._df()
        clean = g.gate_dataframe(df, protocol_id="NO_SUCH_PROTOCOL")
        # dry_run returns df unchanged when protocol is missing
        self.assertEqual(len(clean.columns), len(df.columns))

    def test_export_usage_report_html(self):
        g = self._gate()
        g.register_protocol("IRB-R", "R study", "Dr. R",
                             "2024-01-01", self._future())
        g.gate_dataframe(self._df(), protocol_id="IRB-R")
        out = pathlib.Path(self._tmp) / "irb_report.html"
        g.export_usage_report(out)
        self.assertTrue(out.exists())
        self.assertIn("IRB-R", out.read_text())

    def test_irb_data_access_event_fired(self):
        g = self._gate()
        g.register_protocol("IRB-EVT", "E study", "PI",
                             "2024-01-01", self._future())
        g.gate_dataframe(self._df(), protocol_id="IRB-EVT")
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("IRB_DATA_ACCESS" in c for c in calls))

    def test_registry_persists(self):
        g = self._gate()
        g.register_protocol("IRB-PERSIST", "P study", "PI",
                             "2024-01-01", self._future())
        reg_file = pathlib.Path(self._tmp) / "irb_registry.json"
        self.assertTrue(reg_file.exists())
        data = json.loads(reg_file.read_text())
        self.assertIn("IRB-PERSIST", data)


# ═════════════════════════════════════════════════════════════════════════════
#  OMOPTransformer
# ═════════════════════════════════════════════════════════════════════════════

class TestOMOPTransformer(_TmpMixin):

    def _transformer(self):
        return OMOPTransformer(self.gov)

    def _patient_df(self):
        return pd.DataFrame({
            "PAT_ID":          ["P001", "P002", "P003"],
            "SEX_C":           ["1", "2", "1"],
            "BIRTH_DATE":      ["1980-06-15", "1995-01-22", "1965-11-03"],
            "PATIENT_RACE_C":  ["1", "2", "6"],
            "ETHNIC_GROUP_C":  ["2", "1", "2"],
        })

    def _encounter_df(self):
        return pd.DataFrame({
            "PAT_ENC_CSN_ID":  ["E001", "E002", "E003"],
            "PAT_ID":          ["P001", "P002", "P003"],
            "CONTACT_DATE":    ["2024-01-10", "2024-03-21", "2024-06-05"],
            "ADT_PAT_CLASS_C": ["1", "2", "3"],
            "HOSP_ADMSN_TIME": ["2024-01-10 08:00", "2024-03-21 09:30", None],
            "HOSP_DISCH_TIME": ["2024-01-12 14:00", None, None],
            "VISIT_PROV_ID":   ["PROV1", "PROV2", "PROV3"],
        })

    def _dx_df(self):
        return pd.DataFrame({
            "PAT_ENC_CSN_ID":     ["E001", "E001", "E002"],
            "PAT_ID":             ["P001", "P001", "P002"],
            "LINE":               [1, 2, 1],
            "CURRENT_ICD10_LIST": ["E11.9", "I10", "J18.9"],
            "CURRENT_ICD9_LIST":  ["250.00", "401.9", "486"],
            "PRIMARY_DX_YN":      ["Y", "N", "Y"],
            "CONTACT_DATE":       ["2024-01-10", "2024-01-10", "2024-03-21"],
        })

    def _med_df(self):
        return pd.DataFrame({
            "ORDER_MED_ID":  ["M001", "M002"],
            "PAT_ID":        ["P001", "P002"],
            "PAT_ENC_CSN_ID":["E001", "E002"],
            "MEDICATION_ID": ["310965", "308460"],
            "ORDERING_DATE": ["2024-01-11", "2024-03-22"],
            "QUANTITY":      ["30", "60"],
            "SIG":           ["Take 1 daily", "Take 2 daily"],
        })

    def _lab_df(self):
        return pd.DataFrame({
            "RESULT_ID":     ["L001", "L002"],
            "PAT_ID":        ["P001", "P002"],
            "PAT_ENC_CSN_ID":["E001", "E002"],
            "COMPONENT_ID":  ["2345-7", "2093-3"],
            "RESULT_DATE":   ["2024-01-11", "2024-03-22"],
            "ORD_VALUE":     ["5.8", "120"],
            "REFERENCE_LOW": ["4.0", "70"],
            "REFERENCE_HIGH":["6.0", "100"],
        })

    def _proc_df(self):
        return pd.DataFrame({
            "ORDER_PROC_ID": ["OP001", "OP002"],
            "PAT_ID":        ["P001", "P002"],
            "PAT_ENC_CSN_ID":["E001", "E002"],
            "PROC_CODE":     ["99213", "99215"],
            "ORDERING_DATE": ["2024-01-10", "2024-03-21"],
        })

    # ── to_person ──────────────────────────────────────────────────────────

    def test_to_person_returns_correct_shape(self):
        omop = self._transformer()
        out  = omop.to_person(self._patient_df())
        self.assertEqual(len(out), 3)
        for col in ("person_id", "gender_concept_id", "year_of_birth",
                    "race_concept_id", "ethnicity_concept_id"):
            self.assertIn(col, out.columns, f"Missing OMOP column: {col}")

    def test_to_person_gender_mapping(self):
        omop = self._transformer()
        out  = omop.to_person(self._patient_df())
        # SEX_C "1" = Male = 8507
        male_row = out[out["person_id"] == "P001"].iloc[0]
        self.assertEqual(male_row["gender_concept_id"], 8507)
        # SEX_C "2" = Female = 8532
        female_row = out[out["person_id"] == "P002"].iloc[0]
        self.assertEqual(female_row["gender_concept_id"], 8532)

    def test_to_person_birth_year(self):
        omop = self._transformer()
        out  = omop.to_person(self._patient_df())
        row  = out[out["person_id"] == "P001"].iloc[0]
        self.assertEqual(row["year_of_birth"], 1980)
        self.assertEqual(row["month_of_birth"], 6)
        self.assertEqual(row["day_of_birth"], 15)

    # ── to_visit_occurrence ───────────────────────────────────────────────

    def test_to_visit_occurrence_columns(self):
        omop = self._transformer()
        out  = omop.to_visit_occurrence(self._encounter_df())
        for col in ("visit_occurrence_id", "person_id", "visit_concept_id",
                    "visit_start_date", "visit_end_date",
                    "visit_type_concept_id"):
            self.assertIn(col, out.columns)

    def test_to_visit_occurrence_inpatient_concept(self):
        omop = self._transformer()
        out  = omop.to_visit_occurrence(self._encounter_df())
        inpt = out[out["visit_occurrence_id"] == "E001"].iloc[0]
        # ADT_PAT_CLASS_C "1" = inpatient = 9201
        self.assertEqual(inpt["visit_concept_id"], 9201)

    # ── to_condition_occurrence ───────────────────────────────────────────

    def test_to_condition_occurrence_shape(self):
        omop = self._transformer()
        out  = omop.to_condition_occurrence(self._dx_df())
        self.assertEqual(len(out), 3)
        for col in ("condition_occurrence_id", "person_id",
                    "condition_source_value", "condition_concept_id",
                    "condition_start_date"):
            self.assertIn(col, out.columns)

    def test_to_condition_icd10_preserved_in_source_value(self):
        omop = self._transformer()
        out  = omop.to_condition_occurrence(self._dx_df())
        self.assertIn("E11.9", out["condition_source_value"].values)

    def test_to_condition_concept_id_zero_without_vocab(self):
        omop = self._transformer()
        out  = omop.to_condition_occurrence(self._dx_df())
        # Without vocabulary, all concept_ids should be 0
        self.assertTrue((out["condition_concept_id"] == 0).all())

    # ── to_drug_exposure ──────────────────────────────────────────────────

    def test_to_drug_exposure_columns(self):
        omop = self._transformer()
        out  = omop.to_drug_exposure(self._med_df())
        for col in ("drug_exposure_id", "person_id", "drug_concept_id",
                    "drug_source_value", "drug_exposure_start_date"):
            self.assertIn(col, out.columns)

    def test_to_drug_quantity_numeric(self):
        omop = self._transformer()
        out  = omop.to_drug_exposure(self._med_df())
        self.assertTrue(pd.to_numeric(out["quantity"], errors="coerce")
                        .notna().all())

    # ── to_measurement ────────────────────────────────────────────────────

    def test_to_measurement_columns(self):
        omop = self._transformer()
        out  = omop.to_measurement(self._lab_df())
        for col in ("measurement_id", "person_id", "measurement_concept_id",
                    "measurement_date", "value_as_number"):
            self.assertIn(col, out.columns)

    def test_to_measurement_numeric_value(self):
        omop = self._transformer()
        out  = omop.to_measurement(self._lab_df())
        # "5.8" should become 5.8
        self.assertAlmostEqual(
            float(out.loc[out["measurement_id"] == "L001", "value_as_number"].iloc[0]),
            5.8, places=2
        )

    def test_to_measurement_range_fields(self):
        omop = self._transformer()
        out  = omop.to_measurement(self._lab_df())
        self.assertIn("range_low", out.columns)
        self.assertIn("range_high", out.columns)

    # ── to_procedure_occurrence ───────────────────────────────────────────

    def test_to_procedure_occurrence_columns(self):
        omop = self._transformer()
        out  = omop.to_procedure_occurrence(self._proc_df())
        for col in ("procedure_occurrence_id", "person_id",
                    "procedure_concept_id", "procedure_source_value",
                    "procedure_date"):
            self.assertIn(col, out.columns)

    def test_to_procedure_source_value_preserved(self):
        omop = self._transformer()
        out  = omop.to_procedure_occurrence(self._proc_df())
        self.assertIn("99213", out["procedure_source_value"].values)

    # ── Vocabulary resolution ─────────────────────────────────────────────

    def test_vocabulary_resolves_concept_id(self):
        # Build a tiny vocabulary DataFrame
        vocab = pd.DataFrame({
            "source_code":         ["E11.9", "J18.9"],
            "source_vocabulary_id":["ICD10CM", "ICD10CM"],
            "concept_id":          ["201826", "255848"],
        })
        vocab_path = pathlib.Path(self._tmp) / "vocab.csv"
        vocab.to_csv(vocab_path, index=False)

        omop = OMOPTransformer(self.gov, vocabulary_path=vocab_path)
        out  = omop.to_condition_occurrence(self._dx_df())
        # E11.9 → concept_id 201826
        e11_row = out[out["condition_source_value"] == "E11.9"].iloc[0]
        self.assertEqual(e11_row["condition_concept_id"], 201826)

    def test_governance_event_fired_per_domain(self):
        omop = self._transformer()
        omop.to_person(self._patient_df())
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("OMOP_DOMAIN_MAPPED" in c for c in calls))


# ═════════════════════════════════════════════════════════════════════════════
#  PHIKAnonymityChecker
# ═════════════════════════════════════════════════════════════════════════════

class TestPHIKAnonymityChecker(_TmpMixin):

    def _checker(self, **kw):
        return PHIKAnonymityChecker(self.gov, **kw)

    def _clean_df(self):
        """DataFrame where all quasi-id groups have >= 5 members."""
        rows = []
        for age in ("20-30", "30-40", "40-50"):
            for sex in ("M", "F"):
                for _ in range(5):
                    rows.append({
                        "age_group": age,
                        "sex":       sex,
                        "zip3":      "100",
                        "diagnosis": "E11" if age == "40-50" else "Z00",
                    })
        return pd.DataFrame(rows)

    def _risky_df(self):
        """DataFrame with some groups that have < 5 rows."""
        df = self._clean_df().copy()
        # Add a unique combination that appears only once
        df = pd.concat([df, pd.DataFrame([{
            "age_group": "90+",
            "sex":       "M",
            "zip3":      "036",
            "diagnosis": "C50",
        }])], ignore_index=True)
        return df

    def test_check_passes_for_clean_df(self):
        c      = self._checker(k=5)
        report = c.check(self._clean_df(),
                         quasi_ids=["age_group", "sex"])
        self.assertTrue(report["passes_k_anonymity"])
        self.assertEqual(report["k_violating_groups"], 0)

    def test_check_detects_violation(self):
        c      = self._checker(k=5)
        report = c.check(self._risky_df(),
                         quasi_ids=["age_group", "sex", "zip3"])
        self.assertFalse(report["passes_k_anonymity"])
        self.assertGreater(report["k_violating_groups"], 0)

    def test_enforce_suppress_removes_violating_rows(self):
        c      = self._checker(k=5)
        df     = self._risky_df()
        before = len(df)
        clean  = c.enforce(df, quasi_ids=["age_group", "sex", "zip3"],
                           action="suppress")
        self.assertLess(len(clean), before,
                        "Suppress should remove violating rows")

    def test_enforce_suppress_all_remaining_groups_valid(self):
        c      = self._checker(k=5)
        df     = self._risky_df()
        clean  = c.enforce(df, quasi_ids=["age_group", "sex", "zip3"],
                           action="suppress")
        # After suppression, check the result passes k-anonymity
        report = c.check(clean, quasi_ids=["age_group", "sex", "zip3"])
        self.assertTrue(report["passes_k_anonymity"])

    def test_enforce_report_does_not_modify_df(self):
        c    = self._checker(k=5)
        df   = self._risky_df()
        out  = c.enforce(df, quasi_ids=["age_group", "sex", "zip3"],
                         action="report")
        self.assertEqual(len(out), len(df),
                         "report action should not remove any rows")

    def test_enforce_raise_raises_on_violation(self):
        c  = self._checker(k=5)
        df = self._risky_df()
        with self.assertRaises(PHIAnonymityError):
            c.enforce(df, quasi_ids=["age_group", "sex", "zip3"],
                      action="raise")

    def test_enforce_raise_no_error_when_clean(self):
        c  = self._checker(k=5)
        df = self._clean_df()
        out = c.enforce(df, quasi_ids=["age_group", "sex"],
                        action="raise")
        self.assertEqual(len(out), len(df))

    def test_l_diversity_check(self):
        c   = self._checker(k=2, l_diversity=2)
        # Build a df where one group is k-anonymous but not l-diverse
        df  = pd.DataFrame({
            "age_group": ["20-30"] * 5 + ["30-40"] * 5,
            "sex":       ["M"]     * 5 + ["F"]     * 5,
            # The "20-30/M" group all have same diagnosis — l-diversity fails
            "diagnosis": ["E11"]   * 5 + ["E11", "J18", "Z00", "E11", "J18"],
        })
        report = c.check(df, quasi_ids=["age_group", "sex"],
                         sensitive_col="diagnosis")
        self.assertFalse(report["passes_l_diversity"])
        self.assertGreater(report["l_violating_groups"], 0)

    def test_l_diversity_pass_when_diverse(self):
        c  = self._checker(k=2, l_diversity=2)
        df = pd.DataFrame({
            "age_group": ["20-30"] * 6,
            "sex":       ["M"]     * 6,
            "diagnosis": ["E11", "J18", "Z00", "E11", "J18", "Z00"],
        })
        report = c.check(df, quasi_ids=["age_group", "sex"],
                         sensitive_col="diagnosis")
        self.assertTrue(report["passes_l_diversity"])

    def test_invalid_action_raises_valueerror(self):
        c  = self._checker(k=5)
        df = self._clean_df()
        with self.assertRaises(ValueError) as ctx:
            c.enforce(df, quasi_ids=["age_group"], action="delete")
        self.assertIn("action must be", str(ctx.exception))

    def test_missing_quasi_id_raises_valueerror(self):
        c  = self._checker(k=5)
        df = self._clean_df()
        with self.assertRaises(ValueError):
            c.check(df, quasi_ids=["nonexistent_col"])

    def test_dry_run_suppress_does_not_remove_rows(self):
        c   = self._checker(k=5, dry_run=True)
        df  = self._risky_df()
        out = c.enforce(df, quasi_ids=["age_group", "sex", "zip3"],
                        action="suppress")
        self.assertEqual(len(out), len(df))

    def test_save_report_html(self):
        c   = self._checker(k=5)
        c.check(self._risky_df(), quasi_ids=["age_group", "sex", "zip3"])
        out = pathlib.Path(self._tmp) / "kanon_report.html"
        c.save_report(out, fmt="html")
        self.assertTrue(out.exists())
        self.assertIn("k-Anonymity", out.read_text())

    def test_save_report_json(self):
        c   = self._checker(k=5)
        c.check(self._risky_df(), quasi_ids=["age_group", "sex", "zip3"])
        out = pathlib.Path(self._tmp) / "kanon_report.json"
        c.save_report(out, fmt="json")
        data = json.loads(out.read_text())
        self.assertIn("k_violations", data)

    def test_save_report_requires_prior_check(self):
        c = self._checker()
        with self.assertRaises(RuntimeError):
            c.save_report(pathlib.Path(self._tmp) / "x.html")

    def test_governance_event_fired(self):
        c = self._checker(k=5)
        c.check(self._clean_df(), quasi_ids=["age_group", "sex"])
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("KANONYMITY_CHECK_COMPLETE" in c for c in calls))

    def test_suppression_event_fired(self):
        c = self._checker(k=5)
        c.enforce(self._risky_df(),
                  quasi_ids=["age_group", "sex", "zip3"],
                  action="suppress")
        calls = [str(c) for c in self.gov._event.call_args_list]
        self.assertTrue(any("KANONYMITY_ROWS_SUPPRESSED" in c for c in calls))


# ═════════════════════════════════════════════════════════════════════════════
#  ClarityExtractor  —  connection tests (no live DB needed; logic tests only)
# ═════════════════════════════════════════════════════════════════════════════

class TestClarityExtractorNoDB(_TmpMixin):
    """Tests that don't require a live SQL Server connection."""

    def test_import_error_without_sqlalchemy(self):
        """ClarityExtractor raises ImportError when SQLAlchemy is not available."""
        from epic_extensions import ClarityExtractor
        import epic_extensions as em
        orig = em._SA_AVAILABLE
        em._SA_AVAILABLE = False
        try:
            with self.assertRaises(ImportError):
                ClarityExtractor(self.gov, cfg={
                    "host": "x", "db_name": "y",
                    "user": "u", "password": "p",
                })
        finally:
            em._SA_AVAILABLE = orig

    def test_refresh_window_blocked(self):
        """Queries are blocked during the configured refresh window."""
        from epic_extensions import ClarityExtractor
        import epic_extensions as em
        if not em._SA_AVAILABLE:
            self.skipTest("SQLAlchemy not installed")

        cx = ClarityExtractor(
            self.gov,
            cfg={"host": "x", "db_name": "y", "user": "u", "password": "p"},
            refresh_window_start=0,
            refresh_window_end=23,    # virtually always in window
            block_during_refresh=True,
        )
        # Mock the engine so we don't need a real DB
        cx._engine = MagicMock()
        with self.assertRaises(RuntimeError) as ctx:
            cx._check_refresh_window()
        self.assertIn("ETL refresh window", str(ctx.exception))

    def test_refresh_window_not_blocked_when_disabled(self):
        from epic_extensions import ClarityExtractor
        import epic_extensions as em
        if not em._SA_AVAILABLE:
            self.skipTest("SQLAlchemy not installed")

        cx = ClarityExtractor(
            self.gov,
            cfg={"host": "x", "db_name": "y", "user": "u", "password": "p"},
            refresh_window_start=0,
            refresh_window_end=23,
            block_during_refresh=False,
        )
        # Should not raise
        cx._check_refresh_window()


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()
    for cls in (
        TestHIPAASafeHarborFilter,
        TestBAATracker,
        TestIRBApprovalGate,
        TestOMOPTransformer,
        TestPHIKAnonymityChecker,
        TestClarityExtractorNoDB,
    ):
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
