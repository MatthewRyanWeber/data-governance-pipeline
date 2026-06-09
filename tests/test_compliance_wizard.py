"""
Tests for the interactive GDPR/CCPA compliance wizard.

The wizard reads operator choices via interactive_prompt / confirm_yes_no /
input(); these are patched to drive each branch (lawful basis, CCPA sale
opt-out, PII strategy, retention mapping, column dropping) and the returned
decision dict is asserted.

Revision history
────────────────
1.0   2026-06-09   Initial release: branch coverage for run_compliance_wizard.
"""

import unittest
from unittest.mock import MagicMock, patch

from pipeline import compliance_wizard


class TestComplianceWizard(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()

    def _run(self, prompts, confirms, pii_findings=None, input_value=""):
        """Drive the wizard with scripted prompt/confirm/input responses."""
        with patch.object(compliance_wizard, "interactive_prompt", side_effect=prompts), \
             patch.object(compliance_wizard, "confirm_yes_no", side_effect=confirms), \
             patch("builtins.input", return_value=input_value):
            return compliance_wizard.run_compliance_wizard(self.gov, pii_findings or [])

    def test_default_path_no_pii(self):
        # basis=2(Contract), purpose, retention=3(365). confirms: consent yes,
        # sale no, drop-cols no.
        result = self._run(prompts=["2", "Data analysis", "3"],
                            confirms=[True, False, False])
        self.assertEqual(result["lawful_basis"], "Contract")
        self.assertEqual(result["retention_days"], 365)
        self.assertEqual(result["pii_strategy"], "retain")
        self.assertEqual(result["drop_cols"], [])
        self.gov.consent_recorded.assert_called_once()

    def test_consent_lawful_basis(self):
        result = self._run(prompts=["1", "Marketing", "1"],
                            confirms=[True, False, False])
        self.assertEqual(result["lawful_basis"], "Consent")
        self.assertEqual(result["retention_days"], 30)

    def test_ccpa_sale_optout_recorded(self):
        # sale=yes, opted_out=yes
        self._run(prompts=["2", "Resale", "3"],
                  confirms=[True, True, True, False])
        self.gov.consent_event.assert_called_once()
        args = self.gov.consent_event.call_args[0]
        self.assertEqual(args[0], "CCPA_SALE_OPTOUT")
        self.assertTrue(args[1]["opted_out"])

    def test_pii_strategy_mask(self):
        pii = [{"field": "email", "special_category": False},
               {"field": "ssn", "special_category": True}]
        result = self._run(prompts=["2", "Analytics", "1", "3"],
                           confirms=[True, False, False],
                           pii_findings=pii)
        self.assertEqual(result["pii_strategy"], "mask")

    def test_pii_strategy_drop(self):
        pii = [{"field": "email", "special_category": False}]
        result = self._run(prompts=["2", "Analytics", "2", "3"],
                           confirms=[True, False, False],
                           pii_findings=pii)
        self.assertEqual(result["pii_strategy"], "drop")

    def test_indefinite_retention(self):
        result = self._run(prompts=["2", "Archive", "6"],
                            confirms=[True, False, False])
        self.assertIsNone(result["retention_days"])
        self.gov.retention_policy.assert_called_once()

    def test_drop_columns_parsed(self):
        result = self._run(prompts=["2", "Analytics", "3"],
                           confirms=[True, False, True],
                           input_value="ssn, dob , ")
        self.assertEqual(result["drop_cols"], ["ssn", "dob"])


if __name__ == "__main__":
    unittest.main()
