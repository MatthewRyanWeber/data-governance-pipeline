"""
Tests for the referential integrity checker.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock

import pandas as pd

from pipeline.referential_integrity import ReferentialIntegrityChecker


class TestReferentialIntegrityChecker(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gov = MagicMock()
        self.dlq = MagicMock()
        self.dlq.write.side_effect = lambda df, indices, reason: df.drop(index=[df.index[i] for i in indices])
        self.checker = ReferentialIntegrityChecker(self.gov, self.dlq)

        ref_df = pd.DataFrame({"dept_id": [1, 2, 3]})
        self.ref_path = os.path.join(self.tmpdir, "departments.csv")
        ref_df.to_csv(self.ref_path, index=False, encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_all_valid_fks(self):
        df = pd.DataFrame({"dept_id": [1, 2, 3], "name": ["A", "B", "C"]})
        result = self.checker.check(df, "dept_id", self.ref_path, "dept_id")
        self.assertEqual(len(result), 3)
        self.dlq.write.assert_not_called()
        self.gov.referential_integrity_checked.assert_called_once()

    def test_invalid_fks_routed_to_dlq(self):
        df = pd.DataFrame({"dept_id": [1, 999, 3], "name": ["A", "B", "C"]})
        self.checker.check(df, "dept_id", self.ref_path, "dept_id")
        self.dlq.write.assert_called_once()
        args = self.dlq.write.call_args
        self.assertIn("REFERENTIAL_INTEGRITY", args[0][2])

    def test_missing_fk_column_returns_unchanged(self):
        df = pd.DataFrame({"name": ["A", "B"]})
        result = self.checker.check(df, "dept_id", self.ref_path, "dept_id")
        self.assertEqual(len(result), 2)
        self.gov.referential_integrity_checked.assert_not_called()

    def test_unsupported_reference_format(self):
        unsupported = os.path.join(self.tmpdir, "ref.yaml")
        with open(unsupported, "w") as f:
            f.write("key: value")
        df = pd.DataFrame({"dept_id": [1]})
        unchanged = self.checker.check(df, "dept_id", unsupported, "dept_id")
        self.assertEqual(len(unchanged), 1)

    def test_json_reference(self):
        import json
        ref_data = [{"dept_id": 10}, {"dept_id": 20}]
        ref_path = os.path.join(self.tmpdir, "departments.json")
        with open(ref_path, "w", encoding="utf-8") as f:
            json.dump(ref_data, f)

        df = pd.DataFrame({"dept_id": [10, 99], "name": ["A", "B"]})
        self.checker.check(df, "dept_id", ref_path, "dept_id")
        self.dlq.write.assert_called_once()

    def test_governance_event_logged(self):
        df = pd.DataFrame({"dept_id": [1, 2], "name": ["A", "B"]})
        self.checker.check(df, "dept_id", self.ref_path, "dept_id")
        self.gov.referential_integrity_checked.assert_called_once_with(
            "dept_id", self.ref_path, 2, 0,
        )


if __name__ == "__main__":
    unittest.main()
