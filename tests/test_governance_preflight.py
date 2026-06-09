"""
Tests for the governance pre-flight gate.

Each of the seven checks only runs when its state file exists, so tests
redirect CONFIG_DIR and BASE_DIR to a temp dir and drop in exactly the
files needed for the branch under test.  confirm_yes_no is scripted to
drive accept/reject/abort paths.

Revision history
────────────────
1.0   2026-06-09   Initial release: branch coverage for run_governance_preflight.
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline import governance_preflight as gp


class _PreflightCase(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.tmp = Path(tempfile.mkdtemp())
        self.df = pd.DataFrame({"id": [1, 2, 3], "email": ["a@x.com", "b@x.com", "c@x.com"]})

    def _run(self, confirms):
        with patch.object(gp, "CONFIG_DIR", self.tmp), \
             patch.object(gp, "BASE_DIR", self.tmp), \
             patch.object(gp, "confirm_yes_no", side_effect=confirms):
            return gp.run_governance_preflight(
                self.gov, self.df, str(self.tmp / "src.csv"), "src.csv", []
            )

    def _write(self, name, obj):
        (self.tmp / name).write_text(json.dumps(obj), encoding="utf-8")


class TestNoStateFiles(_PreflightCase):
    def test_clean_first_run_discovers_nothing(self):
        df_out, summary = self._run(confirms=[])
        self.assertEqual(summary["checks_discovered"], 0)
        self.assertEqual(len(df_out), 3)
        self.gov.transformation_applied.assert_any_call(
            "PREFLIGHT_GATE_COMPLETE", unittest.mock.ANY
        )


class TestSchemaDrift(_PreflightCase):
    def test_drift_accepted_updates_registry(self):
        self._write("schema_registry.json",
                    {"src.csv": {"columns": ["id"]}})  # missing 'email' -> added
        _df, summary = self._run(confirms=[True])
        self.assertEqual(summary["schema_drift"]["added"], ["email"])
        self.assertEqual(summary["checks_applied"], 1)
        # Registry rewritten to include the new column.
        reg = json.loads((self.tmp / "schema_registry.json").read_text(encoding="utf-8"))
        self.assertIn("email", reg["src.csv"]["columns"])

    def test_drift_rejected_keeps_registry(self):
        self._write("schema_registry.json", {"src.csv": {"columns": ["id"]}})
        _df, summary = self._run(confirms=[False])
        self.assertEqual(summary["checks_skipped"], 1)
        reg = json.loads((self.tmp / "schema_registry.json").read_text(encoding="utf-8"))
        self.assertEqual(reg["src.csv"]["columns"], ["id"])  # unchanged

    def test_no_drift_when_schema_matches(self):
        self._write("schema_registry.json", {"src.csv": {"columns": ["id", "email"]}})
        _df, summary = self._run(confirms=[])
        self.assertEqual(summary["schema_drift"], [])
        self.assertEqual(summary["checks_applied"], 1)


class TestAnomalies(_PreflightCase):
    def test_row_count_anomaly_continue(self):
        self._write("anomaly_baseline.json",
                    {"src.csv": {"expected_row_count": 1000, "row_count_tolerance": 0.1}})
        _df, summary = self._run(confirms=[True])  # continue despite anomaly
        self.assertTrue(summary["anomalies"])
        self.assertEqual(summary["checks_applied"], 1)

    def test_anomaly_abort_returns_early(self):
        self._write("anomaly_baseline.json",
                    {"src.csv": {"expected_row_count": 1000}})
        df_out, summary = self._run(confirms=[False])  # abort
        self.assertEqual(summary["checks_aborted"], 1)
        # Aborts before later checks; df returned unchanged.
        self.assertEqual(len(df_out), 3)

    def test_no_anomaly_when_within_range(self):
        self._write("anomaly_baseline.json",
                    {"src.csv": {"expected_row_count": 3, "row_count_tolerance": 0.2}})
        _df, summary = self._run(confirms=[])
        self.assertEqual(summary["anomalies"], [])


class TestColumnPurposesInformational(_PreflightCase):
    def test_column_purposes_listed(self):
        self._write("column_purpose.json",
                    {"src.csv": {"id": "identifier", "email": "contact"}})
        _df, summary = self._run(confirms=[])
        self.assertEqual(summary["checks_applied"], 1)


class TestPurposeLimitation(_PreflightCase):
    def test_excess_columns_dropped(self):
        self._write("purpose_registry.json",
                    {"src.csv": {"allowed_columns": ["id"], "purpose": "billing"}})
        df_out, summary = self._run(confirms=[True])  # drop excess
        self.assertIn("email", summary["columns_dropped"])
        self.assertNotIn("email", df_out.columns)
        self.gov.transformation_applied.assert_any_call(
            "PURPOSE_LIMITATION_APPLIED", unittest.mock.ANY
        )

    def test_excess_columns_retained_when_declined(self):
        self._write("purpose_registry.json",
                    {"src.csv": {"allowed_columns": ["id"], "purpose": "billing"}})
        df_out, summary = self._run(confirms=[False])  # keep
        self.assertEqual(summary["checks_skipped"], 1)
        self.assertIn("email", df_out.columns)

    def test_all_columns_within_allowed(self):
        self._write("purpose_registry.json",
                    {"src.csv": {"allowed_columns": ["id", "email"], "purpose": "x"}})
        _df, summary = self._run(confirms=[])
        self.assertEqual(summary["checks_applied"], 1)


class TestConsentDatabase(_PreflightCase):
    def _make_consent_db(self, rows):
        db = self.tmp / "consent.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE consent (subject_id TEXT, consented INTEGER)")
        conn.executemany("INSERT INTO consent VALUES (?, ?)", rows)
        conn.commit()
        conn.close()

    def test_rows_without_consent_blocked(self):
        # df has email column used as the subject match; only a@x.com consented.
        self._make_consent_db([("a@x.com", 1), ("b@x.com", 0)])
        df_out, summary = self._run(confirms=[True])  # filter
        self.assertEqual(summary["consent_blocked_rows"], 2)  # b and c removed
        self.assertEqual(list(df_out["email"]), ["a@x.com"])

    def test_consent_filter_skipped(self):
        self._make_consent_db([("a@x.com", 1)])
        df_out, summary = self._run(confirms=[False])  # keep all
        self.assertEqual(summary["consent_blocked_rows"], 0)
        self.assertEqual(len(df_out), 3)

    def test_empty_consent_db_is_informational(self):
        self._make_consent_db([])
        _df, summary = self._run(confirms=[])
        self.assertEqual(summary["consent_blocked_rows"], 0)


class TestPriorViolations(_PreflightCase):
    def test_violations_for_source_listed(self):
        lines = "\n".join(json.dumps(r) for r in [
            {"source": "src.csv", "contract": "c1", "failure_count": 2,
             "timestamp": "2026-01-01T00:00:00"},
            {"source": "other.csv", "contract": "c2"},  # filtered out
        ])
        (self.tmp / "contract_violations.jsonl").write_text(lines, encoding="utf-8")
        _df, summary = self._run(confirms=[])
        self.assertEqual(summary["checks_applied"], 1)


if __name__ == "__main__":
    unittest.main()
