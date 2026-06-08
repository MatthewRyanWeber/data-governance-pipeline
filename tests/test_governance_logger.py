"""
Tests for pipeline.governance_logger.GovernanceLogger.

Covers ledger integrity (chained SHA-256 hashes), event structure, dry-run
mode, thread safety, verify_ledger tamper detection, and correctness of
the most important public event methods.

Revision history
────────────────
1.0   2026-06-08   Initial release: 25 tests covering ledger, events, dry-run,
                   thread safety, verification, and cross-border inference.
"""

import hashlib
import json
import logging
import shutil
import tempfile
import threading
import unittest

from pipeline.constants import EventCategory, RunContext
from pipeline.governance_logger import (
    GovernanceLogger,
    _infer_cross_border_transfer,
)


class TestLedgerWritesValidJsonl(unittest.TestCase):
    """Ledger file is well-formed JSONL: one valid JSON object per line."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("test_source", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_single_event_produces_one_jsonl_line(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            lines = [ln for ln in f if ln.strip()]
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertIsInstance(parsed, dict)

    def test_multiple_events_produce_matching_line_count(self):
        for i in range(5):
            self.gov.quality_event("CHECK", {"iteration": i})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            lines = [ln for ln in f if ln.strip()]
        self.assertEqual(len(lines), 5)
        for line in lines:
            json.loads(line)  # raises on invalid JSON


class TestEventStructure(unittest.TestCase):
    """Every ledger event contains the required governance fields."""

    REQUIRED_KEYS = {
        "timestamp_utc", "pipeline_id", "category", "action",
        "prev_hash", "self_hash", "event_id", "detail",
    }

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ctx = RunContext(pipeline_id="struct-test-id")
        self.gov = GovernanceLogger(
            "test_source", log_dir=self.tmp, run_context=self.ctx,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_event_contains_all_required_keys(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            event = json.loads(f.readline())
        missing = self.REQUIRED_KEYS - event.keys()
        self.assertEqual(missing, set(), f"Missing keys: {missing}")

    def test_pipeline_id_matches_run_context(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            event = json.loads(f.readline())
        self.assertEqual(event["pipeline_id"], "struct-test-id")

    def test_timestamp_is_iso_format(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            event = json.loads(f.readline())
        ts = event["timestamp_utc"]
        self.assertIn("T", ts)
        self.assertTrue(ts.endswith("+00:00") or ts.endswith("Z"))


class TestChainedHashIntegrity(unittest.TestCase):
    """Second event's prev_hash must equal first event's self_hash."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("chain_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_genesis_prev_hash(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            first = json.loads(f.readline())
        self.assertEqual(first["prev_hash"], "GENESIS")

    def test_second_event_chains_to_first(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        self.gov.pipeline_end({"rows": 100})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            lines = [json.loads(ln) for ln in f if ln.strip()]
        self.assertEqual(lines[1]["prev_hash"], lines[0]["self_hash"])

    def test_self_hash_matches_recomputed_sha256(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            event = json.loads(f.readline())
        entry_for_hash = {k: v for k, v in event.items() if k != "self_hash"}
        recomputed = hashlib.sha256(
            json.dumps(entry_for_hash, sort_keys=True).encode()
        ).hexdigest()
        self.assertEqual(event["self_hash"], recomputed)

    def test_five_event_chain_is_contiguous(self):
        for i in range(5):
            self.gov.quality_event("STEP", {"i": i})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            events = [json.loads(ln) for ln in f if ln.strip()]
        self.assertEqual(events[0]["prev_hash"], "GENESIS")
        for idx in range(1, len(events)):
            self.assertEqual(
                events[idx]["prev_hash"], events[idx - 1]["self_hash"],
                f"Chain broken between event {idx - 1} and {idx}",
            )


class TestVerifyLedger(unittest.TestCase):
    """verify_ledger() returns True for intact ledger, False for tampered."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("verify_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_intact_ledger_passes(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        self.gov.pipeline_end({"rows": 42})
        self.assertTrue(self.gov.verify_ledger())

    def test_tampered_action_field_detected(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        self.gov.pipeline_end({"rows": 42})
        # Overwrite first line with a modified action field
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            lines = f.readlines()
        event = json.loads(lines[0])
        event["action"] = "TAMPERED_ACTION"
        lines[0] = json.dumps(event, sort_keys=True) + "\n"
        with open(self.gov.ledger_file, "w", encoding="utf-8") as f:
            f.writelines(lines)
        logging.disable(logging.CRITICAL)
        try:
            self.assertFalse(self.gov.verify_ledger())
        finally:
            logging.disable(logging.NOTSET)

    def test_tampered_middle_event_breaks_chain(self):
        for i in range(4):
            self.gov.quality_event("CHECK", {"i": i})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            lines = f.readlines()
        # Corrupt the second line's detail
        event = json.loads(lines[1])
        event["detail"]["i"] = 999
        lines[1] = json.dumps(event, sort_keys=True) + "\n"
        with open(self.gov.ledger_file, "w", encoding="utf-8") as f:
            f.writelines(lines)
        logging.disable(logging.CRITICAL)
        try:
            self.assertFalse(self.gov.verify_ledger())
        finally:
            logging.disable(logging.NOTSET)

    def test_empty_ledger_passes(self):
        # No events written, file does not exist
        self.assertTrue(self.gov.verify_ledger())


class TestEventMethods(unittest.TestCase):
    """Important event methods produce the correct category and action."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("methods_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _last_event(self):
        return self.gov.ledger_entries[-1]

    def test_pipeline_start_category_and_action(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        ev = self._last_event()
        self.assertEqual(ev["category"], EventCategory.LIFECYCLE)
        self.assertEqual(ev["action"], "PIPELINE_STARTED")

    def test_pipeline_end_category_and_action(self):
        self.gov.pipeline_end({"rows": 50})
        ev = self._last_event()
        self.assertEqual(ev["category"], EventCategory.LIFECYCLE)
        self.assertEqual(ev["action"], "PIPELINE_COMPLETED")

    def test_pii_detected_category_and_detail(self):
        findings = [
            {"field": "email", "pattern": "email", "value": "alice@example.com"},
            {"field": "phone", "pattern": "phone", "value": "555-0101"},
        ]
        self.gov.pii_detected(findings)
        ev = self._last_event()
        self.assertEqual(ev["category"], EventCategory.PRIVACY)
        self.assertEqual(ev["action"], "PII_DETECTED")
        self.assertEqual(ev["detail"]["findings_count"], 2)
        self.assertIn("email", ev["detail"]["fields"])

    def test_pii_action_category_and_action(self):
        self.gov.pii_action("email", "MASKED")
        ev = self._last_event()
        self.assertEqual(ev["category"], EventCategory.PRIVACY)
        self.assertEqual(ev["action"], "PII_MASKED")
        self.assertEqual(ev["detail"]["field"], "email")

    def test_validation_result_category_and_detail(self):
        self.gov.validation_result("basic_suite", True, 10, 0, 10)
        ev = self._last_event()
        self.assertEqual(ev["category"], EventCategory.VALIDATION)
        self.assertEqual(ev["action"], "SUITE_RESULT")
        self.assertTrue(ev["detail"]["overall_success"])

    def test_consent_recorded_category_and_detail(self):
        self.gov.consent_recorded("analytics", "LEGITIMATE_INTEREST", True)
        ev = self._last_event()
        self.assertEqual(ev["category"], EventCategory.CONSENT)
        self.assertEqual(ev["action"], "LAWFUL_BASIS_RECORDED")
        self.assertTrue(ev["detail"]["user_confirmed"])

    def test_erasure_executed_hashes_subject_id(self):
        self.gov.erasure_executed("alice@example.com", "users", 1, "DELETE")
        ev = self._last_event()
        self.assertEqual(ev["category"], EventCategory.ERASURE)
        self.assertEqual(ev["action"], "GDPR_ERASURE_EXECUTED")
        # Raw PII must never appear in audit trail
        self.assertNotIn("alice@example.com", json.dumps(ev))
        self.assertIn("subject_id_hash", ev["detail"])

    def test_dlq_written_accumulates_total(self):
        self.gov.dlq_written(5, "null_pk")
        self.gov.dlq_written(3, "schema_mismatch")
        self.assertEqual(self.gov.dlq_rows_total, 8)
        ev = self._last_event()
        self.assertEqual(ev["category"], EventCategory.DLQ)


class TestDryRunMode(unittest.TestCase):
    """dry_run=True must NOT write events to disk, but must record in memory."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger(
            "dryrun_test", log_dir=self.tmp, dry_run=True,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_ledger_file_created(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        self.gov.pipeline_end({"rows": 10})
        self.assertFalse(
            self.gov.ledger_file.exists(),
            "Ledger file must not exist in dry-run mode",
        )

    def test_events_recorded_in_memory(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        self.assertEqual(len(self.gov.ledger_entries), 1)

    def test_chained_hashes_still_computed_in_memory(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        self.gov.pipeline_end({"rows": 10})
        entries = self.gov.ledger_entries
        self.assertEqual(entries[0]["prev_hash"], "GENESIS")
        self.assertEqual(entries[1]["prev_hash"], entries[0]["self_hash"])


class TestThreadSafety(unittest.TestCase):
    """10 concurrent threads writing events must not corrupt the ledger."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gov = GovernanceLogger("threadsafe_test", log_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_concurrent_writes_produce_valid_chain(self):
        errors = []

        def writer(thread_id):
            try:
                for i in range(10):
                    self.gov.quality_event(
                        f"T{thread_id}_CHECK",
                        {"thread": thread_id, "i": i},
                    )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Thread errors: {errors}")

        # All 100 events must be present
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            lines = [ln for ln in f if ln.strip()]
        self.assertEqual(len(lines), 100)

        # Chain must be intact
        self.assertTrue(self.gov.verify_ledger())


class TestRunContextPipelineId(unittest.TestCase):
    """Custom pipeline_id from RunContext appears in every event."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ctx = RunContext(pipeline_id="custom-run-42")
        self.gov = GovernanceLogger(
            "ctx_test", log_dir=self.tmp, run_context=self.ctx,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_events_carry_custom_pipeline_id(self):
        self.gov.pipeline_start({"source": "synth.csv"})
        self.gov.pii_action("phone", "REDACTED")
        self.gov.pipeline_end({"rows": 1})
        with open(self.gov.ledger_file, encoding="utf-8") as f:
            events = [json.loads(ln) for ln in f if ln.strip()]
        for ev in events:
            self.assertEqual(ev["pipeline_id"], "custom-run-42")


class TestCrossBorderTransferInference(unittest.TestCase):
    """_infer_cross_border_transfer returns correct metadata or None."""

    def test_snowflake_eu_region(self):
        result = _infer_cross_border_transfer("snowflake", "acct.eu-west-1/db")
        self.assertIsNotNone(result)
        self.assertEqual(result["dest_country"], "EU")
        self.assertEqual(result["transfer_type"], "SNOWFLAKE_CLOUD_REGION")

    def test_bigquery_eu_location(self):
        result = _infer_cross_border_transfer("bigquery", "project.dataset@EU")
        self.assertIsNotNone(result)
        self.assertEqual(result["dest_country"], "EU")
        self.assertEqual(result["transfer_type"], "INTRA_EU")

    def test_unknown_db_returns_none(self):
        result = _infer_cross_border_transfer("sqlite", "local.db")
        self.assertIsNone(result)


class TestSourceNameSanitisation(unittest.TestCase):
    """Special characters in source_name are sanitised for file paths."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_slashes_replaced(self):
        gov = GovernanceLogger("path/to\\file", log_dir=self.tmp)
        self.assertNotIn("/", gov.source_name)
        self.assertNotIn("\\", gov.source_name)

    def test_empty_name_defaults_to_pipeline(self):
        gov = GovernanceLogger("", log_dir=self.tmp)
        self.assertEqual(gov.source_name, "pipeline")


if __name__ == "__main__":
    unittest.main()
