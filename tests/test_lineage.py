"""
Tests for pipeline.lineage.openlineage_emitter.OpenLineageEmitter.

Covers START/COMPLETE/FAIL event structure, JSONL persistence,
dry-run mode, dataset normalisation, and run-ID rotation.

Revision history
────────────────
1.0   2026-06-08   Initial release: 7 tests covering event types, JSONL output,
                   dry-run mode, dataset normalisation, and run rotation.
"""

import json
import logging
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pipeline.lineage.openlineage_emitter import OpenLineageEmitter

_OL_SCHEMA = "https://openlineage.io/spec/2-0-2/OpenLineage.json"


class TestOpenLineageEventStructure(unittest.TestCase):
    """Verify START, COMPLETE, and FAIL events have correct OpenLineage shape."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.gov = MagicMock()
        self.gov.log_dir = Path(self.tmp_dir)
        self.emitter = OpenLineageEmitter(
            self.gov,
            namespace="test-namespace",
            output_file=Path(self.tmp_dir) / "events.jsonl",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _assert_common_fields(self, event, expected_type, expected_job):
        """Check fields shared by every event type."""
        self.assertEqual(event["eventType"], expected_type)
        self.assertIn("eventTime", event)
        self.assertEqual(event["schemaURL"], _OL_SCHEMA)
        self.assertIn("producer", event)
        self.assertEqual(event["job"]["namespace"], "test-namespace")
        self.assertEqual(event["job"]["name"], expected_job)
        self.assertIn("runId", event["run"])
        self.assertIsInstance(event["inputs"], list)
        self.assertIsInstance(event["outputs"], list)

    def test_start_event_structure(self):
        """emit_start produces a valid START event with inputs normalised."""
        event = self.emitter.emit_start(
            "extract",
            inputs=["s3://bucket/raw.csv"],
        )
        self._assert_common_fields(event, "START", "extract")
        self.assertEqual(len(event["inputs"]), 1)
        self.assertEqual(event["inputs"][0]["name"], "s3://bucket/raw.csv")
        self.assertEqual(event["inputs"][0]["namespace"], "test-namespace")

    def test_complete_event_structure(self):
        """emit_complete produces a valid COMPLETE event with outputs."""
        event = self.emitter.emit_complete(
            "load",
            outputs=["postgres://db/staging"],
        )
        self._assert_common_fields(event, "COMPLETE", "load")
        self.assertEqual(len(event["outputs"]), 1)
        self.assertEqual(event["outputs"][0]["name"], "postgres://db/staging")

    def test_fail_event_includes_error_facet(self):
        """emit_fail attaches an errorMessage facet when error_message is set."""
        event = self.emitter.emit_fail(
            "transform",
            error_message="Column 'amount' has nulls",
        )
        self._assert_common_fields(event, "FAIL", "transform")
        error_facet = event["run"]["facets"]["errorMessage"]
        self.assertEqual(error_facet["message"], "Column 'amount' has nulls")
        self.assertEqual(error_facet["programmingLanguage"], "python")
        self.assertEqual(error_facet["_schemaURL"], _OL_SCHEMA)

    def test_fail_event_no_error_message(self):
        """emit_fail without error_message has empty run facets."""
        event = self.emitter.emit_fail("transform")
        self.assertEqual(event["run"]["facets"], {})


class TestOpenLineageJSONLOutput(unittest.TestCase):
    """Verify events are persisted correctly as JSONL."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.gov = MagicMock()
        self.gov.log_dir = Path(self.tmp_dir)
        self.jsonl_path = Path(self.tmp_dir) / "lineage.jsonl"
        self.emitter = OpenLineageEmitter(
            self.gov,
            namespace="test-ns",
            output_file=self.jsonl_path,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_events_written_as_valid_jsonl(self):
        """Multiple emitted events produce one valid JSON object per line."""
        self.emitter.emit_start("step_a", inputs=["file://a.csv"])
        self.emitter.emit_complete("step_a", outputs=["file://b.parquet"])
        self.emitter.emit_fail("step_a", error_message="bad data")

        lines = self.jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 3)

        types_found = []
        for line in lines:
            obj = json.loads(line)
            types_found.append(obj["eventType"])
            self.assertIn("eventTime", obj)
            self.assertEqual(obj["schemaURL"], _OL_SCHEMA)

        self.assertEqual(types_found, ["START", "COMPLETE", "FAIL"])

    def test_governance_logger_notified_per_event(self):
        """Each non-dry-run emit calls gov.transformation_applied once."""
        self.emitter.emit_start("ingest")
        self.emitter.emit_complete("ingest")
        self.assertEqual(self.gov.transformation_applied.call_count, 2)


class TestOpenLineageDryRun(unittest.TestCase):
    """Verify dry_run=True prevents file writes and HTTP calls."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.gov = MagicMock()
        self.gov.log_dir = Path(self.tmp_dir)
        self.jsonl_path = Path(self.tmp_dir) / "dry_events.jsonl"
        self.emitter = OpenLineageEmitter(
            self.gov,
            namespace="dry-ns",
            output_file=self.jsonl_path,
            dry_run=True,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_dry_run_returns_event_without_writing(self):
        """dry_run=True returns a well-formed event but writes no file."""
        event = self.emitter.emit_start("extract", inputs=["s3://data/in.csv"])
        self.assertEqual(event["eventType"], "START")
        self.assertEqual(event["job"]["name"], "extract")
        self.assertFalse(self.jsonl_path.exists())

    def test_dry_run_does_not_notify_governance_logger(self):
        """dry_run=True skips the gov.transformation_applied call."""
        self.emitter.emit_complete("load")
        self.gov.transformation_applied.assert_not_called()

    def test_dry_run_logs_info_message(self):
        """dry_run=True emits an INFO log indicating the skipped write."""
        with self.assertLogs("pipeline.lineage.openlineage_emitter", level="INFO") as cm:
            self.emitter.emit_start("validate")
        self.assertTrue(any("DRY RUN" in m for m in cm.output))
        self.assertTrue(any("validate" in m for m in cm.output))


class TestOpenLineageRunRotation(unittest.TestCase):
    """Verify new_run generates a fresh run ID."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.gov = MagicMock()
        self.gov.log_dir = Path(self.tmp_dir)
        self.emitter = OpenLineageEmitter(
            self.gov,
            namespace="rotation-ns",
            output_file=Path(self.tmp_dir) / "events.jsonl",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_new_run_changes_run_id(self):
        """new_run() produces a distinct run ID used in subsequent events."""
        event_before = self.emitter.emit_start("step1")
        old_run_id = event_before["run"]["runId"]

        new_id = self.emitter.new_run()
        event_after = self.emitter.emit_start("step2")

        self.assertNotEqual(old_run_id, new_id)
        self.assertEqual(event_after["run"]["runId"], new_id)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()
