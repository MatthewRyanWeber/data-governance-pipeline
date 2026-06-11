"""
Tests for pipeline.helpers — pure utility functions.

Covers read_jsonl_tail (including the 8KB chunk-boundary rejoin regression),
flatten_record depth limiting, and load_file_cached (path, mtime) caching.

Revision history
────────────────
1.0   2026-06-11   Initial release: chunk-boundary regression for
                   read_jsonl_tail, flatten_record max_depth, load_file_cached.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from pipeline.helpers import flatten_record, load_file_cached, read_jsonl_tail


class TestReadJsonlTail(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = Path(self.tmp) / "events.jsonl"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_records(self, record_count, payload_size=80):
        records = []
        with open(self.path, "w", encoding="utf-8") as f:
            for index in range(record_count):
                record = {"sequence": index, "payload": "x" * payload_size}
                records.append(record)
                f.write(json.dumps(record) + "\n")
        return records

    def test_missing_file_returns_empty(self):
        self.assertEqual(read_jsonl_tail(Path(self.tmp) / "nope.jsonl"), [])

    def test_tail_returns_newest_first(self):
        self._write_records(10)
        result = read_jsonl_tail(self.path, count=3)
        self.assertEqual([r["sequence"] for r in result], [9, 8, 7])

    def test_no_record_corrupted_at_chunk_boundary(self):
        # Regression: the line split across each 8KB read boundary was never
        # rejoined, corrupting one record per chunk. Write well over 8KB and
        # verify every tailed record parses with intact fields.
        written = self._write_records(400, payload_size=80)
        self.assertGreater(self.path.stat().st_size, 3 * 8192)

        result = read_jsonl_tail(self.path, count=300)
        self.assertEqual(len(result), 300)
        expected_sequences = [r["sequence"] for r in reversed(written[-300:])]
        self.assertEqual([r["sequence"] for r in result], expected_sequences)
        for record in result:
            self.assertEqual(record["payload"], "x" * 80)

    def test_boundary_record_intact_for_every_offset(self):
        # Sweep payload sizes so the boundary lands at many different
        # positions inside a record.
        for payload_size in (37, 53, 71, 97):
            path = Path(self.tmp) / f"sweep_{payload_size}.jsonl"
            with open(path, "w", encoding="utf-8") as f:
                for index in range(300):
                    f.write(json.dumps(
                        {"sequence": index, "payload": "y" * payload_size}
                    ) + "\n")
            result = read_jsonl_tail(path, count=250)
            self.assertEqual(len(result), 250, f"payload_size={payload_size}")
            self.assertEqual(
                [r["sequence"] for r in result],
                list(range(299, 49, -1)),
                f"payload_size={payload_size}",
            )

    def test_filter_fn_applied(self):
        self._write_records(20)
        result = read_jsonl_tail(
            self.path, count=5, filter_fn=lambda r: r["sequence"] % 2 == 0,
        )
        self.assertEqual([r["sequence"] for r in result], [18, 16, 14, 12, 10])

    def test_corrupt_line_skipped_with_warning(self):
        self._write_records(5)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("{definitely not json\n")
        with self.assertLogs("pipeline.helpers", level="WARNING"):
            result = read_jsonl_tail(self.path, count=10)
        self.assertEqual(len(result), 5)


class TestFlattenRecordDepth(unittest.TestCase):
    def test_unlimited_by_default(self):
        record = {"a": {"b": {"c": {"d": 1}}}}
        self.assertEqual(flatten_record(record), {"a__b__c__d": 1})

    def test_max_depth_one_keeps_nested_values(self):
        record = {"a": {"b": {"c": 1}}}
        self.assertEqual(
            flatten_record(record, max_depth=1),
            {"a": {"b": {"c": 1}}},
        )

    def test_max_depth_two_flattens_one_nesting_level(self):
        record = {"a": {"b": {"c": 1}}}
        self.assertEqual(
            flatten_record(record, max_depth=2),
            {"a__b": {"c": 1}},
        )

    def test_custom_separator(self):
        record = {"a": {"b": 1}}
        self.assertEqual(flatten_record(record, separator="."), {"a.b": 1})

    def test_lists_respect_depth(self):
        record = {"scores": [[1, 2], [3]]}
        self.assertEqual(
            flatten_record(record, max_depth=2),
            {"scores__0": [1, 2], "scores__1": [3]},
        )


class TestLoadFileCached(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = Path(self.tmp) / "lookup.json"
        self.path.write_text(json.dumps({"value": 1}), encoding="utf-8")
        self.loader_calls = 0

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _loader(self, path):
        self.loader_calls += 1
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def test_second_call_uses_cache(self):
        first = load_file_cached(self.path, self._loader)
        second = load_file_cached(self.path, self._loader)
        self.assertEqual(self.loader_calls, 1)
        self.assertIs(first, second)

    def test_modified_file_reloads(self):
        load_file_cached(self.path, self._loader)
        self.path.write_text(json.dumps({"value": 2}), encoding="utf-8")
        # Force a different mtime even on coarse-granularity filesystems.
        stat = self.path.stat()
        os.utime(self.path, (stat.st_atime, stat.st_mtime + 10))
        result = load_file_cached(self.path, self._loader)
        self.assertEqual(self.loader_calls, 2)
        self.assertEqual(result["value"], 2)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_file_cached(Path(self.tmp) / "ghost.json", self._loader)


if __name__ == "__main__":
    unittest.main()
