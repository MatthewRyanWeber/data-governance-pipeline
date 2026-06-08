"""
Tests that DeadLetterQueue handles concurrent writes safely.

Verifies the threading.Lock protects _header_written and CSV output.
"""

import os
import tempfile
import threading
import unittest
from unittest.mock import MagicMock

import pandas as pd


class TestDLQThreadSafety(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.dlq_path = os.path.join(self.tmpdir, "dlq.csv")

    def tearDown(self):
        if os.path.exists(self.dlq_path):
            os.remove(self.dlq_path)
        os.rmdir(self.tmpdir)

    def _make_dlq(self):
        from pipeline.dead_letter_queue import DeadLetterQueue
        gov = MagicMock()
        gov.dlq_file = self.dlq_path
        gov.dlq_written = MagicMock()
        dlq = DeadLetterQueue(gov)
        return dlq

    def test_single_write(self):
        dlq = self._make_dlq()
        df = pd.DataFrame({"id": [1, 2, 3], "val": ["a", "b", "c"]})
        result = dlq.write(df, [1], "TEST_REASON")
        self.assertEqual(len(result), 2)
        self.assertTrue(os.path.exists(self.dlq_path))

    def test_header_written_once(self):
        dlq = self._make_dlq()
        df1 = pd.DataFrame({"id": [1, 2], "val": ["a", "b"]})
        df2 = pd.DataFrame({"id": [3, 4], "val": ["c", "d"]})
        dlq.write(df1, [0], "REASON_1")
        dlq.write(df2, [0], "REASON_2")
        with open(self.dlq_path, encoding="utf-8") as f:
            lines = f.readlines()
        header_count = sum(1 for line in lines if "id" in line and "val" in line
                          and "_dlq_reason" in line)
        self.assertEqual(header_count, 1)

    def test_concurrent_writes_no_duplicate_headers(self):
        dlq = self._make_dlq()
        errors = []

        def writer(thread_id):
            try:
                df = pd.DataFrame({
                    "id": [thread_id * 10 + i for i in range(5)],
                    "val": [f"t{thread_id}_{i}" for i in range(5)],
                })
                dlq.write(df, [0, 1], f"THREAD_{thread_id}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")

        with open(self.dlq_path, encoding="utf-8") as f:
            lines = f.readlines()

        header_lines = [
            line for line in lines
            if "_dlq_pipeline_id" in line and "_dlq_reason" in line
            and "_dlq_timestamp" in line and not line.startswith("THREAD")
        ]
        self.assertEqual(len(header_lines), 1,
                         f"Expected 1 header, got {len(header_lines)}")

    def test_lock_attribute_exists(self):
        dlq = self._make_dlq()
        self.assertIsInstance(dlq._lock, type(threading.Lock()))


if __name__ == "__main__":
    unittest.main()
