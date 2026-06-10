"""
Tests for the parallel file runner.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import unittest

from pipeline.parallel_runner import run_parallel


class TestRunParallel(unittest.TestCase):

    def test_empty_file_list(self):
        results = run_parallel([], lambda f: None)
        self.assertEqual(results, [])

    def test_single_file_success(self):
        results = run_parallel(["a.csv"], lambda f: None, max_workers=1)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["success"])
        self.assertIsNone(results[0]["error"])
        self.assertEqual(results[0]["file"], "a.csv")
        self.assertIsInstance(results[0]["duration_s"], float)

    def test_multiple_files(self):
        files = [f"file_{i}.csv" for i in range(5)]
        results = run_parallel(files, lambda f: None, max_workers=2)
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r["success"] for r in results))

    def test_failure_does_not_halt_others(self):
        def failing_fn(f):
            if "bad" in str(f):
                raise ValueError("bad file")

        files = ["good1.csv", "bad.csv", "good2.csv"]
        results = run_parallel(files, failing_fn, max_workers=1)
        self.assertEqual(len(results), 3)

        by_file = {r["file"]: r for r in results}
        self.assertTrue(by_file["good1.csv"]["success"])
        self.assertTrue(by_file["good2.csv"]["success"])
        self.assertFalse(by_file["bad.csv"]["success"])
        self.assertIn("bad file", by_file["bad.csv"]["error"])

    def test_duration_recorded(self):
        import time

        def slow_fn(f):
            time.sleep(0.05)

        results = run_parallel(["x.csv"], slow_fn, max_workers=1)
        self.assertGreaterEqual(results[0]["duration_s"], 0.04)

    def test_max_workers_respected(self):
        import threading
        peak = {"value": 0}
        current = {"value": 0}
        lock = threading.Lock()

        def tracking_fn(f):
            import time
            with lock:
                current["value"] += 1
                peak["value"] = max(peak["value"], current["value"])
            time.sleep(0.05)
            with lock:
                current["value"] -= 1

        files = [f"f{i}" for i in range(10)]
        run_parallel(files, tracking_fn, max_workers=2)
        self.assertLessEqual(peak["value"], 2)

    def test_pathlib_paths(self):
        from pathlib import Path
        results = run_parallel([Path("a.csv"), Path("b.csv")], lambda f: None, max_workers=1)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["success"] for r in results))


if __name__ == "__main__":
    unittest.main()
