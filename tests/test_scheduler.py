"""
Tests for the cron-style pipeline scheduler.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import unittest
from unittest.mock import MagicMock

from pipeline.scheduler import PipelineScheduler


class TestCronParsing(unittest.TestCase):

    def test_every_minute(self):
        parts = PipelineScheduler._parse_cron("* * * * *")
        self.assertEqual(parts["minute"], set(range(60)))
        self.assertEqual(parts["hour"], set(range(24)))

    def test_specific_minute(self):
        parts = PipelineScheduler._parse_cron("30 * * * *")
        self.assertEqual(parts["minute"], {30})

    def test_step_expression(self):
        parts = PipelineScheduler._parse_cron("*/15 * * * *")
        self.assertEqual(parts["minute"], {0, 15, 30, 45})

    def test_range_expression(self):
        parts = PipelineScheduler._parse_cron("0 9-17 * * *")
        self.assertEqual(parts["hour"], set(range(9, 18)))

    def test_comma_list(self):
        parts = PipelineScheduler._parse_cron("0,15,30 * * * *")
        self.assertEqual(parts["minute"], {0, 15, 30})

    def test_invalid_field_count(self):
        with self.assertRaises(ValueError):
            PipelineScheduler._parse_cron("* * *")

    def test_complex_expression(self):
        parts = PipelineScheduler._parse_cron("0 8 1,15 * 1-5")
        self.assertEqual(parts["minute"], {0})
        self.assertEqual(parts["hour"], {8})
        self.assertEqual(parts["day"], {1, 15})
        self.assertEqual(parts["weekday"], {1, 2, 3, 4, 5})

    def test_month_field(self):
        parts = PipelineScheduler._parse_cron("0 0 1 1,6,12 *")
        self.assertEqual(parts["month"], {1, 6, 12})


class TestSchedulerLifecycle(unittest.TestCase):

    def test_start_and_stop(self):
        fn = MagicMock()
        sched = PipelineScheduler(fn, cron_expr="0 0 1 1 *")
        sched.start()
        self.assertTrue(sched._thread.is_alive())
        sched.stop()
        self.assertIsNone(sched._thread)

    def test_double_start_is_safe(self):
        fn = MagicMock()
        sched = PipelineScheduler(fn, cron_expr="0 0 1 1 *")
        sched.start()
        sched.start()
        sched.stop()

    def test_stop_without_start_is_safe(self):
        fn = MagicMock()
        sched = PipelineScheduler(fn, cron_expr="0 0 1 1 *")
        sched.stop()

    def test_invalid_timezone_falls_back_to_utc(self):
        fn = MagicMock()
        sched = PipelineScheduler(fn, timezone_name="Invalid/Zone")
        from datetime import timezone
        self.assertEqual(sched._tz, timezone.utc)


if __name__ == "__main__":
    unittest.main()
