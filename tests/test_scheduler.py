"""
Tests for the cron-style pipeline scheduler.

Revision history
────────────────
1.0   2026-06-09   Initial release.
1.1   2026-06-11   Regression tests: daily cron re-fires on later days,
                   range/step parsing, weekday 7 alias, minute-boundary sleep.
"""

import unittest
from datetime import datetime, timezone
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

    def test_step_over_range(self):
        # Regression: "1-5/2" used to crash because the step branch called
        # int("1-5").
        parts = PipelineScheduler._parse_cron("1-5/2 * * * *")
        self.assertEqual(parts["minute"], {1, 3, 5})

    def test_step_over_range_in_hour_field(self):
        parts = PipelineScheduler._parse_cron("0 9-17/4 * * *")
        self.assertEqual(parts["hour"], {9, 13, 17})

    def test_weekday_seven_maps_to_sunday(self):
        # Regression: weekday 7 was accepted but could never match because
        # the matcher only produces 0-6.
        parts = PipelineScheduler._parse_cron("0 0 * * 7")
        self.assertEqual(parts["weekday"], {0})

    def test_weekday_range_ending_at_seven(self):
        parts = PipelineScheduler._parse_cron("0 0 * * 5-7")
        self.assertEqual(parts["weekday"], {0, 5, 6})


class TestDailyCronRefires(unittest.TestCase):
    """Regression for daily/weekly crons firing exactly once ever."""

    def setUp(self):
        self.fn = MagicMock()
        self.sched = PipelineScheduler(self.fn, cron_expr="30 2 * * *")

    def test_fires_on_first_match(self):
        day_one = datetime(2026, 6, 10, 2, 30, tzinfo=timezone.utc)
        self.assertTrue(self.sched._should_fire(day_one, None))

    def test_does_not_refire_within_same_minute(self):
        day_one = datetime(2026, 6, 10, 2, 30, 5, tzinfo=timezone.utc)
        fired_key = day_one.replace(second=0, microsecond=0)
        later_same_minute = day_one.replace(second=45)
        self.assertFalse(self.sched._should_fire(later_same_minute, fired_key))

    def test_same_time_on_later_day_fires_again(self):
        # The old dedup key was hour*60+minute with no date, so 02:30 on day
        # two compared equal to 02:30 on day one and never fired again.
        day_one = datetime(2026, 6, 10, 2, 30, tzinfo=timezone.utc)
        day_two = datetime(2026, 6, 11, 2, 30, tzinfo=timezone.utc)
        fired_key = day_one.replace(second=0, microsecond=0)
        self.assertTrue(self.sched._should_fire(day_two, fired_key))

    def test_non_matching_minute_does_not_fire(self):
        off_schedule = datetime(2026, 6, 10, 2, 31, tzinfo=timezone.utc)
        self.assertFalse(self.sched._should_fire(off_schedule, None))


class TestMinuteBoundarySleep(unittest.TestCase):
    """The loop sleeps to the next minute boundary instead of a fixed 60s."""

    def test_mid_minute_sleeps_to_boundary(self):
        now = datetime(2026, 6, 10, 2, 30, 12, 500_000, tzinfo=timezone.utc)
        seconds = PipelineScheduler._seconds_until_next_minute(now)
        self.assertAlmostEqual(seconds, 47.5, places=3)

    def test_on_boundary_sleeps_full_minute(self):
        now = datetime(2026, 6, 10, 2, 30, 0, 0, tzinfo=timezone.utc)
        seconds = PipelineScheduler._seconds_until_next_minute(now)
        self.assertAlmostEqual(seconds, 60.0, places=3)

    def test_never_returns_zero_or_negative(self):
        now = datetime(2026, 6, 10, 2, 30, 59, 999_999, tzinfo=timezone.utc)
        seconds = PipelineScheduler._seconds_until_next_minute(now)
        self.assertGreater(seconds, 0)


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
