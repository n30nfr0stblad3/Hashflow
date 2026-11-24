"""Test 5/9 — hashrate parsing and unit math against realistic xmrig output."""
import unittest

from tests import REPO_ROOT  # noqa: F401
from hashflow.stats import (
    MovingAverage, acceptance_rate, aggregate_hashrate, fmt_hashrate,
    hr_to_float, parse_xmrig_line,
)


class TestHashrateMath(unittest.TestCase):
    def test_unit_conversion(self):
        self.assertEqual(hr_to_float("1", "H/s"), 1.0)
        self.assertEqual(hr_to_float("1", "kH/s"), 1e3)
        self.assertEqual(hr_to_float("2.5", "MH/s"), 2.5e6)
        self.assertEqual(hr_to_float("1", "GH/s"), 1e9)
        self.assertAlmostEqual(hr_to_float("1", "kh/s"), 1e3)  # lowercase unit

    def test_garbage_value_returns_zero(self):
        self.assertEqual(hr_to_float("abc", "kH/s"), 0.0)

    def test_fmt_hashrate_si_prefixes(self):
        self.assertEqual(fmt_hashrate(4_200_000), "4.20 MH/s")
        self.assertEqual(fmt_hashrate(1_200), "1.20 kH/s")
        self.assertEqual(fmt_hashrate(512), "512 H/s")
        self.assertEqual(fmt_hashrate(0), "0 H/s")


class TestXmrigLineParsing(unittest.TestCase):
    def test_speed_line(self):
        evt = parse_xmrig_line("speed  10s/60s/15m 1234.5 1200.1 1100.0 H/s  max 1300.0 H/s")
        self.assertEqual(evt["type"], "speed")
        self.assertAlmostEqual(evt["hashrate"], 1234.5)
        self.assertAlmostEqual(evt["h900"], 1100.0)

    def test_speed_line_with_kilo_units(self):
        evt = parse_xmrig_line("speed  10s/60s/15m 4.20 4.10 4.00 kH/s")
        self.assertAlmostEqual(evt["hashrate"], 4200.0)

    def test_share_line(self):
        evt = parse_xmrig_line("accepted (12/1) diff 100000 (35 ms)")
        self.assertEqual(evt, {"type": "share", "accepted": 12, "rejected": 1})

    def test_thread_line(self):
        evt = parse_xmrig_line("CPU thread #2  (3)  1.20 kH/s")
        self.assertEqual(evt["type"], "thread")
        self.assertEqual(evt["thread"], 2)
        self.assertAlmostEqual(evt["hashrate"], 1200.0)

    def test_error_line(self):
        evt = parse_xmrig_line("error: connection lost")
        self.assertEqual(evt["type"], "error")

    def test_unrelated_line_returns_none(self):
        self.assertIsNone(parse_xmrig_line(" * ABOUT XMRig/6.20.0"))
        self.assertIsNone(parse_xmrig_line(""))


class TestAggregation(unittest.TestCase):
    def test_moving_average(self):
        ma = MovingAverage(window=3)
        for v in (1.0, 2.0, 3.0, 4.0):
            ma.add(v)
        self.assertAlmostEqual(ma.avg, 3.0)  # (2+3+4)/3 — first evicted

    def test_moving_average_empty(self):
        self.assertEqual(MovingAverage().avg, 0.0)

    def test_aggregate_hashrate_ignores_nonpositive(self):
        self.assertAlmostEqual(aggregate_hashrate([100, 0, 300, -5, "x"]), 200.0)
        self.assertEqual(aggregate_hashrate([]), 0.0)

    def test_acceptance_rate(self):
        self.assertAlmostEqual(acceptance_rate(90, 10), 90.0)
        self.assertAlmostEqual(acceptance_rate(0, 0), 100.0)


if __name__ == "__main__":
    unittest.main()
