"""Test 1/9 — allocation math: thread splits and plan-mode selection."""
import unittest

from tests import REPO_ROOT  # noqa: F401
from hashflow.core import (
    SPLIT_TOLERANCE_PP, THREADSPLIT_MIN_CORES, Split,
    build_allocation_plan, clamp, compute_thread_split,
)


class TestClamp(unittest.TestCase):
    def test_clamp_bounds(self):
        self.assertEqual(clamp(-1, 0, 5), 0)
        self.assertEqual(clamp(7, 0, 5), 5)
        self.assertEqual(clamp(3, 0, 5), 3)


class TestThreadSplit(unittest.TestCase):
    def test_single_thread_all_contributor(self):
        s = compute_thread_split(1, 0.05)
        self.assertEqual((s.contrib_threads, s.owner_threads), (1, 0))

    def test_zero_donation_is_solo(self):
        s = compute_thread_split(16, 0.0)
        self.assertEqual(s.owner_threads, 0)
        self.assertEqual(s.contrib_threads, 16)

    def test_owner_never_gets_everything(self):
        for total in range(2, 65):
            s = compute_thread_split(total, 0.05)
            self.assertLess(s.owner_threads, total)
            self.assertGreaterEqual(s.owner_threads, 1)

    def test_fraction_clamped_to_max_5pct_policy(self):
        s = compute_thread_split(64, 0.9)  # request 90% -> policy max 5%
        self.assertLessEqual(s.realized_owner_fraction, 0.0625 + 1e-9)

    def test_realized_fraction_reported(self):
        s = compute_thread_split(20, 0.05)
        self.assertAlmostEqual(s.realized_owner_fraction, 0.05)
        self.assertEqual((s.contrib_threads, s.owner_threads), (19, 1))


class TestAllocationPlan(unittest.TestCase):
    def test_zero_donation_selects_solo(self):
        plan = build_allocation_plan(8, 0.0)
        self.assertEqual(plan.mode, "solo")
        self.assertEqual(plan.realized_owner_fraction, 0.0)

    def test_small_core_count_uses_timeslice(self):
        # 4 cores: a whole thread is 25% — far from the 5% request.
        plan = build_allocation_plan(4, 0.05)
        self.assertEqual(plan.mode, "timeslice")
        self.assertAlmostEqual(plan.realized_owner_fraction, 0.05)

    def test_accurate_static_split_uses_threads_mode(self):
        plan = build_allocation_plan(20, 0.05)  # 1/20 == 5.0% exactly
        self.assertEqual(plan.mode, "threads")
        self.assertAlmostEqual(plan.realized_owner_fraction, 0.05)

    def test_timeslice_windows_sum_to_window(self):
        plan = build_allocation_plan(4, 0.05, timeslice_window_s=600)
        self.assertAlmostEqual(
            plan.owner_window_s + plan.contrib_window_s,
            plan.timeslice_window_s, places=3)
        self.assertGreater(plan.contrib_window_s, plan.owner_window_s)

    def test_forced_mode_respected(self):
        self.assertEqual(build_allocation_plan(4, 0.05, force_mode="threads").mode,
                         "threads")
        self.assertEqual(build_allocation_plan(64, 0.05, force_mode="timeslice").mode,
                         "timeslice")
        self.assertEqual(build_allocation_plan(8, 0.0, force_mode="solo").mode, "solo")

    def test_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            build_allocation_plan(8, 0.05, force_mode="bogus")

    def test_threads_mode_small_core_still_within_tolerance_check(self):
        # Property: whenever mode == 'threads' is auto-chosen, realized share is
        # within tolerance of the request (this is the honesty guarantee).
        for total in range(1, 129):
            plan = build_allocation_plan(total, 0.05)
            if plan.mode == "threads":
                self.assertLessEqual(
                    abs(plan.realized_owner_fraction - 0.05),
                    SPLIT_TOLERANCE_PP + 1e-9)
                self.assertGreaterEqual(total, THREADSPLIT_MIN_CORES)

    def test_summary_mentions_percentage(self):
        plan = build_allocation_plan(4, 0.05)
        self.assertIn("5.0% to owner", plan.summary)


if __name__ == "__main__":
    unittest.main()
