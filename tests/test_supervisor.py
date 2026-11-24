"""Test 7/9 — supervisor process management against a fake miner binary
(real subprocesses: startup, output parsing, crash restart, stop escalation)."""
import sys
import threading
import time
import unittest
from pathlib import Path

from tests import REPO_ROOT  # noqa: F401
from hashflow.core import AllocationPlan, Split, build_allocation_plan
from hashflow.supervisor import MinerProcess, Supervisor, build_xmrig_cmd, find_xmrig

FAKE_MINER = str(Path(__file__).parent / "fixtures" / "fake_miner.py")
PY = sys.executable


def run_fake(args, mode="steady"):
    return [PY, FAKE_MINER, mode] + args


class TestBuildCmd(unittest.TestCase):
    def test_cmd_contains_required_flags(self):
        cmd = build_xmrig_cmd("/usr/bin/xmrig", "WALLET", 4, "pool:3333")
        self.assertEqual(cmd[0], "/usr/bin/xmrig")
        self.assertIn("WALLET", cmd)
        self.assertIn("--threads", cmd)
        self.assertEqual(cmd[cmd.index("--threads") + 1], "4")
        self.assertIn("--donate-level", cmd)

    def test_find_xmrig_missing_returns_none(self):
        self.assertIsNone(find_xmrig("/nonexistent/xmrig-binary"))


class TestMinerProcess(unittest.TestCase):
    def test_output_parsed_and_stopped(self):
        events = []
        proc = MinerProcess("contrib", run_fake([], "steady"),
                            lambda k, d: events.append((k, d)))
        proc.start()
        time.sleep(1.2)
        self.assertTrue(proc.alive)
        proc.stop()
        time.sleep(0.3)
        self.assertFalse(proc.alive)
        kinds = [k for k, _ in events]
        self.assertIn("speed", kinds)      # parsed hashrate lines
        self.assertIn("share", kinds)      # parsed accepted lines
        self.assertIn("proc_start", kinds)

    def test_crash_exit_code_surfaced(self):
        events = []
        proc = MinerProcess("contrib", run_fake([], "crash"),
                            lambda k, d: events.append((k, d)))
        proc.start()
        deadline = time.time() + 5
        while time.time() < deadline and not any(k == "proc_exit" for k, _ in events):
            time.sleep(0.1)
        exits = [d for k, d in events if k == "proc_exit"]
        self.assertTrue(exits, "crash must raise a proc_exit event (v1 failed silently)")
        self.assertEqual(exits[0]["code"], 3)


class TestSupervisor(unittest.TestCase):
    def test_solo_mode_runs_until_stopped(self):
        events = []
        plan = build_allocation_plan(2, 0.0)
        sup = Supervisor(FAKE_MINER, plan, "WALLET", None, "pool:3333",
                         on_event=lambda k, d: events.append(k))
        # Replace cmd builder by monkeypatching _make_proc to use the fake miner
        sup._make_proc = lambda label, wallet: MinerProcess(
            label, run_fake([], "steady"), sup.on_event)
        t = threading.Thread(target=sup.run, daemon=True)
        t.start()
        time.sleep(1.0)
        sup.stop()
        t.join(timeout=5)
        self.assertFalse(t.is_alive())
        self.assertIn("speed", events)

    def test_timeslice_rotation_between_wallets(self):
        events = []
        # Construct a plan with tiny windows so both rotations occur in-test.
        plan = AllocationPlan(
            mode="timeslice", total_threads=2, split=Split(2, 0),
            realized_owner_fraction=0.05, timeslice_window_s=2.4,
            contrib_window_s=1.6, owner_window_s=0.8)
        sup = Supervisor(FAKE_MINER, plan, "CONTRIB", "OWNER", "pool:3333",
                         on_event=lambda k, d: events.append((k, d)))
        sup._make_proc = lambda label, wallet: MinerProcess(
            label, run_fake([], "steady"), sup.on_event)
        t = threading.Thread(target=sup.run, daemon=True)
        t.start()
        time.sleep(4.5)   # spans >= one contrib window and one owner window
        sup.stop()
        t.join(timeout=5)
        self.assertFalse(t.is_alive())
        labels = {d.get("label") for k, d in events if k == "proc_start"}
        self.assertEqual(labels, {"contrib", "owner"})  # both wallets ran

    def test_crash_restart_backoff_emits_events(self):
        events = []
        plan = build_allocation_plan(2, 0.0)
        sup = Supervisor(FAKE_MINER, plan, "WALLET", None, "pool:3333",
                         on_event=lambda k, d: events.append((k, d)))
        sup._make_proc = lambda label, wallet: MinerProcess(
            label, run_fake([], "crash"), sup.on_event)
        # Short-lived windows so _run_window returns before hitting the cap
        t = threading.Thread(target=lambda: sup._run_window("contrib", "W", 3.5),
                             daemon=True)
        t.start()
        t.join(timeout=15)
        kinds = [k for k, _ in events]
        self.assertIn("proc_restart", kinds)


if __name__ == "__main__":
    unittest.main()
