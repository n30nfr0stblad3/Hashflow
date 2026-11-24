"""Test 4/9 — group registry ledger: dedup, capacity, corruption recovery,
atomic writes (exercises the file layer against a real temp dir)."""
import json
import tempfile
import unittest
from pathlib import Path

from tests import REPO_ROOT  # noqa: F401
from hashflow.core import register_user


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = str(Path(self.tmp.name) / "miners.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_registration_persists(self):
        ok, msg, members = register_user("alice", "dev-001", self.ledger)
        self.assertTrue(ok)
        self.assertEqual(len(members), 1)
        data = json.loads(Path(self.ledger).read_text())
        self.assertEqual(data[0]["username"], "alice")

    def test_duplicate_registration_is_idempotent(self):
        register_user("alice", "dev-001", self.ledger)
        ok, msg, members = register_user("alice", "dev-001", self.ledger)
        self.assertTrue(ok)
        self.assertIn("Already registered", msg)
        self.assertEqual(len(members), 1)

    def test_same_user_new_device_gets_new_row(self):
        register_user("alice", "dev-001", self.ledger)
        _, _, members = register_user("alice", "dev-002", self.ledger)
        self.assertEqual(len(members), 2)

    def test_capacity_enforced(self):
        for i in range(3):
            register_user(f"u{i}", f"d{i}", self.ledger, max_size=3)
        ok, msg, members = register_user("overflow", "dX", self.ledger, max_size=3)
        self.assertFalse(ok)
        self.assertIn("capacity", msg)
        self.assertEqual(len(members), 3)

    def test_corrupt_ledger_preserved_not_destroyed(self):
        Path(self.ledger).write_text("{ this is not json")
        ok, msg, members = register_user("bob", "dev-009", self.ledger)
        self.assertFalse(ok)
        self.assertIn("corrupt", msg)
        backup = Path(self.ledger + ".bak")
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_text(), "{ this is not json")

    def test_malformed_rows_filtered(self):
        Path(self.ledger).write_text(json.dumps([
            {"username": "good", "device_id": "d1"},
            {"username": "broken"},
            "not-a-dict",
        ]))
        _, _, members = register_user("new", "d2", self.ledger)
        self.assertEqual(len(members), 2)  # only valid rows survive

    def test_no_temp_files_left_behind(self):
        register_user("alice", "dev-001", self.ledger)
        leftovers = [p for p in Path(self.tmp.name).iterdir() if p.suffix == ".tmp"]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
