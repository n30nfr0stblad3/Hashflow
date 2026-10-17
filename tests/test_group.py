import os, sys, tempfile, json
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hashflow.group import GroupManager

def test_group_registration():
    with tempfile.TemporaryDirectory() as tmp:
        group_file = Path(tmp) / "miners.json"
        manager = GroupManager(str(group_file))
        manager.max_size = 2

        device_id = "abc123def456"
        m1 = manager.register("alice", device_id, "4xxx")
        assert m1["username"] == "alice"
        assert len(manager.load_group()) == 1

        # Duplicate should not increase count
        m1_dup = manager.register("alice", device_id, "4xxx")
        assert len(manager.load_group()) == 1

        m2 = manager.register("bob", "other123", "4yyy")
        assert len(manager.load_group()) == 2

        # Should fail at capacity
        try:
            manager.register("charlie", "third123", "4zzz")
            assert False, "Should have raised"
        except ValueError:
            pass

def test_device_id():
    manager = GroupManager()
    did = manager.get_device_id()
    assert len(did) == 12
    assert isinstance(did, str)

if __name__ == "__main__":
    test_group_registration()
    test_device_id()
    print("All group tests passed")
