import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hashflow.miner import compute_thread_split, build_xmrig_cmd, find_xmrig
from hashflow.config import config

def test_thread_split():
    contrib, owner = compute_thread_split(8, 0.05)
    assert contrib + owner == 8
    assert owner >= 1
    assert contrib >= 1

    contrib, owner = compute_thread_split(1, 0.05)
    assert contrib == 1 and owner == 0

    contrib, owner = compute_thread_split(100, 0.02)
    assert owner == 2  # ceil(100*0.02)=2

def test_build_cmd():
    cmd = build_xmrig_cmd("/usr/bin/xmrig", "4xxx", 4, 0, 3, pool="pool.example:3333")
    assert "/usr/bin/xmrig" in cmd
    assert "4xxx" in cmd
    assert "4" in cmd
    assert "pool.example:3333" in cmd

def test_find_xmrig_not_found():
    # Should return None if not exists
    result = find_xmrig("/nonexistent/path/xmrig")
    assert result is None

if __name__ == "__main__":
    test_thread_split()
    test_build_cmd()
    test_find_xmrig_not_found()
    print("All miner tests passed")
