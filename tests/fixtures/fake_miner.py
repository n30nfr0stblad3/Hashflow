#!/usr/bin/env python3
"""Fake xmrig for supervisor integration tests: emits console-like lines."""
import sys
import time

mode = sys.argv[1] if len(sys.argv) > 1 else "steady"

print(" * ABOUT         XMRig/6.20.0 (fake)", flush=True)
n = 0
if mode == "crash":
    print("error something went wrong", flush=True)
    sys.exit(3)
while True:
    n += 1
    print(f"speed  10s/60s/15m 1234.5 1200.1 1100.0 H/s  max 1300.0 H/s", flush=True)
    if n % 3 == 0:
        print(f"accepted ({n}/{n // 10}) diff 100000 (35 ms)", flush=True)
    if n == 2 and mode == "flaky":
        print("error connection lost", flush=True)
        sys.exit(1)
    time.sleep(0.2)
