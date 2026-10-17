#!/usr/bin/env python3
"""
Hashflow - Legacy entry point (backward compatible)
Now powered by the new hashflow package with stealth limiter

This file maintains backward compatibility with:
    python3 miner.py <wallet> --username <name> --agree

But internally uses the new modular architecture.
"""

import sys
import os

# Try to use new package if available
try:
    from hashflow.cli import main as new_main
    # If called as python miner.py <wallet> ..., we need to handle legacy args
    # Check if first arg is wallet-like and not a subcommand
    if len(sys.argv) > 1 and sys.argv[1] not in ('mine', 'status', 'group', 'config', 'dashboard', '-h', '--help', '--version'):
        # Legacy mode: python miner.py <wallet> --username ...
        # Convert to: hashflow mine <wallet> --username ...
        sys.argv.insert(1, 'mine')
    new_main()
    sys.exit(0)
except ImportError:
    # Fallback to old implementation if new package not installed
    pass

# Fallback: Original implementation with added stealth features
import argparse
import json
import math
import re
import shutil
import signal
import subprocess
import threading
import time
from collections import deque, defaultdict
from pathlib import Path
import hashlib
import random

# --- Configuration defaults ---
DEFAULT_POOL = "pool.supportxmr.com:3333"
DEFAULT_OWNER_CONFIG = "owner_wallet.txt"
DEFAULT_XMRIG_NAME = "xmrig"
DEFAULT_DONATE = 0
DEFAULT_CPU_PRIORITY = 3
MIN_DONATION = 0.02
MAX_DONATION = 0.05
GROUP_FILE = "miners.json"
MAX_GROUP_SIZE = 100
REFRESH_INTERVAL = 3.0
SAMPLES = 8

_child_procs = []
_stop_event = threading.Event()

stats_lock = threading.Lock()
miner_stats = {
    "contrib": {
        "samples": deque(maxlen=SAMPLES),
        "per_thread": defaultdict(lambda: deque(maxlen=SAMPLES)),
        "last_total": 0.0,
        "device_label": None
    },
    "owner": {
        "samples": deque(maxlen=SAMPLES),
        "per_thread": defaultdict(lambda: deque(maxlen=SAMPLES)),
        "last_total": 0.0,
        "device_label": None
    }
}

def debug(msg, verbose):
    if verbose:
        print("[DEBUG]", msg)

def get_device_id():
    import platform, uuid
    unique_string = platform.node() + str(uuid.getnode()) + str(os.getpid())
    device_hash = hashlib.sha256(unique_string.encode()).hexdigest()[:12]
    return device_hash

def register_user(username, device_id):
    group_path = Path(GROUP_FILE)
    if group_path.exists():
        with group_path.open("r") as f:
            try:
                group_data = json.load(f)
            except Exception:
                group_data = []
    else:
        group_data = []

    group_data = [m for m in group_data if m.get("username") and m.get("device_id")]
    for member in group_data:
        if member["username"] == username and member["device_id"] == device_id:
            return

    if len(group_data) >= MAX_GROUP_SIZE:
        print(f"[ERROR] Group/circle is at full capacity ({MAX_GROUP_SIZE} miners). Registration failed.")
        print("Please contact the group admin to open a slot.")
        sys.exit(1)

    group_data.append({"username": username, "device_id": device_id})
    with group_path.open("w") as f:
        json.dump(group_data, f, indent=2)
    print(f"[INFO] Registered '{username}' (device {device_id}). Group size: {len(group_data)}/{MAX_GROUP_SIZE}")

def find_xmrig(provided_path):
    if provided_path:
        xmrig_path = Path(provided_path)
        if xmrig_path.is_file() and os.access(xmrig_path, os.X_OK):
            return str(xmrig_path)
        if xmrig_path.is_file():
            return str(xmrig_path)
        return None
    p = Path.cwd() / DEFAULT_XMRIG_NAME
    if p.is_file() and os.access(p, os.X_OK):
        return str(p)
    which = shutil.which(DEFAULT_XMRIG_NAME)
    if which:
        return which
    return None

def read_owner_wallet(owner_config_path):
    p = Path(owner_config_path)
    if not p.exists():
        # Try data dir
        alt = Path.home() / ".hashflow" / "owner_wallet.txt"
        if alt.exists():
            p = alt
        else:
            return None
    text = p.read_text().strip()
    return text if text else None

def compute_thread_split(total_threads, owner_fraction=MAX_DONATION):
    owner_fraction = max(MIN_DONATION, min(owner_fraction, MAX_DONATION))
    if total_threads <= 1:
        return total_threads, 0
    owner_threads = max(1, math.ceil(total_threads * owner_fraction))
    if owner_threads >= total_threads:
        owner_threads = total_threads - 1
    contrib_threads = total_threads - owner_threads
    return contrib_threads, owner_threads

def build_xmrig_cmd(xmrig_path, wallet, threads, donate_level, cpu_priority, pool=DEFAULT_POOL, api_port=None):
    cmd = [xmrig_path, "--url", pool, "--user", wallet, "--pass", "x", "--threads", str(threads),
           "--donate-level", str(donate_level), "--cpu-priority", str(cpu_priority)]
    if api_port:
        cmd += ["--api-port", str(api_port)]
    return cmd

# Stealth limiter (embedded for legacy fallback)
class SimpleStealthLimiter:
    def __init__(self, cpu_limit=0, stealth=False):
        self.cpu_limit = cpu_limit
        self.stealth = stealth
        self._delay = 0.0
        self._factor = 1.0

    def get_refresh_interval(self, base):
        if not self.stealth:
            return base
        return base * random.uniform(0.7, 1.7) + (random.uniform(1.0, 3.0) if random.random() < 0.1 else 0)

    def calculate_delay(self, current_cpu, threads):
        if self.cpu_limit == 0:
            return 0
        if current_cpu <= self.cpu_limit:
            self._factor = max(0.5, self._factor * 0.95)
            self._delay = max(0, self._delay * 0.8)
            return self._delay
        overage = current_cpu - self.cpu_limit
        base = (overage / 100.0) * 2.0
        thread_factor = 1.0 + (threads / 10.0) * 0.3
        self._factor = min(3.0, self._factor * 1.05)
        delay = base * thread_factor * self._factor
        if self.stealth:
            delay += random.uniform(-0.2, 0.4)
        self._delay = max(0, delay)
        return self._delay

GEN_HASH_RE = re.compile(r'([\d\.]+)\s*([kKmMgGtT]?H/s)')
THREAD_HASH_RE = re.compile(r'(?:thread|thread#|thread\s+#|CPU thread\W*)(\d+).*?([\d\.]+)\s*([kKmMgGtT]?H/s)')

UNIT_MULT = {
    'H/s': 1.0,
    'kH/s': 1e3, 'kh/s': 1e3,
    'MH/s': 1e6, 'mh/s': 1e6,
    'GH/s': 1e9, 'gh/s': 1e9,
    'TH/s': 1e12, 'th/s': 1e12
}

def hr_to_float(value_str, unit_str):
    unit = unit_str.strip()
    mult = UNIT_MULT.get(unit, 1.0)
    try:
        return float(value_str) * mult
    except Exception:
        return 0.0

def main():
    parser = argparse.ArgumentParser(description="XMRig wrapper with group cap, donation range, and stealth limiter.")
    parser.add_argument("wallet", help="Your Monero wallet address")
    parser.add_argument("--username", required=True, help="Your unique username for the group")
    parser.add_argument("--xmrig", help="Path to xmrig binary")
    parser.add_argument("--threads", type=int, help="Total mining threads")
    parser.add_argument("--donation", type=float, default=MAX_DONATION, help="Fractional donation to owner (between 0.02 and 0.05)")
    parser.add_argument("--owner-config", default=DEFAULT_OWNER_CONFIG, help="Owner wallet file")
    parser.add_argument("--pool", default=DEFAULT_POOL, help="Mining pool")
    parser.add_argument("--refresh", type=float, default=REFRESH_INTERVAL, help="Refresh interval for stats")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--agree", action="store_true", help="Agree to ethical mining terms")
    parser.add_argument("--limit-cpu", type=float, default=0, help="Max CPU usage % (e.g. 30 for 30%) - stealth limiter")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (randomized intervals, suppressed output)")
    args = parser.parse_args()

    # Ethical agreement check
    if not args.agree:
        print("="*60)
        print("⚠️  Ethical Mining Agreement Required")
        print("="*60)
        print("By using Hashflow, you agree that:")
        print("• You mine directly to YOUR own wallet (you keep rewards)")
        print("• 2-5% of threads are donated to project owner")
        print("• This is transparent and consensual dual-mining")
        print("• You will not use for unauthorized mining")
        print("")
        print("Run with --agree to accept.")
        print("Example: python3 miner.py <wallet> --username alice --agree")
        sys.exit(1)

    donation = max(MIN_DONATION, min(MAX_DONATION, args.donation))
    if args.donation != donation:
        print(f"[INFO] Donation clamped to {donation * 100:.1f}%")

    device_id = get_device_id()
    register_user(args.username, device_id)

    xmrig_bin = find_xmrig(args.xmrig)
    if not xmrig_bin:
        print("[ERROR] Could not find xmrig binary.")
        print("Install: https://github.com/xmrig/xmrig")
        print("Or: --xmrig /path/to/xmrig")
        sys.exit(1)

    owner_wallet = read_owner_wallet(args.owner_config)
    if not owner_wallet:
        print(f"[WARN] Owner wallet missing ({args.owner_config}), running in solo mode (100% to you)")
        owner_wallet = args.wallet
        donation = 0

    total_threads = args.threads or os.cpu_count() or 4
    contrib_threads, owner_threads = compute_thread_split(total_threads, owner_fraction=donation)

    if not args.quiet:
        print(f"Total threads: {total_threads} | You: {contrib_threads} | Owner: {owner_threads}")
        print(f"Donation share: {donation*100:.1f}%")
        print(f"Mining pool: {args.pool}")
        if args.limit_cpu > 0:
            print(f"CPU Limit: {args.limit_cpu}% | Stealth: {args.stealth}")

    limiter = SimpleStealthLimiter(cpu_limit=args.limit_cpu, stealth=args.stealth)

    contrib_cmd = build_xmrig_cmd(xmrig_bin, args.wallet, contrib_threads, 0, DEFAULT_CPU_PRIORITY, pool=args.pool)
    owner_cmd = build_xmrig_cmd(xmrig_bin, owner_wallet, owner_threads, 0, DEFAULT_CPU_PRIORITY, pool=args.pool)

    try:
        import psutil
        has_psutil = True
    except ImportError:
        has_psutil = False

    contrib_proc = subprocess.Popen(contrib_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    owner_proc = subprocess.Popen(owner_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    _child_procs.extend([contrib_proc, owner_proc])

    def shutdown(signum, frame):
        print("Exiting, terminating miners.")
        _stop_event.set()
        for proc in _child_procs:
            try:
                proc.terminate()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    def monitor(proc, label):
        for line in iter(proc.stdout.readline, b''):
            if _stop_event.is_set():
                break
            try:
                line_str = line.decode().strip()
            except Exception:
                continue
            if not args.quiet:
                if not args.stealth or "accepted" in line_str.lower() or "error" in line_str.lower():
                    print(f"[{label}] {line_str}")

            # CPU limiting logic
            if args.limit_cpu > 0 and has_psutil:
                try:
                    cpu = psutil.cpu_percent(interval=0.1)
                    delay = limiter.calculate_delay(cpu, total_threads)
                    if delay > 0:
                        time.sleep(min(delay, 2.0))
                        # Lower priority
                        try:
                            psutil.Process(proc.pid).nice(10)
                        except:
                            pass
                except:
                    pass

            # Stealth refresh jitter
            if args.stealth and limiter.get_refresh_interval:
                if random.random() < 0.05:
                    time.sleep(random.uniform(0.1, 0.5))

    t1 = threading.Thread(target=monitor, args=(contrib_proc, "CONTRIB"))
    t2 = threading.Thread(target=monitor, args=(owner_proc, "OWNER"))
    t1.start()
    t2.start()

    # Main loop with adaptive refresh
    try:
        while True:
            if contrib_proc.poll() is not None and owner_proc.poll() is not None:
                break
            time.sleep(limiter.get_refresh_interval(args.refresh))
    except KeyboardInterrupt:
        shutdown(None, None)

    t1.join()
    t2.join()

if __name__ == "__main__":
    main()
