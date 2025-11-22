#!/usr/bin/env python3
import argparse
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque, defaultdict
from pathlib import Path
import hashlib

# --- Configuration defaults ---
DEFAULT_POOL = "pool.supportxmr.com:3333"
DEFAULT_OWNER_CONFIG = "owner_wallet.txt"
DEFAULT_XMRIG_NAME = "xmrig"
DEFAULT_DONATE = 0
DEFAULT_CPU_PRIORITY = 3
MIN_DONATION = 0.02  # 2%
MAX_DONATION = 0.05  # 5%
GROUP_FILE = "miners.json"
MAX_GROUP_SIZE = 100
REFRESH_INTERVAL = 3.0  # seconds for status display
SAMPLES = 8  # number of recent samples to average for smoothing
# -------------------------------

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

# ---- User/Group management ----

def get_device_id():
    # Use a hash of MAC + platform info for uniqueness (not perfect, but OK for Termux/VPS context)
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

    # Prevent duplicate device or username+device combo
    group_data = [m for m in group_data if m.get("username") and m.get("device_id")]
    for member in group_data:
        if member["username"] == username and member["device_id"] == device_id:
            return  # already present

    if len(group_data) >= MAX_GROUP_SIZE:
        print(f"[ERROR] Group/circle is at full capacity ({MAX_GROUP_SIZE} miners). Registration failed.")
        print("Please contact the group admin to open a slot.")
        sys.exit(1)

    group_data.append({"username": username, "device_id": device_id})
    with group_path.open("w") as f:
        json.dump(group_data, f, indent=2)
    print(f"[INFO] Registered '{username}' (device {device_id}). Group size: {len(group_data)}/{MAX_GROUP_SIZE}")

# ------ XMRIG mgmt -------

def find_xmrig(provided_path):
    if provided_path:
        xmrig_path = Path(provided_path)
        if xmrig_path.is_file() and os.access(xmrig_path, os.X_OK):
            return str(xmrig_path)
        return None
    # try cwd
    p = Path.cwd() / DEFAULT_XMRIG_NAME
    if p.is_file() and os.access(p, os.XMRIG_NAME):
        return str(p)
    # try PATH
    which = shutil.which(DEFAULT_XMRIG_NAME)
    if which:
        return which
    return None

def read_owner_wallet(owner_config_path):
    p = Path(owner_config_path)
    if not p.exists():
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

# Regexes for hashrate parsing
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

# Main routine
def main():
    parser = argparse.ArgumentParser(description="XMRig wrapper with group cap and donation range.")
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
    args = parser.parse_args()

    # Clamp donation
    donation = max(MIN_DONATION, min(MAX_DONATION, args.donation))
    if args.donation != donation:
        print(f"[INFO] Donation clamped to {donation * 100:.1f}%")

    # Group registration
    device_id = get_device_id()
    register_user(args.username, device_id)

    xmrig_bin = find_xmrig(args.xmrig)
    if not xmrig_bin:
        print("[ERROR] Could not find xmrig binary.")
        sys.exit(1)

    owner_wallet = read_owner_wallet(args.owner_config)
    if not owner_wallet:
        print("[ERROR] Owner wallet configuration missing.")
        sys.exit(1)

    # Thread split
    total_threads = args.threads or os.cpu_count()
    contrib_threads, owner_threads = compute_thread_split(total_threads, owner_fraction=donation)

    # Show assignment
    if not args.quiet:
        print(f"Total threads: {total_threads} | You: {contrib_threads} | Owner: {owner_threads}")
        print(f"Donation share: {donation*100:.1f}%")
        print(f"Mining pool: {args.pool}")

    # Start both subprocesses
    contrib_cmd = build_xmrig_cmd(xmrig_bin, args.wallet, contrib_threads, 0, DEFAULT_CPU_PRIORITY, pool=args.pool)
    owner_cmd = build_xmrig_cmd(xmrig_bin, owner_wallet, owner_threads, 0, DEFAULT_CPU_PRIORITY, pool=args.pool)

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
            try:
                line_str = line.decode().strip()
            except Exception:
                continue
            if not args.quiet:
                print(f"[{label}] {line_str}")
            # ... could add hash parsing/stats

    t1 = threading.Thread(target=monitor, args=(contrib_proc, "CONTRIB"))
    t2 = threading.Thread(target=monitor, args=(owner_proc, "OWNER"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

if __name__ == "__main__":
    main()