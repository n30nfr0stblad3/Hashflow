#!/usr/bin/env python3
"""Hashflow — transparent Monero mining wrapper for XMRig.

Fixes over v1 (see DESIGN.md):
  * informed consent gate (--agree or interactive YES) before any mining
  * honest donation accounting: static thread splits are only used when they
    match the requested share within 1pp; otherwise wallets rotate over time
  * donation is optional (--donation 0 / --no-donate); the owner wallet is
    only required when a donation is active
  * wallet validation, atomic group registry, stable device IDs
  * cross-platform (Windows/macOS/Linux/Termux): no platform-specific calls
  * child exit codes are surfaced instead of failing silently

Usage:
  python3 miner.py WALLET --username NAME --agree
  python3 miner.py WALLET --username NAME --agree --donation 0
  python3 miner.py --dashboard            # launch the Fleet Command UI (demo)
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hashflow.core import (  # noqa: E402
    DEFAULT_CPU_PRIORITY, DEFAULT_DONATION, DEFAULT_POOL,
    MAX_DONATION, MIN_DONATION,
    build_allocation_plan, get_device_id, read_owner_wallet, register_user,
    require_consent, validate_wallet,
)
from hashflow.stats import fmt_hashrate  # noqa: E402
from hashflow.supervisor import Supervisor, find_xmrig  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="XMRig wrapper with transparent donation accounting "
                    "and group registration.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("wallet", nargs="?", help="Your Monero wallet address")
    parser.add_argument("--username", help="Your unique username for the group")
    parser.add_argument("--agree", action="store_true",
                        help="Confirm you have read the consent summary and are "
                             "authorized to mine on this device")
    parser.add_argument("--xmrig", help="Path to xmrig binary")
    parser.add_argument("--threads", type=int,
                        help="Total mining threads (default: all CPU cores)")
    parser.add_argument("--donation", type=float, default=DEFAULT_DONATION,
                        help="Fraction of compute donated to the project "
                             f"({MIN_DONATION:.0%}-{MAX_DONATION:.0%}; 0 disables)")
    parser.add_argument("--no-donate", action="store_true",
                        help="Shortcut for --donation 0")
    parser.add_argument("--mode", choices=("auto", "threads", "timeslice"),
                        default="auto",
                        help="Allocation mode: static thread split vs wallet "
                             "rotation over time (auto picks the accurate one)")
    parser.add_argument("--owner-config", default="owner_wallet.txt",
                        help="File holding the project owner wallet address")
    parser.add_argument("--pool", default=DEFAULT_POOL, help="Mining pool")
    parser.add_argument("--skip-wallet-check", action="store_true",
                        help="Skip Monero address format validation")
    parser.add_argument("--group-file", default="miners.json",
                        help="Group registration ledger")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch the Fleet Command web dashboard (demo mode) "
                             "instead of mining")
    parser.add_argument("--cpu-priority", type=int, default=DEFAULT_CPU_PRIORITY,
                        help="XMRig CPU priority (1-5)")
    return parser


def _die(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def run_dashboard(port: int = 8765) -> int:
    from hashflow.server import main as server_main
    return server_main(["--demo", "--port", str(port)])


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.dashboard:
        return run_dashboard()

    if not args.wallet:
        parser.print_help()
        _die("a wallet address is required (or use --dashboard).")
    if not args.username:
        _die("--username is required so the group ledger can identify this device.")

    if not args.skip_wallet_check:
        ok, reason = validate_wallet(args.wallet)
        if not ok:
            _die(f"invalid wallet address: {reason} (use --skip-wallet-check to override)")

    donation = 0.0 if args.no_donate else args.donation
    if not (MIN_DONATION <= donation <= MAX_DONATION):
        print(f"[INFO] Donation clamped to {max(MIN_DONATION, min(MAX_DONATION, donation)):.0%}")
        donation = max(MIN_DONATION, min(MAX_DONATION, donation))

    owner_wallet = None
    if donation > 0:
        owner_wallet = read_owner_wallet(args.owner_config)
        if not owner_wallet:
            _die(
                f"Donation is enabled ({donation:.0%}) but no owner wallet was found in "
                f"'{args.owner_config}'. Create that file with the project wallet, or run "
                "with --no-donate to mine 100% to your own wallet."
            )

    total_threads = args.threads or os.cpu_count() or 1
    if total_threads < 1:
        _die("--threads must be >= 1")
    mode = None if args.mode == "auto" else args.mode
    plan = build_allocation_plan(total_threads, donation, force_mode=mode)

    # Group registration (stable device id — no PID component)
    ok, message, _ = register_user(args.username, get_device_id(),
                                  group_file=args.group_file)
    print(f"[INFO] {message}")
    if not ok:
        sys.exit(1)

    xmrig_bin = find_xmrig(args.xmrig)
    if not xmrig_bin:
        hint = ""
        if args.xmrig:
            hint = " Check the path and that the file is executable (chmod +x)."
        _die("Could not find the xmrig binary. Run scripts/fetch_xmrig.py to "
             f"download it automatically, or pass --xmrig PATH.{hint}")

    # Informed consent — prints the EXACT realized split before mining
    if not require_consent(args.agree, args.wallet, owner_wallet, donation,
                           plan, args.pool):
        sys.exit(1)

    print(f"[PLAN] {plan.summary}")

    events_lock = threading.Lock()

    def on_event(kind: str, data: dict) -> None:
        with events_lock:
            if kind == "speed":
                label = data.get("label", "?").upper()
                print(f"[{label}] {fmt_hashrate(data.get('hashrate', 0.0))}")
            elif kind == "share":
                print(f"[SHARE] accepted={data.get('accepted')} "
                      f"rejected={data.get('rejected')}")
            elif kind in ("proc_exit", "proc_failed", "proc_restart"):
                print(f"[WATCHDOG] {kind}: {data}")

    sup = Supervisor(
        xmrig_path=xmrig_bin,
        plan=plan,
        contrib_wallet=args.wallet,
        owner_wallet=owner_wallet,
        pool=args.pool,
        cpu_priority=args.cpu_priority,
        on_event=on_event,
    )

    def shutdown(signum, frame):
        print("\nExiting, terminating miners.")
        sup.stop()

    for sig_name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, shutdown)
            except (ValueError, OSError):
                pass

    sup.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
