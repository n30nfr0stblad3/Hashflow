"""Core domain logic: allocation math, identity, registry, wallet validation,
consent gating, and run configuration.

Everything here is pure or near-pure and unit-tested. No third-party imports.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# --- Allocation policy -------------------------------------------------------
MIN_DONATION = 0.0
MAX_DONATION = 0.05
DEFAULT_DONATION = 0.05
DEFAULT_DONATE_LEVEL = 0  # xmrig internal dev-fee: we manage donation ourselves
DEFAULT_CPU_PRIORITY = 3
DEFAULT_POOL = "pool.supportxmr.com:3333"

# Static thread splitting only stays within +/-1pp of the requested share on
# machines with at least this many cores; below it we time-slice instead.
THREADSPLIT_MIN_CORES = 10
SPLIT_TOLERANCE_PP = 0.01  # 1 percentage point
DEFAULT_TIMELICE_WINDOW_S = 600.0  # 10-minute rotation windows

# --- Group registry ---------------------------------------------------------
GROUP_FILE = "miners.json"
MAX_GROUP_SIZE = 100

# --- Wallet validation ------------------------------------------------------
# Monero mainnet standard (95 ch, '4'), integrated (106 ch, '4'), subaddress
# (95 ch, '8'); testnet standard starts with '9'. Base58 excludes 0 O I l.
_B58 = r"1-9A-HJ-NP-Za-km-z"
MONERO_ADDR_RE = re.compile(
    rf"^(4[{_B58}]{{94}}"          # standard: '4' + 94 = 95 chars
    rf"|4[{_B58}]{{105}}"          # integrated: '4' + 105 = 106 chars
    rf"|8[{_B58}]{{94}}"           # subaddress: '8' + 94 = 95 chars
    rf"|9[{_B58}]{{94}})$"         # testnet standard: '9' + 94 = 95 chars
)


def clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def validate_wallet(address: str) -> Tuple[bool, str]:
    """Return (ok, reason). Reason is human-actionable on failure."""
    addr = (address or "").strip()
    if not addr:
        return False, "Wallet address is empty."
    if any(c.isspace() for c in addr):
        return False, "Wallet address contains whitespace. Paste the address only."
    if len(addr) < 95:
        return False, (
            f"Wallet address is {len(addr)} characters; a Monero address is "
            "95 (standard/subaddress) or 106 (integrated) characters."
        )
    if not MONERO_ADDR_RE.match(addr):
        return False, (
            "Wallet address failed the Monero base58 format check "
            "(prefix must be '4', '8' or testnet '9'; no 0/O/I/l characters)."
        )
    return True, "ok"


# --- Allocation -------------------------------------------------------------

@dataclass(frozen=True)
class Split:
    """Result of a static thread split."""
    contrib_threads: int
    owner_threads: int

    @property
    def realized_owner_fraction(self) -> float:
        total = self.contrib_threads + self.owner_threads
        return (self.owner_threads / total) if total else 0.0


def compute_thread_split(total_threads: int, owner_fraction: float = DEFAULT_DONATION) -> Split:
    """Split *whole threads* between contributor and owner.

    Note: with small core counts a whole-thread split cannot represent a 2-5%
    share (1 of 4 threads is 25%). Callers should prefer
    :func:`build_allocation_plan`, which falls back to time-slicing there.
    """
    frac = clamp(owner_fraction, MIN_DONATION, MAX_DONATION)
    if total_threads <= 1 or frac <= 0:
        return Split(total_threads, 0)
    owner_threads = max(1, math.ceil(total_threads * frac))
    if owner_threads >= total_threads:
        owner_threads = total_threads - 1
    return Split(total_threads - owner_threads, owner_threads)


@dataclass(frozen=True)
class AllocationPlan:
    """How CPU time is divided between the contributor and owner wallets.

    modes:
      * ``solo``       - 100% contributor (donation disabled)
      * ``threads``    - static thread split (accurate on many-core hosts)
      * ``timeslice``  - one miner, wallet rotation windows (exact over time)
    """
    mode: str
    total_threads: int
    split: Split
    realized_owner_fraction: float
    timeslice_window_s: float = DEFAULT_TIMELICE_WINDOW_S
    owner_window_s: float = 0.0
    contrib_window_s: float = 0.0

    @property
    def summary(self) -> str:
        if self.mode == "solo":
            return f"{self.total_threads} threads, 100% to contributor (donation off)"
        if self.mode == "threads":
            return (
                f"{self.total_threads} threads: {self.split.contrib_threads} contributor "
                f"+ {self.split.owner_threads} owner = "
                f"{self.realized_owner_fraction * 100:.1f}% to owner"
            )
        return (
            f"{self.total_threads} threads, rotated every "
            f"{self.timeslice_window_s / 60:.0f} min: "
            f"{self.contrib_window_s / 60:.1f} min contributor / "
            f"{self.owner_window_s / 60:.1f} min owner = "
            f"{self.realized_owner_fraction * 100:.1f}% to owner"
        )


def build_allocation_plan(
    total_threads: int,
    owner_fraction: float,
    force_mode: Optional[str] = None,
    timeslice_window_s: float = DEFAULT_TIMELICE_WINDOW_S,
) -> AllocationPlan:
    """Choose the allocation mode that most honestly matches *owner_fraction*.

    A static whole-thread split is only used when its realized share is within
    +/-1 percentage point of the request on >= THREADSPLIT_MIN_CORES cores;
    otherwise we rotate wallets over time windows for an exact long-run share.
    """
    frac = clamp(owner_fraction, MIN_DONATION, MAX_DONATION)
    total_threads = max(1, int(total_threads or 1))
    if force_mode is not None and force_mode not in ("solo", "threads", "timeslice"):
        raise ValueError(f"unknown allocation mode: {force_mode!r}")

    if frac <= 0 or force_mode == "solo":
        split = Split(total_threads, 0)
        return AllocationPlan("solo", total_threads, split, 0.0)

    split = compute_thread_split(total_threads, frac)
    realized = split.realized_owner_fraction
    static_ok = (
        total_threads >= THREADSPLIT_MIN_CORES
        and abs(realized - frac) <= SPLIT_TOLERANCE_PP
    )

    if force_mode == "threads" or (static_ok and force_mode is None):
        return AllocationPlan("threads", total_threads, split, realized)

    window = max(60.0, float(timeslice_window_s))
    owner_window = max(5.0, window * frac)
    contrib_window = max(5.0, window - owner_window)
    # Renormalize so the ratio of the two windows is exactly `frac`.
    scale = window / (owner_window + contrib_window)
    owner_window *= scale
    contrib_window *= scale
    return AllocationPlan(
        "timeslice", total_threads, split, frac,
        timeslice_window_s=owner_window + contrib_window,
        owner_window_s=owner_window, contrib_window_s=contrib_window,
    )


# --- Device identity --------------------------------------------------------

def get_device_id() -> str:
    """Stable per-device fingerprint (hostname + MAC).

    Deliberately excludes the PID: a changing ID defeats registry dedup (the
    original implementation re-registered the same device on every launch).
    """
    unique_string = platform.node() + str(uuid.getnode())
    return hashlib.sha256(unique_string.encode()).hexdigest()[:12]


# --- Group registry ---------------------------------------------------------

def _atomic_write_json(path: Path, data) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def register_user(
    username: str,
    device_id: str,
    group_file: str = GROUP_FILE,
    max_size: int = MAX_GROUP_SIZE,
) -> Tuple[bool, str, List[dict]]:
    """Register (username, device_id) in the group ledger.

    Returns (ok, message, members). Duplicate registrations are idempotent.
    Corrupt ledgers are preserved as ``<file>.bak`` instead of being silently
    destroyed. The write is atomic to survive concurrent launches.
    """
    path = Path(group_file)
    members: List[dict] = []
    if path.exists():
        try:
            loaded = json.loads(path.read_text())
            if isinstance(loaded, list):
                members = [m for m in loaded if isinstance(m, dict)
                           and m.get("username") and m.get("device_id")]
            else:
                raise ValueError("ledger root is not a list")
        except Exception as exc:
            backup = path.with_suffix(path.suffix + ".bak")
            try:
                backup.write_text(path.read_text())
            except OSError:
                pass
            return (
                False,
                f"Registration ledger was corrupt ({exc}); preserved as {backup.name}. "
                "Re-run to start a fresh ledger.",
                [],
            )

    for m in members:
        if m["username"] == username and m["device_id"] == device_id:
            return True, f"Already registered as '{username}' (device {device_id}).", members

    if len(members) >= max_size:
        return False, (
            f"Group is at capacity ({max_size} miners). "
            "Contact the group admin to open a slot."
        ), members

    members.append({"username": username, "device_id": device_id})
    _atomic_write_json(path, members)
    return True, (
        f"Registered '{username}' (device {device_id}). "
        f"Group size: {len(members)}/{max_size}"
    ), members


# --- Consent gate -----------------------------------------------------------

def consent_message(
    wallet: str,
    owner_wallet: Optional[str],
    donation_fraction: float,
    plan: AllocationPlan,
    pool: str,
) -> str:
    """Full informed-consent text shown before any mining starts."""
    lines = [
        "=== Hashflow mining consent ===",
        f"Pool:            {pool}",
        f"Your wallet:     {wallet[:12]}...{wallet[-6:] if len(wallet) > 18 else ''}",
    ]
    if donation_fraction > 0 and owner_wallet:
        lines += [
            f"Owner wallet:    {owner_wallet[:12]}...{owner_wallet[-6:] if len(owner_wallet) > 18 else ''}",
            f"Donation:        {donation_fraction * 100:.1f}% of compute over time",
            f"Actual split:    {plan.summary}",
        ]
    else:
        lines.append("Donation:        disabled (0%)")
    lines += [
        "",
        "Mining will use this device's CPU. It raises power use and heat, and",
        "may violate the terms of service of some hosting providers. Only run",
        "this on hardware you own or are authorized to use.",
    ]
    return "\n".join(lines)


def require_consent(
    agree_flag: bool,
    wallet: str,
    owner_wallet: Optional[str],
    donation_fraction: float,
    plan: AllocationPlan,
    pool: str,
    interactive: Optional[bool] = None,
    input_fn=input,
    print_fn=print,
) -> bool:
    """Gate mining start behind explicit, informed consent.

    * ``--agree``  -> proceed (non-interactive automation path).
    * interactive  -> print the exact split and require typing ``YES``.
    * otherwise    -> refuse, with instructions on how to consent.
    """
    if agree_flag:
        return True
    if interactive is None:
        interactive = bool(sys.stdin is not None and sys.stdin.isatty())
    message = consent_message(wallet, owner_wallet, donation_fraction, plan, pool)
    if not interactive:
        print_fn(message)
        print_fn(
            "\n[ERROR] Consent required. Re-run with --agree to confirm you have "
            "read the above and are authorized to mine on this device."
        )
        return False
    print_fn(message)
    answer = input_fn("\nType YES to start mining: ")
    return answer.strip().upper() == "YES"


# --- Owner wallet file ------------------------------------------------------

def read_owner_wallet(owner_config_path: str) -> Optional[str]:
    p = Path(owner_config_path)
    if not p.exists():
        return None
    # First non-empty, non-comment line only (files with notes must not leak
    # into the --user argument).
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    return None


# --- Run configuration ------------------------------------------------------

@dataclass
class RunConfig:
    wallet: str
    username: str
    pool: str = DEFAULT_POOL
    donation: float = DEFAULT_DONATION
    owner_wallet: Optional[str] = None
    total_threads: int = field(default_factory=lambda: os.cpu_count() or 1)
    force_mode: Optional[str] = None
    xmrig_path: Optional[str] = None
    cpu_priority: int = DEFAULT_CPU_PRIORITY

    def plan(self) -> AllocationPlan:
        return build_allocation_plan(self.total_threads, self.donation, self.force_mode)
