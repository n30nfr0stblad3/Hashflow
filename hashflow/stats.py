"""XMRig output parsing and hashrate math. Pure functions, unit-tested."""
from __future__ import annotations

import re
from collections import deque
from typing import Deque, Dict, Optional

# "speed  10s/60s/15m 1234.5 1200.1 1100.0 H/s"  (xmrig console summary)
SPEED_LINE_RE = re.compile(
    r"speed\s+10s/60s/15m\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*([kKmMgGtT]?H/s)"
)
# Generic "4.20 kH/s" mention
GEN_HASH_RE = re.compile(r"([\d.]+)\s*([kKmMgGtT]?H/s)")
# "accepted (12/0) diff 100000 (35 ms)"
ACCEPT_RE = re.compile(r"accepted\s*\((\d+)\s*/\s*(\d+)\)")
# "cpu  #2  ..." per-thread line with a rate: "CPU thread #2  (3)  1.20 kH/s"
THREAD_HASH_RE = re.compile(
    r"thread\s*#?\s*(\d+).*?([\d.]+)\s*([kKmMgGtT]?H/s)", re.IGNORECASE
)

UNIT_MULT = {
    "h/s": 1.0, "kh/s": 1e3, "mh/s": 1e6, "gh/s": 1e9, "th/s": 1e12,
}


def hr_to_float(value_str: str, unit_str: str) -> float:
    mult = UNIT_MULT.get(unit_str.strip().lower(), 1.0)
    try:
        return float(value_str) * mult
    except (TypeError, ValueError):
        return 0.0


def fmt_hashrate(value: float) -> str:
    """Format H/s with SI prefix, e.g. 4_200_000 -> '4.20 MH/s'."""
    if value <= 0:
        return "0 H/s"
    for unit, mult in (("TH/s", 1e12), ("GH/s", 1e9), ("MH/s", 1e6), ("kH/s", 1e3)):
        if value >= mult:
            return f"{value / mult:.2f} {unit}"
    return f"{value:.0f} H/s"


def parse_xmrig_line(line: str) -> Optional[Dict]:
    """Extract telemetry from one console line, or None if nothing usable."""
    if not line:
        return None
    m = SPEED_LINE_RE.search(line)
    if m:
        v10, unit = m.group(1), m.group(4)
        return {"type": "speed", "hashrate": hr_to_float(v10, unit),
                "h60": hr_to_float(m.group(2), unit),
                "h900": hr_to_float(m.group(3), unit)}
    m = ACCEPT_RE.search(line)
    if m:
        return {"type": "share", "accepted": int(m.group(1)), "rejected": int(m.group(2))}
    m = THREAD_HASH_RE.search(line)
    if m:
        return {"type": "thread", "thread": int(m.group(1)),
                "hashrate": hr_to_float(m.group(2), m.group(3))}
    if "error" in line.lower() or "failed" in line.lower():
        return {"type": "error", "text": line.strip()}
    return None


class MovingAverage:
    """Ring-buffer average with optional exponential smoothing."""

    def __init__(self, window: int = 8):
        self.samples: Deque[float] = deque(maxlen=max(1, window))

    def add(self, value: float) -> None:
        self.samples.append(float(value))

    @property
    def avg(self) -> float:
        return sum(self.samples) / len(self.samples) if self.samples else 0.0

    def __len__(self) -> int:
        return len(self.samples)


def aggregate_hashrate(samples) -> float:
    vals = [s for s in samples if isinstance(s, (int, float)) and s > 0]
    return sum(vals) / len(vals) if vals else 0.0


def acceptance_rate(accepted: int, rejected: int) -> float:
    total = accepted + rejected
    return (accepted / total * 100.0) if total else 100.0
