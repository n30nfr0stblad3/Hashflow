"""
Stats parsing and monitoring for Hashflow
Parses xmrig output for hashrate, handles smoothing, per-thread tracking
"""
import re
import time
import threading
from collections import deque, defaultdict
from typing import Dict, Deque, Optional, Tuple
from dataclasses import dataclass, field

# Regexes for hashrate parsing - improved from original
GEN_HASH_RE = re.compile(r'([\d\.]+)\s*([kKmMgGtT]?H/s)')
THREAD_HASH_RE = re.compile(r'(?:thread|thread#|thread\s+#|CPU thread\W*)(\d+).*?([\d\.]+)\s*([kKmMgGtT]?H/s)', re.IGNORECASE)
# XMRig typical patterns: "speed 10s/60s/15m 1234.5 1230.1 1225.0 H/s"
SPEED_RE = re.compile(r'speed\s+10s/60s/15m\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s*([kKmMgGtT]?H/s)?', re.IGNORECASE)
ACCEPTED_RE = re.compile(r'accepted\s+\((\d+)/\d+\)', re.IGNORECASE)
REJECTED_RE = re.compile(r'rejected\s+\((\d+)/\d+\)', re.IGNORECASE)

UNIT_MULT = {
    'H/s': 1.0,
    'kH/s': 1e3, 'kh/s': 1e3, 'KH/s': 1e3,
    'MH/s': 1e6, 'mh/s': 1e6,
    'GH/s': 1e9, 'gh/s': 1e9,
    'TH/s': 1e12, 'th/s': 1e12
}

def hr_to_float(value_str: str, unit_str: str) -> float:
    unit = unit_str.strip()
    # Normalize unit
    if unit.lower() == 'h/s':
        mult = 1.0
    else:
        mult = UNIT_MULT.get(unit, UNIT_MULT.get(unit.lower(), 1.0))
        # Also try case-insensitive
        if mult == 1.0 and unit.lower() != 'h/s':
            # Try to find matching lower
            for k, v in UNIT_MULT.items():
                if k.lower() == unit.lower():
                    mult = v
                    break
    try:
        return float(value_str) * mult
    except Exception:
        return 0.0

def format_hashrate(h: float) -> str:
    """Human readable hashrate"""
    if h >= 1e12:
        return f"{h/1e12:.2f} TH/s"
    elif h >= 1e9:
        return f"{h/1e9:.2f} GH/s"
    elif h >= 1e6:
        return f"{h/1e6:.2f} MH/s"
    elif h >= 1e3:
        return f"{h/1e3:.2f} kH/s"
    else:
        return f"{h:.2f} H/s"

@dataclass
class MinerStats:
    samples: Deque[float] = field(default_factory=lambda: deque(maxlen=8))
    per_thread: Dict[int, Deque[float]] = field(default_factory=lambda: defaultdict(lambda: deque(maxlen=8)))
    last_total: float = 0.0
    device_label: Optional[str] = None
    accepted: int = 0
    rejected: int = 0
    uptime: float = 0.0
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)

    def add_sample(self, total_hash: float):
        self.samples.append(total_hash)
        self.last_total = total_hash
        self.last_update = time.time()

    def add_thread_sample(self, thread_id: int, hash_val: float):
        self.per_thread[thread_id].append(hash_val)

    def avg_hashrate(self) -> float:
        if not self.samples:
            return 0.0
        return sum(self.samples) / len(self.samples)

    def current_hashrate(self) -> float:
        return self.last_total

    def per_thread_avg(self) -> Dict[int, float]:
        result = {}
        for tid, dq in self.per_thread.items():
            if dq:
                result[tid] = sum(dq) / len(dq)
        return result

    def to_dict(self) -> Dict:
        return {
            "current": self.current_hashrate(),
            "current_formatted": format_hashrate(self.current_hashrate()),
            "average": self.avg_hashrate(),
            "average_formatted": format_hashrate(self.avg_hashrate()),
            "per_thread": {str(k): v for k, v in self.per_thread_avg().items()},
            "per_thread_current": {str(k): (list(dq)[-1] if dq else 0) for k, dq in self.per_thread.items()},
            "accepted": self.accepted,
            "rejected": self.rejected,
            "uptime": time.time() - self.start_time,
            "uptime_formatted": self._format_uptime(),
            "last_update": self.last_update,
        }

    def _format_uptime(self) -> str:
        secs = int(time.time() - self.start_time)
        h = secs // 3600
        m = (secs % 3600) // 60
        s = secs % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

class StatsManager:
    def __init__(self, samples: int = 8):
        self.samples = samples
        self.lock = threading.Lock()
        self.miners: Dict[str, MinerStats] = {
            "contrib": MinerStats(),
            "owner": MinerStats(),
        }
        self.logs: Dict[str, Deque[str]] = {
            "contrib": deque(maxlen=200),
            "owner": deque(maxlen=200),
            "system": deque(maxlen=200),
        }

    def parse_line(self, line: str, label: str) -> Optional[float]:
        """
        Parse a single xmrig log line, update stats, return hashrate if found
        """
        line_lower = line.lower()
        hashrate = None

        # Try speed pattern first (most common in xmrig)
        speed_match = SPEED_RE.search(line)
        if speed_match:
            try:
                # 10s average is most relevant
                val_10s = float(speed_match.group(1))
                unit = speed_match.group(4) or "H/s"
                hashrate = hr_to_float(str(val_10s), unit)
            except Exception:
                pass

        # Fallback to general hash regex
        if hashrate is None:
            gen_match = GEN_HASH_RE.search(line)
            if gen_match and ("h/s" in line_lower or "hash" in line_lower):
                hashrate = hr_to_float(gen_match.group(1), gen_match.group(2))

        # Per-thread
        thread_match = THREAD_HASH_RE.search(line)
        if thread_match:
            try:
                tid = int(thread_match.group(1))
                t_hash = hr_to_float(thread_match.group(2), thread_match.group(3))
                with self.lock:
                    if label in self.miners:
                        self.miners[label].add_thread_sample(tid, t_hash)
            except Exception:
                pass

        # Accepted/rejected
        acc_match = ACCEPTED_RE.search(line)
        if acc_match:
            with self.lock:
                if label in self.miners:
                    try:
                        self.miners[label].accepted = int(acc_match.group(1))
                    except:
                        pass

        rej_match = REJECTED_RE.search(line)
        if rej_match:
            with self.lock:
                if label in self.miners:
                    try:
                        self.miners[label].rejected = int(rej_match.group(1))
                    except:
                        pass

        if hashrate is not None and hashrate > 0:
            with self.lock:
                if label in self.miners:
                    self.miners[label].add_sample(hashrate)

        # Log
        with self.lock:
            if label in self.logs:
                self.logs[label].append(line)
            else:
                self.logs["system"].append(f"[{label}] {line}")

        return hashrate

    def get_combined_stats(self) -> Dict:
        with self.lock:
            contrib = self.miners["contrib"].to_dict()
            owner = self.miners["owner"].to_dict()
            total_current = self.miners["contrib"].current_hashrate() + self.miners["owner"].current_hashrate()
            total_avg = self.miners["contrib"].avg_hashrate() + self.miners["owner"].avg_hashrate()

            return {
                "contrib": contrib,
                "owner": owner,
                "total": {
                    "current": total_current,
                    "current_formatted": format_hashrate(total_current),
                    "average": total_avg,
                    "average_formatted": format_hashrate(total_avg),
                },
                "timestamp": time.time(),
            }

    def get_logs(self, label: Optional[str] = None, limit: int = 100) -> Dict[str, list]:
        with self.lock:
            if label:
                return {label: list(self.logs.get(label, []))[-limit:]}
            else:
                return {k: list(v)[-limit:] for k, v in self.logs.items()}

    def reset(self):
        with self.lock:
            for miner in self.miners.values():
                miner.samples.clear()
                miner.per_thread.clear()
                miner.last_total = 0.0
                miner.accepted = 0
                miner.rejected = 0
                miner.start_time = time.time()
            for log_deque in self.logs.values():
                log_deque.clear()

# Global stats manager
stats_manager = StatsManager()
