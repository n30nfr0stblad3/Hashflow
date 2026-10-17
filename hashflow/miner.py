"""
Core miner wrapper for Hashflow
Manages xmrig processes, thread splitting, dual mining, and lifecycle
"""
import math
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional, List, Tuple, Callable

from .config import config
from .stats import stats_manager
from .stealth import StealthLimiter, ThermalGuard

_child_procs: List[subprocess.Popen] = []
_stop_event = threading.Event()

def find_xmrig(provided_path: Optional[str] = None) -> Optional[str]:
    if provided_path:
        xmrig_path = Path(provided_path)
        if xmrig_path.is_file() and os.access(xmrig_path, os.X_OK):
            return str(xmrig_path)
        # Try even if not executable yet
        if xmrig_path.is_file():
            return str(xmrig_path)
        return None
    # try cwd
    p = Path.cwd() / config.get("xmrig_name", "xmrig")
    if p.is_file() and os.access(p, os.X_OK):
        return str(p)
    # try config data_dir
    p2 = Path(config.get("data_dir")) / "xmrig"
    if p2.is_file() and os.access(p2, os.X_OK):
        return str(p2)
    # try PATH
    which = shutil.which(config.get("xmrig_name", "xmrig"))
    if which:
        return which
    return None

def validate_wallet_input(wallet: str) -> bool:
    """Basic Monero address validation (95 or 106 chars, starts with 4 or 8)."""
    if not wallet or len(wallet) < 90:
        return False
    if wallet[0] not in ('4', '8'):
        return False
    return True

def read_owner_wallet(owner_config_path: Optional[str] = None) -> Optional[str]:
    path_str = owner_config_path or config.get("owner_config", "owner_wallet.txt")
    # Try multiple locations
    candidates = [
        Path(path_str),
        Path.cwd() / path_str,
        Path(config.get("data_dir")) / path_str,
        Path(config.get("data_dir")) / "owner_wallet.txt",
    ]
    for p in candidates:
        if p.exists():
            try:
                text = p.read_text().strip()
                if text:
                    # Basic Monero address validation (starts with 4 or 8, length 95 or 106)
                    if len(text) >= 90 and text[0] in ('4', '8'):
                        return text
                    # Still return even if not strict
                    return text
            except Exception:
                continue
    return None

def compute_thread_split(total_threads: int, owner_fraction: float = 0.05) -> Tuple[int, int]:
    min_donation = config.get("min_donation", 0.02)
    max_donation = config.get("max_donation", 0.05)
    owner_fraction = max(min_donation, min(owner_fraction, max_donation))
    if total_threads <= 1:
        return total_threads, 0
    owner_threads = max(1, math.ceil(total_threads * owner_fraction))
    if owner_threads >= total_threads:
        owner_threads = total_threads - 1
    contrib_threads = total_threads - owner_threads
    return contrib_threads, owner_threads

def build_xmrig_cmd(xmrig_path: str, wallet: str, threads: int, donate_level: int,
                    cpu_priority: int, pool: str = None, api_port: Optional[int] = None,
                    extra_args: Optional[List[str]] = None) -> List[str]:
    pool = pool or config.get("pool")
    cmd = [
        xmrig_path,
        "--url", pool,
        "--user", wallet,
        "--pass", "x",
        "--threads", str(threads),
        "--donate-level", str(donate_level),
        "--cpu-priority", str(cpu_priority),
        "--no-color",
        "--print-time", "2",
    ]
    if api_port and api_port != 0:
        cmd += ["--api-port", str(api_port)]
    if extra_args:
        cmd += extra_args
    return cmd

class HashflowMiner:
    def __init__(self, wallet: str, owner_wallet: str, xmrig_bin: str,
                 total_threads: Optional[int] = None,
                 donation: float = 0.05,
                 pool: Optional[str] = None,
                 cpu_priority: Optional[int] = None,
                 donate_level: Optional[int] = None,
                 refresh_interval: float = 3.0,
                 stealth: bool = False,
                 limit_cpu: float = 0,
                 verbose: bool = True,
                 quiet: bool = False,
                 log_callback: Optional[Callable[[str, str], None]] = None):
        
        self.wallet = wallet
        self.owner_wallet = owner_wallet
        self.xmrig_bin = xmrig_bin
        self.total_threads = total_threads or os.cpu_count() or 4
        self.donation = max(config.get("min_donation"), min(config.get("max_donation"), donation))
        self.pool = pool or config.get("pool")
        self.cpu_priority = cpu_priority if cpu_priority is not None else config.get("cpu_priority", 3)
        self.donate_level = donate_level if donate_level is not None else config.get("donate_level", 0)
        self.refresh_interval = refresh_interval
        self.stealth = stealth
        self.limit_cpu = limit_cpu
        self.verbose = verbose and not quiet and not stealth
        self.quiet = quiet
        self.log_callback = log_callback

        self.contrib_threads, self.owner_threads = compute_thread_split(self.total_threads, self.donation)

        self.contrib_proc: Optional[subprocess.Popen] = None
        self.owner_proc: Optional[subprocess.Popen] = None
        self.stealth_limiter = StealthLimiter(cpu_limit=limit_cpu, stealth_mode=stealth, verbose=verbose)
        self.thermal_guard = ThermalGuard()
        self._stop_event = threading.Event()
        self._monitor_threads: List[threading.Thread] = []

    def _log(self, msg: str, label: str = "SYSTEM"):
        if self.quiet and label not in ("ERROR", "SYSTEM"):
            return
        if self.stealth and label not in ("ERROR",):
            # Suppress most logs in stealth
            pass
        else:
            if self.verbose:
                print(f"[{label}] {msg}")
        if self.log_callback:
            try:
                self.log_callback(msg, label)
            except Exception:
                pass

    def start(self) -> bool:
        if not self.xmrig_bin or not Path(self.xmrig_bin).exists():
            self._log(f"XMRig binary not found: {self.xmrig_bin}", "ERROR")
            return False

        contrib_cmd = build_xmrig_cmd(
            self.xmrig_bin, self.wallet, self.contrib_threads,
            self.donate_level, self.cpu_priority, pool=self.pool
        )
        owner_cmd = build_xmrig_cmd(
            self.xmrig_bin, self.owner_wallet, self.owner_threads,
            self.donate_level, self.cpu_priority, pool=self.pool
        )

        self._log(f"Total threads: {self.total_threads} | You: {self.contrib_threads} | Owner: {self.owner_threads}", "SYSTEM")
        self._log(f"Donation share: {self.donation*100:.1f}% | Pool: {self.pool}", "SYSTEM")
        if self.limit_cpu > 0:
            self._log(f"CPU Limit: {self.limit_cpu}% | Stealth: {self.stealth}", "SYSTEM")

        try:
            self.contrib_proc = subprocess.Popen(
                contrib_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=False
            )
            self.owner_proc = subprocess.Popen(
                owner_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=False
            )
            global _child_procs
            _child_procs = [self.contrib_proc, self.owner_proc]

            # Start monitoring threads
            t1 = threading.Thread(target=self._monitor, args=(self.contrib_proc, "contrib"), daemon=True)
            t2 = threading.Thread(target=self._monitor, args=(self.owner_proc, "owner"), daemon=True)
            t1.start()
            t2.start()
            self._monitor_threads = [t1, t2]

            # Start stealth monitoring if needed
            if self.limit_cpu > 0 or self.stealth:
                self.stealth_limiter.start_monitoring(
                    self.total_threads,
                    callback=self._stealth_callback
                )

            return True
        except Exception as e:
            self._log(f"Failed to start miners: {e}", "ERROR")
            return False

    def _stealth_callback(self, sys_cpu: float, delay: float, factor: float):
        if delay > 0.5 and self.verbose:
            self._log(f"CPU {sys_cpu:.1f}% > limit {self.limit_cpu}% | Delay {delay:.2f}s x{factor:.2f}", "STEALTH")
        # Check thermal
        overheating, temp = self.thermal_guard.is_overheating()
        if overheating:
            self._log(f"Thermal throttling: {temp:.1f}°C > {self.thermal_guard.max_temp}°C - pausing", "THERMAL")
            time.sleep(2.0)

    def _monitor(self, proc: subprocess.Popen, label: str):
        try:
            for line in iter(proc.stdout.readline, b''):
                if self._stop_event.is_set():
                    break
                try:
                    line_str = line.decode('utf-8', errors='ignore').strip()
                except Exception:
                    continue
                if not line_str:
                    continue

                # Parse stats
                stats_manager.parse_line(line_str, label)

                # Apply stealth throttling logic to logging (not to actual mining, which is limited via CPU limiter)
                if not self.quiet:
                    if not self.stealth or "accepted" in line_str.lower() or "error" in line_str.lower():
                        self._log(line_str, label.upper())

                # Adaptive delay for refresh in stealth mode
                if self.stealth:
                    # Random small delay to avoid pattern detection
                    if len(stats_manager.logs[label]) % 10 == 0:
                        time.sleep(self.stealth_limiter.get_refresh_interval(0.1))

                # Check if CPU limit requires throttling via nice/renice or pause
                if self.limit_cpu > 0 and self.stealth_limiter.should_throttle(stats_manager.miners[label].current_hashrate()):
                    # For actual CPU limiting, we use psutil to lower process priority temporarily
                    try:
                        import psutil
                        p = psutil.Process(proc.pid)
                        # Lower priority when over limit
                        if self.stealth_limiter._current_delay > 1.0:
                            p.nice(10)  # lower priority
                        else:
                            p.nice(0)
                    except Exception:
                        pass
        except Exception as e:
            self._log(f"Monitor for {label} exited: {e}", "ERROR")

    def stop(self):
        self._log("Shutting down miners...", "SYSTEM")
        self._stop_event.set()
        self.stealth_limiter.stop_monitoring()
        for proc in [self.contrib_proc, self.owner_proc]:
            if proc:
                try:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                except Exception:
                    pass
        self.contrib_proc = None
        self.owner_proc = None
        self._log("Miners stopped", "SYSTEM")

    def is_running(self) -> bool:
        return (self.contrib_proc and self.contrib_proc.poll() is None) or \
               (self.owner_proc and self.owner_proc.poll() is None)

    def wait(self):
        try:
            while self.is_running() and not self._stop_event.is_set():
                time.sleep(self.stealth_limiter.get_refresh_interval(self.refresh_interval))
        except KeyboardInterrupt:
            self.stop()

    def get_status(self) -> dict:
        stats = stats_manager.get_combined_stats()
        stealth_status = self.stealth_limiter.get_stealth_status()
        overheating, temp = self.thermal_guard.is_overheating()
        return {
            "running": self.is_running(),
            "threads": {
                "total": self.total_threads,
                "contrib": self.contrib_threads,
                "owner": self.owner_threads,
            },
            "donation": self.donation,
            "pool": self.pool,
            "stats": stats,
            "stealth": stealth_status,
            "thermal": {
                "overheating": overheating,
                "temperature": temp,
                "max_temp": self.thermal_guard.max_temp,
            },
            "xmrig": self.xmrig_bin,
        }

# Signal handling helper
def setup_signal_handlers(miner: HashflowMiner):
    def shutdown(signum, frame):
        print("\nExiting, terminating miners.")
        miner.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
