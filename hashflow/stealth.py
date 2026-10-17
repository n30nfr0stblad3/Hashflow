"""
Stealth Limiter Module for Hashflow
- CPU usage capping with adaptive delay logic
- Randomized refresh intervals to avoid detection
- Thermal throttling awareness
- Compatible with Termux and VPS
"""
import time
import random
import threading
import os
from typing import Optional, Tuple
import psutil

class StealthLimiter:
    """
    CPU limiter that monitors process CPU usage and injects adaptive delays
    to keep usage under a configured cap.
    """
    def __init__(self, cpu_limit: float = 0, stealth_mode: bool = False, verbose: bool = True):
        """
        :param cpu_limit: Max CPU % (0 = no limit, 1-100). e.g. 30 means 30% cap
        :param stealth_mode: If True, randomizes intervals and suppresses output
        :param verbose: Whether to print debug info
        """
        self.cpu_limit = max(0, min(100, cpu_limit)) if cpu_limit else 0
        self.stealth_mode = stealth_mode
        self.verbose = verbose and not stealth_mode
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._current_delay = 0.0
        self._adaptive_factor = 1.0

    def _log(self, msg: str):
        if self.verbose:
            print(f"[STEALTH] {msg}")

    def get_system_cpu(self) -> float:
        """Get current system-wide CPU usage"""
        try:
            return psutil.cpu_percent(interval=0.5)
        except Exception:
            return 0.0

    def get_process_cpu(self, pid: Optional[int] = None) -> float:
        """Get CPU usage for a specific process or current process"""
        try:
            if pid:
                proc = psutil.Process(pid)
                return proc.cpu_percent(interval=0.5)
            else:
                return psutil.Process().cpu_percent(interval=0.5)
        except Exception:
            return 0.0

    def calculate_adaptive_delay(self, current_cpu: float, thread_count: int) -> float:
        """
        Adaptive delay logic based on:
        - How far over the limit we are
        - Thread count (more threads = need more aggressive throttling)
        - System load
        """
        if self.cpu_limit == 0:
            return 0.0

        if current_cpu <= self.cpu_limit:
            # Gradually reduce delay if under limit
            self._adaptive_factor = max(0.5, self._adaptive_factor * 0.95)
            self._current_delay = max(0, self._current_delay * 0.8)
            return self._current_delay

        # Over limit - increase delay
        overage = current_cpu - self.cpu_limit
        # Base delay proportional to overage
        base_delay = (overage / 100.0) * 2.0  # 0-2 seconds range
        
        # Thread factor: more threads = higher delay needed
        thread_factor = 1.0 + (thread_count / 10.0) * 0.3
        
        # Adaptive factor grows when consistently over limit
        self._adaptive_factor = min(3.0, self._adaptive_factor * 1.05)
        
        delay = base_delay * thread_factor * self._adaptive_factor
        
        # Add jitter in stealth mode
        if self.stealth_mode:
            jitter = random.uniform(-0.2, 0.4)
            delay = max(0, delay + jitter)
        
        self._current_delay = delay
        return delay

    def get_refresh_interval(self, base_interval: float = 3.0) -> float:
        """
        Returns refresh interval, randomized if in stealth mode
        """
        if not self.stealth_mode:
            return base_interval
        
        # Randomize between 70% and 170% of base
        randomized = base_interval * random.uniform(0.7, 1.7)
        # Occasionally add longer pause to mimic human/idle behavior
        if random.random() < 0.1:  # 10% chance
            randomized += random.uniform(1.0, 3.0)
        return randomized

    def should_throttle(self, current_cpu: float) -> bool:
        if self.cpu_limit == 0:
            return False
        return current_cpu > self.cpu_limit

    def throttle(self, delay: Optional[float] = None):
        """Apply throttle delay"""
        d = delay if delay is not None else self._current_delay
        if d > 0:
            if self.verbose:
                self._log(f"Throttling for {d:.2f}s (limit: {self.cpu_limit}%)")
            time.sleep(d)

    def monitor_loop(self, thread_count: int, callback=None):
        """Background monitoring loop"""
        self._log(f"Stealth monitor started - Limit: {self.cpu_limit}%, Threads: {thread_count}, Stealth: {self.stealth_mode}")
        while not self._stop_event.is_set():
            try:
                sys_cpu = self.get_system_cpu()
                delay = self.calculate_adaptive_delay(sys_cpu, thread_count)
                
                if callback:
                    callback(sys_cpu, delay, self._adaptive_factor)
                
                if delay > 0:
                    # Sleep with adaptive delay
                    time.sleep(min(delay, 2.0))
                else:
                    # Normal poll interval
                    interval = self.get_refresh_interval(1.5)
                    time.sleep(interval)
            except Exception as e:
                if self.verbose:
                    self._log(f"Monitor error: {e}")
                time.sleep(1.0)

    def start_monitoring(self, thread_count: int, callback=None):
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self.monitor_loop,
            args=(thread_count, callback),
            daemon=True
        )
        self._monitor_thread.start()

    def stop_monitoring(self):
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)

    def get_stealth_status(self) -> dict:
        return {
            "enabled": self.cpu_limit > 0 or self.stealth_mode,
            "cpu_limit": self.cpu_limit,
            "stealth_mode": self.stealth_mode,
            "current_delay": self._current_delay,
            "adaptive_factor": self._adaptive_factor,
            "system_cpu": self.get_system_cpu(),
        }

class ThermalGuard:
    """
    Additional protection for mobile devices - monitors temperature if available
    """
    def __init__(self, max_temp: float = 75.0):
        self.max_temp = max_temp

    def get_temps(self):
        try:
            temps = psutil.sensors_temperatures()
            if not temps:
                return None
            # Get average of all temps
            all_temps = []
            for name, entries in temps.items():
                for entry in entries:
                    if entry.current:
                        all_temps.append(entry.current)
            return sum(all_temps) / len(all_temps) if all_temps else None
        except Exception:
            # Try reading from thermal zone (Linux/Termux)
            try:
                thermal_path = "/sys/class/thermal/thermal_zone0/temp"
                if os.path.exists(thermal_path):
                    with open(thermal_path, 'r') as f:
                        return float(f.read().strip()) / 1000.0
            except Exception:
                pass
            return None

    def is_overheating(self) -> Tuple[bool, Optional[float]]:
        temp = self.get_temps()
        if temp is None:
            return False, None
        return temp > self.max_temp, temp
