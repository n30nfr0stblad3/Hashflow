"""Cross-platform miner process supervision.

Handles both allocation modes:
  * ``threads``   - two concurrent xmrig instances (contributor + owner)
  * ``timeslice`` - one xmrig, wallet rotation over time windows (exact share)
  * ``solo``      - one xmrig, contributor only

Safe on Windows/macOS/Linux: signal handling is guarded, termination uses
terminate()->wait()->kill() escalation, and child exit codes are surfaced
instead of failing silently (a review finding in the original script).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .core import DEFAULT_CPU_PRIORITY, DEFAULT_DONATE_LEVEL, AllocationPlan
from .stats import parse_xmrig_line

EventCallback = Callable[[str, Dict], None]

DEFAULT_XMRIG_NAME = "xmrig"


def find_xmrig(provided_path: Optional[str] = None) -> Optional[str]:
    """Locate the xmrig binary: explicit path, cwd, then PATH."""
    if provided_path:
        p = Path(provided_path)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        return None
    p = Path.cwd() / DEFAULT_XMRIG_NAME
    if p.is_file() and os.access(p, os.X_OK):  # os.X_OK (was os.XMRIG_NAME: crash)
        return str(p)
    return shutil.which(DEFAULT_XMRIG_NAME)


def build_xmrig_cmd(
    xmrig_path: str,
    wallet: str,
    threads: int,
    pool: str,
    cpu_priority: int = DEFAULT_CPU_PRIORITY,
    api_port: Optional[int] = None,
) -> List[str]:
    cmd = [
        xmrig_path,
        "--url", pool,
        "--user", wallet,
        "--pass", "x",
        "--threads", str(max(1, threads)),
        "--donate-level", str(DEFAULT_DONATE_LEVEL),
        "--cpu-priority", str(cpu_priority),
    ]
    if api_port:
        cmd += ["--http-port", str(api_port)]
    return cmd


@dataclass
class MinerProcess:
    """One supervised xmrig child process."""
    label: str            # 'contrib' | 'owner'
    cmd: List[str]
    on_event: EventCallback
    proc: Optional[subprocess.Popen] = None
    reader: Optional[threading.Thread] = None
    restarts: int = 0
    last_exit_code: Optional[int] = None
    _stopping: bool = False

    def start(self) -> None:
        self._stopping = False
        self.proc = subprocess.Popen(
            self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        self.on_event("proc_start", {"label": self.label, "pid": self.proc.pid,
                                     "cmd": self.cmd})

    def _read_loop(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for raw in iter(self.proc.stdout.readline, b""):
            try:
                line = raw.decode(errors="replace").strip()
            except Exception:
                continue
            if not line:
                continue
            parsed = parse_xmrig_line(line)
            if parsed:
                parsed["label"] = self.label
                self.on_event(parsed.get("type", "log"), parsed)
            else:
                self.on_event("log", {"label": self.label, "text": line})
        self.last_exit_code = self.proc.poll()
        if not self._stopping:
            self.on_event("proc_exit", {"label": self.label,
                                        "code": self.last_exit_code,
                                        "restarts": self.restarts})

    def stop(self, grace_s: float = 5.0) -> None:
        self._stopping = True
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=grace_s)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            try:
                self.proc.wait(timeout=grace_s)
            except subprocess.TimeoutExpired:
                pass

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


class Supervisor:
    """Runs the allocation plan and relaunches crashed miners with backoff."""

    MAX_RESTARTS = 5

    def __init__(
        self,
        xmrig_path: str,
        plan: AllocationPlan,
        contrib_wallet: str,
        owner_wallet: Optional[str],
        pool: str,
        cpu_priority: int = DEFAULT_CPU_PRIORITY,
        on_event: Optional[EventCallback] = None,
    ):
        self.xmrig_path = xmrig_path
        self.plan = plan
        self.contrib_wallet = contrib_wallet
        self.owner_wallet = owner_wallet
        self.pool = pool
        self.cpu_priority = cpu_priority
        self.on_event = on_event or (lambda kind, data: None)
        self.stop_event = threading.Event()
        self.procs: List[MinerProcess] = []
        self._threads: List[threading.Thread] = []

    # -- helpers -------------------------------------------------------------
    def _make_proc(self, label: str, wallet: str) -> MinerProcess:
        return MinerProcess(
            label=label,
            cmd=build_xmrig_cmd(self.xmrig_path, wallet,
                                self.plan.total_threads, self.pool,
                                self.cpu_priority),
            on_event=self.on_event,
        )

    def _run_window(self, label: str, wallet: str, seconds: float) -> None:
        """Run one wallet for *seconds*, restarting on crash with backoff."""
        proc = self._make_proc(label, wallet)
        self.procs.append(proc)
        proc.start()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not self.stop_event.is_set():
            time.sleep(0.5)
            if not proc.alive:
                if proc.restarts >= self.MAX_RESTARTS:
                    self.on_event("proc_failed", {"label": label,
                                                  "code": proc.last_exit_code})
                    return
                proc.restarts += 1
                backoff = min(30.0, 2.0 ** proc.restarts)
                self.on_event("proc_restart", {"label": label,
                                               "in_s": backoff,
                                               "count": proc.restarts})
                if self.stop_event.wait(backoff):
                    return
                proc.start()
        proc.stop()

    # -- main loops ----------------------------------------------------------
    def run(self) -> None:
        """Blocking run; returns when stop() is called or windows finish."""
        mode = self.plan.mode
        if mode == "threads":
            self._run_threads()
        elif mode == "timeslice":
            self._run_timeslice()
        else:  # solo
            self._run_window("contrib", self.contrib_wallet, float("inf"))

    def _run_threads(self) -> None:
        assert self.plan.split.owner_threads >= 1
        contrib = MinerProcess(
            "contrib",
            build_xmrig_cmd(self.xmrig_path, self.contrib_wallet,
                            self.plan.split.contrib_threads, self.pool,
                            self.cpu_priority),
            self.on_event,
        )
        owner = MinerProcess(
            "owner",
            build_xmrig_cmd(self.xmrig_path, self.owner_wallet or "",
                            self.plan.split.owner_threads, self.pool,
                            self.cpu_priority),
            self.on_event,
        )
        self.procs = [contrib, owner]
        for p in self.procs:
            p.start()
        try:
            while not self.stop_event.wait(1.0):
                pass
        finally:
            for p in self.procs:
                p.stop()

    def _run_timeslice(self) -> None:
        # Rotation stops immediately if the owner share is zero.
        while not self.stop_event.is_set():
            self._run_window("contrib", self.contrib_wallet,
                             self.plan.contrib_window_s)
            if self.stop_event.is_set():
                break
            if self.plan.owner_window_s > 0 and self.owner_wallet:
                self._run_window("owner", self.owner_wallet,
                                 self.plan.owner_window_s)

    def stop(self) -> None:
        self.stop_event.set()
        for p in self.procs:
            p.stop()
