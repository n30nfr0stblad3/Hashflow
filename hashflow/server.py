"""Hashflow Fleet Command server.

Zero-dependency HTTP server (stdlib only) exposing:
  * REST API   - /api/health /api/fleet /api/metrics /api/series /api/alerts
                /api/executive /api/risk  /api/actions/* 
  * SSE stream - /api/stream  (live ticks for the dashboard)
  * Static PWA - the web/ directory (dashboard, manifest, service worker)

Modes:
  * --demo (default) - deterministic simulated fleet, runs anywhere instantly
  * --live           - supervises a real xmrig for this host

Run:  python3 -m hashflow.server --demo --port 8765
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import queue
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from . import __version__
from .simulator import SimulatorFleet, risk_matrix_items

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
TICK_S = 2.0


# ----------------------------------------------------------------- live model

class LiveFleet:
    """Adapter that turns Supervisor events into the dashboard data shape."""

    def __init__(self, supervisor=None, hostname: str = "local"):
        self.supervisor = supervisor
        self.hostname = hostname
        self.started = time.time()
        self.hashrate = 0.0
        self.accepted = 0
        self.rejected = 0
        self.alerts: List[Dict] = []
        self.series: Dict[str, List] = {"hashrate": [], "power": [],
                                        "temp": [], "accepted": []}
        self._seq = 0

    def on_event(self, kind: str, data: Dict) -> None:
        if kind == "speed":
            self.hashrate = float(data.get("hashrate", 0.0))
        elif kind == "share":
            self.accepted = int(data.get("accepted", 0))
            self.rejected = int(data.get("rejected", 0))
        elif kind in ("proc_exit", "proc_failed", "error"):
            self._seq += 1
            self.alerts.append({
                "id": f"alert-{self._seq:05d}", "severity": "critical",
                "code": kind.upper(), "title": "Miner process event",
                "detail": json.dumps(data), "device": self.hostname,
                "zone": "Local", "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                     time.gmtime()),
                "ack": False,
            })

    def tick(self) -> Dict:
        for key, val in (("hashrate", self.hashrate),
                         ("power", self.hashrate / 1e3 * 300.0),
                         ("temp", 0.0), ("accepted", self.accepted)):
            self.series[key].append(val)
            del self.series[key][:-600]
        return self.snapshot()

    def ack_alert(self, alert_id: str) -> bool:
        for a in self.alerts:
            if a["id"] == alert_id:
                a["ack"] = True
                return True
        return False

    def emergency_stop(self) -> None:
        if self.supervisor:
            self.supervisor.stop()

    def snapshot(self) -> Dict:
        up = int(time.time() - self.started)
        metrics = {
            "hashrate_10s": self.hashrate,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "stale": 0,
            "acceptance_pct": (self.accepted / max(1, self.accepted + self.rejected) * 100),
            "active_workers": 1,
            "total_workers": 1,
            "avg_temp": 0.0,
            "total_power_w": self.hashrate / 1e3 * 300.0,
            "efficiency_hs_per_w": 0.0,
            "health_avg": 100.0,
            "throttled": 0,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        fleet = [{
            "id": "local-01", "name": self.hostname, "zone": "Local",
            "site": "This device", "status": "online",
            "hashrate": self.hashrate, "temp_c": 0.0, "fan_pct": 0.0,
            "power_w": metrics["total_power_w"], "uptime_s": up,
            "accepted": self.accepted, "rejected": self.rejected, "stale": 0,
            "throttled": False, "health": 100.0, "utilization": 1.0,
            "threads": os.cpu_count() or 1, "trend": list(self.series["hashrate"][-30:]),
            "last_seen": metrics["timestamp"],
        }]
        return {
            "metrics": metrics, "fleet": fleet,
            "alerts": list(self.alerts[-50:]), "series": dict(self.series),
            "executive": {"xmr_price_usd": 165.0, "xmr_per_day": self.hashrate / 1e3 * 1.1e-5,
                          "revenue_usd_day": 0.0, "energy_kwh_day": 0.0,
                          "energy_cost_usd_day": 0.0, "gross_margin_pct": 0.0,
                          "efficiency_hs_per_w": 0.0, "energy_per_mhash_j": 0.0,
                          "carbon_kg_day": 0.0, "donation_xmr_day": 0.0,
                          "target_hashrate": 0.0, "pct_of_target": 0.0,
                          "uptime_pct": 100.0},
            "ts": metrics["timestamp"],
        }


# ------------------------------------------------------------------ broadcast

class Broadcaster:
    """Fan-out of JSON ticks to SSE subscribers."""

    def __init__(self) -> None:
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=16)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, payload: Dict) -> None:
        data = json.dumps(payload)
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(data)
            except queue.Full:
                pass  # slow client: drop tick, next one will refresh state


# -------------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"Hashflow/{__version__}"
    model = None            # injected by make_server
    broadcaster = None      # injected by make_server
    verbose = False

    # -- plumbing -----------------------------------------------------------
    def log_message(self, fmt, *args):  # noqa: A003
        if self.verbose:
            sys.stderr.write("[http] " + fmt % args + "\n")

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode() or "{}")
        except Exception:
            return {}

    # -- routing ------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/health":
            return self._json({"status": "ok", "version": __version__,
                               "mode": getattr(self.model, "mode", "demo"),
                               "uptime_s": int(time.time() - self.server.start_time)})
        if path == "/api/snapshot":
            return self._json(self.model.snapshot())
        if path == "/api/fleet":
            return self._json(self.model.snapshot()["fleet"])
        if path == "/api/metrics":
            return self._json(self.model.snapshot()["metrics"])
        if path == "/api/series":
            return self._json(self.model.snapshot()["series"])
        if path == "/api/alerts":
            return self._json(self.model.snapshot()["alerts"])
        if path == "/api/executive":
            return self._json(self.model.snapshot()["executive"])
        if path == "/api/risk":
            snap = self.model.snapshot()
            return self._json(risk_matrix_items(snap["alerts"], snap["fleet"]))
        if path == "/api/stream":
            return self._stream()
        return self._static(path)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        body = self._read_json_body()
        if path == "/api/alerts/ack":
            ok = self.model.ack_alert(str(body.get("id", "")))
            return self._json({"ok": ok}, 200 if ok else 404)
        if path == "/api/actions/emergency-stop":
            if body.get("confirm") != "STOP":
                return self._json({"ok": False,
                                   "error": "Send {\"confirm\":\"STOP\"} to confirm."}, 400)
            self.model.emergency_stop()
            return self._json({"ok": True})
        return self._json({"ok": False, "error": "unknown endpoint"}, 404)

    # -- SSE ----------------------------------------------------------------
    def _stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self._cors()
        self.end_headers()
        q = self.broadcaster.subscribe()
        try:
            # Initial full snapshot so clients render instantly.
            self.wfile.write(b"event: snapshot\ndata: "
                             + json.dumps(self.model.snapshot()).encode()
                             + b"\n\n")
            self.wfile.flush()
            while True:
                try:
                    data = q.get(timeout=15.0)
                    self.wfile.write(b"event: tick\ndata: " + data.encode() + b"\n\n")
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.broadcaster.unsubscribe(q)

    # -- static files -------------------------------------------------------
    def _static(self, path: str) -> None:
        if path in ("/", ""):
            path = "/index.html"
        target = (WEB_ROOT / path.lstrip("/")).resolve()
        if not str(target).startswith(str(WEB_ROOT.resolve())) or not target.is_file():
            return self._json({"error": "not found"}, 404)
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if target.name == "sw.js":
            self.send_header("Service-Worker-Allowed", "/")
            self.send_header("Cache-Control", "no-cache")
        elif target.suffix == ".html":
            self.send_header("Cache-Control", "no-cache")
        else:
            self.send_header("Cache-Control", "max-age=3600")
        self._cors()
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------------- entry

class HashflowServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, model, broadcaster):
        super().__init__(addr, handler)
        self.model = model
        self.broadcaster = broadcaster
        self.start_time = time.time()


def make_server(host: str, port: int, model, verbose: bool = False) -> HashflowServer:
    broadcaster = Broadcaster()
    Handler.model = model
    Handler.broadcaster = broadcaster
    Handler.verbose = verbose
    server = HashflowServer((host, port), Handler, model, broadcaster)

    def ticker() -> None:
        while True:
            try:
                snap = model.tick()
                broadcaster.publish(snap)
            except Exception as exc:  # keep the stream alive whatever happens
                sys.stderr.write(f"[tick] {exc}\n")
            time.sleep(TICK_S)

    threading.Thread(target=ticker, daemon=True).start()
    return server


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Hashflow Fleet Command server")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default: all)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--demo", action="store_true", default=True,
                    help="Simulated fleet (default; zero setup)")
    ap.add_argument("--live", action="store_true",
                    help="Supervise a real xmrig on this host")
    ap.add_argument("--seed", type=int, default=1337, help="Demo fleet seed")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.live:
        from .supervisor import Supervisor, find_xmrig
        from .core import RunConfig, read_owner_wallet, build_allocation_plan
        wallet = os.environ.get("HASHFLOW_WALLET", "")
        if not wallet:
            print("[ERROR] --live requires HASHFLOW_WALLET (or use --demo).")
            return 2
        xmrig = find_xmrig(os.environ.get("HASHFLOW_XMRIG"))
        if not xmrig:
            print("[ERROR] xmrig binary not found. Run scripts/fetch_xmrig.py first.")
            return 2
        owner_wallet = read_owner_wallet(os.environ.get("HASHFLOW_OWNER_CONFIG",
                                                        "owner_wallet.txt"))
        plan = build_allocation_plan(os.cpu_count() or 1,
                                    float(os.environ.get("HASHFLOW_DONATION", "0.05")))
        model = LiveFleet(hostname=socket.gethostname())
        sup = Supervisor(xmrig, plan, wallet, owner_wallet,
                         os.environ.get("HASHFLOW_POOL", "pool.supportxmr.com:3333"),
                         on_event=model.on_event)
        model.supervisor = sup
        threading.Thread(target=sup.run, daemon=True).start()
    else:
        model = SimulatorFleet(seed=args.seed)
        model.mode = "demo"

    server = make_server(args.host, args.port, model, args.verbose)
    print(f"Hashflow Fleet Command v{__version__} "
          f"({'LIVE' if args.live else 'DEMO'} mode)")
    print(f"  Dashboard: http://localhost:{args.port}/")
    print(f"  API:       http://localhost:{args.port}/api/health")

    def _sig(_s, _f):
        print("\nShutting down...")
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)
    except (AttributeError, ValueError):  # restricted environments
        pass
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
