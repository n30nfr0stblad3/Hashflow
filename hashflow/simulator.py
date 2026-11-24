"""Deterministic demo fleet simulator.

Lets the entire dashboard run with zero setup on any device ("demo mode"),
and doubles as a deterministic fixture source for tests. Same output shape as
the live collector so the UI has a single code path.
"""
from __future__ import annotations

import math
import random
import time
from collections import deque
from typing import Deque, Dict, List, Optional

ZONES = [
    ("Zone Alpha", "North Cluster"),
    ("Zone Beta", "North Cluster"),
    ("Zone Gamma", "South Cluster"),
]
NAME_PREFIX = ["RIG-ALPHA", "RIG-BETA", "RIG-GAMMA"]
STATUSES = ("online", "online", "online", "online", "degraded", "maintenance")

SERIES_MAXLEN = 600  # 2s cadence -> 20 minutes of fine history


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class SimulatorFleet:
    """Seeded pseudo-fleet: 24 workers across 3 zones with live-ish telemetry."""

    def __init__(self, n_devices: int = 24, seed: int = 1337,
                 xmr_price_usd: float = 165.0, energy_price_kwh: float = 0.12):
        self.rng = random.Random(seed)
        self.xmr_price_usd = xmr_price_usd
        self.energy_price_kwh = energy_price_kwh
        self.devices: List[Dict] = []
        self.alerts: List[Dict] = []
        self.series: Dict[str, Deque] = {
            "hashrate": deque(maxlen=SERIES_MAXLEN),
            "power": deque(maxlen=SERIES_MAXLEN),
            "temp": deque(maxlen=SERIES_MAXLEN),
            "accepted": deque(maxlen=SERIES_MAXLEN),
        }
        self._alert_seq = 0
        self._tick = 0
        self._init_devices(n_devices)
        self.tick()  # prime the series with one sample

    # ------------------------------------------------------------------ init
    def _init_devices(self, n: int) -> None:
        for i in range(n):
            zone_idx = i % len(ZONES)
            zone, site = ZONES[zone_idx]
            base_hr = self.rng.uniform(800.0, 4200.0) * 1e3  # 0.8-4.2 kH/s * 1e3
            self.devices.append({
                "id": f"dev-{i + 1:02d}",
                "name": f"{NAME_PREFIX[zone_idx]}-{i // 3 + 1:02d}",
                "zone": zone,
                "site": site,
                "status": "online",
                "hashrate": base_hr,
                "base_hr": base_hr,
                "temp_c": self.rng.uniform(48.0, 72.0),
                "fan_pct": self.rng.uniform(35.0, 75.0),
                "power_w": base_hr / 1e3 * self.rng.uniform(11.0, 15.0),
                "uptime_s": int(self.rng.uniform(3_600, 900_000)),
                "accepted": self.rng.randint(400, 2400),
                "rejected": self.rng.randint(0, 6),
                "stale": self.rng.randint(0, 2),
                "throttled": False,
                "health": self.rng.uniform(88.0, 99.0),
                "utilization": self.rng.uniform(0.72, 0.98),
                "threads": self.rng.choice([4, 6, 8, 8, 12, 16]),
                "trend": deque(maxlen=30),
                "last_seen": _now_iso(),
            })

    # ------------------------------------------------------------------ tick
    def tick(self) -> Dict:
        """Advance one step (~2s of simulated time) and return a snapshot."""
        self._tick += 1
        rng = self.rng
        for d in self.devices:
            if d["status"] == "offline":
                if rng.random() < 0.05:
                    d["status"] = "online"
                    self._push_alert("info", "DEVICE_RECOVERED",
                                     f"{d['name']} is back online", d)
                else:
                    continue
            # Random-walk hashrate (mean-reverting to base)
            drift = (d["base_hr"] - d["hashrate"]) * 0.05
            d["hashrate"] = max(50.0, d["hashrate"] + drift + rng.gauss(0, d["base_hr"] * 0.02))
            if d["status"] == "degraded":
                d["hashrate"] *= 0.55
            # Thermal model: temp chases load, with noise
            target_temp = 42.0 + d["utilization"] * 38.0 + (12.0 if d["throttled"] else 0.0)
            d["temp_c"] += (target_temp - d["temp_c"]) * 0.08 + rng.gauss(0, 0.6)
            d["temp_c"] = max(30.0, min(99.0, d["temp_c"]))
            d["fan_pct"] = max(20.0, min(100.0, (d["temp_c"] - 35.0) * 1.6 + rng.gauss(0, 2)))
            d["power_w"] = max(20.0, d["hashrate"] / 1e3 * 12.5 + rng.gauss(0, 3))
            d["uptime_s"] += 2
            d["utilization"] = max(0.3, min(1.0, d["utilization"] + rng.gauss(0, 0.008)))
            d["trend"].append(d["hashrate"])
            d["last_seen"] = _now_iso()

            # Shares accrue ~ proportional to hashrate
            d["accepted"] += 1 if rng.random() < 0.82 else 0
            if rng.random() < 0.006:
                d["rejected"] += 1

            # State transitions / events
            r = rng.random()
            if r < 0.002:
                d["status"] = "offline"
                self._push_alert("critical", "DEVICE_OFFLINE",
                                 f"{d['name']} stopped reporting", d)
            elif d["temp_c"] > 86.0 and not d["throttled"]:
                d["throttled"] = True
                self._push_alert("warning", "THERMAL_THROTTLE",
                                 f"{d['name']} thermal throttling at {d['temp_c']:.0f}C", d)
            elif d["throttled"] and d["temp_c"] < 78.0:
                d["throttled"] = False
            elif d["rejected"] > 0 and rng.random() < 0.001:
                self._push_alert("warning", "HIGH_REJECTS",
                                 f"{d['name']} elevated share rejects", d)
            # Health is a composite: temp stability + rejects + uptime
            d["health"] = max(35.0, min(99.5,
                d["health"] * 0.995
                + (0.05 * (95.0 - max(0.0, d["temp_c"] - 70.0) * 2.0))
                - (0.4 if d["throttled"] else 0.0)))

        agg = self._aggregate()
        for key, val in (("hashrate", agg["hashrate_10s"]),
                         ("power", agg["total_power_w"]),
                         ("temp", agg["avg_temp"]),
                         ("accepted", agg["accepted"])):
            self.series[key].append(val)
        return self.snapshot()

    # ------------------------------------------------------------- aggregate
    def _aggregate(self) -> Dict:
        online = [d for d in self.devices if d["status"] in ("online", "degraded")]
        total_hr = sum(d["hashrate"] for d in online)
        accepted = sum(d["accepted"] for d in self.devices)
        rejected = sum(d["rejected"] for d in self.devices)
        total_power = sum(d["power_w"] for d in online)
        avg_temp = (sum(d["temp_c"] for d in online) / len(online)) if online else 0.0
        return {
            "hashrate_10s": total_hr,
            "accepted": accepted,
            "rejected": rejected,
            "stale": sum(d["stale"] for d in self.devices),
            "acceptance_pct": (accepted / (accepted + rejected) * 100.0)
                              if (accepted + rejected) else 100.0,
            "active_workers": len(online),
            "total_workers": len(self.devices),
            "avg_temp": avg_temp,
            "total_power_w": total_power,
            "efficiency_hs_per_w": (total_hr / total_power) if total_power else 0.0,
            "health_avg": (sum(d["health"] for d in self.devices) / len(self.devices))
                          if self.devices else 0.0,
            "throttled": sum(1 for d in self.devices if d["throttled"]),
            "timestamp": _now_iso(),
        }

    # ---------------------------------------------------------------- alerts
    def _push_alert(self, severity: str, code: str, detail: str, device: Dict) -> None:
        self._alert_seq += 1
        self.alerts.append({
            "id": f"alert-{self._alert_seq:05d}",
            "severity": severity,
            "code": code,
            "title": code.replace("_", " ").title(),
            "detail": detail,
            "device": device["name"],
            "zone": device["zone"],
            "ts": _now_iso(),
            "ack": False,
        })
        # Keep the most recent 200 alerts
        del self.alerts[:-200]

    def ack_alert(self, alert_id: str) -> bool:
        for a in self.alerts:
            if a["id"] == alert_id:
                a["ack"] = True
                return True
        return False

    def emergency_stop(self) -> None:
        for d in self.devices:
            d["status"] = "maintenance" if d["status"] != "offline" else d["status"]
        self._push_alert("critical", "EMERGENCY_STOP",
                         "Operator issued fleet-wide emergency stop",
                         {"name": "FLEET", "zone": "All"})

    # ------------------------------------------------------------- snapshot
    def _executive(self, metrics: Dict) -> Dict:
        # XMR/day estimate: rough network-normalized constant for demo purposes.
        xmr_per_day = metrics["hashrate_10s"] / 1e3 * 1.1e-5
        kwh_day = metrics["total_power_w"] / 1000.0 * 24.0
        revenue = xmr_per_day * self.xmr_price_usd
        energy_cost = kwh_day * self.energy_price_kwh
        donation_xmr = xmr_per_day * 0.05
        return {
            "xmr_price_usd": self.xmr_price_usd,
            "xmr_per_day": xmr_per_day,
            "revenue_usd_day": revenue,
            "energy_kwh_day": kwh_day,
            "energy_cost_usd_day": energy_cost,
            "gross_margin_pct": ((revenue - energy_cost) / revenue * 100.0) if revenue else 0.0,
            "efficiency_hs_per_w": metrics["efficiency_hs_per_w"],
            "energy_per_mhash_j": (metrics["total_power_w"] / (metrics["hashrate_10s"] / 1e6)
                                   if metrics["hashrate_10s"] else 0.0),
            "carbon_kg_day": kwh_day * 0.417,
            "donation_xmr_day": donation_xmr,
            "target_hashrate": 75e6,
            "pct_of_target": metrics["hashrate_10s"] / 75e6 * 100.0,
            "uptime_pct": metrics["active_workers"] / max(1, metrics["total_workers"]) * 100.0,
        }

    def snapshot(self) -> Dict:
        metrics = self._aggregate()
        return {
            "metrics": metrics,
            "fleet": [
                {k: (list(v) if k == "trend" else v)
                 for k, v in d.items() if k != "base_hr"}
                for d in self.devices
            ],
            "alerts": list(self.alerts[-50:]),
            "series": {k: list(v) for k, v in self.series.items()},
            "executive": self._executive(metrics),
            "ts": _now_iso(),
        }


def risk_matrix_items(alerts: List[Dict], devices: List[Dict]) -> List[Dict]:
    """Derive a 5x5 risk register (likelihood x impact) for the Safety Center."""
    items = []
    for d in devices:
        if d.get("temp_c", 0) > 86:
            items.append({"name": f"Thermal stress — {d['name']}", "likelihood": 3, "impact": 4,
                          "category": "Thermal"})
        if d.get("status") == "offline":
            items.append({"name": f"Lost worker — {d['name']}", "likelihood": 2, "impact": 3,
                          "category": "Availability"})
    crit = sum(1 for a in alerts if a["severity"] == "critical" and not a["ack"])
    if crit:
        items.append({"name": "Unacknowledged critical alerts", "likelihood": 4,
                      "impact": 4, "category": "Operational"})
    warns = sum(1 for a in alerts if a["severity"] == "warning" and not a["ack"])
    if warns:
        items.append({"name": "Open warning backlog", "likelihood": 3, "impact": 2,
                      "category": "Operational"})
    if not items:
        items.append({"name": "Nominal operations", "likelihood": 1, "impact": 1,
                      "category": "Baseline"})
    return items
