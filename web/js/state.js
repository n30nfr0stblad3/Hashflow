/* =====================================================================
   HF.state — single source of truth + data feeds.
   Live mode: EventSource (/api/stream) against the Hashflow server.
   Demo/offline mode: built-in tick simulator so the dashboard is fully
   functional from file:// or any static host, on any device.
   ===================================================================== */
(function () {
  "use strict";
  window.HF = window.HF || {};
  var state = {
    mode: "demo",            // 'demo' | 'live'
    metrics: {},
    fleet: [],
    alerts: [],
    series: { hashrate: [], power: [], temp: [], accepted: [] },
    executive: {},
    risk: [],
    settings: {
      xmrPrice: 165,
      energyPrice: 0.12,
      donationPct: 5,
      targetHashrate: 75e6,
      textScale: "100",
      highContrast: false,
      reducedMotion: false
    }
  };
  HF.state = state;

  var listeners = {};
  HF.on = function (ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); };
  HF.emit = function (ev, data) {
    (listeners[ev] || []).forEach(function (fn) { fn(data); });
  };

  /* ------------------------- persistence (settings) ------------------------ */
  try {
    var saved = JSON.parse(localStorage.getItem("hf-settings") || "{}");
    Object.keys(saved).forEach(function (k) {
      if (k in state.settings) state.settings[k] = saved[k];
    });
  } catch (e) { /* private mode etc. */ }
  HF.saveSettings = function () {
    try { localStorage.setItem("hf-settings", JSON.stringify(state.settings)); }
    catch (e) { /* ignore */ }
    HF.emit("settings", state.settings);
  };

  /* --------------------------- demo simulator ------------------------------
     Lightweight port of hashflow/simulator.py (random walk, thermal model,
     alerts). Only used when no server is reachable. Seeded LCG = stable. */
  function LCG(seed) {
    var s = seed >>> 0;
    return function () {
      s = (1664525 * s + 1013904223) >>> 0;
      return s / 4294967296;
    };
  }
  var demo = null;
  function initDemo() {
    var rnd = LCG(1337);
    var zones = ["Zone Alpha", "Zone Beta", "Zone Gamma"];
    var pref = ["RIG-ALPHA", "RIG-BETA", "RIG-GAMMA"];
    var devices = [];
    for (var i = 0; i < 24; i++) {
      var zi = i % 3;
      var base = 800 + rnd() * 3400; // kH/s scaled below
      base *= 1000;
      devices.push({
        id: "dev-" + (i + 1 < 10 ? "0" : "") + (i + 1),
        name: pref[zi] + "-" + ("0" + (Math.floor(i / 3) + 1)).slice(-2),
        zone: zones[zi], site: zi < 2 ? "North Cluster" : "South Cluster",
        status: "online", hashrate: base, base_hr: base,
        temp_c: 48 + rnd() * 24, fan_pct: 35 + rnd() * 40,
        power_w: base / 1000 * (11 + rnd() * 4),
        uptime_s: Math.floor(3600 + rnd() * 864000),
        accepted: Math.floor(400 + rnd() * 2000), rejected: Math.floor(rnd() * 6),
        stale: Math.floor(rnd() * 2), throttled: false,
        health: 88 + rnd() * 11, utilization: 0.72 + rnd() * 0.26,
        threads: [4, 6, 8, 8, 12, 16][Math.floor(rnd() * 6)],
        trend: [], last_seen: new Date().toISOString()
      });
    }
    demo = { devices: devices, alerts: [], seq: 0, rnd: rnd };
    for (var t = 0; t < 30; t++) demoTick(true);
  }

  function gauss(rnd) { return (rnd() + rnd() + rnd() - 1.5) * 1.2; }

  function pushAlert(sev, code, detail, dev) {
    demo.seq++;
    demo.alerts.push({
      id: "alert-" + ("0000" + demo.seq).slice(-5),
      severity: sev, code: code,
      title: code.replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); }),
      detail: detail, device: dev.name, zone: dev.zone,
      ts: new Date().toISOString(), ack: false
    });
    if (demo.alerts.length > 200) demo.alerts.splice(0, demo.alerts.length - 200);
  }

  function demoTick(priming) {
    var rnd = demo.rnd;
    demo.devices.forEach(function (d) {
      if (d.status === "offline") {
        if (rnd() < 0.05) {
          d.status = "online";
          pushAlert("info", "DEVICE_RECOVERED", d.name + " is back online", d);
        } else return;
      }
      d.hashrate = Math.max(50, d.hashrate + (d.base_hr - d.hashrate) * 0.05 +
        gauss(rnd) * d.base_hr * 0.02);
      if (d.status === "degraded") d.hashrate *= 0.55;
      var targetTemp = 42 + d.utilization * 38 + (d.throttled ? 12 : 0);
      d.temp_c += (targetTemp - d.temp_c) * 0.08 + gauss(rnd) * 0.6;
      d.temp_c = Math.max(30, Math.min(99, d.temp_c));
      d.fan_pct = Math.max(20, Math.min(100, (d.temp_c - 35) * 1.6 + gauss(rnd) * 2));
      d.power_w = Math.max(20, d.hashrate / 1000 * 12.5 + gauss(rnd) * 3);
      d.uptime_s += 2;
      d.utilization = Math.max(0.3, Math.min(1, d.utilization + gauss(rnd) * 0.008));
      d.trend.push(d.hashrate);
      if (d.trend.length > 30) d.trend.shift();
      d.last_seen = new Date().toISOString();
      if (rnd() < 0.82) d.accepted++;
      if (rnd() < 0.006) d.rejected++;
      var r = rnd();
      if (!priming) {
        if (r < 0.002) {
          d.status = "offline";
          pushAlert("critical", "DEVICE_OFFLINE", d.name + " stopped reporting", d);
        } else if (d.temp_c > 86 && !d.throttled) {
          d.throttled = true;
          pushAlert("warning", "THERMAL_THROTTLE",
            d.name + " thermal throttling at " + d.temp_c.toFixed(0) + "C", d);
        } else if (d.throttled && d.temp_c < 78) {
          d.throttled = false;
        } else if (rnd() < 0.001) {
          pushAlert("warning", "HIGH_REJECTS", d.name + " elevated share rejects", d);
        }
      }
      d.health = Math.max(35, Math.min(99.5,
        d.health * 0.995 + 0.05 * (95 - Math.max(0, d.temp_c - 70) * 2) -
        (d.throttled ? 0.4 : 0)));
    });
  }

  function demoSnapshot() {
    var online = demo.devices.filter(function (d) {
      return d.status === "online" || d.status === "degraded";
    });
    var totalHr = online.reduce(function (a, d) { return a + d.hashrate; }, 0);
    var accepted = demo.devices.reduce(function (a, d) { return a + d.accepted; }, 0);
    var rejected = demo.devices.reduce(function (a, d) { return a + d.rejected; }, 0);
    var power = online.reduce(function (a, d) { return a + d.power_w; }, 0);
    var avgTemp = online.reduce(function (a, d) { return a + d.temp_c; }, 0) /
      Math.max(1, online.length);
    var metrics = {
      hashrate_10s: totalHr, accepted: accepted, rejected: rejected,
      stale: demo.devices.reduce(function (a, d) { return a + d.stale; }, 0),
      acceptance_pct: (accepted + rejected) ? accepted / (accepted + rejected) * 100 : 100,
      active_workers: online.length, total_workers: demo.devices.length,
      avg_temp: avgTemp, total_power_w: power,
      efficiency_hs_per_w: power ? totalHr / power : 0,
      health_avg: demo.devices.reduce(function (a, d) { return a + d.health; }, 0) /
        Math.max(1, demo.devices.length),
      throttled: demo.devices.filter(function (d) { return d.throttled; }).length,
      timestamp: new Date().toISOString()
    };
    var xmrPerDay = totalHr / 1000 * 1.1e-5;
    var kwhDay = power / 1000 * 24;
    var revenue = xmrPerDay * state.settings.xmrPrice;
    var energyCost = kwhDay * state.settings.energyPrice;
    return {
      metrics: metrics,
      fleet: demo.devices,
      alerts: demo.alerts.slice(-50),
      series: state.series,
      executive: {
        xmr_price_usd: state.settings.xmrPrice,
        xmr_per_day: xmrPerDay,
        revenue_usd_day: revenue,
        energy_kwh_day: kwhDay,
        energy_cost_usd_day: energyCost,
        gross_margin_pct: revenue ? (revenue - energyCost) / revenue * 100 : 0,
        efficiency_hs_per_w: metrics.efficiency_hs_per_w,
        energy_per_mhash_j: totalHr ? power / (totalHr / 1e6) : 0,
        carbon_kg_day: kwhDay * 0.417,
        donation_xmr_day: xmrPerDay * state.settings.donationPct / 100,
        target_hashrate: state.settings.targetHashrate,
        pct_of_target: totalHr / state.settings.targetHashrate * 100,
        uptime_pct: metrics.active_workers / Math.max(1, metrics.total_workers) * 100
      }
    };
  }

  function ingest(snap) {
    state.metrics = snap.metrics || state.metrics;
    state.fleet = snap.fleet || state.fleet;
    state.alerts = snap.alerts || state.alerts;
    state.executive = snap.executive || state.executive;
    if (snap.series) {
      Object.keys(snap.series).forEach(function (k) {
        if (state.series[k]) state.series[k] = snap.series[k];
      });
    }
    HF.emit("tick", snap);
    HF.emit("alerts", state.alerts);
  }
  HF.ingest = ingest;

  /* ------------------------------ feed switch ------------------------------ */
  function startLive() {
    try {
      var es = new EventSource("/api/stream");
      es.addEventListener("snapshot", function (ev) {
        state.mode = "live";
        HF.emit("conn", "live");
        ingest(JSON.parse(ev.data));
      });
      es.addEventListener("tick", function (ev) {
        state.mode = "live";
        HF.emit("conn", "live");
        var snap = JSON.parse(ev.data);
        // Keep local series even if server omits them
        if (snap.series) state.series = snap.series;
        ingest(snap);
      });
      es.onerror = function () {
        HF.emit("conn", "reconnecting");
      };
      return true;
    } catch (e) {
      return false;
    }
  }

  function startDemo() {
    state.mode = "demo";
    HF.emit("conn", "demo");
    initDemo();
    setInterval(function () {
      demoTick(false);
      var snap = demoSnapshot();
      // push series locally
      state.series.hashrate.push(snap.metrics.hashrate_10s);
      state.series.power.push(snap.metrics.total_power_w);
      state.series.temp.push(snap.metrics.avg_temp);
      state.series.accepted.push(snap.metrics.accepted);
      ["hashrate", "power", "temp", "accepted"].forEach(function (k) {
        if (state.series[k].length > 600) state.series[k].splice(0,
          state.series[k].length - 600);
      });
      ingest(snap);
    }, 2000);
    ingest(demoSnapshot());
  }

  HF.boot = function () {
    // Probe the API; fall back to the built-in simulator (file:// or offline).
    var started = false;
    try {
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "/api/health", true);
      xhr.timeout = 1500;
      xhr.onload = function () {
        if (xhr.status === 200 && !started) {
          started = true;
          startLive();
        }
      };
      xhr.onerror = function () {
        if (!started) { started = true; startDemo(); }
      };
      xhr.ontimeout = xhr.onerror;
      xhr.send();
      setTimeout(function () {
        if (!started) { started = true; startDemo(); }
      }, 1800);
    } catch (e) {
      startDemo();
    }
  };

  /* ------------------------------- selectors ------------------------------- */
  HF.selectors = {
    openAlerts: function () {
      return state.alerts.filter(function (a) { return !a.ack; });
    },
    criticalAlerts: function () {
      return state.alerts.filter(function (a) { return !a.ack && a.severity === "critical"; });
    },
    deviceByName: function (name) {
      return state.fleet.filter(function (d) { return d.name === name; })[0];
    },
    byStatus: function (status) {
      return state.fleet.filter(function (d) { return d.status === status; });
    },
    worstDevices: function (n) {
      return state.fleet.slice().sort(function (a, b) {
        return a.health - b.health;
      }).slice(0, n || 5);
    },
    hottestDevices: function (n) {
      return state.fleet.slice().sort(function (a, b) {
        return b.temp_c - a.temp_c;
      }).slice(0, n || 5);
    },
    zoneRollup: function () {
      var zones = {};
      state.fleet.forEach(function (d) {
        var z = zones[d.zone] = zones[d.zone] || {
          zone: d.zone, site: d.site, count: 0, hashrate: 0, temp: 0, power: 0,
          offline: 0
        };
        z.count++;
        z.hashrate += d.hashrate;
        z.temp += d.temp_c;
        z.power += d.power_w;
        if (d.status === "offline") z.offline++;
      });
      Object.keys(zones).forEach(function (k) {
        zones[k].avg_temp = zones[k].temp / Math.max(1, zones[k].count);
      });
      return Object.keys(zones).map(function (k) { return zones[k]; });
    }
  };

  /* ----------------------------- alert actions ----------------------------- */
  HF.ackAlert = function (id) {
    if (state.mode === "live") {
      try {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/alerts/ack", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify({ id: id }));
      } catch (e) { /* ignore */ }
    }
    state.alerts.forEach(function (a) { if (a.id === id) a.ack = true; });
    HF.emit("alerts", state.alerts);
  };

  HF.emergencyStop = function () {
    if (state.mode === "live") {
      try {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/actions/emergency-stop", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify({ confirm: "STOP" }));
      } catch (e) { /* ignore */ }
    } else if (demo) {
      demo.devices.forEach(function (d) {
        if (d.status !== "offline") d.status = "maintenance";
      });
      pushAlert("critical", "EMERGENCY_STOP",
        "Operator issued fleet-wide emergency stop",
        { name: "FLEET", zone: "All" });
    }
    HF.emit("alerts", state.alerts);
    HF.emit("tick", {});
  };
})();
