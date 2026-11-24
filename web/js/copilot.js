/* =====================================================================
   HF.copilot — on-device mining copilot (intent engine over live state).
   No cloud dependency: queries are answered from the same telemetry the
   dashboard renders, so it works offline and on any device. An optional
   remote LLM hook can replace `answer` later without UI changes.
   ===================================================================== */
(function () {
  "use strict";
  window.HF = window.HF || {};
  var copilot = {};
  HF.copilot = copilot;

  var S = HF.state, U = HF.ui;

  function tableCards(rows, cols) {
    return { type: "table", cols: cols, rows: rows };
  }

  var INTENTS = [
    {
      id: "help",
      match: /\b(help|what can you|commands|capabilit)/i,
      run: function () {
        return {
          text: "I analyze your live fleet telemetry. Try one of these:",
          cards: [{
            type: "list",
            items: [
              "Show workers with low hashrate",
              "Show workers with high temperature",
              "Predict equipment failures this week",
              "Which zone has the highest productivity?",
              "What is the power consumption?",
              "Show share acceptance rate",
              "Show donation allocation",
              "Estimate profitability",
              "Show open alerts",
              "Emergency stop procedure"
            ]
          }]
        };
      }
    },
    {
      id: "low_hashrate",
      match: /(low|slow|underperform\w*|poor).*(hash|rate|speed|productiv)|(hash|rate|speed).*(low|slow|down)/i,
      run: function () {
        var sorted = S.fleet.slice().sort(function (a, b) {
          return a.hashrate - b.hashrate;
        }).slice(0, 5);
        return {
          text: "These 5 workers currently report the lowest hashrate. " +
            (sorted[0] && sorted[0].status === "offline"
              ? "Note that offline workers report 0 H/s — check their power/network first."
              : "Inspect thermal throttling and share rejects next."),
          cards: [tableCards(sorted.map(function (d) {
            return [d.name, d.zone, U.fmtHash(d.hashrate), d.status, d.health.toFixed(0) + "%"];
          }), ["Worker", "Zone", "Hashrate", "Status", "Health"])]
        };
      }
    },
    {
      id: "high_temp",
      match: /(high|hot|overheat\w*|thermal|temperature|temp)/i,
      run: function () {
        var hot = HF.selectors.hottestDevices(5);
        return {
          text: "Thermal ranking across the fleet. Anything above 86°C is " +
            "throttling risk; the Safety Center tracks the trend.",
          cards: [tableCards(hot.map(function (d) {
            return [d.name, d.zone, d.temp_c.toFixed(1) + "°C",
              d.fan_pct.toFixed(0) + "%", d.throttled ? "THROTTLING" : "nominal"];
          }), ["Worker", "Zone", "Temp", "Fan", "State"])]
        };
      }
    },
    {
      id: "predict_failures",
      match: /(predict|failure|fail|break|downtime|repair|maintenance)/i,
      run: function () {
        var risky = S.fleet.filter(function (d) {
          return d.health < 92 || d.throttled || d.status === "degraded" ||
            d.rejected > 4 || d.status === "offline";
        }).sort(function (a, b) { return a.health - b.health; }).slice(0, 6);
        return {
          text: risky.length
            ? "Heuristic failure-risk forecast for the next 7 days, ranked by " +
              "composite health (thermal stress, reject rate, uptime, throttling)."
            : "All workers are inside nominal envelopes — no elevated failure risk " +
              "detected this week.",
          cards: risky.length ? [tableCards(risky.map(function (d) {
            return [d.name, d.health.toFixed(0) + "%",
              d.throttled ? "thermal" : d.status === "offline" ? "offline" : "degradation",
              d.rejected + " rej", U.fmtDuration(d.uptime_s)];
          }), ["Worker", "Health", "Risk driver", "Rejects", "Uptime"])] : []
        };
      }
    },
    {
      id: "zone_productivity",
      match: /(zone|area|sector|cluster|site).*(productiv|best|highest|top|good)|highest productivity/i,
      run: function () {
        var zones = HF.selectors.zoneRollup().sort(function (a, b) {
          return b.hashrate - a.hashrate;
        });
        var best = zones[0];
        return {
          text: best
            ? best.zone + " (" + best.site + ") leads with " + U.fmtHash(best.hashrate) +
              " across " + best.count + " workers. Per-worker average: " +
              U.fmtHash(best.hashrate / Math.max(1, best.count)) + "."
            : "No zone data yet.",
          cards: [tableCards(zones.map(function (z) {
            return [z.zone, z.site, z.count, U.fmtHash(z.hashrate),
              U.fmtHash(z.hashrate / Math.max(1, z.count)), z.avg_temp.toFixed(1) + "°C"];
          }), ["Zone", "Site", "Workers", "Total", "Avg/worker", "Avg temp"])]
        };
      }
    },
    {
      id: "power_energy",
      match: /(power|energy|kwh|electric|consumption|fuel|watt)/i,
      run: function () {
        var m = S.metrics, e = S.executive;
        return {
          text: "Fleet draws " + U.fmtNum(m.total_power_w, 0) + " W right now ≈ " +
            U.fmtNum(e.energy_kwh_day, 1) + " kWh/day. At your configured tariff (" +
            U.fmtMoney(S.settings.energyPrice) + "/kWh) that is " +
            U.fmtMoney(e.energy_cost_usd_day) + "/day. Efficiency: " +
            (m.efficiency_hs_per_w * 1000).toFixed(2) + " kH/s per watt.",
          cards: [{
            type: "stat",
            items: [
              ["Live draw", U.fmtNum(m.total_power_w, 0) + " W"],
              ["Daily energy", U.fmtNum(e.energy_kwh_day, 1) + " kWh"],
              ["Daily cost", U.fmtMoney(e.energy_cost_usd_day)],
              ["Carbon estimate", U.fmtNum(e.carbon_kg_day, 1) + " kg CO₂/day"]
            ]
          }]
        };
      }
    },
    {
      id: "acceptance",
      match: /(accept|reject|share|stale|effort)/i,
      run: function () {
        var m = S.metrics;
        return {
          text: "Share acceptance is " + U.fmtPct(m.acceptance_pct, 2) +
            " (" + U.fmtNum(m.accepted) + " accepted / " + U.fmtNum(m.rejected) +
            " rejected, " + U.fmtNum(m.stale) + " stale). Values below 98% usually " +
            "point to network latency or an overloaded pool connection.",
          cards: []
        };
      }
    },
    {
      id: "donation",
      match: /(donat|owner|project fund|allocation|split)/i,
      run: function () {
        var pct = S.settings.donationPct;
        return {
          text: "Current allocation: " + (100 - pct).toFixed(1) + "% contributor / " +
            pct.toFixed(1) + "% project fund. The sidebar shows the live split; the " +
            "CLI enforces the same ratio and prints the exact realized share before " +
            "mining starts. You can disable it entirely with --donation 0.",
          cards: []
        };
      }
    },
    {
      id: "profit",
      match: /(profit|revenue|earn|income|roi|xmr|money|cost)/i,
      run: function () {
        var e = S.executive;
        return {
          text: "At " + U.fmtMoney(e.xmr_price_usd) + "/XMR: estimated " +
            e.xmr_per_day.toFixed(6) + " XMR/day ≈ " + U.fmtMoney(e.revenue_usd_day) +
            "/day revenue, minus " + U.fmtMoney(e.energy_cost_usd_day) +
            " energy = " + U.fmtMoney(e.revenue_usd_day - e.energy_cost_usd_day) +
            "/day gross (" + U.fmtPct(e.gross_margin_pct, 1) + " margin). " +
            "Configure price/tariff in Settings.",
          cards: [{
            type: "stat",
            items: [
              ["XMR/day", e.xmr_per_day.toFixed(6)],
              ["Revenue/day", U.fmtMoney(e.revenue_usd_day)],
              ["Energy/day", U.fmtMoney(e.energy_cost_usd_day)],
              ["Project fund share", (e.donation_xmr_day || 0).toFixed(6) + " XMR/day"]
            ]
          }]
        };
      }
    },
    {
      id: "alerts",
      match: /(alert|incident|warning|critical|problem|issue)/i,
      run: function () {
        var open = HF.selectors.openAlerts().slice(-6).reverse();
        return {
          text: open.length
            ? open.length + " open alert(s). The most recent are below — " +
              "the Safety Center has the full register."
            : "No open alerts. The fleet is nominal.",
          cards: open.length ? [tableCards(open.map(function (a) {
            return [U.sevChip(a.severity), a.title, a.device, U.ago(a.ts)];
          }), ["Sev", "Alert", "Device", "Age"])] : []
        };
      }
    },
    {
      id: "emergency",
      match: /(emergency|stop all|halt|shutdown|evacuat)/i,
      run: function () {
        return {
          text: "Emergency stop places every worker into maintenance state and " +
            "stops supervised miners. Use the red button in the Safety Center — " +
            "it requires a two-step confirmation to prevent mis-taps. " +
            "This is the digital equivalent of a site evacuation signal.",
          cards: [{
            type: "action", label: "Open Safety Center", href: "#/safety"
          }]
        };
      }
    },
    {
      id: "status",
      match: /(status|overview|how.*(doing|going)|summary|health)/i,
      run: function () {
        var m = S.metrics;
        return {
          text: "Fleet status: " + m.active_workers + "/" + m.total_workers +
            " workers online, " + U.fmtHash(m.hashrate_10s) + " total, avg temp " +
            (m.avg_temp || 0).toFixed(1) + "°C, acceptance " +
            U.fmtPct(m.acceptance_pct, 2) + ", average health " +
            U.fmtPct(m.health_avg, 0) + ".",
          cards: []
        };
      }
    }
  ];

  copilot.suggestions = [
    "Show workers with low hashrate",
    "Predict equipment failures this week",
    "Which zone has the highest productivity?",
    "What is the power consumption?",
    "Estimate profitability",
    "Show open alerts"
  ];

  copilot.answer = function (query) {
    for (var i = 0; i < INTENTS.length; i++) {
      if (INTENTS[i].match.test(query)) {
        var result = INTENTS[i].run();
        result.intent = INTENTS[i].id;
        return result;
      }
    }
    // Fallback: try to match a device name in the query.
    var dev = S.fleet.filter(function (d) {
      return query.toLowerCase().indexOf(d.name.toLowerCase()) >= 0;
    })[0];
    if (dev) {
      return {
        intent: "device",
        text: dev.name + " (" + dev.zone + "): " + dev.status + ", " +
          U.fmtHash(dev.hashrate) + ", " + dev.temp_c.toFixed(1) + "°C, health " +
          dev.health.toFixed(0) + "%.",
        cards: [{
          type: "action", label: "Open " + dev.name + " details",
          href: "#/fleet", device: dev.name
        }]
      };
    }
    return {
      intent: "unknown",
      text: "I could not map that to a fleet query. I answer questions about " +
        "hashrate, thermal state, failures, zones, power, shares, donations, " +
        "profitability and alerts. Type 'help' for examples.",
      cards: []
    };
  };
})();
