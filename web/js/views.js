/* =====================================================================
   HF.views — nine operational views. Each view owns a render(container)
   and an optional refresh() (targeted updates on live ticks so inputs
   keep focus). Charts register for auto-redraw on resize.
   ===================================================================== */
(function () {
  "use strict";
  window.HF = window.HF || {};
  var views = {};
  HF.views = views;
  var U = HF.ui, C = HF.charts, S = HF.state;

  function seriesLabels(n) {
    var out = [];
    for (var i = 0; i < n; i++) {
      var mins = Math.round((n - 1 - i) * 2 / 60);
      out.push(mins === 0 ? "now" : "-" + mins + "m");
    }
    return out;
  }
  function k(v) { return HF.charts.fmtShort(v); }

  /* ============================== 1. DASHBOARD ==============================
     Command center: 8 KPI tiles (spec: production, equipment, health, fuel,
     workforce, safety, environmental, realtime), production trend, allocation
     donut, worker grid, alert feed. */
  views.dashboard = {
    render: function (root) {
      var m = S.metrics, e = S.executive;
      var open = HF.selectors.openAlerts();
      var crit = open.filter(function (a) { return a.severity === "critical"; });
      var hrSeries = S.series.hashrate.slice(-120);
      root.innerHTML =
        '<div class="page-head"><h1>Operations Dashboard</h1>' +
        '<span class="sub">Live fleet telemetry · refresh 2s</span>' +
        '<div class="page-actions">' +
        '<button class="btn btn-sm" id="dash-refresh">' + U.icon("refresh") + "Refresh</button>" +
        '<button class="btn btn-sm btn-primary" id="dash-copilot">' + U.icon("bot") + "Ask Copilot</button>" +
        "</div></div>" +

        '<div class="grid grid-kpi" id="dash-kpis">' +
        U.kpi({
          label: "Production (hashrate)", state: "info",
          value: U.fmtHash(m.hashrate_10s),
          foot: U.delta(m.hashrate_10s, hrSeries[0]) + " vs 4 min ago",
          spark: true
        }) +
        U.kpi({
          label: "Active equipment",
          state: m.active_workers === m.total_workers ? "ok" :
            m.active_workers > m.total_workers * 0.85 ? "warn" : "crit",
          value: (m.active_workers || 0) + '<span class="unit"> / ' + (m.total_workers || 0) + "</span>",
          foot: (m.throttled || 0) + " throttling · " +
            (m.total_workers - m.active_workers) + " offline"
        }) +
        U.kpi({
          label: "Equipment health",
          state: (m.health_avg || 100) > 93 ? "ok" : (m.health_avg || 0) > 85 ? "warn" : "crit",
          value: U.fmtPct(m.health_avg, 0),
          foot: "composite: thermal · rejects · uptime", spark: true
        }) +
        U.kpi({
          label: "Power draw (fuel)",
          state: "info",
          value: U.fmtNum(m.total_power_w, 0),
          unit: "W",
          foot: U.fmtNum(e.energy_kwh_day, 1) + " kWh/day ≈ " + U.fmtMoney(e.energy_cost_usd_day),
          spark: true
        }) +
        U.kpi({
          label: "Workforce utilization",
          state: "ok",
          value: U.fmtPct(
            S.fleet.reduce(function (a, d) { return a + (d.utilization || 0); }, 0) /
            Math.max(1, S.fleet.length) * 100, 0),
          foot: "avg compute utilization across workers"
        }) +
        U.kpi({
          label: "Safety alerts",
          state: crit.length ? "crit" : open.length ? "warn" : "ok",
          value: String(open.length),
          foot: crit.length + " critical · " +
            open.filter(function (a) { return a.severity === "warning"; }).length + " warning"
        }) +
        U.kpi({
          label: "Environmental (thermal)",
          state: (m.avg_temp || 0) > 75 ? "warn" : "ok",
          value: (m.avg_temp || 0).toFixed(1),
          unit: "°C avg",
          foot: "hottest: " + (HF.selectors.hottestDevices(1)[0] || { name: "—" }).name,
          spark: true
        }) +
        U.kpi({
          label: "Realtime shares",
          state: "ok",
          value: U.fmtNum(m.accepted),
          foot: "acceptance " + U.fmtPct(m.acceptance_pct, 2) + " · " + U.fmtNum(m.rejected) + " rejected"
        }) +
        "</div>" +

        '<div class="grid grid-2 mt-4">' +
        '<section class="card"><div class="card-title">' + U.icon("chart") +
        "Production trend (hasrate)" +
        '<span class="right muted small">' + U.fmtHash(m.hashrate_10s) + " now</span></div>" +
        '<div class="chart-box" id="dash-hr-chart"></div>' +
        '<div class="legend mt-2"><span><span class="sw" style="background:#4cc2ff"></span>Total hashrate</span></div>' +
        "</section>" +

        '<section class="card"><div class="card-title">' + U.icon("coin") +
        "Compute allocation</div>" +
        '<div class="alloc-donut-row"><div id="dash-donut"></div><div style="flex:1">' +
        '<div class="row"><span class="dot dot-ok"></span><div><b>Contributor</b><div class="muted small">Your wallet</div></div>' +
        '<span class="spacer"></span><b class="mono">' + (100 - S.settings.donationPct).toFixed(1) + "%</b></div>" +
        '<div class="row mt-2"><span class="dot" style="background:#4c8dff"></span><div><b>Project fund</b><div class="muted small">Development donation</div></div>' +
        '<span class="spacer"></span><b class="mono">' + S.settings.donationPct.toFixed(1) + "%</b></div>" +
        '<div class="small muted mt-3">Transparent by design: the CLI prints the exact realized share before mining starts; set --donation 0 to opt out.</div>' +
        "</div></div></section></div>" +

        '<div class="grid grid-2 mt-4">' +
        '<section class="card"><div class="card-title">' + U.icon("server") +
        'Worker grid <span class="right muted small">click a worker for detail</span></div>' +
        '<div class="worker-grid" id="dash-workers"></div></section>' +
        '<section class="card"><div class="card-title">' + U.icon("bell") +
        'Alert feed <span class="right"><button class="btn btn-sm btn-ghost" id="dash-ack-all">Acknowledge all</button></span></div>' +
        '<div class="feed" id="dash-feed"></div></section>' +
        "</div>";

      C.area(root.querySelector("#dash-hr-chart"), [{
        name: "Hashrate", color: "#4cc2ff", data: hrSeries
      }], { labels: seriesLabels(hrSeries.length), unit: " H/s", height: 240 });

      C.donut(root.querySelector("#dash-donut"), [
        { name: "Contributor", value: 100 - S.settings.donationPct, color: "#2ed477" },
        { name: "Project fund", value: Math.max(0.5, S.settings.donationPct), color: "#4c8dff" }
      ], {
        size: 140,
        centerTop: (100 - S.settings.donationPct).toFixed(1) + "%",
        centerBottom: "TO YOU"
      });

      C.sparkline(root.querySelector("#dash-kpis .kpi:nth-child(1) .kpi-spark"),
        hrSeries.slice(-30), "#4cc2ff");
      C.sparkline(root.querySelector("#dash-kpis .kpi:nth-child(3) .kpi-spark"),
        S.fleet.map(function (d) { return d.health; }), "#2ed477");
      C.sparkline(root.querySelector("#dash-kpis .kpi:nth-child(4) .kpi-spark"),
        S.series.power.slice(-30), "#f5b83d");
      C.sparkline(root.querySelector("#dash-kpis .kpi:nth-child(7) .kpi-spark"),
        S.series.temp.slice(-30), "#f2812d");

      views._renderWorkers(root.querySelector("#dash-workers"));
      views._renderFeed(root.querySelector("#dash-feed"));

      root.querySelector("#dash-refresh").addEventListener("click", function () {
        views.refresh(root);
        U.toast("Refreshed", "Dashboard re-rendered from live telemetry.", "ok");
      });
      root.querySelector("#dash-copilot").addEventListener("click", function () {
        location.hash = "#/copilot";
      });
      root.querySelector("#dash-ack-all").addEventListener("click", function () {
        HF.selectors.openAlerts().forEach(function (a) { HF.ackAlert(a.id); });
        U.toast("Alerts acknowledged", "The alert register has been cleared.", "ok");
        views.refresh(root);
      });
    },
    refresh: function (root) {
      if (root && !root.hidden) views.dashboard.render(root);
    },
    _renderWorkers: function (host) {
      if (!host) return;
      host.innerHTML = S.fleet.map(function (d) {
        return '<button class="worker-tile" data-state="' + d.status +
          '" data-name="' + U.esc(d.name) + '" title="' + U.esc(d.name) + '">' +
          '<div class="name">' + U.statusChip(d.status) + "</div>" +
          '<div class="hr">' + U.fmtHash(d.hashrate) + "</div>" +
          '<div class="muted">' + d.zone + " · " + d.temp_c.toFixed(0) + "°C</div>" +
          "</button>";
      }).join("");
      U.$$(".worker-tile", host).forEach(function (tile) {
        tile.addEventListener("click", function () {
          var d = HF.selectors.deviceByName(tile.dataset.name);
          if (d) views._deviceDrawer(d);
        });
      });
    },
    _renderFeed: function (host) {
      if (!host) return;
      var items = S.alerts.slice(-12).reverse();
      host.innerHTML = items.length ? items.map(function (a) {
        var cls = a.severity === "critical" ? "crit" : a.severity === "warning" ? "warn" : "info";
        return '<div class="feed-item ' + cls + '">' +
          U.icon(a.severity === "critical" ? "warn" : a.severity === "warning" ? "warn" : "info") +
          "<div><b>" + U.esc(a.title) + "</b><div class='muted'>" + U.esc(a.detail) + "</div></div>" +
          '<span class="feed-time">' + U.ago(a.ts) + "</span></div>";
      }).join("") : '<div class="muted">No alerts — fleet nominal.</div>';
    }
  };

  views._deviceDrawer = function (d) {
    U.drawer(d.name,
      '<div class="row"><b>' + U.statusChip(d.status) + '</b><span class="spacer"></span>' +
      '<span class="chip chip-info">' + U.esc(d.zone) + "</span></div>" +
      '<dl class="kv">' +
      "<dt>Hashrate</dt><dd>" + U.fmtHash(d.hashrate) + "</dd>" +
      "<dt>Temperature</dt><dd>" + d.temp_c.toFixed(1) + " °C</dd>" +
      "<dt>Fan</dt><dd>" + d.fan_pct.toFixed(0) + " %</dd>" +
      "<dt>Power</dt><dd>" + U.fmtNum(d.power_w, 0) + " W</dd>" +
      "<dt>Threads</dt><dd>" + d.threads + "</dd>" +
      "<dt>Accepted / rejected</dt><dd>" + U.fmtNum(d.accepted) + " / " + U.fmtNum(d.rejected) + "</dd>" +
      "<dt>Health score</dt><dd>" + d.health.toFixed(1) + " %</dd>" +
      "<dt>Utilization</dt><dd>" + (d.utilization * 100).toFixed(0) + " %</dd>" +
      "<dt>Uptime</dt><dd>" + U.fmtDuration(d.uptime_s) + "</dd>" +
      "<dt>Last seen</dt><dd>" + U.ago(d.last_seen) + "</dd>" +
      "</dl>" +
      '<div class="chart-box" id="drawer-spark"></div>');
    C.sparkline(document.getElementById("drawer-spark"),
      d.trend && d.trend.length ? d.trend : [d.hashrate], "#4cc2ff");
  };

  /* ================================ 2. FLEET ================================
     Fleet management table: status, hashrate, thermal, health, utilization.
     Table body updates on tick without losing search-field focus. */
  views.fleet = {
    filter: "",
    render: function (root) {
      root.innerHTML =
        '<div class="page-head"><h1>Fleet</h1><span class="sub">Equipment monitoring</span>' +
        '<div class="page-actions">' +
        '<div class="searchbox" style="width:260px"><svg class="icon"><use href="#i-search"/></svg>' +
        '<input id="fleet-search" type="search" placeholder="Filter workers or zones…" aria-label="Filter fleet"></div>' +
        "</div></div>" +
        '<div class="row row-wrap mb-4" id="fleet-summary"></div>' +
        '<div id="fleet-table-host"></div>';
      var input = root.querySelector("#fleet-search");
      input.value = views.fleet.filter;
      input.addEventListener("input", function () {
        views.fleet.filter = input.value.toLowerCase();
        views.fleet._table(root.querySelector("#fleet-table-host"));
      });
      views.fleet._table(root.querySelector("#fleet-table-host"));
      views.fleet._summary(root.querySelector("#fleet-summary"));
    },
    refresh: function (root) {
      if (!root || root.hidden) return;
      views.fleet._table(root.querySelector("#fleet-table-host"));
      views.fleet._summary(root.querySelector("#fleet-summary"));
    },
    _summary: function (host) {
      if (!host) return;
      var m = S.metrics;
      host.innerHTML = [
        ["Workers", m.total_workers, "chip-info"],
        ["Online", m.active_workers, "chip-ok"],
        ["Degraded", HF.selectors.byStatus("degraded").length, "chip-warn"],
        ["Offline", HF.selectors.byStatus("offline").length, "chip-crit"],
        ["Maintenance", HF.selectors.byStatus("maintenance").length, "chip-info"]
      ].map(function (x) {
        return '<span class="chip ' + x[2] + '">' + x[0] + " " + x[1] + "</span>";
      }).join("");
    },
    _table: function (host) {
      if (!host) return;
      var f = views.fleet.filter;
      var rows = S.fleet.filter(function (d) {
        return !f || (d.name + " " + d.zone + " " + d.site + " " + d.status)
          .toLowerCase().indexOf(f) >= 0;
      });
      host.innerHTML = U.table(
        [
          { label: "Status" }, { label: "Worker" }, { label: "Zone" },
          { label: "Hashrate", cls: "num" }, { label: "Temp", cls: "num" },
          { label: "Fan", cls: "num" }, { label: "Power", cls: "num" },
          { label: "Health", cls: "num" }, { label: "Util", cls: "num" },
          { label: "Uptime", cls: "num" }, { label: "A / R", cls: "num" }
        ],
        rows.map(function (d) {
          var healthCls = d.health > 93 ? "text-ok" : d.health > 85 ? "text-warn" : "text-crit";
          return [
            U.statusChip(d.status),
            "<b>" + U.esc(d.name) + "</b>",
            U.esc(d.zone),
            '<span class="num mono">' + U.fmtHash(d.hashrate) + "</span>",
            '<span class="num mono ' + (d.temp_c > 80 ? "text-attn" : "") + '">' +
            d.temp_c.toFixed(1) + "°</span>",
            '<span class="num mono">' + d.fan_pct.toFixed(0) + "%</span>",
            '<span class="num mono">' + U.fmtNum(d.power_w, 0) + " W</span>",
            '<span class="num mono ' + healthCls + '">' + d.health.toFixed(0) + "%</span>",
            '<span class="num mono">' + (d.utilization * 100).toFixed(0) + "%</span>",
            '<span class="num mono">' + U.fmtDuration(d.uptime_s) + "</span>",
            '<span class="num mono">' + U.fmtNum(d.accepted) + " / " + d.rejected + "</span>"
          ];
        }),
        null
      );
      U.bindRows(host, function (i) {
        views._deviceDrawer(rows[i]);
      });
    }
  };

  /* =============================== 3. SECTOR MAP =============================
     Interactive site map (adapted from mine-map spec): zone clusters, live
     nodes colored by status / thermal heat overlay, hazard zones, hashrate
     flow routes to the pool edge, zoom + pan + layer toggles. */
  views.map = {
    zoom: 1, panX: 0, panY: 0, dragging: false,
    layers: { status: true, thermal: true, hashrate: true, zones: true, routes: true },
    render: function (root) {
      root.innerHTML =
        '<div class="page-head"><h1>Sector Map</h1><span class="sub">Live worker topology · thermal & hazard layers</span></div>' +
        '<div class="map-shell" id="map-shell">' +
        '<canvas id="map-canvas" height="520"></canvas>' +
        '<div class="map-layers" role="group" aria-label="Map layers">' +
        ["status", "thermal", "hashrate", "zones", "routes"].map(function (l) {
          return '<label><input type="checkbox" data-layer="' + l + '"' +
            (views.map.layers[l] ? " checked" : "") + "> " + l + "</label>";
        }).join("") +
        "</div>" +
        '<div class="map-controls">' +
        '<button class="iconbtn" id="map-zin" aria-label="Zoom in">' + U.icon("zoom-in") + "</button>" +
        '<button class="iconbtn" id="map-zout" aria-label="Zoom out">' + U.icon("zoom-out") + "</button>" +
        '<button class="iconbtn" id="map-reset" aria-label="Reset view">' + U.icon("refresh") + "</button>" +
        "</div>" +
        '<div class="map-legend"><span class="dot dot-ok"></span> online &nbsp; ' +
        '<span class="dot dot-warn"></span> degraded &nbsp; <span class="dot dot-crit"></span> offline &nbsp; ' +
        '<span class="dot" style="background:#4c8dff"></span> maintenance &nbsp; ' +
        '<span class="muted">node size = hashrate · glow = temperature</span></div>' +
        "</div>" +
        '<div class="grid grid-kpi mt-4" id="map-zone-cards"></div>';

      var canvas = root.querySelector("#map-canvas");
      canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1);
      var shell = root.querySelector("#map-shell");
      U.$$("input[data-layer]", shell).forEach(function (cb) {
        cb.addEventListener("change", function () {
          views.map.layers[cb.dataset.layer] = cb.checked;
          views.map._draw(canvas);
        });
      });
      root.querySelector("#map-zin").addEventListener("click", function () {
        views.map.zoom = Math.min(3, views.map.zoom * 1.25); views.map._draw(canvas);
      });
      root.querySelector("#map-zout").addEventListener("click", function () {
        views.map.zoom = Math.max(0.5, views.map.zoom / 1.25); views.map._draw(canvas);
      });
      root.querySelector("#map-reset").addEventListener("click", function () {
        views.map.zoom = 1; views.map.panX = 0; views.map.panY = 0; views.map._draw(canvas);
      });
      canvas.addEventListener("mousedown", function (ev) {
        views.map.dragging = true; views.map._last = { x: ev.clientX, y: ev.clientY };
      });
      window.addEventListener("mouseup", function () { views.map.dragging = false; });
      canvas.addEventListener("mousemove", function (ev) {
        if (!views.map.dragging) return;
        views.map.panX += ev.clientX - views.map._last.x;
        views.map.panY += ev.clientY - views.map._last.y;
        views.map._last = { x: ev.clientX, y: ev.clientY };
        views.map._draw(canvas);
      });
      canvas.addEventListener("click", function (ev) {
        var rect = canvas.getBoundingClientRect();
        var hit = views.map._hitTest(ev.clientX - rect.left, ev.clientY - rect.top, canvas);
        if (hit) views._deviceDrawer(hit);
      });
      views.map._draw(canvas);
      views.map._zones(root.querySelector("#map-zone-cards"));
    },
    refresh: function (root) {
      if (!root || root.hidden) return;
      var canvas = root.querySelector("#map-canvas");
      if (canvas) views.map._draw(canvas);
      views.map._zones(root.querySelector("#map-zone-cards"));
    },
    _nodePos: function (d, canvas) {
      var w = canvas.clientWidth, h = 520;
      var zones = HF.selectors.zoneRollup();
      var zi = zones.map(function (z) { return z.zone; }).indexOf(d.zone);
      var col = zi % 2, row = Math.floor(zi / 2);
      var baseX = w * (0.22 + col * 0.42), baseY = 150 + row * 240;
      var idx = S.fleet.indexOf(d);
      var perRow = 6;
      var x = baseX + (idx % perRow) * 52 - 110;
      var y = baseY + Math.floor(idx / perRow) * 46 - 40;
      return { x: x, y: y };
    },
    _hitTest: function (mx, my, canvas) {
      var self = views.map;
      var cx = mx - canvas.clientWidth / 2 - self.panX;
      var cy = my - 260 - self.panY;
      for (var i = 0; i < S.fleet.length; i++) {
        var p = self._nodePos(S.fleet[i], canvas);
        var dx = p.x * self.zoom - cx, dy = p.y * self.zoom - cy;
        if (dx * dx + dy * dy < 220) return S.fleet[i];
      }
      return null;
    },
    _draw: function (canvas) {
      if (!canvas) return;
      var ctx = canvas.getContext("2d");
      var r = window.devicePixelRatio || 1;
      var w = canvas.clientWidth, h = 520;
      canvas.width = w * r; canvas.height = h * r;
      ctx.setTransform(r, 0, 0, r, 0, 0);
      ctx.clearRect(0, 0, w, h);
      var self = views.map;

      ctx.save();
      ctx.translate(w / 2 + self.panX, 260 + self.panY);
      ctx.scale(self.zoom, self.zoom);
      ctx.translate(-w / 2, -260);

      // Zone clusters
      if (self.layers.zones) {
        HF.selectors.zoneRollup().forEach(function (z, zi) {
          var col = zi % 2, row = Math.floor(zi / 2);
          var zx = w * (0.22 + col * 0.42) - 150, zy = 150 + row * 240 - 80;
          // hazard halo if zone runs hot
          if (z.avg_temp > 75) {
            ctx.fillStyle = "rgba(240,69,62,.07)";
            ctx.strokeStyle = "rgba(240,69,62,.35)";
          } else {
            ctx.fillStyle = "rgba(76,141,255,.05)";
            ctx.strokeStyle = "rgba(76,141,255,.22)";
          }
          roundRect(ctx, zx, zy, 320, 170, 14);
          ctx.fill();
          ctx.setLineDash(self.layers.zones && z.avg_temp > 75 ? [6, 4] : []);
          ctx.stroke();
          ctx.setLineDash([]);
          ctx.fillStyle = "#aebccb";
          ctx.font = "600 11px system-ui";
          ctx.fillText(z.zone.toUpperCase() + (z.avg_temp > 75 ? "  ⚠ THERMAL HAZARD" : ""),
            zx + 12, zy + 20);
          ctx.fillStyle = "#7c8b9c";
          ctx.font = "10px system-ui";
          ctx.fillText(z.site + " · " + z.count + " workers · " + HF.ui.fmtHash(z.hashrate),
            zx + 12, zy + 36);
        });
      }

      // Routes: each zone -> pool edge node (top right)
      if (self.layers.routes) {
        var poolX = w - 70, poolY = 60;
        HF.selectors.zoneRollup().forEach(function (z, zi) {
          var col = zi % 2, row = Math.floor(zi / 2);
          var zx = w * (0.22 + col * 0.42), zy = 150 + row * 240;
          ctx.beginPath();
          ctx.moveTo(zx, zy);
          ctx.bezierCurveTo(zx + 80, zy - 40, poolX - 80, poolY + 40, poolX, poolY);
          ctx.strokeStyle = "rgba(76,224,255,.28)";
          ctx.lineWidth = Math.max(1.5, z.hashrate / 2e7);
          ctx.setLineDash([2, 6]);
          ctx.stroke();
        });
        ctx.setLineDash([]);
        ctx.beginPath();
        ctx.arc(poolX, poolY, 16, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(76,141,255,.25)";
        ctx.fill();
        ctx.fillStyle = "#4cc2ff";
        ctx.font = "700 10px system-ui";
        ctx.textAlign = "center";
        ctx.fillText("POOL", poolX, poolY + 32);
        ctx.textAlign = "left";
      }

      // Nodes
      S.fleet.forEach(function (d) {
        var p = self._nodePos(d, canvas);
        var radius = self.layers.hashrate
          ? Math.max(6, Math.min(16, 5 + d.hashrate / 9e5)) : 8;
        if (self.layers.thermal && d.temp_c > 62) {
          var glow = ctx.createRadialGradient(p.x, p.y, 2, p.x, p.y, radius * 3.4);
          var heat = Math.min(1, (d.temp_c - 62) / 28);
          glow.addColorStop(0, "rgba(242,129,45," + (0.16 + heat * 0.3) + ")");
          glow.addColorStop(1, "rgba(242,129,45,0)");
          ctx.fillStyle = glow;
          ctx.beginPath();
          ctx.arc(p.x, p.y, radius * 3.4, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.beginPath();
        ctx.arc(p.x, p.y, radius, 0, Math.PI * 2);
        var color = !self.layers.status ? "#8fa3b8" :
          d.status === "online" ? "#2ed477" :
            d.status === "degraded" ? "#f5b83d" :
              d.status === "maintenance" ? "#4c8dff" : "#f0453e";
        ctx.fillStyle = color;
        ctx.fill();
        ctx.lineWidth = 1.5;
        ctx.strokeStyle = "rgba(11,14,19,.9)";
        ctx.stroke();
        if (d.throttled) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, radius + 3.5, 0, Math.PI * 2);
          ctx.strokeStyle = "#f2812d";
          ctx.stroke();
        }
      });
      ctx.restore();
    },
    _zones: function (host) {
      if (!host) return;
      host.innerHTML = HF.selectors.zoneRollup().map(function (z) {
        var state = z.offline > 0 ? "crit" : z.avg_temp > 75 ? "warn" : "ok";
        return '<article class="card kpi" data-state="' + state + '">' +
          '<div class="kpi-label">' + U.esc(z.zone) + "</div>" +
          '<div class="kpi-value">' + U.fmtHash(z.hashrate) + "</div>" +
          '<div class="kpi-foot"><span>' + z.count + " workers · " +
          z.avg_temp.toFixed(1) + "°C avg · " + (z.offline ? z.offline + " offline" : "all up") +
          "</span></div></article>";
      }).join("");
    }
  };

  /* ============================== 4. ANALYTICS ==============================
     Production / fleet / resource analytics: trend, shares, activity heatmap,
     efficiency scatter, allocation sankey. */
  views.analytics = {
    render: function (root) {
      var hr = S.series.hashrate.slice(-180);
      root.innerHTML =
        '<div class="page-head"><h1>Analytics Center</h1><span class="sub">Production · fleet · resource · efficiency</span></div>' +
        '<div class="grid grid-2">' +
        '<section class="card"><div class="card-title">' + U.icon("chart") +
        "Production analytics — hashrate trend</div>" +
        '<div class="chart-box" id="an-hr"></div></section>' +
        '<section class="card"><div class="card-title">' + U.icon("coin") +
        "Compute allocation flow</div>" +
        '<div class="chart-box" id="an-sankey"></div>' +
        '<div class="muted small mt-2">Where compute goes: total hashrate → contributor / project fund → accepted / stale / rejected shares.</div>' +
        "</section></div>" +

        '<div class="grid grid-2 mt-4">' +
        '<section class="card"><div class="card-title">' + U.icon("server") +
        "Fleet analytics — per-zone production</div>" +
        '<div class="chart-box" id="an-zones"></div></section>' +
        '<section class="card"><div class="card-title">' + U.icon("bolt") +
        "Resource analytics — power draw</div>" +
        '<div class="chart-box" id="an-power"></div></section></div>' +

        '<div class="grid grid-2 mt-4">' +
        '<section class="card"><div class="card-title">' + U.icon("grid") +
        "Activity heatmap (workers × recent time)</div>" +
        '<div class="chart-box" id="an-heat"></div></section>' +
        '<section class="card"><div class="card-title">' + U.icon("cpu") +
        "Efficiency — hashrate vs power per worker</div>" +
        '<div class="chart-box" id="an-scatter"></div>' +
        '<div class="muted small mt-2">Upper-left quadrant = best efficiency (high rate, low draw).</div>' +
        "</section></div>";

      C.area(root.querySelector("#an-hr"), [
        { name: "Hashrate", color: "#4cc2ff", data: hr }
      ], { labels: seriesLabels(hr.length), height: 260, unit: " H/s" });

      var m = S.metrics;
      C.sankey(root.querySelector("#an-sankey"), [
        { name: "Total", value: m.hashrate_10s || 1, color: "#4cc2ff", col: 0 },
        { name: "Contributor", value: (m.hashrate_10s || 0) * (100 - S.settings.donationPct) / 100, color: "#2ed477", col: 1 },
        { name: "Project fund", value: (m.hashrate_10s || 0) * S.settings.donationPct / 100, color: "#4c8dff", col: 1 },
        { name: "Accepted", value: (m.hashrate_10s || 0) * 0.985, color: "#2ed477", col: 2 },
        { name: "Stale/Rej", value: (m.hashrate_10s || 0) * 0.015, color: "#f2812d", col: 2 }
      ], [
        { from: "Total", to: "Contributor", value: (m.hashrate_10s || 0) * (100 - S.settings.donationPct) / 100 },
        { from: "Total", to: "Project fund", value: (m.hashrate_10s || 0) * S.settings.donationPct / 100 },
        { from: "Contributor", to: "Accepted", value: (m.hashrate_10s || 0) * (100 - S.settings.donationPct) / 100 * 0.985 },
        { from: "Project fund", to: "Accepted", value: (m.hashrate_10s || 0) * S.settings.donationPct / 100 * 0.985 },
        { from: "Contributor", to: "Stale/Rej", value: (m.hashrate_10s || 0) * (100 - S.settings.donationPct) / 100 * 0.015 }
      ], { height: 250 });

      var zones = HF.selectors.zoneRollup();
      C.bars(root.querySelector("#an-zones"),
        zones.map(function (z) { return z.zone.replace("Zone ", ""); }),
        zones.map(function (z) { return z.hashrate; }),
        { height: 230, color: "#4c8dff", unit: " H/s" });

      C.area(root.querySelector("#an-power"), [
        { name: "Power (W)", color: "#f5b83d", data: S.series.power.slice(-180) }
      ], { labels: seriesLabels(Math.min(180, S.series.power.length)), height: 230, unit: " W" });

      var matrix = S.fleet.slice(0, 12).map(function (d) {
        return d.trend && d.trend.length
          ? d.trend.slice(-12).map(function (v) { return v / 1000; })
          : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      });
      C.heatmap(root.querySelector("#an-heat"), matrix, {
        yLabels: S.fleet.slice(0, 12).map(function (d) { return d.name.slice(0, 12); }),
        xLabels: seriesLabels(12).filter(function (_, i) { return i % 2 === 0; }),
        height: 280
      });

      C.scatter(root.querySelector("#an-scatter"), S.fleet.map(function (d) {
        return {
          x: d.power_w, y: d.hashrate / 1000,
          label: d.name,
          color: d.status === "online" ? "#2ed477" :
            d.status === "degraded" ? "#f5b83d" :
              d.status === "offline" ? "#f0453e" : "#4c8dff"
        };
      }), { xName: "power (W)", yName: "hashrate (kH/s)", height: 250 });
    },
    refresh: function (root) {
      if (root && !root.hidden) views.analytics.render(root);
    }
  };

  /* ================================ 5. SAFETY ================================
     Safety operations: dominant emergency controls, alert register with
     acknowledgement, 5x5 risk matrix, evacuation/safe-shutdown status. */
  views.safety = {
    render: function (root) {
      var open = HF.selectors.openAlerts();
      var crit = open.filter(function (a) { return a.severity === "critical"; });
      root.innerHTML =
        '<div class="page-head"><h1>Safety Center</h1><span class="sub">Thermal · availability · operational risk</span></div>' +

        (crit.length ?
          '<section class="card mb-4" style="border-color:var(--color-crit);background:var(--crit-soft)">' +
          '<div class="card-title" style="color:var(--color-crit)">' + U.icon("warn") +
          "EMERGENCY — " + crit.length + " CRITICAL ALERT" + (crit.length > 1 ? "S" : "") + "</div>" +
          '<div class="small mb-3">' + crit.slice(0, 3).map(function (a) {
            return U.esc(a.detail);
          }).join(" · ") + "</div>" +
          '<div class="row"><button class="btn btn-danger btn-lg" id="btn-emergency">' +
          U.icon("power") + "EMERGENCY STOP — ALL WORKERS</button>" +
          '<button class="btn" id="btn-ack-crit">Acknowledge criticals</button></div>' +
          "</section>" : "") +

        '<div class="grid grid-2">' +
        '<section class="card"><div class="card-title">' + U.icon("shield") +
        'Risk assessment matrix <span class="right muted small">likelihood × impact</span></div>' +
        '<div id="safety-matrix"></div></section>' +
        '<section class="card"><div class="card-title">' + U.icon("users") +
        "Evacuation / safe-shutdown status</div>" +
        '<div class="kv"><dt>Workers under control</dt><dd>' + S.metrics.total_workers + "</dd>" +
        "<dt>Safe-state workers (maintenance)</dt><dd>" + HF.selectors.byStatus("maintenance").length + "</dd>" +
        "<dt>Unacknowledged alerts</dt><dd>" + open.length + "</dd>" +
        "<dt>Thermal throttling now</dt><dd>" + (S.metrics.throttled || 0) + "</dd></div>" +
        '<div class="small muted mt-3">Safe shutdown: stop supervised miners gracefully, place workers in maintenance state, and record the incident below. The emergency stop button performs this sequence for the whole fleet.</div>' +
        '<button class="btn btn-block mt-3" id="btn-safe-shutdown">' + U.icon("pause") +
        "Graceful fleet stand-down</button></section></div>" +

        '<section class="card mt-4"><div class="card-title">' + U.icon("bell") +
        'Incident register <span class="right"><button class="btn btn-sm btn-ghost" id="btn-ack-all-2">Acknowledge all</button></span></div>' +
        '<div id="safety-register"></div></section>';

      views._riskMatrix(root.querySelector("#safety-matrix"));
      views._register(root.querySelector("#safety-register"));

      var em = root.querySelector("#btn-emergency");
      if (em) {
        em.addEventListener("click", function () {
          U.drawer("EMERGENCY STOP",
            '<div class="card" style="border-color:var(--color-crit)">' +
            '<p class="mb-3">This places <b>every worker</b> into maintenance state and stops supervised miners. ' +
            "It is the digital equivalent of a site-wide evacuation order. Confirm only if the situation is real.</p>" +
            '<button class="btn btn-danger btn-block btn-lg" id="em-confirm">CONFIRM — STOP EVERYTHING</button>' +
            '<button class="btn btn-ghost btn-block mt-2" onclick="HF.ui.closeDrawer()">Cancel</button></div>');
          document.getElementById("em-confirm").addEventListener("click", function () {
            HF.emergencyStop();
            U.closeDrawer();
            U.toast("EMERGENCY STOP ISSUED", "All workers placed in safe state.", "crit");
            views.refresh(root);
          });
        });
      }
      var ackC = root.querySelector("#btn-ack-crit");
      if (ackC) ackC.addEventListener("click", function () {
        crit.forEach(function (a) { HF.ackAlert(a.id); });
        views.refresh(root);
      });
      root.querySelector("#btn-ack-all-2").addEventListener("click", function () {
        open.forEach(function (a) { HF.ackAlert(a.id); });
        views.refresh(root);
      });
      root.querySelector("#btn-safe-shutdown").addEventListener("click", function () {
        HF.emergencyStop();
        U.toast("Fleet stand-down initiated", "Graceful stop sequence running.", "warn");
        views.refresh(root);
      });
    },
    refresh: function (root) {
      if (root && !root.hidden) views.safety.render(root);
    },
    _register: function (host) {
      if (!host) return;
      var rows = S.alerts.slice(-25).reverse();
      host.innerHTML = U.table(
        [{ label: "Sev" }, { label: "Alert" }, { label: "Device" }, { label: "Zone" },
        { label: "Age", cls: "num" }, { label: "State" }, { label: "" }],
        rows.map(function (a) {
          return [
            U.sevChip(a.severity), U.esc(a.title) +
            '<div class="muted small">' + U.esc(a.detail) + "</div>",
            U.esc(a.device), U.esc(a.zone),
            '<span class="num mono">' + U.ago(a.ts) + "</span>",
            a.ack ? '<span class="chip chip-ok">ACK</span>' : '<span class="chip chip-warn">OPEN</span>',
            a.ack ? "" : '<button class="btn btn-sm" data-ack="' + a.id + '">Ack</button>'
          ];
        })
      );
      U.$$("button[data-ack]", host).forEach(function (btn) {
        btn.addEventListener("click", function (ev) {
          ev.stopPropagation();
          HF.ackAlert(btn.dataset.ack);
          views.safety.refresh(document.getElementById("view-safety"));
        });
      });
    },
    _riskMatrix: function (host) {
      if (!host) return;
      var items = [];
      S.fleet.forEach(function (d) {
        if (d.temp_c > 86) items.push({ name: d.name + " thermal", l: 3, i: 4 });
        if (d.status === "offline") items.push({ name: d.name + " lost", l: 2, i: 3 });
      });
      var crit = HF.selectors.criticalAlerts().length;
      if (crit) items.push({ name: "Critical backlog", l: 4, i: 4 });
      var openW = HF.selectors.openAlerts().filter(function (a) {
        return a.severity === "warning";
      }).length;
      if (openW) items.push({ name: "Warnings", l: 3, i: 2 });
      if (!items.length) items.push({ name: "Nominal", l: 1, i: 1 });

      var html = '<div class="risk-matrix"><div class="risk-axis"></div>' +
        [1, 2, 3, 4, 5].map(function (i) {
          return '<div class="risk-axis">I' + i + "</div>";
        }).join("");
      for (var l = 5; l >= 1; l--) {
        html += '<div class="risk-axis">L' + l + "</div>";
        for (var imp = 1; imp <= 5; imp++) {
          var score = l * imp;
          var cls = score >= 16 ? "r4" : score >= 9 ? "r3" : score >= 4 ? "r2" : "r1";
          var here = items.filter(function (it) { return it.l === l && it.i === imp; });
          html += '<div class="risk-cell ' + cls + '" title="' +
            U.esc(here.map(function (it) { return it.name; }).join(", ")) + '">' +
            here.map(function (it) {
              return '<span class="tag">' + U.esc(it.name) + "</span>";
            }).join(" ") + "</div>";
        }
      }
      html += '<div class="risk-axis"></div><div class="risk-axis" style="grid-column:span 5">IMPACT →</div>';
      html += "</div>";
      host.innerHTML = html;
    }
  };

  /* ============================== 6. MAINTENANCE ==============================
     Predictive maintenance: health ranking, failure-risk forecast, downtime
     cost, scheduled work queue (adapted: technicians → maintenance windows). */
  views.maintenance = {
    render: function (root) {
      var risky = S.fleet.slice().sort(function (a, b) {
        return a.health - b.health;
      }).slice(0, 8);
      var downtimeHours = S.fleet.filter(function (d) {
        return d.status === "offline" || d.status === "degraded";
      }).length * 3.5;
      var downtimeCost = downtimeHours * (S.executive.revenue_usd_day || 0) /
        Math.max(1, S.metrics.total_workers) / 24;

      root.innerHTML =
        '<div class="page-head"><h1>Maintenance</h1><span class="sub">Predictive health · work queue · downtime cost</span></div>' +
        '<div class="grid grid-kpi">' +
        U.kpi({
          label: "Fleet health average", state: (S.metrics.health_avg || 100) > 93 ? "ok" : "warn",
          value: U.fmtPct(S.metrics.health_avg, 0), foot: "composite health score"
        }) +
        U.kpi({
          label: "At-risk workers", state: risky.filter(function (d) { return d.health < 90; }).length ? "warn" : "ok",
          value: String(risky.filter(function (d) { return d.health < 90; }).length),
          foot: "health below 90%"
        }) +
        U.kpi({
          label: "Downtime cost (est.)", state: "attn",
          value: U.fmtMoney(downtimeCost), foot: U.fmtNum(downtimeHours, 1) + " h degraded/offline this cycle"
        }) +
        U.kpi({
          label: "Throttling now", state: (S.metrics.throttled || 0) ? "warn" : "ok",
          value: String(S.metrics.throttled || 0), foot: "workers in thermal protection"
        }) +
        "</div>" +

        '<div class="grid grid-2 mt-4">' +
        '<section class="card"><div class="card-title">' + U.icon("wrench") +
        "Failure prediction — watch list</div>" +
        '<div id="mnt-watch"></div>' +
        '<div class="muted small mt-3">Composite risk model: health score + thermal stress + reject rate + uptime age. ' +
        "Schedule intervention before health falls below 85%.</div></section>" +
        '<section class="card"><div class="card-title">' + U.icon("clock") +
        "Scheduled maintenance windows</div>" +
        '<div class="feed">' +
        '<div class="feed-item info">' + U.icon("clock") +
        "<div><b>Weekly firmware & dust cycle</b><div class='muted'>Zone Alpha · Sunday 02:00 · owner: ops-team-A</div></div></div>" +
        '<div class="feed-item info">' + U.icon("clock") +
        "<div><b>PSU inspection</b><div class='muted'>Zone Gamma · Wednesday 23:00 · owner: ops-team-B</div></div></div>" +
        '<div class="feed-item warn">' + U.icon("wrench") +
        "<div><b>Thermal paste replacement</b><div class='muted'>Watch-list workers · next available window</div></div></div>" +
        "</div>" +
        '<div class="card-title mt-4">' + U.icon("layers") + "Spare parts inventory</div>" +
        '<div class="kv"><dt>Cooling fans</dt><dd>14 units</dd>' +
        "<dt>PSU 1200W</dt><dd>6 units</dd>" +
        "<dt>Thermal kits</dt><dd>22 kits</dd>" +
        "<dt>Control boards</dt><dd>3 units</dd></div></section></div>";

      views._watch(root.querySelector("#mnt-watch"), risky);
    },
    refresh: function (root) {
      if (root && !root.hidden) views.maintenance.render(root);
    },
    _watch: function (host, risky) {
      if (!host) return;
      host.innerHTML = U.table(
        [{ label: "Worker" }, { label: "Health", cls: "num" }, { label: "Risk driver" },
        { label: "Temp", cls: "num" }, { label: "Rejects", cls: "num" }, { label: "Uptime", cls: "num" }],
        risky.map(function (d) {
          var healthCls = d.health > 93 ? "text-ok" : d.health > 85 ? "text-warn" : "text-crit";
          var driver = d.throttled ? "thermal throttle" :
            d.status === "offline" ? "offline" :
              d.rejected > 4 ? "share rejects" : "age / degradation";
          return [
            "<b>" + U.esc(d.name) + "</b>",
            '<span class="num mono ' + healthCls + '">' + d.health.toFixed(1) + "%</span>",
            driver,
            '<span class="num mono">' + d.temp_c.toFixed(1) + "°</span>",
            '<span class="num mono">' + d.rejected + "</span>",
            '<span class="num mono">' + U.fmtDuration(d.uptime_s) + "</span>"
          ];
        })
      );
      U.bindRows(host, function (i) { views._deviceDrawer(risky[i]); });
    }
  };

  /* ============================== 7. EXECUTIVE ==============================
     Management view: profitability, targets, efficiency, cost & sustainability. */
  views.executive = {
    render: function (root) {
      var e = S.executive, m = S.metrics;
      root.innerHTML =
        '<div class="page-head"><h1>Executive Dashboard</h1><span class="sub">Profitability · targets · sustainability</span></div>' +
        '<div class="grid grid-kpi">' +
        U.kpi({
          label: "Est. production", state: "info",
          value: (e.xmr_per_day || 0).toFixed(4), unit: "XMR/day",
          foot: U.fmtMoney(e.revenue_usd_day) + "/day at " + U.fmtMoney(e.xmr_price_usd) + "/XMR"
        }) +
        U.kpi({
          label: "Energy cost", state: "attn",
          value: U.fmtMoney(e.energy_cost_usd_day), unit: "/day",
          foot: U.fmtNum(e.energy_kwh_day, 1) + " kWh/day @ " + U.fmtMoney(S.settings.energyPrice) + "/kWh"
        }) +
        U.kpi({
          label: "Gross margin", state: (e.gross_margin_pct || 0) > 60 ? "ok" : "warn",
          value: U.fmtPct(e.gross_margin_pct, 1),
          foot: "revenue minus energy cost"
        }) +
        U.kpi({
          label: "Sustainability", state: "ok",
          value: U.fmtNum(e.carbon_kg_day, 1), unit: "kg CO₂/day",
          foot: U.fmtNum(e.energy_per_mhash_j, 1) + " J per MH/s · grid factor 0.417"
        }) +
        "</div>" +

        '<div class="grid grid-2 mt-4">' +
        '<section class="card"><div class="card-title">' + U.icon("crown") +
        "Production vs target</div>" +
        '<div class="row"><div class="big-num">' + U.fmtHash(m.hashrate_10s) + "</div>" +
        '<span class="spacer"></span><div class="muted">target ' +
        U.fmtHash(e.target_hashrate || S.settings.targetHashrate) + "</div></div>" +
        '<div class="bar mt-3 ' + ((e.pct_of_target || 0) > 90 ? "bar-ok" : "bar-warn") + '">' +
        '<span style="width:' + Math.min(100, e.pct_of_target || 0).toFixed(1) + '%"></span></div>' +
        '<div class="row mt-2"><span class="muted small">' +
        U.fmtPct(e.pct_of_target, 1) + " of target</span><span class='spacer'></span>" +
        '<span class="muted small">uptime ' + U.fmtPct(e.uptime_pct, 1) + "</span></div>" +
        '<div class="chart-box mt-4" id="exec-trend"></div></section>' +

        '<section class="card"><div class="card-title">' + U.icon("leaf") +
        "Cost & sustainability metrics</div>" +
        '<div class="kv">' +
        "<dt>Revenue / day</dt><dd>" + U.fmtMoney(e.revenue_usd_day) + "</dd>" +
        "<dt>Energy / day</dt><dd>" + U.fmtMoney(e.energy_cost_usd_day) + "</dd>" +
        "<dt>Gross profit / day</dt><dd>" + U.fmtMoney(e.revenue_usd_day - e.energy_cost_usd_day) + "</dd>" +
        "<dt>Per worker revenue</dt><dd>" + U.fmtMoney(e.revenue_usd_day / Math.max(1, m.total_workers)) + "</dd>" +
        "<dt>Energy per MH/s</dt><dd>" + U.fmtNum(e.energy_per_mhash_j, 1) + " J</dd>" +
        "<dt>Carbon / day</dt><dd>" + U.fmtNum(e.carbon_kg_day, 1) + " kg</dd>" +
        "<dt>Project fund share</dt><dd>" + (e.donation_xmr_day || 0).toFixed(5) + " XMR/day</dd>" +
        "</div>" +
        '<div class="small muted mt-3">All figures derive from live telemetry plus the price/tariff ' +
        "assumptions in Settings. Project-fund share is fully transparent and opt-out.</div></section></div>";

      C.area(root.querySelector("#exec-trend"), [
        { name: "Hashrate", color: "#2ed477", data: S.series.hashrate.slice(-90) }
      ], { height: 180, labels: seriesLabels(Math.min(90, S.series.hashrate.length)) });
    },
    refresh: function (root) {
      if (root && !root.hidden) views.executive.render(root);
    }
  };

  /* ================================ 8. COPILOT ================================
     Conversational mining copilot. Conversation persists across ticks. */
  views.copilot = {
    log: [],
    render: function (root) {
      root.innerHTML =
        '<div class="page-head"><h1>AI Mining Copilot</h1>' +
        '<span class="sub">on-device intent engine · works offline</span></div>' +
        '<div class="chat"><div class="chat-log" id="chat-log" aria-live="polite"></div><div>' +
        '<div class="suggestions" id="chat-suggestions"></div>' +
        '<div class="chat-input">' +
        '<input id="chat-input" type="text" placeholder="Ask about hashrate, failures, zones, power, profit…" aria-label="Ask the copilot">' +
        '<button class="btn btn-primary" id="chat-send">Ask</button></div></div></div>';

      if (!views.copilot.log.length) {
        views.copilot.log.push({
          who: "bot",
          text: "Fleet copilot online. I read the same telemetry as the dashboard — " +
            "ask me about worker performance, thermal risk, failures, zones, power, " +
            "share acceptance, allocation, profitability, or alerts.",
          cards: []
        });
      }
      views.copilot._paint();
      var host = root.querySelector("#chat-suggestions");
      host.innerHTML = HF.copilot.suggestions.map(function (s) {
        return '<button class="suggestion">' + U.esc(s) + "</button>";
      }).join("");
      U.$$(".suggestion", host).forEach(function (btn) {
        btn.addEventListener("click", function () {
          views.copilot.ask(btn.textContent);
        });
      });
      var input = root.querySelector("#chat-input");
      root.querySelector("#chat-send").addEventListener("click", function () {
        views.copilot.ask(input.value);
        input.value = "";
      });
      input.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") {
          views.copilot.ask(input.value);
          input.value = "";
        }
      });
    },
    refresh: function () { /* conversation is stable across ticks */ },
    ask: function (q) {
      if (!q || !q.trim()) return;
      views.copilot.log.push({ who: "user", text: q.trim() });
      var res = HF.copilot.answer(q.trim());
      views.copilot.log.push({ who: "bot", text: res.text, cards: res.cards || [] });
      views.copilot._paint();
    },
    _paint: function () {
      var log = document.getElementById("chat-log");
      if (!log) return;
      log.innerHTML = views.copilot.log.map(function (msg) {
        if (msg.who === "user") {
          return '<div class="msg msg-user">' + U.esc(msg.text) + "</div>";
        }
        return '<div class="msg msg-bot"><div class="msg-head">' + U.icon("bot") +
          "Fleet Copilot</div><div>" + U.esc(msg.text) + "</div>" +
          (msg.cards || []).map(function (card) {
            if (card.type === "table") {
              return '<div class="msg-cards"><div class="msg-card"><table class="tbl">' +
                "<thead><tr>" + card.cols.map(function (c) {
                  return "<th>" + U.esc(c) + "</th>";
                }).join("") + "</tr></thead><tbody>" +
                card.rows.map(function (r) {
                  return "<tr>" + r.map(function (cell) {
                    return "<td>" + cell + "</td>";
                  }).join("") + "</tr>";
                }).join("") + "</tbody></table></div></div>";
            }
            if (card.type === "list") {
              return '<div class="msg-cards"><div class="msg-card"><ul>' +
                card.items.map(function (it) {
                  return "<li>• " + U.esc(it) + "</li>";
                }).join("") + "</ul></div></div>";
            }
            if (card.type === "stat") {
              return '<div class="msg-cards"><div class="msg-card"><dl class="kv">' +
                card.items.map(function (it) {
                  return "<dt>" + U.esc(it[0]) + "</dt><dd>" + U.esc(it[1]) + "</dd>";
                }).join("") + "</dl></div></div>";
            }
            if (card.type === "action") {
              return '<div class="msg-cards"><a class="btn btn-primary" href="' +
                U.esc(card.href) + '">' + U.esc(card.label) + "</a></div>";
            }
            return "";
          }).join("") + "</div>";
      }).join("");
      log.scrollTop = log.scrollHeight;
    }
  };

  /* ================================ 9. SETTINGS ================================ */
  views.settings = {
    render: function (root) {
      var st = S.settings;
      root.innerHTML =
        '<div class="page-head"><h1>Settings</h1><span class="sub">Local preferences · persisted on this device</span></div>' +
        '<div class="grid grid-flat">' +
        '<section class="card"><div class="card-title">' + U.icon("coin") +
        "Economics assumptions</div><div class='form-grid'>" +
        '<div class="field"><label for="set-xmr">XMR price (USD)</label>' +
        '<input id="set-xmr" type="number" step="1" value="' + st.xmrPrice + '">' +
        '<span class="hint">Used for profitability estimates.</span></div>' +
        '<div class="field"><label for="set-energy">Energy price ($/kWh)</label>' +
        '<input id="set-energy" type="number" step="0.01" value="' + st.energyPrice + '">' +
        '<span class="hint">Used for energy cost & margin.</span></div>' +
        '<div class="field"><label for="set-target">Target hashrate (H/s)</label>' +
        '<input id="set-target" type="number" step="1e6" value="' + st.targetHashrate + '"></div>' +
        '<div class="field"><label for="set-donate">Project fund share (%)</label>' +
        '<input id="set-donate" type="number" step="0.5" min="0" max="5" value="' + st.donationPct + '">' +
        '<span class="hint">0–5%. The CLI enforces the same ratio; 0 disables it.</span></div>' +
        "</div></section>" +

        '<section class="card"><div class="card-title">' + U.icon("layers") +
        "Accessibility & display</div>" +
        '<div class="switch-row"><div class="grow"><b>High contrast mode</b>' +
        '<div class="muted small">Stronger borders and text (WCAG AAA targets).</div></div>' +
        '<button class="switch" id="set-contrast" role="switch" aria-checked="' +
        (st.highContrast ? "true" : "false") + '" aria-label="High contrast"></button></div>' +
        '<div class="switch-row"><div class="grow"><b>Reduce motion</b>' +
        '<div class="muted small">Disables animations and transitions.</div></div>' +
        '<button class="switch" id="set-motion" role="switch" aria-checked="' +
        (st.reducedMotion ? "true" : "false") + '" aria-label="Reduce motion"></button></div>' +
        '<div class="field mt-3"><label for="set-scale">Text scale</label>' +
        '<select id="set-scale"><option value="100"' + (st.textScale === "100" ? " selected" : "") + ">100%</option>" +
        '<option value="125"' + (st.textScale === "125" ? " selected" : "") + ">125%</option>" +
        '<option value="150"' + (st.textScale === "150" ? " selected" : "") + ">150%</option>" +
        "</select></div></section></div>" +

        '<section class="card mt-4"><div class="card-title">' + U.icon("info") +
        "About & transparency</div>" +
        '<p class="small muted">Hashflow v2 — Fleet Command. Data source: <b id="set-mode">' +
        (S.mode === "live" ? "live supervisor" : "demo simulator") + "</b>. " +
        "Mining runs on hardware you own or are authorized to use; the CLI enforces " +
        "an informed-consent gate before starting. Donation is transparent (exact " +
        "share printed before start) and optional (--donation 0). " +
        "Install this dashboard as an app from your browser menu for offline use.</p></section>";

      function bindNum(id, key, parse) {
        var el = root.querySelector(id);
        el.addEventListener("change", function () {
          S.settings[key] = parse(el.value);
          HF.saveSettings();
          U.toast("Saved", key + " updated.", "ok");
        });
      }
      bindNum("#set-xmr", "xmrPrice", parseFloat);
      bindNum("#set-energy", "energyPrice", parseFloat);
      bindNum("#set-target", "targetHashrate", parseFloat);
      bindNum("#set-donate", "donationPct", function (v) {
        return Math.max(0, Math.min(5, parseFloat(v) || 0));
      });
      root.querySelector("#set-contrast").addEventListener("click", function () {
        S.settings.highContrast = !S.settings.highContrast;
        HF.saveSettings();
        views.settings.render(root);
      });
      root.querySelector("#set-motion").addEventListener("click", function () {
        S.settings.reducedMotion = !S.settings.reducedMotion;
        HF.saveSettings();
        views.settings.render(root);
      });
      root.querySelector("#set-scale").addEventListener("change", function (ev) {
        S.settings.textScale = ev.target.value;
        HF.saveSettings();
      });
    },
    refresh: function () { }
  };
})();
