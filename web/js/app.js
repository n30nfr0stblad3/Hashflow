/* =====================================================================
   HF.app — shell: hash router, command palette (Ctrl+K), global search,
   keyboard shortcuts, alert banner, connection pill, tick refresh.
   ===================================================================== */
(function () {
  "use strict";
  window.HF = window.HF || {};
  var U = HF.ui;
  var VIEWS = ["dashboard", "fleet", "map", "analytics", "safety",
    "maintenance", "executive", "copilot", "settings"];
  var current = "dashboard";

  /* ------------------------------ preferences ------------------------------ */
  function applySettings() {
    var st = HF.state.settings;
    document.documentElement.dataset.contrast = st.highContrast ? "high" : "normal";
    document.documentElement.dataset.scale = st.textScale || "100";
    if (st.reducedMotion) {
      document.documentElement.style.setProperty("--dur", "0ms");
    } else {
      document.documentElement.style.removeProperty("--dur");
    }
  }
  HF.on("settings", applySettings);

  /* --------------------------------- router -------------------------------- */
  function routeFromHash() {
    var m = (location.hash || "#/dashboard").match(/^#\/([a-z]+)/);
    return m && VIEWS.indexOf(m[1]) >= 0 ? m[1] : "dashboard";
  }
  function navigate() {
    current = routeFromHash();
    VIEWS.forEach(function (v) {
      var section = document.getElementById("view-" + v);
      if (section) section.hidden = v !== current;
    });
    U.$$(".navitem").forEach(function (item) {
      item.classList.toggle("active", item.dataset.view === current);
      if (item.dataset.view === current) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
    var section = document.getElementById("view-" + current);
    if (section && HF.views[current]) {
      HF.views[current].render(section);
    }
    document.getElementById("main").focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }
  window.addEventListener("hashchange", navigate);

  /* ------------------------------- clock pill ------------------------------ */
  setInterval(function () {
    var el = document.getElementById("clock-pill");
    if (el) el.textContent = new Date().toLocaleTimeString(undefined, { hour12: false });
  }, 1000);

  /* ------------------------------ conn status ------------------------------ */
  HF.on("conn", function (mode) {
    var dot = document.getElementById("conn-dot");
    var label = document.getElementById("conn-label");
    if (!dot || !label) return;
    if (mode === "live") {
      dot.className = "dot dot-ok";
      label.textContent = "LIVE";
    } else if (mode === "reconnecting") {
      dot.className = "dot dot-warn";
      label.textContent = "RECONNECT";
    } else {
      dot.className = "dot dot-off";
      label.textContent = "DEMO";
    }
  });

  /* ------------------------------ alert banner ----------------------------- */
  HF.on("alerts", function (alerts) {
    var crit = HF.selectors.criticalAlerts();
    var banner = document.getElementById("alert-banner");
    var badge = document.getElementById("bell-badge");
    var navBadge = document.getElementById("nav-safety-badge");
    var open = HF.selectors.openAlerts();
    if (badge) {
      badge.hidden = open.length === 0;
      badge.textContent = open.length > 99 ? "99+" : open.length;
    }
    if (navBadge) {
      navBadge.hidden = crit.length === 0;
      navBadge.textContent = crit.length;
    }
    if (banner) {
      banner.hidden = crit.length === 0;
      if (crit.length) {
        document.getElementById("alert-banner-text").textContent =
          crit.length + " unacknowledged critical alert" + (crit.length > 1 ? "s" : "") +
          " — " + crit[crit.length - 1].detail;
      }
    }
    // Update sidebar allocation bar from settings
    var pct = HF.state.settings.donationPct;
    var contrib = document.getElementById("split-contrib");
    var owner = document.getElementById("split-owner");
    if (contrib && owner) {
      contrib.style.width = (100 - pct) + "%";
      owner.style.width = Math.max(1.5, pct) + "%";
    }
    var cp = document.getElementById("split-contrib-pct");
    var op = document.getElementById("split-owner-pct");
    if (cp) cp.textContent = (100 - pct).toFixed(1) + "%";
    if (op) op.textContent = pct.toFixed(1) + "%";
  });

  document.getElementById("alert-banner-cta").addEventListener("click", function () {
    location.hash = "#/safety";
  });

  /* ------------------------------- tick loop ------------------------------- */
  HF.on("tick", function () {
    var section = document.getElementById("view-" + current);
    if (section && HF.views[current] && HF.views[current].refresh) {
      HF.views[current].refresh(section);
    }
  });

  /* ------------------------------- searchbox ------------------------------- */
  var searchInput = document.getElementById("global-search");
  searchInput.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter" && searchInput.value.trim()) {
      // Device name hit -> fleet drawer; otherwise run as copilot query.
      var q = searchInput.value.trim();
      var dev = HF.selectors.deviceByName(q.toUpperCase()) ||
        HF.state.fleet.filter(function (d) {
          return d.name.toLowerCase().indexOf(q.toLowerCase()) >= 0;
        })[0];
      if (dev) {
        location.hash = "#/fleet";
        setTimeout(function () { HF.views._deviceDrawer(dev); }, 60);
      } else {
        HF.views.copilot.log.push({ who: "user", text: q });
        var res = HF.copilot.answer(q);
        HF.views.copilot.log.push({ who: "bot", text: res.text, cards: res.cards || [] });
        location.hash = "#/copilot";
      }
      searchInput.value = "";
    }
  });

  /* --------------------------- command palette ----------------------------- */
  var COMMANDS = [
    { label: "Go to Dashboard", kind: "navigate", run: function () { location.hash = "#/dashboard"; } },
    { label: "Go to Fleet", kind: "navigate", run: function () { location.hash = "#/fleet"; } },
    { label: "Go to Sector Map", kind: "navigate", run: function () { location.hash = "#/map"; } },
    { label: "Go to Analytics", kind: "navigate", run: function () { location.hash = "#/analytics"; } },
    { label: "Go to Safety Center", kind: "navigate", run: function () { location.hash = "#/safety"; } },
    { label: "Go to Maintenance", kind: "navigate", run: function () { location.hash = "#/maintenance"; } },
    { label: "Go to Executive Dashboard", kind: "navigate", run: function () { location.hash = "#/executive"; } },
    { label: "Open AI Copilot", kind: "navigate", run: function () { location.hash = "#/copilot"; } },
    { label: "Open Settings", kind: "navigate", run: function () { location.hash = "#/settings"; } },
    {
      label: "Acknowledge all alerts", kind: "action", run: function () {
        HF.selectors.openAlerts().forEach(function (a) { HF.ackAlert(a.id); });
        U.toast("Acknowledged", "All open alerts marked as read.", "ok");
      }
    },
    {
      label: "Show workers with low hashrate", kind: "copilot", run: function () {
        HF.views.copilot.log.push({ who: "user", text: "Show workers with low hashrate" });
        var res = HF.copilot.answer("Show workers with low hashrate");
        HF.views.copilot.log.push({ who: "bot", text: res.text, cards: res.cards || [] });
        location.hash = "#/copilot";
      }
    },
    {
      label: "Predict equipment failures this week", kind: "copilot", run: function () {
        HF.views.copilot.log.push({ who: "user", text: "Predict equipment failures this week" });
        var res = HF.copilot.answer("Predict equipment failures this week");
        HF.views.copilot.log.push({ who: "bot", text: res.text, cards: res.cards || [] });
        location.hash = "#/copilot";
      }
    },
    {
      label: "Toggle high contrast", kind: "display", run: function () {
        HF.state.settings.highContrast = !HF.state.settings.highContrast;
        HF.saveSettings();
      }
    },
    {
      label: "Toggle reduce motion", kind: "display", run: function () {
        HF.state.settings.reducedMotion = !HF.state.settings.reducedMotion;
        HF.saveSettings();
      }
    }
  ];

  var paletteOpen = false;
  var paletteIdx = 0;
  var paletteItems = [];

  function openPalette() {
    paletteOpen = true;
    document.getElementById("palette-overlay").hidden = false;
    var input = document.getElementById("palette-search");
    input.value = "";
    filterPalette("");
    input.focus();
  }
  function closePalette() {
    paletteOpen = false;
    document.getElementById("palette-overlay").hidden = true;
  }
  function filterPalette(q) {
    q = q.toLowerCase();
    paletteItems = COMMANDS.filter(function (c) {
      return c.label.toLowerCase().indexOf(q) >= 0;
    });
    paletteIdx = 0;
    paintPalette();
  }
  function paintPalette() {
    var list = document.getElementById("palette-list");
    list.innerHTML = paletteItems.map(function (c, i) {
      return '<li role="option" aria-selected="' + (i === paletteIdx) + '" data-idx="' + i + '">' +
        U.icon(c.kind === "navigate" ? "grid" : c.kind === "copilot" ? "bot" :
          c.kind === "display" ? "layers" : "bolt") +
        "<span>" + U.esc(c.label) + '</span><span class="kind">' + c.kind + "</span></li>";
    }).join("");
    U.$$("li", list).forEach(function (li) {
      li.addEventListener("click", function () {
        runPalette(+li.dataset.idx);
      });
    });
  }
  function runPalette(idx) {
    var item = paletteItems[idx];
    if (item) {
      closePalette();
      item.run();
    }
  }
  document.getElementById("palette-search").addEventListener("input", function (ev) {
    filterPalette(ev.target.value);
  });
  document.getElementById("palette-search").addEventListener("keydown", function (ev) {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      paletteIdx = Math.min(paletteItems.length - 1, paletteIdx + 1);
      paintPalette();
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      paletteIdx = Math.max(0, paletteIdx - 1);
      paintPalette();
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      runPalette(paletteIdx);
    } else if (ev.key === "Escape") {
      closePalette();
    }
  });
  document.getElementById("palette-overlay").addEventListener("click", function (ev) {
    if (ev.target === ev.currentTarget) closePalette();
  });
  document.getElementById("btn-palette").addEventListener("click", openPalette);

  /* ---------------------------- keyboard shortcuts --------------------------- */
  document.addEventListener("keydown", function (ev) {
    var tag = (ev.target.tagName || "").toLowerCase();
    var typing = tag === "input" || tag === "textarea" || tag === "select";
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
      ev.preventDefault();
      paletteOpen ? closePalette() : openPalette();
    } else if (ev.key === "/" && !typing) {
      ev.preventDefault();
      searchInput.focus();
    } else if (ev.key === "Escape") {
      closePalette();
      U.closeDrawer();
      document.getElementById("more-sheet").hidden = true;
    }
  });

  /* -------------------------------- buttons -------------------------------- */
  document.getElementById("btn-contrast").addEventListener("click", function () {
    HF.state.settings.highContrast = !HF.state.settings.highContrast;
    HF.saveSettings();
  });
  document.getElementById("btn-bell").addEventListener("click", function () {
    location.hash = "#/safety";
  });
  document.getElementById("drawer-close").addEventListener("click", U.closeDrawer);
  document.getElementById("btn-more").addEventListener("click", function () {
    document.getElementById("more-sheet").hidden = false;
  });
  document.getElementById("more-close").addEventListener("click", function () {
    document.getElementById("more-sheet").hidden = true;
  });
  U.$$("#more-sheet .navitem").forEach(function (item) {
    item.addEventListener("click", function () {
      document.getElementById("more-sheet").hidden = true;
    });
  });

  /* ----------------------------- resize redraw ------------------------------ */
  var resizeTimer = null;
  window.addEventListener("resize", function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      HF.charts.redrawAll();
      var section = document.getElementById("view-" + current);
      if (current === "map" && section) {
        var canvas = section.querySelector("#map-canvas");
        if (canvas) HF.views.map._draw(canvas);
      }
    }, 120);
  });

  /* --------------------------------- boot ---------------------------------- */
  applySettings();
  navigate();
  HF.boot();

  // Register service worker (offline shell) when served over http(s).
  if ("serviceWorker" in navigator && location.protocol.indexOf("http") === 0) {
    navigator.serviceWorker.register("sw.js").catch(function () { /* file:// etc. */ });
  }
})();
