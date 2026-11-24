/* =====================================================================
   HF.ui — formatters, toasts, drawer, tables, icons. Small DOM helpers
   shared by all views.
   ===================================================================== */
(function () {
  "use strict";
  window.HF = window.HF || {};
  var ui = {};
  HF.ui = ui;

  /* ------------------------------ formatters ------------------------------ */
  ui.fmtHash = function (v) {
    if (!v || v <= 0) return "0 H/s";
    if (v >= 1e12) return (v / 1e12).toFixed(2) + " TH/s";
    if (v >= 1e9) return (v / 1e9).toFixed(2) + " GH/s";
    if (v >= 1e6) return (v / 1e6).toFixed(2) + " MH/s";
    if (v >= 1e3) return (v / 1e3).toFixed(2) + " kH/s";
    return v.toFixed(0) + " H/s";
  };
  ui.fmtNum = function (v, digits) {
    return (v || 0).toLocaleString(undefined, {
      minimumFractionDigits: digits == null ? 0 : digits,
      maximumFractionDigits: digits == null ? 0 : digits
    });
  };
  ui.fmtPct = function (v, digits) { return (v || 0).toFixed(digits == null ? 1 : digits) + "%"; };
  ui.fmtMoney = function (v) {
    return "$" + (v || 0).toLocaleString(undefined, {
      minimumFractionDigits: 2, maximumFractionDigits: 2
    });
  };
  ui.fmtDuration = function (s) {
    s = Math.max(0, Math.floor(s || 0));
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600),
      m = Math.floor(s % 3600 / 60);
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    return m + "m";
  };
  ui.fmtClock = function (ts) {
    var dt = new Date(ts);
    return dt.toLocaleTimeString(undefined, { hour12: false });
  };
  ui.ago = function (ts) {
    var s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    return Math.floor(s / 3600) + "h ago";
  };

  /* --------------------------------- DOM --------------------------------- */
  ui.esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  };
  ui.icon = function (name, cls) {
    return '<svg class="icon ' + (cls || "") + '" aria-hidden="true"><use href="#i-' +
      name + '"/></svg>';
  };
  ui.$ = function (sel, root) { return (root || document).querySelector(sel); };
  ui.$$ = function (sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  };

  /* status helpers — color AND glyph (color-blind support) */
  var STATUS_GLYPH = {
    online: "●", degraded: "▲", offline: "✕", maintenance: "■"
  };
  ui.statusChip = function (status) {
    return '<span class="status-cell"><span class="status-glyph glyph-' + status +
      '" aria-hidden="true">' + (STATUS_GLYPH[status] || "?") + '</span>' +
      '<span>' + ui.esc(status) + "</span></span>";
  };
  ui.sevChip = function (sev) {
    var cls = { critical: "chip-crit", warning: "chip-warn", info: "chip-info" }[sev] || "chip-info";
    return '<span class="chip ' + cls + '">' + ui.esc(sev.toUpperCase()) + "</span>";
  };

  /* -------------------------------- toasts -------------------------------- */
  ui.toast = function (title, body, kind) {
    var host = document.getElementById("toasts");
    var el = document.createElement("div");
    el.className = "toast toast-" + (kind || "info");
    el.innerHTML = "<div><b>" + ui.esc(title) + "</b><p>" + ui.esc(body || "") + "</p></div>";
    host.appendChild(el);
    setTimeout(function () {
      el.style.opacity = "0";
      el.style.transition = "opacity .3s";
      setTimeout(function () { el.remove(); }, 320);
    }, 4200);
  };

  /* -------------------------------- drawer -------------------------------- */
  ui.drawer = function (title, html) {
    var d = document.getElementById("drawer");
    document.getElementById("drawer-title").textContent = title;
    document.getElementById("drawer-body").innerHTML = html;
    d.hidden = false;
  };
  ui.closeDrawer = function () {
    document.getElementById("drawer").hidden = true;
  };

  /* --------------------------------- table -------------------------------- */
  /* rows: array of arrays; cols: [{label, cls}]; onRow(index) -> click */
  ui.table = function (cols, rows, onRow) {
    var html = '<div class="table-wrap"><table class="tbl"><thead><tr>' +
      cols.map(function (c) {
        return '<th class="' + (c.cls || "") + '">' + ui.esc(c.label) + "</th>";
      }).join("") + "</tr></thead><tbody>" +
      rows.map(function (r, i) {
        return '<tr tabindex="0" data-row="' + i + '">' + r.map(function (cell, ci) {
          return '<td class="' + (cols[ci].cls || "") + '">' + cell + "</td>";
        }).join("") + "</tr>";
      }).join("") + "</tbody></table></div>";
    return html;
  };
  ui.bindRows = function (container, onRow) {
    ui.$$("tr[data-row]", container).forEach(function (tr) {
      var handler = function () { onRow(+tr.dataset.row, tr); };
      tr.addEventListener("click", handler);
      tr.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); handler(); }
      });
    });
  };

  /* kpi card helper */
  ui.kpi = function (opts) {
    var sparkId = "spark-" + Math.random().toString(36).slice(2, 8);
    return '' +
      '<article class="card kpi" data-state="' + (opts.state || "ok") + '">' +
      '<div class="kpi-label">' + ui.esc(opts.label) + "</div>" +
      '<div class="kpi-value">' + opts.value +
      (opts.unit ? ' <span class="unit">' + ui.esc(opts.unit) + "</span>" : "") + "</div>" +
      '<div class="kpi-foot"><span>' + (opts.foot || "") + "</span>" +
      (opts.spark ? '<span class="kpi-spark" id="' + sparkId + '"></span>' : "") +
      "</div></article>";
  };
  ui.renderSparks = function (map) {
    // map: {selector: {data, color}}
    Object.keys(map).forEach(function (sel) {
      var el = ui.$(sel);
      if (el) HF.charts.sparkline(el, map[sel].data, map[sel].color);
    });
  };

  /* relative delta chip */
  ui.delta = function (now, prev) {
    if (!prev) return '<span class="delta-flat">—</span>';
    var d = (now - prev) / prev * 100;
    var cls = d > 0.5 ? "delta-up" : d < -0.5 ? "delta-down" : "delta-flat";
    var arrow = d > 0.5 ? "▲" : d < -0.5 ? "▼" : "■";
    return '<span class="' + cls + '">' + arrow + " " + Math.abs(d).toFixed(1) + "%</span>";
  };
})();
