/* =====================================================================
   HF.charts — dependency-free canvas charting (DPR-aware, hover tooltips,
   auto-redraw registry). Deliberately small: line/area, bars, sparklines,
   rings, donuts, heatmaps, scatter, and a simplified sankey for the
   allocation-flow diagram in Analytics.
   ===================================================================== */
(function () {
  "use strict";
  window.HF = window.HF || {};
  var charts = {};
  HF.charts = charts;

  var registry = []; // {el, draw}
  var gridColor = "#222d3a";
  var axisText = "#7c8b9c";

  function dpr() { return Math.max(1, window.devicePixelRatio || 1); }

  function setup(el, height) {
    var w = el.clientWidth || 300;
    var h = height || el.clientHeight || 160;
    var canvas = el.tagName === "CANVAS" ? el : null;
    if (!canvas) {
      canvas = el.querySelector("canvas");
      if (!canvas) {
        canvas = document.createElement("canvas");
        el.innerHTML = "";
        el.appendChild(canvas);
      }
    }
    var r = dpr();
    canvas.width = Math.round(w * r);
    canvas.height = Math.round(h * r);
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";
    var ctx = canvas.getContext("2d");
    ctx.setTransform(r, 0, 0, r, 0, 0);
    return { ctx: ctx, w: w, h: h, canvas: canvas };
  }

  function register(el, draw) {
    // Replace any previous registration for this element.
    registry = registry.filter(function (r) { return r.el !== el; });
    registry.push({ el: el, draw: draw });
    draw();
    attachTooltip(el);
  }
  charts.register = register;
  charts.redrawAll = function () {
    registry.forEach(function (r) {
      if (document.body.contains(r.el)) {
        try { r.draw(); } catch (e) { /* element detached mid-render */ }
      }
    });
  };

  function attachTooltip(el) {
    if (el._hfTipBound) return;
    el._hfTipBound = true;
    el.addEventListener("mousemove", function (ev) {
      var hits = el._hfHits;
      if (!hits || !hits.length) return;
      var rect = el.getBoundingClientRect();
      var x = ev.clientX - rect.left;
      var best = null, bestD = 1e9;
      hits.forEach(function (hit) {
        var d = Math.abs(hit.x - x);
        if (d < bestD) { bestD = d; best = hit; }
      });
      var tip = el.querySelector(".chart-tip");
      if (!tip) {
        tip = document.createElement("div");
        tip.className = "chart-tip";
        el.appendChild(tip);
      }
      if (best && bestD < 60) {
        tip.style.display = "block";
        tip.style.left = best.x + "px";
        tip.style.top = best.y + "px";
        tip.innerHTML = best.label;
      } else {
        tip.style.display = "none";
      }
    });
    el.addEventListener("mouseleave", function () {
      var tip = el.querySelector(".chart-tip");
      if (tip) tip.style.display = "none";
    });
  }

  function niceMax(v) {
    if (v <= 0) return 1;
    var mag = Math.pow(10, Math.floor(Math.log10(v)));
    return Math.ceil(v / mag) * mag;
  }

  function fmtShort(v) {
    var a = Math.abs(v);
    if (a >= 1e9) return (v / 1e9).toFixed(1) + "G";
    if (a >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (a >= 1e3) return (v / 1e3).toFixed(1) + "k";
    if (a >= 100) return v.toFixed(0);
    return v.toFixed(a >= 10 ? 1 : 2);
  }
  charts.fmtShort = fmtShort;

  /* ------------------------------ sparkline ------------------------------ */
  charts.sparkline = function (el, data, color) {
    register(el, function () {
      var s = setup(el, el.dataset.height ? +el.dataset.height : 30);
      var ctx = s.ctx, w = s.w, h = s.h;
      ctx.clearRect(0, 0, w, h);
      if (!data || data.length < 2) return;
      var min = Math.min.apply(null, data), max = Math.max.apply(null, data);
      if (max === min) { max = min + 1; }
      ctx.beginPath();
      data.forEach(function (v, i) {
        var x = (i / (data.length - 1)) * (w - 2) + 1;
        var y = h - 2 - ((v - min) / (max - min)) * (h - 4);
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      });
      ctx.strokeStyle = color || "#4cc2ff";
      ctx.lineWidth = 1.5;
      ctx.stroke();
      // subtle fill
      ctx.lineTo(w - 1, h); ctx.lineTo(1, h); ctx.closePath();
      var grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, (color || "#4cc2ff") + "33");
      grad.addColorStop(1, (color || "#4cc2ff") + "00");
      ctx.fillStyle = grad;
      ctx.fill();
    });
  };

  /* ------------------------------- ring --------------------------------- */
  charts.ring = function (el, pct, opts) {
    opts = opts || {};
    register(el, function () {
      var size = opts.size || 92;
      var s = setup(el, size);
      var ctx = s.ctx, cx = s.w / 2, cy = size / 2, r = size / 2 - 7;
      ctx.clearRect(0, 0, s.w, size);
      ctx.lineWidth = 8;
      ctx.strokeStyle = "#222d3a";
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();
      var start = -Math.PI / 2;
      var end = start + Math.PI * 2 * Math.max(0, Math.min(1, pct / 100));
      ctx.strokeStyle = opts.color || "#2ed477";
      ctx.lineCap = "round";
      ctx.beginPath();
      ctx.arc(cx, cy, r, start, end);
      ctx.stroke();
      ctx.fillStyle = "#e9eef5";
      ctx.font = "700 15px ui-monospace, monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(opts.text != null ? opts.text : (pct.toFixed(0) + "%"), cx, cy);
      if (opts.label) {
        ctx.fillStyle = "#7c8b9c";
        ctx.font = "600 9px system-ui, sans-serif";
        ctx.fillText(opts.label.toUpperCase(), cx, cy + r + 12 > size ? size - 8 : cy + 14);
      }
    });
  };

  /* ------------------------------- donut -------------------------------- */
  charts.donut = function (el, segments, opts) {
    opts = opts || {};
    register(el, function () {
      var size = opts.size || 130;
      var s = setup(el, size);
      var ctx = s.ctx, cx = s.w / 2, cy = size / 2, r = size / 2 - 8;
      var total = segments.reduce(function (a, seg) { return a + seg.value; }, 0) || 1;
      var angle = -Math.PI / 2;
      segments.forEach(function (seg) {
        var sweep = (seg.value / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.lineWidth = 16;
        ctx.strokeStyle = seg.color;
        ctx.arc(cx, cy, r, angle, angle + sweep - 0.015);
        ctx.stroke();
        angle += sweep;
      });
      if (opts.centerTop) {
        ctx.fillStyle = "#e9eef5";
        ctx.font = "700 15px ui-monospace, monospace";
        ctx.textAlign = "center";
        ctx.fillText(opts.centerTop, cx, cy - 4);
      }
      if (opts.centerBottom) {
        ctx.fillStyle = "#7c8b9c";
        ctx.font = "600 9px system-ui, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(opts.centerBottom, cx, cy + 12);
      }
    });
  };

  /* ------------------------------ area/line ------------------------------ */
  charts.area = function (el, series, opts) {
    opts = opts || {};
    register(el, function () {
      var height = opts.height || 220;
      var s = setup(el, height);
      var ctx = s.ctx, w = s.w, h = s.h;
      var padL = 46, padR = 10, padT = 12, padB = 22;
      ctx.clearRect(0, 0, w, h);
      var n = Math.max.apply(null, series.map(function (sr) { return sr.data.length; })) || 0;
      if (n < 2) {
        ctx.fillStyle = axisText; ctx.font = "12px system-ui";
        ctx.fillText("waiting for data…", 12, h / 2);
        return;
      }
      var maxV = niceMax(Math.max.apply(null, series.reduce(function (acc, sr) {
        return acc.concat(sr.data);
      }, [0])));
      // gridlines + y labels
      ctx.strokeStyle = gridColor;
      ctx.fillStyle = axisText;
      ctx.font = "10px ui-monospace, monospace";
      ctx.textAlign = "right";
      for (var g = 0; g <= 4; g++) {
        var gy = padT + (h - padT - padB) * (g / 4);
        ctx.beginPath();
        ctx.moveTo(padL, gy); ctx.lineTo(w - padR, gy);
        ctx.stroke();
        ctx.fillText(fmtShort(maxV * (1 - g / 4)), padL - 6, gy + 3);
      }
      // x labels
      if (opts.labels) {
        ctx.textAlign = "center";
        var step = Math.ceil(n / 6);
        for (var i = 0; i < n; i += step) {
          var lx = padL + (w - padL - padR) * (i / (n - 1));
          ctx.fillText(opts.labels[i] || "", lx, h - 6);
        }
      }
      // series
      el._hfHits = [];
      series.forEach(function (sr) {
        var pts = [];
        for (var i = 0; i < sr.data.length; i++) {
          var x = padL + (w - padL - padR) * (i / (n - 1));
          var y = padT + (h - padT - padB) * (1 - (sr.data[i] || 0) / maxV);
          pts.push([x, y]);
        }
        if (opts.fill !== false) {
          ctx.beginPath();
          pts.forEach(function (p, i) { i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]); });
          ctx.lineTo(pts[pts.length - 1][0], h - padB);
          ctx.lineTo(pts[0][0], h - padB);
          ctx.closePath();
          var grad = ctx.createLinearGradient(0, padT, 0, h - padB);
          grad.addColorStop(0, sr.color + "44");
          grad.addColorStop(1, sr.color + "05");
          ctx.fillStyle = grad;
          ctx.fill();
        }
        ctx.beginPath();
        pts.forEach(function (p, i) { i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]); });
        ctx.strokeStyle = sr.color;
        ctx.lineWidth = 2;
        ctx.stroke();
      });
      // hit targets from first series
      var primary = series[0];
      for (var i = 0; i < primary.data.length; i++) {
        var x = padL + (w - padL - padR) * (i / (n - 1));
        var y = padT + (h - padT - padB) * (1 - (primary.data[i] || 0) / maxV);
        var label = "<b>" + (opts.labels && opts.labels[i] ? opts.labels[i] : "#" + i) + "</b><br>" +
          series.map(function (sr) {
            return '<span style="color:' + sr.color + '">●</span> ' + sr.name + " " +
              fmtShort(sr.data[i] || 0) + (opts.unit || "");
          }).join("<br>");
        el._hfHits.push({ x: x, y: y, label: label });
      }
    });
  };

  /* ------------------------------ bar charts ----------------------------- */
  charts.bars = function (el, labels, values, opts) {
    opts = opts || {};
    register(el, function () {
      var s = setup(el, opts.height || 200);
      var ctx = s.ctx, w = s.w, h = s.h;
      var padL = 40, padR = 8, padT = 10, padB = 22;
      ctx.clearRect(0, 0, w, h);
      if (!values.length) return;
      var maxV = niceMax(Math.max.apply(null, values.concat([0])));
      ctx.strokeStyle = gridColor; ctx.fillStyle = axisText;
      ctx.font = "10px ui-monospace, monospace";
      for (var g = 0; g <= 3; g++) {
        var gy = padT + (h - padT - padB) * (g / 3);
        ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(w - padR, gy); ctx.stroke();
        ctx.textAlign = "right";
        ctx.fillText(fmtShort(maxV * (1 - g / 3)), padL - 6, gy + 3);
      }
      var n = values.length;
      var slot = (w - padL - padR) / n;
      var bw = Math.max(3, Math.min(38, slot * 0.62));
      el._hfHits = [];
      values.forEach(function (v, i) {
        var x = padL + slot * i + (slot - bw) / 2;
        var bh = (h - padT - padB) * (v / maxV);
        var y = h - padB - bh;
        ctx.fillStyle = (typeof opts.color === "function")
          ? opts.color(v, i) : (opts.color || "#4c8dff");
        ctx.beginPath();
        var r = Math.min(4, bw / 2);
        ctx.moveTo(x, y + r); ctx.arcTo(x, y, x + r, y, r);
        ctx.lineTo(x + bw - r, y); ctx.arcTo(x + bw, y, x + bw, y + r, r);
        ctx.lineTo(x + bw, y + bh); ctx.lineTo(x, y + bh);
        ctx.closePath(); ctx.fill();
        if (labels[i]) {
          ctx.fillStyle = axisText;
          ctx.textAlign = "center";
          ctx.fillText(labels[i], x + bw / 2, h - 6);
        }
        el._hfHits.push({
          x: x + bw / 2, y: y,
          label: "<b>" + (labels[i] || "") + "</b><br>" + fmtShort(v) + (opts.unit || "")
        });
      });
    });
  };

  charts.stackedBars = function (el, labels, series, opts) {
    opts = opts || {};
    register(el, function () {
      var s = setup(el, opts.height || 210);
      var ctx = s.ctx, w = s.w, h = s.h;
      var padL = 40, padR = 8, padT = 10, padB = 22;
      ctx.clearRect(0, 0, w, h);
      var n = labels.length;
      if (!n) return;
      var totals = labels.map(function (_, i) {
        return series.reduce(function (a, sr) { return a + (sr.data[i] || 0); }, 0);
      });
      var maxV = niceMax(Math.max.apply(null, totals.concat([0])));
      ctx.strokeStyle = gridColor; ctx.fillStyle = axisText;
      ctx.font = "10px ui-monospace, monospace";
      for (var g = 0; g <= 3; g++) {
        var gy = padT + (h - padT - padB) * (g / 3);
        ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(w - padR, gy); ctx.stroke();
        ctx.textAlign = "right";
        ctx.fillText(fmtShort(maxV * (1 - g / 3)), padL - 6, gy + 3);
      }
      var slot = (w - padL - padR) / n;
      var bw = Math.max(3, Math.min(34, slot * 0.62));
      el._hfHits = [];
      labels.forEach(function (lab, i) {
        var x = padL + slot * i + (slot - bw) / 2;
        var acc = 0;
        series.forEach(function (sr) {
          var v = sr.data[i] || 0;
          var bh = (h - padT - padB) * (v / maxV);
          var y = h - padB - acc - bh;
          ctx.fillStyle = sr.color;
          ctx.fillRect(x, y, bw, Math.max(0, bh));
          acc += bh;
        });
        ctx.fillStyle = axisText;
        ctx.textAlign = "center";
        ctx.fillText(lab, x + bw / 2, h - 6);
        el._hfHits.push({
          x: x + bw / 2, y: h - padB - acc,
          label: "<b>" + lab + "</b><br>" + series.map(function (sr) {
            return '<span style="color:' + sr.color + '">■</span> ' + sr.name + " " +
              fmtShort(sr.data[i] || 0);
          }).join("<br>")
        });
      });
    });
  };

  /* ------------------------------- heatmap ------------------------------- */
  charts.heatmap = function (el, matrix, opts) {
    opts = opts || {};
    register(el, function () {
      var rows = matrix.length, cols = matrix[0] ? matrix[0].length : 0;
      var s = setup(el, opts.height || rows * 30 + 46);
      var ctx = s.ctx, w = s.w, h = s.h;
      var padL = 46, padT = 22, padB = 22;
      var cw = (w - padL - 8) / Math.max(1, cols);
      var ch = (h - padT - padB) / Math.max(1, rows);
      ctx.clearRect(0, 0, w, h);
      ctx.font = "9px system-ui";
      for (var r = 0; r < rows; r++) {
        ctx.fillStyle = axisText;
        ctx.textAlign = "right";
        ctx.fillText(opts.yLabels ? (opts.yLabels[r] || "") : "r" + r, padL - 6, padT + ch * r + ch / 2 + 3);
        for (var c = 0; c < cols; c++) {
          var v = matrix[r][c];
          var t = opts.max ? v / opts.max : v;
          ctx.fillStyle = heatColor(t, opts.invert);
          ctx.fillRect(padL + cw * c + 1, padT + ch * r + 1, cw - 2, ch - 2);
          if (cw > 30 && ch > 18 && v > 0) {
            ctx.fillStyle = "rgba(255,255,255,.8)";
            ctx.textAlign = "center";
            ctx.fillText(fmtShort(v), padL + cw * c + cw / 2, padT + ch * r + ch / 2 + 3);
          }
        }
      }
      if (opts.xLabels) {
        ctx.fillStyle = axisText;
        ctx.textAlign = "center";
        for (var c2 = 0; c2 < cols; c2++) {
          if (cols <= 12 || c2 % Math.ceil(cols / 12) === 0) {
            ctx.fillText(opts.xLabels[c2] || "", padL + cw * c2 + cw / 2, h - 8);
          }
        }
      }
    });
  };

  function heatColor(t, invert) {
    t = Math.max(0, Math.min(1, t));
    if (invert) t = 1 - t;
    // charcoal -> info blue -> warn -> crit
    if (t < 0.4) {
      var k = t / 0.4;
      return mix([22, 30, 41], [76, 141, 255], k);
    } else if (t < 0.75) {
      var k2 = (t - 0.4) / 0.35;
      return mix([76, 141, 255], [245, 184, 61], k2);
    }
    var k3 = (t - 0.75) / 0.25;
    return mix([245, 184, 61], [240, 69, 62], k3);
  }
  function mix(a, b, k) {
    return "rgb(" + Math.round(a[0] + (b[0] - a[0]) * k) + "," +
      Math.round(a[1] + (b[1] - a[1]) * k) + "," +
      Math.round(a[2] + (b[2] - a[2]) * k) + ")";
  }

  /* ------------------------------- scatter -------------------------------- */
  charts.scatter = function (el, points, opts) {
    opts = opts || {};
    register(el, function () {
      var s = setup(el, opts.height || 220);
      var ctx = s.ctx, w = s.w, h = s.h;
      var padL = 40, padR = 10, padT = 12, padB = 26;
      ctx.clearRect(0, 0, w, h);
      if (!points.length) return;
      var xs = points.map(function (p) { return p.x; });
      var ys = points.map(function (p) { return p.y; });
      var maxX = niceMax(Math.max.apply(null, xs)), maxY = niceMax(Math.max.apply(null, ys));
      ctx.strokeStyle = gridColor;
      for (var g = 0; g <= 3; g++) {
        var gy = padT + (h - padT - padB) * (g / 3);
        ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(w - padR, gy); ctx.stroke();
      }
      el._hfHits = [];
      points.forEach(function (p) {
        var x = padL + (w - padL - padR) * (p.x / maxX);
        var y = padT + (h - padT - padB) * (1 - p.y / maxY);
        ctx.beginPath();
        ctx.arc(x, y, 5, 0, Math.PI * 2);
        ctx.fillStyle = (p.color || "#4cc2ff") + "cc";
        ctx.fill();
        el._hfHits.push({
          x: x, y: y,
          label: "<b>" + (p.label || "") + "</b><br>" +
            (opts.xName || "x") + " " + fmtShort(p.x) + " · " +
            (opts.yName || "y") + " " + fmtShort(p.y)
        });
      });
      ctx.fillStyle = axisText;
      ctx.font = "10px system-ui";
      ctx.textAlign = "center";
      ctx.fillText(opts.xName || "", (padL + w - padR) / 2, h - 6);
      ctx.save();
      ctx.translate(11, (padT + h - padB) / 2);
      ctx.rotate(-Math.PI / 2);
      ctx.fillText(opts.yName || "", 0, 0);
      ctx.restore();
    });
  };

  /* -------------------------- simplified sankey --------------------------- */
  /* columns: [{name, value, color}], links: [{from, to, value}] where from/to
     are node names. 2-3 columns, drawn as bezier ribbons. */
  charts.sankey = function (el, columns, links, opts) {
    opts = opts || {};
    register(el, function () {
      var s = setup(el, opts.height || 240);
      var ctx = s.ctx, w = s.w, h = s.h;
      ctx.clearRect(0, 0, w, h);
      if (!columns.length || !links.length) return;
      var padT = 16, padB = 16, nodeW = 13;
      var cols = Math.max.apply(null, columns.map(function (c) { return c.col || 0; })) + 1;
      var xOf = function (col) {
        return 20 + (w - 60 - nodeW) * (cols === 1 ? 0 : col / (cols - 1));
      };
      // compute node positions
      var byCol = {};
      columns.forEach(function (c) {
        var col = c.col || 0;
        (byCol[col] = byCol[col] || []).push(c);
      });
      var totalH = h - padT - padB;
      Object.keys(byCol).forEach(function (col) {
        var nodes = byCol[col];
        var sum = nodes.reduce(function (a, n) { return a + n.value; }, 0) || 1;
        var y = padT;
        nodes.forEach(function (n) {
          n._x = xOf(+col);
          n._y = y;
          n._h = Math.max(8, totalH * (n.value / sum));
          y += n._h + 12;
        });
      });
      // ribbons
      var outUsed = {}, inUsed = {};
      links.forEach(function (lk) {
        var a = columns.filter(function (c) { return c.name === lk.from; })[0];
        var b = columns.filter(function (c) { return c.name === lk.to; })[0];
        if (!a || !b) return;
        var aOff = outUsed[lk.from] || 0;
        var bOff = inUsed[lk.to] || 0;
        var fracA = a.value ? lk.value / a.value : 0;
        var fracB = b.value ? lk.value / b.value : 0;
        var y1 = a._y + aOff, th1 = a._h * fracA;
        var y2 = b._y + bOff, th2 = b._h * fracB;
        outUsed[lk.from] = aOff + th1;
        inUsed[lk.to] = bOff + th2;
        var x1 = a._x + nodeW, x2 = b._x;
        var grad = ctx.createLinearGradient(x1, 0, x2, 0);
        grad.addColorStop(0, (a.color || "#4c8dff") + "55");
        grad.addColorStop(1, (b.color || "#4c8dff") + "55");
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.bezierCurveTo((x1 + x2) / 2, y1, (x1 + x2) / 2, y2, x2, y2);
        ctx.lineTo(x2, y2 + th2);
        ctx.bezierCurveTo((x1 + x2) / 2, y2 + th2, (x1 + x2) / 2, y1 + th1, x1, y1 + th1);
        ctx.closePath();
        ctx.fill();
      });
      // nodes + labels
      columns.forEach(function (c) {
        ctx.fillStyle = c.color || "#4c8dff";
        ctx.fillRect(c._x, c._y, nodeW, c._h);
        ctx.fillStyle = "#e9eef5";
        ctx.font = "600 10px system-ui";
        ctx.textAlign = c._x > w / 2 ? "right" : "left";
        var lx = c._x > w / 2 ? c._x - 6 : c._x + nodeW + 6;
        ctx.fillText(c.name + "  " + fmtShort(c.value), lx, c._y + c._h / 2 + 3);
      });
    });
  };
})();
