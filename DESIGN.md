# Hashflow Fleet Command — Design Document

Mission-control UI/UX for mining fleet management, engineered against
industrial HMI practice (ISA-101 / High-Performance HMI), the reference
systems named in the brief (Tesla Fleet, SpaceX Mission Control, Caterpillar
MineStar, Hexagon Mining, modern SCADA), and enterprise SaaS standards.

---

## 1. Domain adaptation

The brief's reference model is *physical* mining (excavators, haul trucks,
blast zones). This product manages *compute* mining fleets. Every capability
maps 1:1; only the nouns change — the operational principles (situational
awareness, safety color discipline, glanceability, 24/7 operation) transfer
directly:

| Brief concept | Hashflow equivalent | Where it lives |
|---|---|---|
| Production overview | Fleet hashrate vs target | Dashboard KPI 1, Executive |
| Equipment (excavators, trucks…) | Mining workers / rigs | Fleet view, Sector Map |
| Fuel consumption | Power draw & kWh cost | Dashboard KPI 4, Executive |
| GPS position / live tracking | Zone/cluster placement, live node state | Sector Map |
| Hazard / blast / restricted zones | Thermal hazard zones, throttling halos, dashed perimeters | Sector Map layers |
| Operational routes | Hashrate flow routes worker-zone → pool edge | Sector Map (routes layer) |
| Workforce status | Fleet utilization & online status | Dashboard KPI 5 |
| Safety alerts / evacuation | Thermal/electrical/availability alerts, safe stand-down | Safety Center |
| Environmental metrics | Thermal envelope (avg/hottest °C) | Dashboard KPI 7 |
| Fuel / operator panels | Spare-parts inventory, maintenance windows | Maintenance |
| MineStar-style fleet health | Composite health score (0–100) | Fleet, Maintenance |

## 2. Information architecture

```
Fleet Command
├── Dashboard        "Should I worry?"  — 8 KPI tiles + trend + allocation + feed
├── Fleet            "Which worker?"    — filterable equipment table + detail drawer
├── Sector Map       "Where?"           — spatial topology, hazard layers, zoom/pan
├── Analytics        "Why / trend?"     — production, fleet, resource, efficiency
├── Safety           "Is it safe?"      — emergency controls, risk matrix, register
├── Maintenance      "What breaks next?"— prediction, windows, parts, downtime cost
├── Executive        "Is it worth it?"  — profitability, targets, sustainability
├── AI Copilot       "Ask anything"     — natural-language queries over live state
└── Settings         "Tune assumptions" — price/tariff, accessibility, display
Global: command palette (Ctrl+K) · global search (/) · alert banner · toasts
        detail drawer · connection pill (LIVE/DEMO) · allocation transparency
```

Navigation depth: every view is **1 click** from anywhere (persistent sidenav /
bottom nav). Every worker detail is **≤ 2 clicks** (view + tile/row). Every
common task (acknowledge alerts, filter fleet, ask copilot, emergency stop) is
**≤ 3 clicks**, satisfying the workflow target.

## 3. User journeys

**Manager (morning check, 60 seconds):** open app → Dashboard answers “any
problems?” via the critical banner + status rails → glance KPI row (production
vs yesterday: delta chips) → Executive for margin. *2 clicks total.*

**Supervisor (thermal incident):** critical banner appears unprompted →
“Open Safety Center” (1 click) → risk matrix shows the affected zone →
acknowledge or issue graceful stand-down (2 clicks, confirm dialog). Critical
alerts are **visually dominant** (sticky red banner + nav badge + KPI rail) —
zero-click visibility.

**Field engineer (diagnose a weak worker):** press `/` → type worker name →
Enter opens its detail drawer (temp, fan, rejects, health, trend sparkline) →
one more click to Maintenance watch-list. *3 actions, no menus.*

**Owner (transparency check):** sidebar “Allocation” card shows the live
contributor/project split on every screen; Settings explains the economics;
the CLI prints the exact realized share before mining starts.

## 4. Wireframes (structure)

Desktop ≥ 1280px:
```
┌──────────────────────────────────────────────────────────────────────┐
│ # HASHFLOW  [search workers, zones…]        ● LIVE  12:04:31  ⌘K ◐ 🔔 │
├──────────────┬───────────────────────────────────────────────────────┤
│ DASHBOARD    │ Operations Dashboard        [Refresh] [Ask Copilot]   │
│ FLEET        │ ┌KPI─┐ ┌KPI─┐ ┌KPI─┐ ┌KPI─┐ ┌KPI─┐ ┌KPI─┐ ┌KPI─┐ ┌KPI─┐│
│ SECTOR MAP   │ │ ▌4.2│ │ ▌22/24│ │ ▌94%│ │ ▌18kW│ │ ▌87%│ │ ▌2 ⚠│ │ ▌63°│ │ ▌99%│
│ ANALYTICS    │ └────┘ └────┘ └────┘ └────┘ └────┘ └────┘ └────┘ └────┘│
│ SAFETY       │ ┌ Production trend (area) ──────┐ ┌ Allocation donut ┐│
│ MAINTENANCE  │ │ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ │ │  95% to you      ││
│ EXECUTIVE    │ └───────────────────────────────┘ └──────────────────┘│
│ AI COPILOT   │ ┌ Worker grid ─────────────────┐ ┌ Alert feed ──────┐│
│ SETTINGS     │ │ [RIG-A-01][RIG-A-02]…        │ │ ⚠ thermal…  2m ago││
│              │ └──────────────────────────────┘ └──────────────────┘│
│ ▐ Allocation │                                                        │
│  95% / 5%    │                                                        │
└──────────────┴───────────────────────────────────────────────────────┘
```

Mobile ≤ 720px: KPI cards stack 2-up → 1-up; bottom tab bar
(Home · Fleet · Map · Safety · More); tables become row-cards; drawer goes
full-screen; all touch targets ≥ 44px (`pointer: coarse` media query).

## 5. Design system

**Tokens** (in `web/css/app.css`): charcoal surface ladder `--bg-0 #0B0E13 →
--panel #141B24 → --panel-2 #1A222D`; border `--263241`; text `#E9EEF5 /
#AEBCCC / #7C8B9C`; safety palette green `#2ED477`, yellow `#F5B83D`,
orange `#F2812D`, red `#F0453E`, blue `#4C8DFF`; 4px spacing grid; radius
6/10/14; type scale 11→34px with tabular numerals for all data.

**Components:** KPI card (4px status rail), status chip (color **and**
glyph ●▲✕■), pill, button (default/primary/danger/ghost), data table
(sticky header, keyboard rows), drawer, command palette, toast, alert banner,
progress ring, bar, split bar, risk matrix, chat bubbles, switch, form field,
map layers panel, feed item.

**Color discipline (ISA-101):** chrome is grayscale-charcoal; color appears
**only to carry status or data series**. This is what makes alarms pop: on a
quiet screen one red rail is unmissable. Traditional mining software paints
every panel a color, which destroys preattentive alarm detection.

## 6. Rationale & measurable improvements

| Decision | Rationale (evidence) | Measurable improvement vs traditional UIs |
|---|---|---|
| 8 KPI tiles with status rails, big tabular numbers | Preattentive processing (Healey & Enns): color+position detected in <200 ms | Target time-to-glance-answer ≤ 2 s vs 8–15 s scanning dense grids; instrumented via “first interaction” telemetry hook |
| Sticky critical banner + nav badge + KPI rail (3 channels) | Alarm visibility must not depend on the current screen (ISA-101 §5) | Critical alerts visible at **0 clicks** from any view; ack flow ≤ 2 clicks |
| Command palette (Ctrl+K) + `/` search | Hick-Hyman: search beats nested menus for expert operators | Common tasks ≤ 3 clicks / ≤ 5 keystrokes; expert path to any worker ≤ 2 actions |
| Status = color **and** glyph **and** label | WCAG 1.4.1 (color alone); ~8% of males have CVD | 100% of states distinguishable in grayscale (test: desaturate screenshot) |
| Dark charcoal, AA/AAA text contrast | 24/7 control rooms; glare and fatigue management | All body text ≥ 7:1 (AAA), labels ≥ 4.5:1 (AA) — checked per token |
| Tabular numerals, mono for data | Digit misreading in monitoring tables | Columns align; estimated 30–50% faster numeric comparison (typography research, Microsoft/IBM legibility studies) |
| Live 2 s ticks with decimated series (≤ 600 pts) | Bounded memory; smooth scrolling sparklines | Renders 24 workers + 4 charts at 2 s cadence in <16 ms/frame (rAF-batched redraw) |
| Detail drawer instead of page navigation | Context preservation; Fitts's law (small travel) | Worker drill-down = 1 click, zero page loads, back = Esc |
| Two-step emergency stop (confirm drawer) | Prevents mis-taps (safety-critical UX law); deliberate friction only here | Stops accidental activation; deliberate activation still ≤ 3 clicks |
| Risk matrix 5×5 | Standard safety practice (ISO 31000-style register) | Residual risk visible at a glance; auditable incident trail |
| Allocation transparency panel (always visible) | Trust through disclosure; consent ethics | Donation share readable on **every** screen; opt-out documented |
| Copilot answers with structured cards over live state | NL + structured output beats free text for ops data | Example queries answerable in 1 interaction; no hallucination surface (rule-based over live data) |
| Demo mode with identical data shape | Zero-setup evaluation; offline/`file://` works on any device | App fully functional with **0 install steps, 0 dependencies** |
| Responsive shell (sidenav ↔ bottom nav) | Same IA at every breakpoint; thumb-zone nav on mobile | ≤ 720px: 5 primary targets ≥ 44px; deep views behind “More” sheet |
| Reduced-motion & high-contrast toggles | WCAG 2.3.3 / 1.4.3; user control | Both one click from the top bar; persisted per device |

## 7. Accessibility conformance

* **1.4.3 Contrast (minimum):** AA for all text; AAA targets for data.  
* **1.4.1 Use of color:** every state also carries glyph + text.  
* **2.1.1 Keyboard:** all interactive elements focusable; palette supports
  ↑↓/Enter/Esc; tables rows are tabbable with Enter activation.  
* **2.4.1 Bypass blocks:** skip-link to `#main`.  
* **2.4.7 Focus visible:** 2px accent outline, never removed.  
* **1.4.4 Resize text:** rem-based scale + 100/125/150% setting.  
* **2.3.3 Animation:** `prefers-reduced-motion` honored + manual toggle.  
* **4.1.2 ARIA:** landmarks (`main`, labelled `nav`s), `role="switch"`,
  `aria-live` toast feed and chat log, modal dialogs labelled.  

## 8. Performance budget

| Budget | Technique |
|---|---|
| First paint < 1 s on 3G-class links | 6 classic scripts, no framework, no fonts to fetch; total JS ≈ 90 KB uncompressed |
| 2 s tick cost < 16 ms | Targeted refresh per view (search inputs keep focus), rAF redraw registry, sparkline decimation |
| Thousands of sensors | Series capped at 600 pts; fleet table virtualization-ready (windowed render for >50 rows) |
| Offline / low bandwidth | Service worker caches the shell; API degrades to cached/demo feed; SSE heartbeats prevent proxy timeouts |

## 9. AI copilot design

On-device intent engine (`web/js/copilot.js`) over the same state the
dashboard renders: **no cloud dependency, works offline, no data leaves the
device**. Intent catalog: low hashrate, thermal, failure prediction, zone
productivity, power/energy, share acceptance, donation/allocation,
profitability, alerts, emergency procedure, device lookup, help. Answers
compose **structured cards** (tables, stats, actions). The `answer()` seam is
a drop-in point for a hosted LLM later without UI changes.

## 10. Distribution: PWA + APK

1. **PWA (zero setup):** open `web/index.html` (double-click) or the server
   URL → install via the browser on Android/iOS/desktop. Offline shell via
   service worker. Works on *any* device — no Termux, no compiler.  
2. **Native APK:** `scripts/build_apk.sh` wraps the same bundle with
   Capacitor (see `android/README.md`). The app is a **management console**
   (Play-policy compliant: it manages mining remotely, never mines on-device).

## 11. Test matrix (9 suites, 85 tests)

| Suite | Type | Covers |
|---|---|---|
| `test_allocation` | unit | split math, honesty guarantee (mode selection), clamps |
| `test_wallet` | unit | Monero address formats, edge cases, actionable errors |
| `test_identity` | unit | stable device IDs (PID regression fix) |
| `test_registry` | file I/O | dedup, capacity, corruption recovery, atomic writes |
| `test_stats` | unit | xmrig line parsing, SI units, aggregation |
| `test_consent` | unit | informed-consent gate (the legal control) |
| `test_supervisor` | integration (real subprocesses) | startup, parsing, crash+restart backoff, wallet rotation, stop escalation |
| `test_server_api` | integration (real HTTP) | REST shapes, action confirm-token, SSE stream, path traversal |
| `test_web_assets` | structure smoke | views, landmarks, manifest, service worker, design tokens |
