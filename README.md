# Hashflow — Monero Mining Wrapper + Fleet Command Dashboard

A transparent, cross-platform Monero (XMR) mining manager with a
mission-control web dashboard.

- **Miner CLI** — wraps [`xmrig`](https://github.com/xmrig/xmrig) with honest
  donation accounting, informed consent, group registration, and automatic
  crash recovery.
- **Fleet Command** — a dark, industrial-grade operations dashboard (live
  telemetry, sector map, analytics, safety center, maintenance prediction,
  executive KPIs, and an on-device AI mining copilot). Runs in any browser and
  installs as an app (PWA) on Android, iOS, and desktop.

> **Run mining only on hardware you own or are authorized to use.** Some
> hosting providers prohibit cryptocurrency mining in their terms of service.

---

## Quick start (zero setup)

```bash
# 1. Launch the Fleet Command dashboard with a simulated fleet
python3 miner.py --dashboard
#    → open http://localhost:8765/
```

Works with **Python 3.8+ and nothing else** — no pip installs, no Termux, no
build step. The dashboard also runs by simply double-clicking
`web/index.html` (it falls back to an on-device simulator when no server is
reachable).

## Mining for real

```bash
# 1. Get the official xmrig binary for your OS/arch (Windows/macOS/Linux):
python3 scripts/fetch_xmrig.py

# 2. Optional: support the project with a small, transparent donation.
#    Create owner_wallet.txt with the project wallet address (first line).
#    Skip this and pass --no-donate to mine 100% to your own wallet.

# 3. Start mining (the consent summary prints the EXACT split before start):
python3 miner.py YOUR_MONERO_WALLET --username yourname --agree
python3 miner.py YOUR_MONERO_WALLET --username yourname --agree --no-donate
```

`--agree` confirms you have read the consent summary and are authorized to
mine on this device. Without it (and without a terminal prompt) the miner
refuses to start.

## Donation & transparency

| Setting | Behavior |
|---|---|
| Default | 5% of compute over time goes to the project fund wallet |
| `--donation 0.02` … `--donation 0.05` | Any share in the 2–5% band |
| `--donation 0` / `--no-donate` | 100% to your wallet; owner wallet not required |

The wrapper is honest about *realized* shares: on machines where a whole-thread
split cannot represent the requested percentage (e.g. 1 of 4 threads is 25%),
it automatically switches to **time-sliced wallet rotation**, which delivers
the exact percentage over time (`--mode threads|timeslice` to force either).
The realized share is printed before mining starts and shown live in the
dashboard sidebar.

## Fleet Command dashboard

`python3 -m hashflow.server` (or `python3 miner.py --dashboard`) serves:

| View | What it does |
|---|---|
| Dashboard | 8 live KPIs, production trend, allocation donut, worker grid, alert feed |
| Fleet | Equipment table: status, hashrate, thermal, health, utilization, uptime |
| Sector Map | Interactive topology: zone clusters, thermal hazard layers, hashrate routes, zoom/pan |
| Analytics | Production/fleet/resource charts, activity heatmap, efficiency scatter, allocation sankey |
| Safety | Emergency stop (2-step), 5×5 risk matrix, incident register, safe stand-down |
| Maintenance | Failure prediction watch list, maintenance windows, spare parts, downtime cost |
| Executive | Profitability, target tracking, cost & sustainability metrics |
| AI Copilot | Natural-language questions over live data (works offline, on-device) |

Extras: command palette (**Ctrl+K**), global search (**/**), high-contrast
mode, reduced-motion mode, text scaling, keyboard navigation, and offline
support. Design rationale: see [DESIGN.md](DESIGN.md).

**Phone / tablet:** open the dashboard URL in any browser → *Install app*
(PWA). For a native APK see [`android/README.md`](android/README.md) and
`scripts/build_apk.sh`.

## Platform support

| Platform | Miner CLI | Dashboard |
|---|---|---|
| Windows 10+ | ✅ (`scripts/fetch_xmrig.py` fetches the binary) | ✅ any browser / PWA |
| macOS (Intel & Apple Silicon) | ✅ | ✅ |
| Linux / VPS | ✅ | ✅ |
| Android | ❌ use the app as the control room | ✅ PWA / APK |
| iOS | — | ✅ PWA |
| Anything with a browser | — | ✅ (even from `web/index.html`) |

## Development

```bash
python3 -m unittest discover -s tests -v     # 85 tests, 9 suites, zero deps
```

Layout: `miner.py` (CLI), `hashflow/` (core, stats, supervisor, simulator,
server), `web/` (dashboard PWA), `tests/`, `scripts/`, `android/` (APK
wrapper docs). Stdlib-only at runtime; see [DESIGN.md](DESIGN.md) for the full
architecture and test matrix.

## Configuration reference (CLI)

```
python3 miner.py WALLET --username NAME --agree
  --donation 0.02..0.05 | --no-donate   compute share to the project fund
  --mode auto|threads|timeslice         allocation strategy
  --threads N                           mining threads (default: all cores)
  --pool HOST:PORT                      stratum pool
  --owner-config FILE                   project wallet file (default owner_wallet.txt)
  --xmrig PATH                          explicit xmrig binary
  --skip-wallet-check                   accept non-standard addresses
  --dashboard                           launch the web dashboard instead
```

`owner_wallet.txt` and `miners.json` (group ledger) are git-ignored so wallet
material and device IDs never get committed.

## License

Apache 2.0 — see [LICENSE](LICENSE).
