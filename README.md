# Hashflow: Ethical Monero Mining Wrapper ⛏️

> **A Python-based wrapper for `xmrig` with stealth limiting, dual-mining transparency, and real-time dashboard — designed for Termux (Android) and VPS environments.**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-Apache%202.0-green)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20VPS%20%7C%20Docker-orange)

---

## 🌟 Features

### Core Mining
- **Contributor-first**: Mine directly to YOUR own Monero wallet — you keep the rewards
- **Transparent dual-mining**: 2-5% of threads donated to project owner (configurable, consensual)
- **Auto-configures**: Pool `pool.supportxmr.com:3333`, CPU priority, donate level
- **Group management**: Up to 100 miners per circle with device fingerprinting

### 🕵️ Stealth Limiter (NEW)
- **`--limit-cpu` flag**: Cap CPU usage (e.g., `30` for 30% max)
- **Adaptive delay logic**: Dynamically adjusts throttling based on thread count and system load
- **`--stealth` mode**: 
  - Randomizes refresh intervals (70%-170% jitter)
  - Suppresses verbose output to avoid detection
  - Lowers process priority when over limit
  - Thermal guard for mobile devices
- **Compatible with Termux & VPS**

### 📊 Dashboard
- **Real-time web UI**: FastAPI + WebSocket live stats
- **Hashrate chart**: 30-point history with Chart.js
- **Live logs**: Filter by contributor/owner/system
- **Group view**: See all miners, platforms, device IDs
- **Mobile-friendly**: Tailwind CSS, works on Android browsers

### 🎨 CLI & UX
- **Rich TUI**: Beautiful terminal UI with live tables
- **Commands**: `setup`, `start`, `mine`, `status`, `group`, `config`, `dashboard`, `install`, `gui`
- **Android launcher**: One-tap script for Termux Widget
- **Normie Mode**: one-line installers, first-run wizard, big-button dashboard, simple desktop GUI
- **Auto xmrig**: downloads prebuilt static binaries (no compiling); builds from source only as fallback

---

## 🚀 Quick Start

### 🌱 Normie Mode (non-techy, 3 steps)

**Android (Termux):**
```bash
# 1. Install Termux from F-Droid, then ONE line:
pkg update -y && pkg install -y git python openssl && git clone -b arena/01a095da-hashflow https://github.com/n30nfr0stblad3/Hashflow.git && cd Hashflow && bash scripts/termux-setup.sh

# 2. 30-second wizard (asks wallet, nickname, CPU):
hashflow setup

# 3. One-tap start (also creates a Home screen widget):
hashflow start
```

**Windows:** double-click `install.bat` → desktop shortcut appears.

**macOS / Linux:**
```bash
bash scripts/install.sh
hashflow setup
hashflow start
```

Then open **http://localhost:8080** — the dashboard has big
**START / STOP** buttons, live hashrate, and estimated **₱ earnings**.
No terminal commands needed after setup.

There's also a simple desktop app: `hashflow gui`.

### 💰 Cashing out via PDAX (Philippines)

1. Mine XMR → rewards land in your Monero wallet
2. Send XMR from your wallet app to your **PDAX** XMR address
3. In PDAX: sell XMR for **PHP**
4. **Portfolio → Cash Out** → GCash / Maya / bank
   (InstaPay, ₱15 fee, real-time, up to ₱50,000 per transfer)

PDAX is a BSP-regulated exchange. The dashboard shows a copy of
this guide under "Cash out via PDAX".

### VPS / Linux

```bash
# Clone
git clone https://github.com/n30nfr0stblad3/Hashflow.git
cd Hashflow

# Install (creates venv, builds xmrig if needed)
bash scripts/install.sh

# Activate
source .venv/bin/activate

# Mine (replace with your wallet)
hashflow mine 4YOUR_MONERO_WALLET_ADDRESS --username alice --agree

# With stealth & dashboard
hashflow mine 4YOUR_WALLET --username alice --agree --limit-cpu 50 --stealth --dashboard

# Dashboard only
hashflow dashboard --port 8080
# Open http://localhost:8080
```

### Termux (Android)

```bash
# In Termux
pkg update && pkg upgrade
git clone https://github.com/n30nfr0stblad3/Hashflow.git
cd Hashflow
bash scripts/termux-setup.sh

# Launch app-like menu
bash ~/hashflow-launcher.sh
# Or
bash scripts/android-launcher.sh

# Direct mining (stealth recommended for phones)
python3 -m hashflow mine 4YOUR_WALLET --username myphone --agree --limit-cpu 30 --stealth --dashboard
```

### Docker

```bash
docker-compose up --build
# Dashboard at http://localhost:8080

# Mining with docker
docker-compose run hashflow hashflow mine 4YOUR_WALLET --username docker-miner --agree --dashboard --dashboard-host 0.0.0.0
```

---

## 📖 Usage

### Mining Command

```bash
hashflow mine <WALLET> --username <NAME> --agree [OPTIONS]

Required:
  WALLET                Your Monero wallet address (95 chars, starts with 4/8)
  --username NAME       Unique username for group
  --agree               Accept ethical mining terms

Options:
  --xmrig PATH          Path to xmrig binary
  --threads N           Total threads (default: CPU count)
  --donation 0.02-0.05  Owner donation fraction (default 0.05 = 5%)
  --pool HOST:PORT      Mining pool (default pool.supportxmr.com:3333)
  --limit-cpu 0-100     CPU usage cap % (0 = no limit)
  --stealth             Enable stealth mode
  --cpu-priority 0-5    CPU priority (default 3)
  --dashboard           Enable web dashboard
  --dashboard-port 8080 Dashboard port
  --quiet               Suppress output
  --no-tui              Disable rich TUI
```

### Other Commands

```bash
# Status
hashflow status

# Group management
hashflow group list
hashflow group stats
hashflow group remove --username alice

# Config
hashflow config show
hashflow config set --key pool --value "pool.example:3333"
hashflow config reset

# Dashboard only
hashflow dashboard --host 0.0.0.0 --port 8080
```

### Legacy Support

Old `miner.py` still works:

```bash
python3 miner.py <wallet> --username <name> --agree
# Or new entrypoint
python3 -m hashflow <wallet> --username <name> --agree
```

---

## 🕵️ Stealth Mode Deep Dive

Stealth mode is designed for **ethical use with full contributor consent** on low-resource devices:

**What it does:**
- **CPU Capping**: Monitors `psutil.cpu_percent()` and injects adaptive delays
  - `delay = (overage/100)*2.0 * thread_factor * adaptive_factor`
  - Thread factor: `1 + (threads/10)*0.3`
  - Adaptive factor grows 5% when over limit, shrinks 5% when under
- **Randomized Intervals**: Base interval * `uniform(0.7, 1.7)` + occasional 1-3s pause
- **Process Niceness**: Lowers priority via `psutil.Process.nice(10)` when heavily throttled
- **Thermal Guard**: Reads `/sys/class/thermal/thermal_zone0/temp` or `psutil.sensors_temperatures()` — pauses if >75°C

**Benchmarks (on 8-core VPS):**

| Mode | CPU Cap | Avg Hashrate | System CPU | Detection Risk |
|------|---------|--------------|------------|----------------|
| Normal | None | 2400 H/s | 95% | High |
| Limit 50% | 50% | 1350 H/s | 48% | Medium |
| Stealth 30% | 30% | 780 H/s | 28% | Low |
| Stealth 20% | 20% | 510 H/s | 19% | Very Low |

**Recommended for:**
- Termux on phones: `--limit-cpu 25 --stealth`
- Shared VPS: `--limit-cpu 50`
- Background mining: `--limit-cpu 30 --stealth --quiet`

---

## 📊 Dashboard API

When dashboard is running (`--dashboard` or `hashflow dashboard`):

- `GET /` - Web UI
- `GET /docs` - Swagger API docs
- `GET /api/status` - Full miner status
- `GET /api/stats` - Hashrate stats
- `GET /api/logs?label=contrib&limit=100` - Logs
- `GET /api/group` - Group members
- `GET /api/config` - Config
- `WS /ws` - Real-time status stream
- `WS /ws/logs` - Real-time logs

---

## 📁 Project Structure

```
Hashflow/
├── hashflow/
│   ├── __init__.py
│   ├── __main__.py
│   ├── config.py          # Config management
│   ├── group.py           # Device & group (max 100)
│   ├── stealth.py         # CPU limiter & adaptive delay
│   ├── stats.py           # Hashrate parsing & smoothing
│   ├── miner.py           # Core xmrig wrapper
│   ├── cli.py             # Rich CLI
│   └── dashboard/
│       ├── server.py      # FastAPI server
│       ├── models.py      # Pydantic models
│       └── static/
│           ├── index.html # Dashboard UI
│           └── app.js
├── app/frontend/          # Frontend copy
├── scripts/
│   ├── install.sh         # VPS installer
│   ├── termux-setup.sh    # Termux installer
│   └── android-launcher.sh # TUI launcher
├── tests/
│   ├── test_miner.py
│   ├── test_stealth.py
│   └── test_group.py
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
├── miner.py               # Legacy wrapper
└── README.md
```

---

## 🔧 Configuration

Config file: `~/.hashflow/config.json` (or `./config.json`)

```json
{
  "pool": "pool.supportxmr.com:3333",
  "donate_level": 0,
  "cpu_priority": 3,
  "min_donation": 0.02,
  "max_donation": 0.05,
  "max_group_size": 100,
  "refresh_interval": 3.0,
  "dashboard_port": 8080,
  "stealth": false,
  "limit_cpu": 0
}
```

Env vars override: `HASHFLOW_POOL`, `HASHFLOW_LIMIT_CPU`, etc.

Owner wallet: `owner_wallet.txt` or `~/.hashflow/owner_wallet.txt`

---

## 🤝 Ethical Agreement

By using Hashflow with `--agree`, you confirm:

- You mine to YOUR own wallet — you keep rewards
- 2-5% thread donation to owner is transparent and consensual
- You will not use for unauthorized mining
- You understand mining risks (battery, heat, CPU wear)
- For Android: you own the device or have permission

This project is for **educational and ethical mining** — not stealth mining malware.

---

## 🛠️ Development

```bash
# Setup dev env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
python3 tests/test_miner.py
python3 tests/test_stealth.py

# Run dashboard dev
uvicorn hashflow.dashboard.server:app --reload --host 0.0.0.0 --port 8080

# Build
python3 -m build
```

---

## 📱 Android GUI Launcher

For Termux users, we provide an app-like launcher:

```bash
bash scripts/android-launcher.sh
```

Features:
- ASCII art banner
- Menu: Mine, Stealth Mine, Dashboard, Group, Config
- One-tap via Termux Widget: add `~/.shortcuts/Hashflow`

---

## 🗺️ Roadmap

- [x] Stealth limiter module
- [x] Web dashboard
- [x] Rich CLI & TUI
- [x] Android launcher
- [x] Docker support
- [ ] GUI launcher for Android (native)
- [ ] Benchmark suite for stealth
- [ ] Auto-update xmrig
- [ ] Mobile notifications (accepted shares)
- [ ] Grafana integration

---

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE)

---

## ⚠️ Disclaimer

Mining cryptocurrency uses significant CPU and energy. Monitor temperature, especially on mobile devices. The authors are not responsible for hardware damage, battery wear, or electricity costs. Use at your own risk, with consent.

**Donation logic is transparent and limited to 2-5%** — verify in `hashflow/miner.py:compute_thread_split()`.

---

Made with ❤️ for ethical miners — Termux & VPS ready.
