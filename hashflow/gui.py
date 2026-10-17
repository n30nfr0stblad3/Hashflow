"""
Simple desktop GUI for Hashflow (tkinter, no extra dependencies).

Designed for non-technical users: big START / STOP buttons,
wallet + nickname fields, CPU slider, live hashrate and
estimated PHP earnings.
"""
import json
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional

from .config import config

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    HAS_TK = True
except ImportError:
    HAS_TK = False

from . import binaries
from .miner import HashflowMiner, find_xmrig, read_owner_wallet
from .stats import stats_manager

# Rough offline estimate: XMR per kH/s per day (varies with network)
XMR_PER_KS_DAY = 0.00042


def validate_wallet(w: str) -> bool:
    return bool(w) and len(w) >= 90 and w[0] in ("4", "8")


class HashflowApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hashflow ⛏️ Monero Miner")
        self.root.geometry("520x620")
        self.root.resizable(False, False)
        self.miner: Optional[HashflowMiner] = None
        self._poll_after = None

        self._build()
        self._load_saved()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI ----------
    def _build(self):
        pad = dict(padx=14, pady=4)
        tk.Label(self.root, text="⛏️  Hashflow", font=("Segoe UI", 22, "bold"),
                 fg="#22d3ee").pack(pady=(14, 0))
        tk.Label(self.root, text="Mine Monero (XMR) in the background",
                 fg="#666").pack()

        form = tk.Frame(self.root)
        form.pack(fill="x", **pad)

        tk.Label(form, text="Your Monero wallet", anchor="w").pack(fill="x")
        self.wallet_var = tk.StringVar()
        tk.Entry(form, textvariable=self.wallet_var, width=52).pack(fill="x")

        tk.Label(form, text="Nickname", anchor="w").pack(fill="x", pady=(8, 0))
        self.user_var = tk.StringVar()
        tk.Entry(form, textvariable=self.user_var, width=52).pack(fill="x")

        tk.Label(form, text="CPU usage (lower = cooler device)", anchor="w").pack(
            fill="x", pady=(8, 0))
        self.cpu_var = tk.IntVar(value=30)
        tk.Scale(form, from_=10, to=100, orient="horizontal",
                 variable=self.cpu_var, length=420).pack(fill="x")

        self.stealth_var = tk.BooleanVar(value=True)
        tk.Checkbutton(form, text="Stealth mode (quiet, harder to notice)",
                       variable=self.stealth_var).pack(anchor="w")

        btnframe = tk.Frame(self.root)
        btnframe.pack(pady=(14, 6))
        self.start_btn = tk.Button(btnframe, text="▶  START MINING",
                                   font=("Segoe UI", 14, "bold"), bg="#10b981",
                                   fg="white", width=16, height=2,
                                   command=self.start_mining)
        self.start_btn.pack(side="left", padx=6)
        self.stop_btn = tk.Button(btnframe, text="■  STOP",
                                  font=("Segoe UI", 14, "bold"), bg="#ef4444",
                                  fg="white", width=12, height=2,
                                  command=self.stop_mining, state="disabled")
        self.stop_btn.pack(side="left", padx=6)

        dash = tk.Button(self.root, text="📊 Open Dashboard",
                         command=lambda: webbrowser.open(
                             f"http://127.0.0.1:{config.get('dashboard_port', 8080)}"))
        dash.pack()

        stats = tk.LabelFrame(self.root, text="Live Status", padx=10, pady=8)
        stats.pack(fill="x", **pad)
        self.hash_var = tk.StringVar(value="0 H/s")
        self.xmr_var = tk.StringVar(value="0.000000 XMR/day (est.)")
        self.php_var = tk.StringVar(value="≈ ₱0.00/day (est.)")
        self.state_var = tk.StringVar(value="Idle")
        tk.Label(stats, textvariable=self.state_var, fg="#888").pack(anchor="w")
        tk.Label(stats, textvariable=self.hash_var, font=("Segoe UI", 18, "bold"),
                 fg="#22d3ee").pack(anchor="w")
        tk.Label(stats, textvariable=self.xmr_var).pack(anchor="w")
        tk.Label(stats, textvariable=self.php_var, fg="#10b981").pack(anchor="w")

        self.log = tk.Text(self.root, height=8, width=62, state="disabled",
                           bg="#111", fg="#a5f3fc")
        self.log.pack(fill="x", **pad)

    def _load_saved(self):
        self.wallet_var.set(config.get("wallet", ""))
        self.user_var.set(config.get("username", ""))
        self.cpu_var.set(int(config.get("limit_cpu", 30) or 30))

    # ---------- actions ----------
    def log(self, msg: str):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def start_mining(self):
        wallet = self.wallet_var.get().strip()
        username = self.user_var.get().strip() or "miner"
        if not validate_wallet(wallet):
            messagebox.showerror("Wallet needed",
                                 "Please paste a valid Monero wallet address\n"
                                 "(95 characters, starts with 4 or 8).")
            return

        config.set("wallet", wallet)
        config.set("username", username)
        config.set("limit_cpu", float(self.cpu_var.get()))
        config.set("stealth", self.stealth_var.get())

        xmrig = find_xmrig() or binaries.ensure_xmrig()
        if not xmrig:
            messagebox.showerror("xmrig missing",
                                 "Could not find or install xmrig.\n"
                                 "Run: hashflow install")
            return

        owner = read_owner_wallet()
        if not owner:
            owner = wallet  # solo mode

        limit = float(self.cpu_var.get())
        self.miner = HashflowMiner(
            wallet=wallet,
            owner_wallet=owner,
            xmrig_bin=str(xmrig),
            donation=0.05,
            limit_cpu=limit,
            stealth=limit < 80 or self.stealth_var.get(),
            verbose=True,
            log_callback=lambda m, l=None: self.log(m),
        )
        threading.Thread(target=self._run_miner, daemon=True).start()

    def _run_miner(self):
        try:
            ok = self.miner.start()
            if not ok:
                self.root.after(0, lambda: messagebox.showerror(
                    "Start failed", "xmrig could not start. Check the log."))
                return
            self.root.after(0, self._on_started)
            self.miner.wait()
        except Exception as e:
            self.root.after(0, lambda: self.log(f"Error: {e}"))
        finally:
            self.root.after(0, self._on_stopped)

    def _on_started(self):
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.state_var.set("Mining…")
        self._poll_stats()

    def _on_stopped(self):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.state_var.set("Idle")
        if self._poll_after:
            self.root.after_cancel(self._poll_after)
            self._poll_after = None

    def stop_mining(self):
        if self.miner:
            threading.Thread(target=self.miner.stop, daemon=True).start()

    def _poll_stats(self):
        stats = stats_manager.get_combined_stats()
        total = stats.get("total", {})
        contrib = stats.get("contrib", {})
        h = total.get("current") or contrib.get("current") or 0.0
        self.hash_var.set(f"{h:,.0f} H/s")

        xmr_day = (h / 1000.0) * XMR_PER_KS_DAY * 0.95  # user keeps 95%
        self.xmr_var.set(f"{xmr_day:.6f} XMR/day (est.)")

        php = self._xmr_to_php(xmr_day)
        self.php_var.set(f"≈ ₱{php:,.2f}/day (est.)" if php else "≈ ₱—/day (est.)")

        self._poll_after = self.root.after(3000, self._poll_stats)

    @staticmethod
    def _xmr_to_php(xmr: float) -> Optional[float]:
        try:
            import urllib.request
            url = "https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=usd&include_24hr_vol=false"
            with urllib.request.urlopen(url, timeout=8) as r:
                data = json.loads(r.read().decode())
            usd = float(data["monero"]["usd"])
        except Exception:
            usd = 150.0  # offline fallback estimate
        try:
            url = "https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=php"
            with urllib.request.urlopen(url, timeout=8) as r:
                data = json.loads(r.read().decode())
            return xmr * float(data["monero"]["php"])
        except Exception:
            return xmr * usd * 56.0  # offline PHP fallback

    def _on_close(self):
        if self.miner and self.miner.is_running():
            self.miner.stop()
        self.root.destroy()


def run_gui():
    if not HAS_TK:
        print("tkinter is not available on this system.")
        print("Use the web dashboard instead:  hashflow dashboard")
        raise SystemExit(1)
    root = tk.Tk()
    HashflowApp(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
