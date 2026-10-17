"""
First-run setup wizard for Hashflow.

Plain-language questions, saves everything, and creates a one-tap
launcher so the user never types a long command again.
"""
import json
import os
import platform
import stat
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.panel import Panel

from .config import config
from .miner import validate_wallet_input
from . import binaries

console = Console()

WELCOME = """
Welcome to [bold cyan]Hashflow[/bold cyan]! ⛏️

Hashflow lets your device earn Monero (XMR) in the background.

How it works:
  • [green]You keep 95%[/green] of what your device mines
  • [yellow]5%[/yellow] supports the Hashflow project (the "host")
  • It automatically slows down if your device gets hot
  • You can watch everything at the [cyan]dashboard[/cyan]

We will ask you 4 quick questions. You can change everything later
by running: [bold]hashflow setup[/bold] again
"""


def ask_wallet() -> str:
    console.print("\n[bold]1) Your Monero wallet address[/bold]")
    console.print("[dim]This is where your Monero (XMR) rewards go.[/dim]")
    console.print("[dim]Get one free from: Cake Wallet, Monero.com, or Exodus[/dim]")
    console.print("[dim]It's 95 characters and starts with 4 or 8.[/dim]")
    while True:
        wallet = Prompt.ask("   Paste your wallet address").strip()
        if validate_wallet_input(wallet):
            return wallet
        console.print("[red]That doesn't look like a Monero address.[/red]")
        console.print("[dim]It should be 95 characters long and start with 4 or 8.[/dim]")
        console.print("[dim]Check you copied the whole thing.[/dim]")


def ask_username() -> str:
    console.print("\n[bold]2) Pick a nickname[/bold]")
    console.print("[dim]This shows your device in the Hashflow group list.[/dim]")
    default = "miner-" + binaries.platform_key()[0][:3]
    name = Prompt.ask("   Nickname", default=default)
    return (name or default).strip()[:32] or default


def ask_cpu_limit() -> float:
    console.print("\n[bold]3) How much CPU can Hashflow use?[/bold]")
    is_phone = binaries.is_termux()
    default = 30 if is_phone else 70
    console.print("[dim]Lower = cooler device and less battery used, but slower mining.[/dim]")
    console.print(f"[dim]Phones/tablets: [green]30[/green] is a good safe choice. (default: {default})[/dim]")
    while True:
        try:
            val = Prompt.ask("   CPU percent (10-100)", default=str(default))
            v = float(val)
            if 5 <= v <= 100:
                return v
        except ValueError:
            pass
        console.print("[red]Enter a number between 10 and 100 (like 30).[/red]")


def confirm_donation() -> bool:
    console.print("\n[bold]4) Support Hashflow?[/bold]")
    console.print("[dim]Hashflow runs by donating 5% of your mining power to the project.[/dim]")
    console.print("[dim]You keep the other 95%. This is the deal that keeps it free.[/dim]")
    return Confirm.ask("   Mine with the 5% donation?", default=True)


def save_setup(wallet: str, username: str, cpu_limit: float, donate: bool, pool: str) -> None:
    config.set("wallet", wallet)
    config.set("username", username)
    config.set("limit_cpu", cpu_limit)
    config.set("stealth", cpu_limit < 80)
    config.set("pool", pool)
    config.set("setup_done", True)
    if donate:
        # Keep existing owner wallet; ensure file exists in data dir
        owner_path = Path(config.get("data_dir")) / "owner_wallet.txt"
        if not owner_path.exists():
            try:
                owner_path.touch()
            except OSError:
                pass


def make_launcher() -> Optional[Path]:
    """Write a one-tap start script for the user's platform."""
    is_win = platform.system().lower() == "windows"
    if is_win:
        target = Path.home() / "Hashflow Start.bat"
        content = "@echo off\r\ncd /d %~dp0\r\nhashflow start --dashboard\r\npause\r\n"
    else:
        target = Path.home() / "hashflow-start.sh"
        content = "#!/usr/bin/env bash\ncd \"$HOME\"\nhashflow start --dashboard\n"
    try:
        target.write_text(content)
        if not is_win:
            target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return target
    except OSError:
        return None


def run_wizard() -> dict:
    console.print(Panel(WELCOME, title="Hashflow Setup", border_style="cyan"))

    wallet = ask_wallet()
    username = ask_username()
    cpu_limit = ask_cpu_limit()
    donate = confirm_donation()
    pool = Prompt.ask(
        "\nMining pool (press Enter for default)",
        default=config.get("pool", "pool.supportxmr.com:3333"),
    ).strip() or "pool.supportxmr.com:3333"

    save_setup(wallet, username, cpu_limit, donate, pool)
    launcher = make_launcher()

    console.print("\n[bold green]All set! ✅[/bold green]")
    console.print(Panel(
        f"[cyan]Wallet:[/cyan] {wallet[:10]}...{wallet[-6:]}\n"
        f"[cyan]Nickname:[/cyan] {username}\n"
        f"[cyan]CPU limit:[/cyan] {cpu_limit:.0f}%\n"
        f"[cyan]Donation:[/cyan] {'5% (thank you!)' if donate else 'off'}\n"
        f"[cyan]Pool:[/cyan] {pool}\n\n"
        + (f"One-tap launcher: [bold]{launcher}[/bold]\n" if launcher else "")
        + "\nTo start mining now, just type:\n"
          "[bold green]hashflow start[/bold green]",
        title="Saved",
        border_style="green",
    ))
    return {
        "wallet": wallet,
        "username": username,
        "cpu_limit": cpu_limit,
        "donation": donate,
        "pool": pool,
    }


if __name__ == "__main__":
    run_wizard()
