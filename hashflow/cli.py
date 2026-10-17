"""
CLI for Hashflow - Rich terminal UI
"""
import argparse
import os
import sys
import time
import threading
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.text import Text

from .config import config
from .group import group_manager
from .miner import find_xmrig, read_owner_wallet, HashflowMiner, setup_signal_handlers, validate_wallet_input
from .stats import stats_manager, format_hashrate
from .stealth import StealthLimiter
from . import binaries
from . import __version__

console = Console()

BANNER = """
[bold cyan]██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗██╗      ██████╗ ██╗    ██╗[/bold cyan]
[bold cyan]██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██║     ██╔═══██╗██║    ██║[/bold cyan]
[bold cyan]███████║███████║███████╗███████║█████╗  ██║     ██║   ██║██║ █╗ ██║[/bold cyan]
[bold cyan]██╔══██║██╔══██║╚════██║██╔══██║██╔══╝  ██║     ██║   ██║██║███╗██║[/bold cyan]
[bold cyan]██║  ██║██║  ██║███████║██║  ██║██║     ███████╗╚██████╔╝╚███╔███╔╝[/bold cyan]
[bold cyan]╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝[/bold cyan]
[dim]Ethical Monero Mining Wrapper • v{version} • Termux & VPS Ready[/dim]
"""

def print_banner():
    console.print(BANNER.format(version=__version__))
    console.print()

def validate_wallet(wallet: str) -> bool:
    return validate_wallet_input(wallet)

def ensure_agreement(args):
    if not args.agree:
        console.print(Panel(
            "[bold yellow]Ethical Mining Agreement[/bold yellow]\n\n"
            "By using Hashflow, you agree that:\n"
            "• You mine directly to YOUR own wallet (you keep rewards)\n"
            "• 2-5% of threads are donated to project owner to support development\n"
            "• This is transparent and consensual dual-mining\n"
            "• You will not use this for unauthorized mining\n"
            "• You understand the risks of mining on your device\n\n"
            "Run with [bold green]--agree[/bold green] to accept.",
            title="⚠️  Agreement Required",
            border_style="yellow"
        ))
        sys.exit(1)

def cmd_mine(args):
    print_banner()
    ensure_agreement(args)

    # Wallet: arg, or saved from setup wizard
    wallet = args.wallet or config.get("wallet")
    if not wallet:
        console.print("[bold red]Error:[/bold red] No wallet set")
        console.print("Run [bold green]hashflow setup[/bold green] first, or pass your wallet:")
        console.print("  hashflow mine 4YOUR_WALLET --username alice --agree")
        sys.exit(1)

    if not validate_wallet(wallet):
        console.print(f"[bold red]Invalid Monero wallet address:[/bold red] {wallet[:20]}...")
        console.print("Monero addresses should be 95 chars starting with 4 or 8")
        sys.exit(1)

    # Username: arg or saved
    username = args.username or config.get("username")
    if not username:
        username = Prompt.ask("Pick a nickname for the group")
        config.set("username", username)

    # Find or install xmrig automatically
    if args.xmrig:
        xmrig_bin = find_xmrig(args.xmrig)
        if not xmrig_bin:
            console.print(f"[bold red]Error:[/bold red] xmrig not found at {args.xmrig}")
            sys.exit(1)
    else:
        xmrig_bin = find_xmrig(None)
        if not xmrig_bin:
            console.print("[cyan]No xmrig found - downloading prebuilt binary...[/cyan]")
            from . import binaries
            got = binaries.ensure_xmrig(verbose=True, allow_build=True)
            xmrig_bin = str(got) if got else None
        else:
            xmrig_bin = str(xmrig_bin)

    if not xmrig_bin:
        console.print("[bold red]Error:[/bold red] Could not get xmrig")
        console.print("• Run [bold green]hashflow install[/bold green] to retry")
        console.print("• Or install xmrig manually and pass --xmrig /path/to/xmrig")
        sys.exit(1)

    console.print(f"[green]✓[/green] Found xmrig: {xmrig_bin}")

    # Owner wallet
    owner_wallet = read_owner_wallet(args.owner_config)
    if not owner_wallet:
        console.print("[bold red]Error:[/bold red] Owner wallet configuration missing")
        console.print(f"Create file: {args.owner_config} with owner's Monero address")
        # Create placeholder for demo if not exists
        if args.owner_config == config.get("owner_config"):
            # Check if file exists in data_dir
            owner_path = Path(config.get("data_dir")) / "owner_wallet.txt"
            if not owner_path.exists():
                console.print(f"[yellow]Creating demo owner wallet placeholder at {owner_path}[/yellow]")
                # For demo, use a dummy - in production this should be real owner wallet
                # We'll use same as contrib for demo if owner not set, but warn
                console.print("[yellow]Using contributor wallet as owner for demo (donation disabled in demo mode)[/yellow]")
                owner_wallet = wallet
            else:
                owner_wallet = read_owner_wallet(str(owner_path))
        
        if not owner_wallet:
            console.print("[yellow]No owner wallet found, running in solo mode (100% to you)[/yellow]")
            owner_wallet = wallet
            args.donation = 0

    # Device and group registration
    device_id = group_manager.get_device_id()
    console.print(f"[cyan]Device ID:[/cyan] {device_id} | [cyan]User:[/cyan] {username}")

    try:
        member = group_manager.register(username, device_id, wallet)
        console.print(f"[green]✓[/green] Registered '{username}' | Group: {len(group_manager.load_group())}/{config.get('max_group_size')}")
    except ValueError as e:
        console.print(f"[bold red]Registration failed:[/bold red] {e}")
        sys.exit(1)

    # Thread calculation
    total_threads = args.threads or os.cpu_count() or 4
    from .miner import compute_thread_split
    contrib_threads, owner_threads = compute_thread_split(total_threads, args.donation)
    
    # Dashboard
    miner_instance = None
    dashboard_thread = None
    if args.dashboard:
        from .dashboard.server import set_miner_instance
        # We'll start dashboard in thread
        pass

    # Create miner
    miner = HashflowMiner(
        wallet=wallet,
        owner_wallet=owner_wallet,
        xmrig_bin=xmrig_bin,
        total_threads=total_threads,
        donation=args.donation,
        pool=args.pool,
        cpu_priority=args.cpu_priority,
        donate_level=args.donate_level,
        refresh_interval=args.refresh,
        stealth=args.stealth,
        limit_cpu=args.limit_cpu,
        verbose=not args.quiet,
        quiet=args.quiet,
    )

    setup_signal_handlers(miner)

    # Start dashboard if requested
    if args.dashboard:
        from .dashboard.server import app, set_miner_instance
        import uvicorn
        set_miner_instance(miner)
        
        def run_dashboard():
            try:
                uvicorn.run(app, host=args.dashboard_host, port=args.dashboard_port, log_level="error", access_log=False)
            except Exception as e:
                console.print(f"[red]Dashboard failed: {e}[/red]")

        dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
        dashboard_thread.start()
        console.print(f"[green]✓[/green] Dashboard: http://{args.dashboard_host}:{args.dashboard_port} (and preview URL)")

    # Start mining
    if not miner.start():
        console.print("[red]Failed to start miners[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold green]Mining Started![/bold green]\n\n"
        f"Pool: {args.pool}\n"
        f"Your threads: {contrib_threads} | Owner: {owner_threads} | Total: {total_threads}\n"
        f"Donation: {args.donation*100:.1f}%\n"
        f"CPU Limit: {args.limit_cpu if args.limit_cpu else 'None'}% | Stealth: {args.stealth}\n"
        f"Wallet: {wallet[:12]}...{wallet[-8:]}\n\n"
        f"[dim]Press Ctrl+C to stop[/dim]",
        title="⛏️  Hashflow Active",
        border_style="green"
    ))

    # Live stats display
    if not args.quiet and not args.no_tui:
        try:
            with Live(refresh_per_second=2, console=console) as live:
                while miner.is_running():
                    # Build table
                    table = Table(title="Hashflow Live Stats", show_header=True, header_style="bold magenta")
                    table.add_column("Miner", style="cyan")
                    table.add_column("Hashrate", justify="right")
                    table.add_column("Avg", justify="right")
                    table.add_column("Accepted", justify="right")
                    table.add_column("Rejected", justify="right")
                    table.add_column("Uptime", justify="right")

                    stats = stats_manager.get_combined_stats()
                    contrib = stats["contrib"]
                    owner = stats["owner"]
                    total = stats["total"]

                    table.add_row(
                        "You",
                        contrib["current_formatted"],
                        contrib["average_formatted"],
                        str(contrib["accepted"]),
                        str(contrib["rejected"]),
                        contrib["uptime_formatted"]
                    )
                    table.add_row(
                        "Owner",
                        owner["current_formatted"],
                        owner["average_formatted"],
                        str(owner["accepted"]),
                        str(owner["rejected"]),
                        owner["uptime_formatted"]
                    )
                    table.add_row(
                        "[bold]Total[/bold]",
                        f"[bold]{total['current_formatted']}[/bold]",
                        f"[bold]{total['average_formatted']}[/bold]",
                        str(contrib["accepted"] + owner["accepted"]),
                        str(contrib["rejected"] + owner["rejected"]),
                        "",
                    )

                    # Stealth info
                    stealth_info = miner.stealth_limiter.get_stealth_status()
                    thermal = miner.thermal_guard.get_temps()
                    extra = ""
                    if stealth_info["cpu_limit"] > 0:
                        extra += f"\n[dim]CPU Limit: {stealth_info['cpu_limit']}% | Current Delay: {stealth_info['current_delay']:.2f}s[/dim]"
                    if thermal:
                        extra += f"\n[dim]Temp: {thermal:.1f}°C[/dim]"
                    if args.dashboard:
                        extra += f"\n[dim]Dashboard: http://{args.dashboard_host}:{args.dashboard_port}[/dim]"

                    panel = Panel(table, title="⛏️ Mining", border_style="green")
                    if extra:
                        layout = Layout()
                        layout.split_column(
                            Layout(panel),
                            Layout(Panel(extra, title="System", border_style="blue"))
                        )
                        live.update(layout)
                    else:
                        live.update(panel)

                    time.sleep(args.refresh if not args.stealth else miner.stealth_limiter.get_refresh_interval(args.refresh))
        except KeyboardInterrupt:
            pass
        finally:
            miner.stop()
    else:
        # No TUI, just wait
        try:
            miner.wait()
        except KeyboardInterrupt:
            miner.stop()

    console.print("[yellow]Miner stopped. Thank you for using Hashflow![/yellow]")

def cmd_status(args):
    print_banner()
    stats = stats_manager.get_combined_stats()
    group = group_manager.get_stats()
    
    table = Table(title="Hashflow Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Group Size", f"{group['total']}/{group['max']}")
    table.add_row("Available Slots", str(group['available']))
    table.add_row("Your Hashrate", stats["contrib"]["current_formatted"])
    table.add_row("Total Hashrate", stats["total"]["current_formatted"])
    table.add_row("Accepted Shares", str(stats["contrib"]["accepted"] + stats["owner"]["accepted"]))

    console.print(table)
    console.print(f"\n[dim]Platforms: {group['platforms']}[/dim]")

def cmd_group(args):
    print_banner()
    if args.action == "list":
        members = group_manager.list_members()
        if not members:
            console.print("[yellow]No members registered yet[/yellow]")
            return
        table = Table(title=f"Group Members ({len(members)}/{config.get('max_group_size')})")
        table.add_column("Username", style="cyan")
        table.add_column("Device ID", style="magenta")
        table.add_column("Platform")
        table.add_column("Joined")
        for m in members:
            import datetime
            joined = datetime.datetime.fromtimestamp(m.get("joined_at", 0)).strftime("%Y-%m-%d %H:%M") if m.get("joined_at") else "Unknown"
            table.add_row(m.get("username", "Unknown"), m.get("device_id", "")[:8], m.get("platform", "Unknown")[:30], joined)
        console.print(table)
    elif args.action == "stats":
        stats = group_manager.get_stats()
        console.print(Panel(
            f"Total: {stats['total']}/{stats['max']}\n"
            f"Available: {stats['available']}\n"
            f"Platforms: {stats['platforms']}",
            title="Group Stats"
        ))
    elif args.action == "remove":
        if not args.username:
            console.print("[red]Username required[/red]")
            return
        if group_manager.unregister(args.username):
            console.print(f"[green]Removed {args.username}[/green]")
        else:
            console.print(f"[yellow]User {args.username} not found[/yellow]")

def cmd_config(args):
    print_banner()
    if args.action == "show":
        cfg = config.all()
        table = Table(title="Hashflow Config")
        table.add_column("Key", style="cyan")
        table.add_column("Value")
        for k, v in cfg.items():
            table.add_row(k, str(v))
        console.print(table)
    elif args.action == "set":
        if not args.key or args.value is None:
            console.print("[red]Key and value required[/red]")
            return
        # Try parse value
        val = args.value
        try:
            import json
            val = json.loads(args.value)
        except:
            if args.value.isdigit():
                val = int(args.value)
            else:
                try:
                    val = float(args.value)
                except:
                    val = args.value
        config.set(args.key, val)
        console.print(f"[green]Set {args.key} = {val}[/green]")
    elif args.action == "reset":
        if Confirm.ask("Reset config to defaults?"):
            config_path = config.config_path
            if config_path.exists():
                config_path.unlink()
            console.print("[green]Config reset[/green]")

def cmd_dashboard(args):
    print_banner()
    console.print(f"[cyan]Starting Hashflow Dashboard on {args.host}:{args.port}[/cyan]")
    console.print(f"[dim]API docs: http://{args.host}:{args.port}/docs[/dim]")
    console.print(f"[dim]If running in Arena preview, use the preview URL shown above[/dim]\n")

    from .dashboard.server import run_server
    try:
        run_server(host=args.host, port=args.port)
    except KeyboardInterrupt:
        console.print("[yellow]Dashboard stopped[/yellow]")

def cmd_setup(args):
    from .setup_wizard import run_wizard
    print_banner()
    run_wizard()

def cmd_install(args):
    print_banner()
    console.print("[cyan]Locating / installing xmrig...[/cyan]")
    got = binaries.ensure_xmrig(verbose=True, allow_build=True)
    if got:
        console.print(f"[green]✓[/green] xmrig ready: {got}")
    else:
        console.print("[red]Could not get xmrig automatically.[/red]")
        console.print("• Debian/Ubuntu: sudo apt install xmrig")
        console.print("• macOS: brew install xmrig")
        console.print("• Termux: build from source (see README)")
        sys.exit(1)

def cmd_gui(args):
    from .gui import run_gui
    run_gui()

def cmd_start(args):
    """One-command start using saved setup."""
    print_banner()
    wallet = config.get("wallet")
    if not wallet:
        console.print("[yellow]First time? Let's set up (30 seconds).[/yellow]")
        from .setup_wizard import run_wizard
        run_wizard()
        wallet = config.get("wallet")
        if not wallet:
            console.print("[red]Setup did not complete - no wallet saved.[/red]")
            sys.exit(1)

    from argparse import Namespace
    mine_args = Namespace(
        wallet=wallet,
        username=config.get("username") or "miner",
        xmrig=None,
        threads=None,
        donation=config.get("max_donation", 0.05),
        owner_config=config.get("owner_config"),
        pool=config.get("pool"),
        refresh=config.get("refresh_interval", 3.0),
        cpu_priority=config.get("cpu_priority", 3),
        donate_level=config.get("donate_level", 0),
        limit_cpu=config.get("limit_cpu", 0) or 0,
        stealth=bool(config.get("stealth", False)),
        agree=True,
        quiet=False,
        no_tui=bool(getattr(args, "no_tui", False)),
        dashboard=True,
        dashboard_host=config.get("dashboard_host"),
        dashboard_port=config.get("dashboard_port", 8080),
        verbose=False,
    )
    cmd_mine(mine_args)

def main():
    parser = argparse.ArgumentParser(
        description="Hashflow - Ethical Monero Mining Wrapper with Stealth Limiter & Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Easy start (recommended):
  hashflow setup            # answer 4 questions, saves everything
  hashflow start            # mines with your saved settings + dashboard

Examples:
  hashflow mine 4xxxxx... --username alice --agree
  hashflow mine 4xxxxx... --username alice --agree --limit-cpu 30 --stealth
  hashflow mine 4xxxxx... --username alice --agree --dashboard --threads 4
  hashflow install          # downloads xmrig automatically
  hashflow gui              # simple desktop app
  hashflow group list
  hashflow dashboard --port 8080
  hashflow config show
        """
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Mine command
    mine_parser = subparsers.add_parser("mine", help="Start mining")
    mine_parser.add_argument("wallet", nargs="?", default=None, help="Your Monero wallet address (optional if saved via setup)")
    mine_parser.add_argument("--username", default=None, help="Your unique username for the group (optional if saved)")
    mine_parser.add_argument("--xmrig", help="Path to xmrig binary")
    mine_parser.add_argument("--threads", type=int, help="Total mining threads (default: cpu count)")
    mine_parser.add_argument("--donation", type=float, default=0.05, help="Fractional donation to owner (0.02-0.05)")
    mine_parser.add_argument("--owner-config", default=config.get("owner_config"), help="Owner wallet file")
    mine_parser.add_argument("--pool", default=config.get("pool"), help="Mining pool")
    mine_parser.add_argument("--refresh", type=float, default=config.get("refresh_interval"), help="Refresh interval for stats")
    mine_parser.add_argument("--cpu-priority", type=int, default=config.get("cpu_priority"), help="CPU priority 0-5")
    mine_parser.add_argument("--donate-level", type=int, default=config.get("donate_level"), help="XMRig donate level")
    mine_parser.add_argument("--limit-cpu", type=float, default=0, help="Max CPU usage %% (e.g. 30 for 30%%)")
    mine_parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (randomized intervals, suppressed output)")
    mine_parser.add_argument("--agree", action="store_true", help="Agree to ethical mining terms")
    mine_parser.add_argument("--quiet", action="store_true", help="Quiet mode")
    mine_parser.add_argument("--no-tui", action="store_true", help="Disable TUI, log only")
    mine_parser.add_argument("--dashboard", action="store_true", help="Enable web dashboard")
    mine_parser.add_argument("--dashboard-host", default=config.get("dashboard_host"), help="Dashboard host")
    mine_parser.add_argument("--dashboard-port", type=int, default=config.get("dashboard_port"), help="Dashboard port")
    mine_parser.add_argument("--verbose", action="store_true", help="Verbose output")

    # Status command
    status_parser = subparsers.add_parser("status", help="Show mining status")

    # Group command
    group_parser = subparsers.add_parser("group", help="Group management")
    group_parser.add_argument("action", choices=["list", "stats", "remove"], help="Group action")
    group_parser.add_argument("--username", help="Username for remove")

    # Config command
    cfg_parser = subparsers.add_parser("config", help="Config management")
    cfg_parser.add_argument("action", choices=["show", "set", "reset"], help="Config action")
    cfg_parser.add_argument("--key", help="Config key")
    cfg_parser.add_argument("--value", help="Config value")

    # Dashboard command
    dash_parser = subparsers.add_parser("dashboard", help="Run dashboard only")
    dash_parser.add_argument("--host", default=config.get("dashboard_host"), help="Host")
    dash_parser.add_argument("--port", type=int, default=config.get("dashboard_port"), help="Port")

    # Setup wizard
    subparsers.add_parser("setup", help="First-run setup wizard (easy mode)")

    # Start with saved settings
    start_parser = subparsers.add_parser("start", help="Start mining with saved settings (one command)")
    start_parser.add_argument("--no-tui", action="store_true", help="Disable TUI")

    # Install xmrig
    subparsers.add_parser("install", help="Download/install the xmrig miner binary")

    # Simple GUI
    subparsers.add_parser("gui", help="Open the simple desktop app (no terminal needed)")

    # Legacy support - if first arg looks like wallet, treat as mine
    args = parser.parse_args()

    # If no command but wallet provided as first positional? Check sys.argv
    if not args.command:
        # Check if legacy invocation: python -m hashflow <wallet> --username ...
        # We'll try to parse as mine if wallet-like arg present
        if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
            # Might be wallet, try to re-parse as mine
            # Create new parser for legacy
            legacy_parser = argparse.ArgumentParser()
            legacy_parser.add_argument("wallet", help="Your Monero wallet address")
            legacy_parser.add_argument("--username", required=True)
            legacy_parser.add_argument("--xmrig")
            legacy_parser.add_argument("--threads", type=int)
            legacy_parser.add_argument("--donation", type=float, default=0.05)
            legacy_parser.add_argument("--owner-config", default=config.get("owner_config"))
            legacy_parser.add_argument("--pool", default=config.get("pool"))
            legacy_parser.add_argument("--refresh", type=float, default=config.get("refresh_interval"))
            legacy_parser.add_argument("--cpu-priority", type=int, default=config.get("cpu_priority"))
            legacy_parser.add_argument("--donate-level", type=int, default=config.get("donate_level"))
            legacy_parser.add_argument("--limit-cpu", type=float, default=0)
            legacy_parser.add_argument("--stealth", action="store_true")
            legacy_parser.add_argument("--agree", action="store_true")
            legacy_parser.add_argument("--quiet", action="store_true")
            legacy_parser.add_argument("--no-tui", action="store_true")
            legacy_parser.add_argument("--dashboard", action="store_true")
            legacy_parser.add_argument("--dashboard-host", default=config.get("dashboard_host"))
            legacy_parser.add_argument("--dashboard-port", type=int, default=config.get("dashboard_port"))
            legacy_parser.add_argument("--verbose", action="store_true")
            try:
                legacy_args = legacy_parser.parse_args()
                legacy_args.command = "mine"
                args = legacy_args
            except SystemExit:
                parser.print_help()
                sys.exit(1)
        else:
            parser.print_help()
            sys.exit(1)

    if args.command == "mine":
        cmd_mine(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "group":
        cmd_group(args)
    elif args.command == "config":
        cmd_config(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "setup":
        cmd_setup(args)
    elif args.command == "start":
        cmd_start(args)
    elif args.command == "install":
        cmd_install(args)
    elif args.command == "gui":
        cmd_gui(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
