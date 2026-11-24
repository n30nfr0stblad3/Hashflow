#!/usr/bin/env python3
"""Download the right XMRig binary for this platform — no Termux, no manual
compiling, no package manager needed. Stdlib only.

Usage:  python3 scripts/fetch_xmrig.py [--dest DIR] [--version TAG]

Detects OS/arch (Windows/macOS/Linux, x64/arm64/armv7), fetches the official
release from github.com/xmrig/xmrig, extracts just the binary, and marks it
executable. Works on any device with Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

API_LATEST = "https://api.github.com/repos/xmrig/xmrig/releases/latest"
UA = {"User-Agent": "hashflow-fetch/2.0"}


def detect_asset_name() -> str:
    sysname = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    elif machine.startswith("armv7") or machine == "arm":
        arch = "armv7"
    else:
        arch = machine

    if sysname == "windows":
        return "msvc-win64.zip"
    if sysname == "darwin":
        # Apple Silicon vs Intel
        return "macos-arm64.tar.gz" if arch == "arm64" else "macos-x64.tar.gz"
    # linux
    if arch == "arm64":
        return "linux-static-arm64.tar.gz"
    if arch == "armv7":
        return "linux-static-arm32.tar.gz"
    return "linux-static-x64.tar.gz"


def pick_asset(assets, suffix: str):
    for a in assets:
        if a["name"].endswith(suffix):
            return a
    return None


def download(url: str, dest: Path) -> None:
    print(f"  Downloading {url}")
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as f:
        shutil.copyfileobj(resp, f)


def extract_binary(archive: Path, dest_dir: Path) -> Path:
    want = "xmrig.exe" if platform.system().lower() == "windows" else "xmrig"
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as z:
                z.extractall(tmp_path)
        else:
            with tarfile.open(archive) as t:
                t.extractall(tmp_path)
        found = None
        for p in tmp_path.rglob(want):
            found = p
            break
        if not found:
            raise RuntimeError(f"{want} not found inside {archive.name}")
        target = dest_dir / want
        shutil.copy2(found, target)
    if platform.system().lower() != "windows":
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch the official XMRig binary")
    ap.add_argument("--dest", default=".", help="Destination directory (default: cwd)")
    ap.add_argument("--version", default="latest", help="Release tag (e.g. v6.21.0)")
    args = ap.parse_args(argv)

    suffix = detect_asset_name()
    print(f"Platform: {platform.system()} {platform.machine()} -> asset '*{suffix}'")

    if args.version == "latest":
        req = urllib.request.Request(API_LATEST, headers=UA)
        with urllib.request.urlopen(req, timeout=30) as resp:
            release = json.load(resp)
        tag = release["tag_name"]
        assets = release["assets"]
    else:
        tag = args.version
        req = urllib.request.Request(
            f"https://api.github.com/repos/xmrig/xmrig/releases/tags/{tag}",
            headers=UA)
        with urllib.request.urlopen(req, timeout=30) as resp:
            assets = json.load(resp)["assets"]

    asset = pick_asset(assets, suffix)
    if not asset:
        print(f"[ERROR] No release asset matching '*{suffix}' in {tag}.", file=sys.stderr)
        return 1

    dest_dir = Path(args.dest).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / asset["name"]
        download(asset["browser_download_url"], archive)
        binary = extract_binary(archive, dest_dir)

    print(f"[OK] XMRig {tag} installed: {binary}")
    print("     Run the miner:  python3 miner.py WALLET --username NAME --agree")
    print("     Or the dashboard:  python3 miner.py --dashboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
