"""
Binary manager for Hashflow.

Downloads prebuilt xmrig static binaries so users never have to compile.
Platforms: Linux x64/arm64, Windows x64, macOS x64/arm64.

On Termux (Android), official static builds target glibc and may not run on
Android's bionic libc. We try the prebuilt binary first, verify it actually
runs, and fall back to building from source if it fails.
"""
import io
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional, Tuple

# Pinned xmrig release (static builds published on GitHub releases)
XMRIG_VERSION = "6.26.0"
RELEASE_BASE = f"https://github.com/xmrig/xmrig/releases/download/v{XMRIG_VERSION}"

# Official release assets (note: no linux-arm64 static build exists,
# so Termux/Android falls back to building from source)
LINUX_X64_ASSET = f"xmrig-{XMRIG_VERSION}-linux-static-x64.tar.gz"
WINDOWS_X64_ASSET = f"xmrig-{XMRIG_VERSION}-windows-x64.zip"
MACOS_X64_ASSET = f"xmrig-{XMRIG_VERSION}-macos-x64.tar.gz"
MACOS_ARM64_ASSET = f"xmrig-{XMRIG_VERSION}-macos-arm64.tar.gz"


def is_termux() -> bool:
    """Detect running inside Termux on Android."""
    prefix = os.environ.get("PREFIX", "")
    if prefix.startswith("/data/data/com.termux"):
        return True
    if os.path.exists("/system/bin/termux-setup-storage") or "ANDROID_ROOT" in os.environ:
        return True
    return False


def platform_key() -> Tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64", "x64"):
        arch = "x64"
    elif machine in ("aarch64", "arm64", "armv8l"):
        arch = "arm64"
    else:
        arch = machine
    return system, arch


def asset_for(system: str, arch: str) -> Optional[Tuple[str, str]]:
    """Return (asset_filename, binary_name) for the platform, or None."""
    if system == "linux" and arch == "x64":
        return LINUX_X64_ASSET, "xmrig"
    # No official linux-arm64 static build - Termux builds from source
    if system == "windows" and arch == "x64":
        return WINDOWS_X64_ASSET, "xmrig.exe"
    if system == "darwin" and arch == "x64":
        return MACOS_X64_ASSET, "xmrig"
    if system == "darwin" and arch == "arm64":
        return MACOS_ARM64_ASSET, "xmrig"
    return None


def bin_dir() -> Path:
    data_dir = Path.home() / ".hashflow"
    bdir = data_dir / "bin"
    bdir.mkdir(parents=True, exist_ok=True)
    return bdir


def _download(url: str, dest: Path, progress_cb=None) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hashflow-installer"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0) or 0)
            data = resp.read()
        dest.write_bytes(data)
        return True
    except Exception as e:
        print(f"[WARN] Download failed ({e})", file=sys.stderr)
        return False


def _safe_extract_members(members_names):
    """Guard against path traversal archives."""
    safe = []
    for name in members_names:
        p = Path(name)
        if p.is_absolute() or ".." in p.parts:
            continue
        safe.append(str(p))
    return safe


def _extract_archive(archive: Path, dest_dir: Path) -> None:
    suffixes = archive.name.lower()
    if suffixes.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            names = _safe_extract_members(z.namelist())
            for name in names:
                z.extract(name, dest_dir)
    else:
        with tarfile.open(archive, "r:*") as t:
            names = _safe_extract_members(t.getnames())
            for name in names:
                member = t.getmember(name)
                t.extract(member, dest_dir)


def _find_binary(root: Path, binary_name: str) -> Optional[Path]:
    matches = list(root.rglob(binary_name))
    for m in matches:
        if m.is_file():
            return m
    return None


def _binary_runs(path: Path) -> bool:
    """Verify a downloaded binary actually executes on this system."""
    if not path.exists():
        return False
    try:
        result = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            timeout=15,
        )
        return result.returncode == 0
    except Exception:
        return False


def download_prebuilt(verbose: bool = True) -> Optional[Path]:
    """Download and cache a prebuilt static xmrig. Returns path or None."""
    system, arch = platform_key()
    mapping = asset_for(system, arch)
    if not mapping:
        if verbose:
            print(f"[INFO] No prebuilt xmrig for {system}/{arch} - will try system/build path")
        return None

    asset, binary_name = mapping
    cache = bin_dir() / binary_name

    if cache.exists() and _binary_runs(cache):
        return cache

    url = f"{RELEASE_BASE}/{asset}"
    if verbose:
        print(f"[INFO] Downloading prebuilt xmrig: {asset}")

    tmp = bin_dir() / ("dl_" + asset)
    try:
        ok = _download(url, tmp)
        if not ok or not tmp.exists() or tmp.stat().st_size < 100_000:
            if verbose:
                print("[WARN] Prebuilt download failed or too small")
            return None

        with tempfile.TemporaryDirectory(prefix="hf_extract_") as td:
            _extract_archive(tmp, Path(td))
            found = _find_binary(Path(td), binary_name)
            if not found:
                if verbose:
                    print("[WARN] Could not locate xmrig inside archive")
                return None
            shutil.copy2(found, cache)
        cache.chmod(0o755)
        if verbose:
            print(f"[INFO] Installed xmrig to {cache}")
        # Final verification - catches glibc-incompatible builds (e.g. on Termux)
        if not _binary_runs(cache):
            if verbose:
                print("[WARN] Downloaded binary does not run on this system (libc mismatch)")
            try:
                cache.unlink()
            except OSError:
                pass
            return None
        return cache
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def build_from_source(verbose: bool = True) -> Optional[Path]:
    """Fallback: clone and build xmrig from source (Termux-safe flags)."""
    build_tools = shutil.which("cmake") and shutil.which("make")
    if not build_tools:
        if verbose:
            print("[WARN] cmake/make not found - cannot build xmrig from source")
        return None

    src = bin_dir() / "xmrig-src"
    build = src / "build"
    try:
        if not src.exists():
            if verbose:
                print("[INFO] Cloning xmrig source (one time, takes a few minutes)...")
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", f"v{XMRIG_VERSION}",
                 "https://github.com/xmrig/xmrig.git", str(src)],
                check=True, capture_output=True, timeout=600,
            )
        build.mkdir(parents=True, exist_ok=True)
        if verbose:
            print("[INFO] Building xmrig (this can take 5-10 minutes on phones)...")
        subprocess.run(
            ["cmake", "..", "-DWITH_OPENCL=OFF", "-DWITH_CUDA=OFF", "-DWITH_HWLOC=OFF"],
            cwd=build, check=True, capture_output=True, timeout=600,
        )
        subprocess.run(
            ["make", "-j", str(max(1, (os.cpu_count() or 2)))],
            cwd=build, check=True, capture_output=True, timeout=1800,
        )
        built = build / "xmrig"
        if built.exists():
            dest = bin_dir() / "xmrig"
            shutil.copy2(built, dest)
            dest.chmod(0o755)
            return dest
    except Exception as e:
        if verbose:
            print(f"[WARN] Source build failed: {e}", file=sys.stderr)
    return None


def find_system_xmrig() -> Optional[Path]:
    which = shutil.which("xmrig")
    if which:
        p = Path(which)
        if _binary_runs(p):
            return p
    # cwd fallback
    local = Path.cwd() / "xmrig"
    if local.exists() and _binary_runs(local):
        return local
    return None


def ensure_xmrig(verbose: bool = True, allow_build: bool = True) -> Optional[Path]:
    """
    Full resolution order:
      1. Cached prebuilt binary in ~/.hashflow/bin
      2. Fresh prebuilt download
      3. System xmrig on PATH
      4. Build from source (if allowed)
    Returns a Path to a working xmrig, or None.
    """
    system, arch = platform_key()
    binary_name = "xmrig.exe" if system == "windows" else "xmrig"

    cache = bin_dir() / binary_name
    if cache.exists() and _binary_runs(cache):
        return cache

    prebuilt = download_prebuilt(verbose=verbose)
    if prebuilt:
        return prebuilt

    system_bin = find_system_xmrig()
    if system_bin:
        return system_bin

    # On Termux the glibc static build often fails; source build is the reliable path
    if allow_build and is_termux():
        built = build_from_source(verbose=verbose)
        if built:
            return built

    if allow_build and not system_bin:
        built = build_from_source(verbose=verbose)
        if built:
            return built

    return None


if __name__ == "__main__":
    p = ensure_xmrig()
    if p:
        print(f"xmrig ready: {p}")
    else:
        print("xmrig could not be located/installed")
        sys.exit(1)
