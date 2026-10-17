"""Tests for Hashflow v2 accessibility layer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hashflow import binaries
from hashflow.config import config


def test_platform_key():
    system, arch = binaries.platform_key()
    assert system in ("linux", "windows", "darwin")
    assert arch in ("x64", "arm64", system)  # may be unusual arch


def test_asset_mapping():
    assert binaries.asset_for("linux", "x64") == (
        f"xmrig-{binaries.XMRIG_VERSION}-linux-static-x64.tar.gz", "xmrig")
    # No official linux-arm64 static build -> source build fallback
    assert binaries.asset_for("linux", "arm64") is None
    assert binaries.asset_for("windows", "x64")[0].endswith("-windows-x64.zip")
    assert binaries.asset_for("darwin", "arm64")[0].endswith("-macos-arm64.tar.gz")
    assert binaries.asset_for("plan9", "x64") is None


def test_bin_dir():
    b = binaries.bin_dir()
    assert b.name == "bin"
    assert b.exists()


def test_config_saves_user_keys():
    config.set("wallet", "4" + "A" * 94)
    config.set("username", "tester")
    assert config.get("wallet").startswith("4")
    assert config.get("username") == "tester"


def test_wallet_validation():
    from hashflow.miner import validate_wallet_input
    assert validate_wallet_input("4" + "A" * 94) is True
    assert validate_wallet_input("8" + "B" * 94) is True
    assert validate_wallet_input("short") is False
    assert validate_wallet_input("") is False
    assert validate_wallet_input("1" + "A" * 94) is False
