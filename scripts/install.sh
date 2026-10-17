#!/bin/bash
# Hashflow installer - VPS / Linux / macOS
set -e

echo "⛏️  Hashflow Installer"

# Python check
if ! command -v python3 &> /dev/null; then
    echo "Installing python3..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv git
    elif command -v brew &> /dev/null; then
        brew install python git
    else
        echo "Please install Python 3.10+ first: https://python.org"
        exit 1
    fi
fi

if ! command -v git &> /dev/null; then
    if command -v apt-get &> /dev/null; then sudo apt-get install -y git
    elif command -v brew &> /dev/null; then brew install git
    fi
fi

# Get the repo (if run via curl|bash from raw URL, clone first)
if [ ! -f "pyproject.toml" ] && [ ! -d "hashflow" ]; then
    git clone -b arena/01a095da-hashflow https://github.com/n30nfr0stblad3/Hashflow.git
    cd Hashflow
fi

# Virtual env
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# xmrig: prebuilt binary (no compile needed)
echo "Getting xmrig..."
hashflow install || echo "xmrig auto-install failed - you can retry later with: hashflow install"

mkdir -p ~/.hashflow

# Owner wallet (host donation wallet)
if [ ! -f "owner_wallet.txt" ] && [ ! -f ~/.hashflow/owner_wallet.txt ]; then
    echo ""
    read -p "Owner (host) Monero wallet, or leave empty for solo mode: " owner_wallet
    if [ -n "$owner_wallet" ]; then
        echo "$owner_wallet" > owner_wallet.txt
        echo "$owner_wallet" > ~/.hashflow/owner_wallet.txt
    fi
fi

echo ""
echo "✅ Hashflow installed!"
echo ""
echo "Easy start (first time):"
echo "  hashflow setup     # 30-second wizard"
echo "  hashflow start     # mine with your saved settings + dashboard"
echo ""
echo "Manual:"
echo "  hashflow mine <WALLET> --username <NAME> --agree --dashboard"
echo ""
