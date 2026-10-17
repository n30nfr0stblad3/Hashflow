#!/data/data/com.termux/files/usr/bin/bash
# Hashflow Termux installer - Normie Mode
# One line:  bash <(curl -sL https://tinyurl.com/hashflow-termux)
set -e

echo "⛏️  Hashflow installer for Android (Termux)"
echo "============================================"

# 1. Dependencies (hwloc may be missing on some mirrors - not required)
echo "[1/5] Installing system packages..."
pkg update -y || true
pkg install -y python git openssl libuv termux-tools || \
pkg install -y python git openssl termux-tools || true

# 2. Get Hashflow (the app branch with everything in it)
echo "[2/5] Getting Hashflow..."
if [ ! -d "$HOME/Hashflow" ]; then
    git clone -b arena/01a095da-hashflow https://github.com/n30nfr0stblad3/Hashflow.git "$HOME/Hashflow" || \
    git clone https://github.com/n30nfr0stblad3/Hashflow.git "$HOME/Hashflow"
fi
cd "$HOME/Hashflow"

# 3. Python package
echo "[3/5] Installing Hashflow (Python)..."
pip install --upgrade pip >/dev/null 2>&1 || true
pip install -e . 2>/dev/null || pip install . 2>/dev/null || {
    pip install psutil rich fastapi uvicorn websockets pydantic || true
}

# 4. xmrig binary (prebuilt first, builds from source if needed)
echo "[4/5] Getting xmrig miner (may take 5-10 min on phone if building)..."
python3 -m hashflow install || true

# 5. Easy setup
echo "[5/5] Almost done..."
mkdir -p ~/.hashflow

# One-tap launcher
cat > $HOME/hashflow-start.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$HOME/Hashflow"
python3 -m hashflow start
EOF
chmod +x $HOME/hashflow-start.sh

# Termux widget shortcut (tap from home screen)
mkdir -p ~/.shortcuts 2>/dev/null || true
cp $HOME/hashflow-start.sh ~/.shortcuts/Hashflow 2>/dev/null || true
chmod +x ~/.shortcuts/Hashflow 2>/dev/null || true

echo ""
echo "✅ Hashflow installed!"
echo ""
echo "Next steps (only once):"
echo "  1) Run the setup wizard:"
echo "       cd ~/Hashflow && python3 -m hashflow setup"
echo "  2) Then just tap your Home screen 'Hashflow' widget, or run:"
echo "       ~/hashflow-start.sh"
echo ""
echo "Dashboard: http://localhost:8080  (open in Chrome)"
echo "Cash out:  mine XMR -> send to PDAX -> sell for PHP -> GCash/Maya"
echo ""
