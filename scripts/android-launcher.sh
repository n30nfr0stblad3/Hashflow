#!/data/data/com.termux/files/usr/bin/bash
# Hashflow Android App Launcher (TUI menu)

clear
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}"
cat << "EOF"
 ██░ ██  ▄▄▄       ██████  ██░ ██   █████▒██▓
▓██░ ██▒▒████▄   ▒██    ▒ ▓██░ ██▒▓██   ▒▓██▒
▒██▀▀██░▒██  ▀█▄ ░ ▓██▄   ▒██▀▀██░▒████ ░▒██░
░▓█ ░██ ░██▄▄▄▄██  ▒   ██▒░▓█ ░██ ░▓█▒  ░▒██░
░▓█▒░██▓▓█   ▓██▒▒██████▒▒░▓█▒░██▓░▒█░   ░██████▒
 ▒ ░░▒░▒▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░ ▒░▓  ░░ ▒░▓  ░
 ▒ ░▒░ ░ ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░░ ░ ▒  ░░ ░ ▒  ░
 ░  ░░ ░ ░   ▒   ░  ░  ░   ░  ░░ ░░ ░   ░   ░ ░
 ░  ░  ░      ░  ░      ░   ░  ░  ░      ░     ░
EOF
echo -e "${NC}"
echo -e "${GREEN} Ethical Monero Mining - Android Edition${NC}"

cd "$HOME/Hashflow" 2>/dev/null || {
    echo -e "${RED}Hashflow not found. Run: bash scripts/termux-setup.sh${NC}"
    exit 1
}

while true; do
    echo ""
    echo -e "${CYAN}=== Hashflow Menu ===${NC}"
    echo "1) ⚡ Setup (first time only)"
    echo "2) ▶️  Start Mining (uses saved settings)"
    echo "3) 🕵️  Start Mining - Stealth 30% CPU (phone-safe)"
    echo "4) 📊 Open Dashboard (http://localhost:8080)"
    echo "5) 💰 How to cash out via PDAX"
    echo "6) 👥 Group Status"
    echo "7) ⚙️  Settings"
    echo "8) ❌ Exit"
    echo ""
    read -p "Choose [1-8]: " choice

    case $choice in
        1)
            python3 -m hashflow setup
            ;;
        2)
            python3 -m hashflow start --no-tui
            ;;
        3)
            WALLET=$(python3 -c "from hashflow.config import config; print(config.get('wallet',''))")
            USER=$(python3 -c "from hashflow.config import config; print(config.get('username','miner'))")
            if [ -z "$WALLET" ]; then
                echo -e "${YELLOW}Run Setup first (option 1)${NC}"
                read -p "Monero Wallet: " WALLET
                read -p "Nickname: " USER
            fi
            python3 -m hashflow mine "$WALLET" --username "$USER" --agree --limit-cpu 30 --stealth --dashboard --no-tui
            ;;
        4)
            echo -e "${GREEN}Dashboard: http://localhost:8080${NC}"
            echo -e "${YELLOW}Tip: open Chrome and visit the link above${NC}"
            python3 -m hashflow dashboard --port 8080
            ;;
        5)
            echo -e "${CYAN}Cash out via PDAX:${NC}"
            echo "1. Mine XMR to your wallet"
            echo "2. Send XMR from your wallet app to your PDAX XMR address"
            echo "3. In PDAX app: sell XMR for PHP"
            echo "4. Portfolio > Cash Out > GCash / Maya / Bank"
            echo "   (InstaPay, ₱15 fee, real-time, up to ₱50,000)"
            ;;
        6)
            python3 -m hashflow group list
            python3 -m hashflow group stats
            ;;
        7)
            python3 -m hashflow config show
            ;;
        8)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            ;;
    esac
done
