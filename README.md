# Hashflow: Monero Mining Wrapper

This is a Python-based wrapper script for the `xmrig` miner, designed to simplify Monero (XMR) mining on Termux (Android) and VPS environments.

## 🔧 Features
- Contributors mine directly to their own Monero wallet
- 5% of CPU threads are reserved for the project owner's wallet (dual mining logic)
- Auto-configures:
  - Mining pool: `pool.supportxmr.com:3333`
  - CPU priority: `3`
  - Donation level: `0`
- Optional: CPU limiter and stealth logic
- Run with:
  ```bash
  python3 miner.py <your_wallet_address> --agree