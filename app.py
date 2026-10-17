#!/usr/bin/env python3
"""
Hashflow App - Main entry point
Runs dashboard + optional mining

Usage:
    python app.py --dashboard
    python app.py --mine <wallet> --username <name>
"""
import sys
from hashflow.cli import main

if __name__ == "__main__":
    # If no args, show banner and run dashboard
    if len(sys.argv) == 1:
        sys.argv.append("dashboard")
    main()
