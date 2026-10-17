"""
Hashflow: Ethical Monero Mining Wrapper
A Python-based wrapper for xmrig with dual-mining, stealth limiting, and dashboard.
"""

__version__ = "2.0.0"
__author__ = "Hashflow Team"
__license__ = "Apache-2.0"

from .config import Config, DEFAULTS

__all__ = ["__version__", "Config", "DEFAULTS"]
