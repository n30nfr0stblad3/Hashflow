"""
Configuration management for Hashflow
"""
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any

DEFAULTS = {
    "pool": "pool.supportxmr.com:3333",
    "owner_config": "owner_wallet.txt",
    "xmrig_name": "xmrig",
    "donate_level": 0,
    "cpu_priority": 3,
    "min_donation": 0.02,
    "max_donation": 0.05,
    "group_file": "miners.json",
    "max_group_size": 100,
    "refresh_interval": 3.0,
    "samples": 8,
    "api_port": 0,  # 0 = disabled
    "dashboard_port": 8080,
    "dashboard_host": "0.0.0.0",
    "stealth": False,
    "limit_cpu": 0,  # 0 = no limit, otherwise percentage 1-100
    "log_file": "hashflow.log",
    "data_dir": str(Path.home() / ".hashflow"),
}

class Config:
    def __init__(self, config_path: Optional[str] = None):
        self.data_dir = Path(DEFAULTS["data_dir"])
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.config_path = Path(config_path) if config_path else self.data_dir / "config.json"
        self._config: Dict[str, Any] = dict(DEFAULTS)
        self.load()

    def load(self):
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    loaded = json.load(f)
                    self._config.update(loaded)
            except Exception as e:
                print(f"[WARN] Failed to load config {self.config_path}: {e}")

        # Override from env vars: HASHFLOW_POOL etc
        for key in DEFAULTS:
            env_key = f"HASHFLOW_{key.upper()}"
            if env_key in os.environ:
                val = os.environ[env_key]
                # Try to parse as json, else string
                try:
                    self._config[key] = json.loads(val)
                except:
                    # try int/float conversion
                    if val.isdigit():
                        self._config[key] = int(val)
                    else:
                        try:
                            self._config[key] = float(val)
                        except:
                            self._config[key] = val

    def save(self):
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            print(f"[WARN] Failed to save config: {e}")

    def get(self, key: str, default=None):
        return self._config.get(key, default if default is not None else DEFAULTS.get(key))

    def set(self, key: str, value: Any):
        self._config[key] = value
        self.save()

    def update(self, data: Dict[str, Any]):
        self._config.update(data)
        self.save()

    def all(self) -> Dict[str, Any]:
        return dict(self._config)

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        self.set(key, value)

# Global config instance
config = Config()
