"""
Group and device management for Hashflow
Handles user registration, device fingerprinting, and group capacity
"""
import json
import hashlib
import os
import platform
import uuid
from pathlib import Path
from typing import List, Dict, Optional
from .config import config

class GroupManager:
    def __init__(self, group_file: Optional[str] = None):
        self.group_file = Path(group_file) if group_file else Path(config.get("group_file", "miners.json"))
        self.max_size = config.get("max_group_size", 100)

    def get_device_id(self) -> str:
        """Generate a semi-unique device ID from platform info"""
        try:
            # Combine multiple sources for uniqueness
            node = platform.node() or "unknown"
            machine = platform.machine() or "unknown"
            system = platform.system() or "unknown"
            mac = uuid.getnode()
            # Include ANDROID_ROOT or TERMUX env for Termux detection
            extra = os.environ.get("PREFIX", "") + os.environ.get("ANDROID_ROOT", "")
            unique_string = f"{node}-{machine}-{system}-{mac}-{extra}-{os.getpid()}"
            device_hash = hashlib.sha256(unique_string.encode()).hexdigest()[:12]
            return device_hash
        except Exception:
            # Fallback to random-ish but stable for session
            return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:12]

    def load_group(self) -> List[Dict]:
        if not self.group_file.exists():
            return []
        try:
            with open(self.group_file, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Filter invalid entries
                    return [m for m in data if m.get("username") and m.get("device_id")]
                return []
        except Exception:
            return []

    def save_group(self, group_data: List[Dict]):
        try:
            self.group_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.group_file, 'w') as f:
                json.dump(group_data, f, indent=2)
        except Exception as e:
            raise IOError(f"Failed to save group file: {e}")

    def is_registered(self, username: str, device_id: str) -> bool:
        group = self.load_group()
        for member in group:
            if member.get("username") == username and member.get("device_id") == device_id:
                return True
        return False

    def register(self, username: str, device_id: Optional[str] = None, wallet: Optional[str] = None) -> Dict:
        device_id = device_id or self.get_device_id()
        group = self.load_group()

        # Check if already registered
        for member in group:
            if member["username"] == username and member["device_id"] == device_id:
                # Update wallet if provided
                if wallet and member.get("wallet") != wallet:
                    member["wallet"] = wallet
                    self.save_group(group)
                return member

        # Check capacity
        if len(group) >= self.max_size:
            raise ValueError(f"Group/circle is at full capacity ({self.max_size} miners). Registration failed.")

        new_member = {
            "username": username,
            "device_id": device_id,
            "wallet": wallet,
            "joined_at": __import__("time").time(),
            "platform": platform.platform(),
        }
        group.append(new_member)
        self.save_group(group)
        return new_member

    def unregister(self, username: str, device_id: Optional[str] = None) -> bool:
        group = self.load_group()
        original_len = len(group)
        if device_id:
            group = [m for m in group if not (m["username"] == username and m["device_id"] == device_id)]
        else:
            group = [m for m in group if m["username"] != username]
        if len(group) < original_len:
            self.save_group(group)
            return True
        return False

    def list_members(self) -> List[Dict]:
        return self.load_group()

    def get_stats(self) -> Dict:
        group = self.load_group()
        platforms = {}
        for m in group:
            plat = m.get("platform", "Unknown")
            # Simplify platform string
            if "Android" in plat or "aarch64" in plat.lower():
                key = "Android/Termux"
            elif "Linux" in plat:
                key = "Linux/VPS"
            else:
                key = plat.split("-")[0]
            platforms[key] = platforms.get(key, 0) + 1

        return {
            "total": len(group),
            "max": self.max_size,
            "available": self.max_size - len(group),
            "platforms": platforms,
            "members": group,
        }

# Singleton
group_manager = GroupManager()
