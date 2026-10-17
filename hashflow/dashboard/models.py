"""Pydantic models for dashboard API"""
from pydantic import BaseModel
from typing import Dict, Optional, List
import time

class MinerStatus(BaseModel):
    running: bool
    threads: Dict
    donation: float
    pool: str
    stats: Dict
    stealth: Dict
    thermal: Dict
    xmrig: str

class GroupStats(BaseModel):
    total: int
    max: int
    available: int
    platforms: Dict[str, int]
    members: List[Dict]

class LogResponse(BaseModel):
    logs: Dict[str, List[str]]
    timestamp: float = time.time()

class ConfigUpdate(BaseModel):
    pool: Optional[str] = None
    donation: Optional[float] = None
    limit_cpu: Optional[float] = None
    stealth: Optional[bool] = None
    refresh_interval: Optional[float] = None
