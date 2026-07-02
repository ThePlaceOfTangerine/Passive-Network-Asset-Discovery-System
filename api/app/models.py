from datetime import datetime
from typing import Any, Dict

from pydantic import BaseModel, Field


class AssetEvent(BaseModel):
    event_id: str
    asset_id: str
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    source: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    raw: Dict[str, Any] = {}
