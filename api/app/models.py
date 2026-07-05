from datetime import datetime
from typing import Any, Dict

from pydantic import BaseModel


class AssetEvent(BaseModel):
    event_id: str
    asset_id: str
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    source: str
    first_seen: datetime
    last_seen: datetime
    raw: Dict[str, Any] = {}
