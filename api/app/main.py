import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, Query

from app.db import ch_insert_json, ch_query
from app.models import AssetEvent


app = FastAPI(
    title="Passive Network Asset Discovery System",
    version="0.1.0",
)

metrics = {
    "asset_events_ingested": 0,
    "ingest_errors": 0,
}

OUI_VENDOR_MAP = {
    # Add known MAC OUI prefixes here when available.
    # Format: "AA:BB:CC": "Vendor Name"
    #
    # Example:
    # "00:1A:2B": "Example Vendor"
}


def normalize_mac_prefix(mac: str) -> str:
    if not mac:
        return ""

    cleaned = mac.strip().upper().replace("-", ":")
    parts = cleaned.split(":")

    if len(parts) < 3:
        return ""

    return ":".join(parts[:3])


def is_locally_administered_mac(mac: str) -> bool:
    if not mac:
        return False

    try:
        first_octet = mac.strip().split(":")[0]
        value = int(first_octet, 16)
        return bool(value & 0b00000010)
    except Exception:
        return False


def lookup_vendor(mac: str) -> str:
    prefix = normalize_mac_prefix(mac)

    if not prefix:
        return ""

    if is_locally_administered_mac(mac):
        return "Locally administered"

    return OUI_VENDOR_MAP.get(prefix, "Unknown")

def get_asset_status(last_seen: str) -> str:
    if not last_seen:
        return "unknown"

    try:
        value = str(last_seen).replace("Z", "+00:00")

        if "T" in value:
            dt = datetime.fromisoformat(value)
        else:
            dt = datetime.strptime(value[:19], "%Y-%m-%d %H:%M:%S")

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        age_seconds = (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds()

        if age_seconds <= 300:
            return "active"
        if age_seconds <= 3600:
            return "stale"
        return "inactive"

    except Exception:
        return "unknown"

@app.get("/health")
def health():
    try:
        ch_query("SELECT 1")
        return {"status": "ok", "clickhouse": "ok"}
    except Exception as exc:
        return {"status": "error", "clickhouse": str(exc)}


@app.get("/metrics")
def get_metrics():
    return metrics


@app.post("/api/v1/ingest/asset-events")
def ingest_asset_events(events: List[AssetEvent]):
    rows = []

    for event in events:
        data = event.model_dump()

        if not data.get("vendor"):
            data["vendor"] = lookup_vendor(event.mac)

        data["first_seen"] = event.first_seen.strftime("%Y-%m-%d %H:%M:%S")
        data["last_seen"] = event.last_seen.strftime("%Y-%m-%d %H:%M:%S")
        data["raw"] = json.dumps(event.raw)
        rows.append(data)

    try:
        ch_insert_json("asset_events", rows)
        upsert_assets(events)
        metrics["asset_events_ingested"] += len(events)

        return {"status": "ok", "accepted": len(events)}
    except Exception as exc:
        metrics["ingest_errors"] += 1
        return {"status": "error", "accepted": 0, "error": str(exc)}

def sql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def format_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def parse_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None

    try:
        text = str(value).replace("Z", "+00:00")
        if "T" in text:
            return datetime.fromisoformat(text)
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def get_existing_asset(asset_id: str) -> Optional[dict]:
    safe_asset_id = sql_escape(asset_id)

    query = f"""
    SELECT
        asset_id,
        ip,
        mac,
        hostname,
        vendor,
        sources,
        first_seen,
        last_seen,
        last_source
    FROM assets_latest FINAL
    WHERE asset_id = '{safe_asset_id}'
    ORDER BY last_seen DESC
    LIMIT 1
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    lines = [line for line in result.strip().splitlines() if line]

    if not lines:
        return None

    return json.loads(lines[0])


def merge_sources(existing_sources, new_source: str):
    sources = []

    if isinstance(existing_sources, list):
        sources.extend(existing_sources)

    if new_source and new_source not in sources:
        sources.append(new_source)

    return sources



def now_string() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def new_asset_alert(asset_id: str, ip: str, mac: str, source: str) -> dict:
    label = ip if ip else "unknown-ip"

    return {
        "alert_id": uuid.uuid4().hex[:16],
        "alert_type": "new_asset",
        "severity": "medium",
        "asset_id": asset_id,
        "ip": ip,
        "mac": mac,
        "source": source,
        "message": f"New asset discovered: {label} / {mac}",
        "created_at": now_string(),
    }

def ip_changed_alert(
    asset_id: str,
    old_ip: str,
    new_ip: str,
    mac: str,
    source: str,
) -> dict:
    return {
        "alert_id": uuid.uuid4().hex[:16],
        "alert_type": "ip_changed",
        "severity": "low",
        "asset_id": asset_id,
        "ip": new_ip,
        "mac": mac,
        "source": source,
        "message": f"Asset IP changed from {old_ip} to {new_ip}: {mac}",
        "created_at": now_string(),
    }


RESURFACE_THRESHOLD_SECONDS = 3600


def seconds_since_last_seen(old_last_seen: str, new_last_seen: datetime) -> Optional[float]:
    old_dt = parse_datetime(old_last_seen)

    if old_dt is None or new_last_seen is None:
        return None

    if old_dt.tzinfo is not None:
        old_dt = old_dt.astimezone(timezone.utc).replace(tzinfo=None)

    if new_last_seen.tzinfo is not None:
        new_last_seen = new_last_seen.astimezone(timezone.utc).replace(tzinfo=None)

    return (new_last_seen - old_dt).total_seconds()


def asset_resurfaced_alert(
    asset_id: str,
    ip: str,
    mac: str,
    source: str,
    silence_seconds: float,
) -> dict:
    hours = silence_seconds / 3600
    label = ip if ip else "unknown-ip"

    return {
        "alert_id": uuid.uuid4().hex[:16],
        "alert_type": "asset_resurfaced",
        "severity": "medium",
        "asset_id": asset_id,
        "ip": ip,
        "mac": mac,
        "source": source,
        "message": f"Asset resurfaced after {hours:.1f} hour(s): {label} / {mac}",
        "created_at": now_string(),
    }


def upsert_assets(events: List[AssetEvent]):
    grouped = {}

    for event in events:
        grouped.setdefault(event.asset_id, []).append(event)

    rows = []
    alert_rows = []

    for asset_id, asset_events in grouped.items():
        existing = get_existing_asset(asset_id)

        existing_ip = existing.get("ip", "") if existing else ""
        existing_hostname = existing.get("hostname", "") if existing else ""
        existing_vendor = existing.get("vendor", "") if existing else ""
        existing_sources = existing.get("sources", []) if existing else []
        existing_first_seen = existing.get("first_seen") if existing else None
        existing_last_seen = existing.get("last_seen", "") if existing else ""

        final_ip = existing_ip
        final_hostname = existing_hostname
        final_vendor = existing_vendor
        final_sources = list(existing_sources)
        final_last_seen = None
        final_last_source = ""

        first_seen_candidates = []

        if existing_first_seen:
            first_seen_candidates.append(existing_first_seen)

        for event in asset_events:
            if event.first_seen:
                first_seen_candidates.append(format_datetime(event.first_seen))

            event_last_seen = event.last_seen

            if final_last_seen is None or event_last_seen > final_last_seen:
                final_last_seen = event_last_seen
                final_last_source = event.source

            if event.ip:
                final_ip = event.ip

            if event.hostname:
                final_hostname = event.hostname

            if event.vendor:
                final_vendor = event.vendor

            final_sources = merge_sources(final_sources, event.source)

        if not final_vendor:
            final_vendor = lookup_vendor(asset_events[-1].mac)

        if first_seen_candidates:
            final_first_seen = min(first_seen_candidates)
        else:
            final_first_seen = format_datetime(asset_events[0].first_seen)

        mac = asset_events[-1].mac

        rows.append(
            {
                "asset_id": asset_id,
                "ip": final_ip,
                "mac": mac,
                "hostname": final_hostname,
                "vendor": final_vendor,
                "sources": final_sources,
                "first_seen": final_first_seen,
                "last_seen": format_datetime(final_last_seen),
                "last_source": final_last_source,
            }
        )

        if existing is None:
            alert_rows.append(
                new_asset_alert(
                asset_id=asset_id,
                ip=final_ip,
                mac=mac,
                source=final_last_source,
            )   
        )   
        else:
            old_ip = existing.get("ip", "")

            if old_ip and final_ip and old_ip != final_ip:
                alert_rows.append(
                    ip_changed_alert(
                        asset_id=asset_id,
                        old_ip=old_ip,
                        new_ip=final_ip,
                        mac=mac,
                        source=final_last_source,
                    )
                )

            silence_seconds = seconds_since_last_seen(existing_last_seen, final_last_seen)

            if silence_seconds is not None and silence_seconds > RESURFACE_THRESHOLD_SECONDS:
                alert_rows.append(
                    asset_resurfaced_alert(
                        asset_id=asset_id,
                        ip=final_ip,
                        mac=mac,
                        source=final_last_source,
                        silence_seconds=silence_seconds,
                    )
                )

    if rows:
        ch_insert_json("assets_latest", rows)

    if alert_rows:
        ch_insert_json("asset_alerts", alert_rows)


@app.get("/api/v1/alerts")
def list_alerts(
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    where = []

    if alert_type:
        where.append(f"alert_type = '{sql_escape(alert_type)}'")
    if severity:
        where.append(f"severity = '{sql_escape(severity)}'")

    where_sql = ""
    if where:
        where_sql = "WHERE " + " AND ".join(where)

    query = f"""
    SELECT
        alert_id,
        alert_type,
        severity,
        asset_id,
        ip,
        mac,
        source,
        message,
        created_at
    FROM asset_alerts
    {where_sql}
    ORDER BY created_at DESC
    LIMIT {limit}
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    rows = [json.loads(line) for line in result.strip().splitlines() if line]

    return {"total": len(rows), "items": rows}


@app.get("/api/v1/assets")
def list_assets(
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    where = []

    if ip:
        where.append(f"ip = '{ip}'")
    if mac:
        where.append(f"mac = '{mac}'")
    if source:
        where.append(f"has(sources, '{source}')")

    where_sql = ""
    if where:
        where_sql = "WHERE " + " AND ".join(where)

    query = f"""
    SELECT
        asset_id,
        ip,
        mac,
        hostname,
        vendor,
        sources,
        first_seen,
        last_seen,
        last_source
    FROM assets_latest FINAL
    {where_sql}
    ORDER BY last_seen DESC
    LIMIT {limit}
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    rows = [json.loads(line) for line in result.strip().splitlines() if line]

    for row in rows:
        row["status"] = get_asset_status(row.get("last_seen"))

    return {"total": len(rows), "items": rows}

@app.get("/api/v1/asset-events")
def list_asset_events(
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    where = []

    if ip:
        where.append(f"ip = '{ip}'")
    if mac:
        where.append(f"mac = '{mac}'")
    if source:
        where.append(f"source = '{source}'")

    where_sql = ""
    if where:
        where_sql = "WHERE " + " AND ".join(where)

    query = f"""
    SELECT
        event_id,
        asset_id,
        ip,
        mac,
        hostname,
        vendor,
        source,
        first_seen,
        last_seen,
        raw,
        ingested_at
    FROM asset_events
    {where_sql}
    ORDER BY last_seen DESC
    LIMIT {limit}
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    rows = [json.loads(line) for line in result.strip().splitlines() if line]

    return {"total": len(rows), "items": rows}


@app.get("/api/v1/assets/summary")
def asset_summary():
    total_assets = ch_query("SELECT count() FROM assets_latest FINAL").strip()
    total_events = ch_query("SELECT count() FROM asset_events").strip()
    unique_ips = ch_query("SELECT uniqExact(ip) FROM asset_events").strip()
    unique_macs = ch_query("SELECT uniqExact(mac) FROM asset_events WHERE mac != ''").strip()

    return {
        "total_assets": int(total_assets),
        "total_events": int(total_events),
        "unique_ips": int(unique_ips),
        "unique_macs": int(unique_macs),
    }
