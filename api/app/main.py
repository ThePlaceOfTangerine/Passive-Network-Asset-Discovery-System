import json
import uuid
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, Query
from pydantic import BaseModel

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


class KnownAssetInput(BaseModel):
    mac: str
    label: str = ""
    owner: str = ""
    expected_ip: str = ""
    device_type: str = ""
    notes: str = ""


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



@app.get("/api/v1/known-assets")
def list_known_assets():
    return {
        "total": len(known_asset_rows()),
        "items": known_asset_rows(),
    }


@app.post("/api/v1/known-assets")
def add_known_asset(asset: KnownAssetInput):
    mac = normalize_full_mac(asset.mac)

    if not mac or len(mac) < 12:
        return {
            "status": "error",
            "message": "Invalid MAC address",
        }

    row = {
        "mac": mac,
        "label": asset.label,
        "owner": asset.owner,
        "expected_ip": asset.expected_ip,
        "device_type": asset.device_type,
        "notes": asset.notes,
        "created_at": now_string(),
        "updated_at": now_string(),
    }

    ch_insert_json("known_assets", [row])

    return {
        "status": "ok",
        "item": row,
    }


@app.get("/api/v1/policy/assets")
def list_assets_with_policy(limit: int = Query(100, ge=1, le=1000)):
    query = f"""
    SELECT
        asset_id,
        ip,
        mac,
        hostname,
        vendor,
        device_type,
        model_hint,
        os_hint,
        service_hints,
        sources,
        first_seen,
        last_seen,
        last_source
    FROM assets_latest FINAL
    ORDER BY last_seen DESC
    LIMIT {limit}
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    assets = [json.loads(line) for line in result.strip().splitlines() if line]

    known_map = {
        normalize_full_mac(row.get("mac", "")): row
        for row in known_asset_rows()
    }

    for asset in assets:
        mac = normalize_full_mac(asset.get("mac") or asset.get("asset_id"))
        known = known_map.get(mac)

        asset["is_known"] = known is not None
        asset["policy_status"] = "allowed" if known else "unknown"
        asset["recommended_action"] = "allow" if known else "restrict"
        asset["known_label"] = known.get("label", "") if known else ""
        asset["owner"] = known.get("owner", "") if known else ""
        asset["expected_ip"] = known.get("expected_ip", "") if known else ""
        asset["status"] = get_asset_status(asset.get("last_seen", ""))

    return {
        "total": len(assets),
        "items": assets,
    }

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
        insert_unknown_asset_alerts(events)
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
        device_type,
        model_hint,
        os_hint,
        service_hints,
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



def normalize_full_mac(mac: str) -> str:
    hex_chars = "".join(ch for ch in str(mac).lower() if ch in "0123456789abcdef")

    if len(hex_chars) < 12:
        return str(mac).strip().lower().replace("-", ":")

    return ":".join(hex_chars[i:i + 2] for i in range(0, 12, 2))


def known_asset_rows() -> List[dict]:
    query = """
    SELECT
        mac,
        label,
        owner,
        expected_ip,
        device_type,
        notes,
        created_at,
        updated_at
    FROM known_assets FINAL
    ORDER BY updated_at DESC
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    return [json.loads(line) for line in result.strip().splitlines() if line]


def get_known_asset(mac: str) -> Optional[dict]:
    normalized_mac = normalize_full_mac(mac)

    if not normalized_mac:
        return None

    safe_mac = sql_escape(normalized_mac)

    query = f"""
    SELECT
        mac,
        label,
        owner,
        expected_ip,
        device_type,
        notes,
        created_at,
        updated_at
    FROM known_assets FINAL
    WHERE mac = '{safe_mac}'
    ORDER BY updated_at DESC
    LIMIT 1
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    lines = [line for line in result.strip().splitlines() if line]

    if not lines:
        return None

    return json.loads(lines[0])


def unknown_asset_alert(asset_id: str, ip: str, mac: str, source: str) -> dict:
    label = ip if ip else "unknown-ip"

    return {
        "alert_id": uuid.uuid4().hex[:16],
        "alert_type": "unknown_asset",
        "severity": "high",
        "asset_id": asset_id,
        "ip": ip,
        "mac": mac,
        "source": source,
        "message": f"Unknown asset detected by whitelist policy: {label} / {mac}",
        "created_at": now_string(),
    }


def unknown_asset_alert_exists(asset_id: str) -> bool:
    if not asset_id:
        return False

    safe_asset_id = sql_escape(asset_id)

    query = f"""
    SELECT count() AS count
    FROM asset_alerts
    WHERE alert_type = 'unknown_asset'
      AND asset_id = '{safe_asset_id}'
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    lines = [line for line in result.strip().splitlines() if line]

    if not lines:
        return False

    return int(json.loads(lines[0]).get("count", 0)) > 0


def insert_unknown_asset_alerts(events: List[AssetEvent]):
    alerts = []
    queued_asset_ids = set()

    for event in events:
        mac = normalize_full_mac(event.mac or event.asset_id)
        asset_id = event.asset_id or mac

        if not mac or not asset_id:
            continue

        if asset_id in queued_asset_ids:
            continue

        if get_known_asset(mac):
            continue

        if unknown_asset_alert_exists(asset_id):
            continue

        alerts.append(
            unknown_asset_alert(
                asset_id=asset_id,
                ip=event.ip,
                mac=mac,
                source=event.source,
            )
        )

        queued_asset_ids.add(asset_id)

    if alerts:
        ch_insert_json("asset_alerts", alerts)




VENDOR_MEMORY_CACHE = {}


def normalize_oui_prefix(mac: str) -> str:
    hex_chars = "".join(ch for ch in str(mac).upper() if ch in "0123456789ABCDEF")

    if len(hex_chars) < 6:
        return ""

    return f"{hex_chars[0:2]}:{hex_chars[2:4]}:{hex_chars[4:6]}"


def is_local_or_random_mac(mac: str) -> bool:
    hex_chars = "".join(ch for ch in str(mac).upper() if ch in "0123456789ABCDEF")

    if len(hex_chars) < 2:
        return False

    first_byte = int(hex_chars[0:2], 16)

    return bool(first_byte & 0x02)


def get_vendor_from_cache(prefix: str) -> str:
    if not prefix:
        return ""

    if prefix in VENDOR_MEMORY_CACHE:
        return VENDOR_MEMORY_CACHE[prefix]

    safe_prefix = sql_escape(prefix)

    query = f"""
    SELECT vendor
    FROM mac_vendor_cache FINAL
    WHERE prefix = '{safe_prefix}'
    ORDER BY last_checked DESC
    LIMIT 1
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    lines = [line for line in result.strip().splitlines() if line]

    if not lines:
        return ""

    row = json.loads(lines[0])
    vendor = row.get("vendor", "")

    if vendor:
        VENDOR_MEMORY_CACHE[prefix] = vendor

    return vendor


def save_vendor_cache(prefix: str, vendor: str, source: str):
    if not prefix or not vendor:
        return

    VENDOR_MEMORY_CACHE[prefix] = vendor

    ch_insert_json(
        "mac_vendor_cache",
        [
            {
                "prefix": prefix,
                "vendor": vendor,
                "source": source,
                "last_checked": now_string(),
            }
        ],
    )


def lookup_vendor_online(mac: str) -> str:
    try:
        encoded_mac = urllib.parse.quote(str(mac), safe="")
        url = f"https://api.maclookup.app/v2/macs/{encoded_mac}/company/name"

        request = urllib.request.Request(
            url,
            headers={"User-Agent": "PassiveAssetDiscovery/1.0"},
        )

        with urllib.request.urlopen(request, timeout=2) as response:
            vendor = response.read().decode("utf-8", errors="ignore").strip()

        if not vendor:
            return ""

        if vendor.startswith("*NO COMPANY*"):
            return ""

        if vendor.startswith("*PRIVATE*"):
            return "Private Vendor"

        if "Too Many Requests" in vendor:
            return ""

        if "MAC must be greater" in vendor:
            return ""

        return vendor[:200]

    except Exception:
        return ""


def lookup_vendor(mac: str) -> str:
    prefix = normalize_oui_prefix(mac)

    if not prefix:
        return "Unknown"

    cached_vendor = get_vendor_from_cache(prefix)
    if cached_vendor:
        return cached_vendor

    if is_local_or_random_mac(mac):
        vendor = "Private/Randomized MAC"
        save_vendor_cache(prefix, vendor, "local_rule")
        return vendor

    online_vendor = lookup_vendor_online(mac)

    if online_vendor:
        save_vendor_cache(prefix, online_vendor, "maclookup.app")
        return online_vendor

    return "Unknown"



def merge_unique_list(existing, new_items):
    result = []

    if isinstance(existing, list):
        result.extend(existing)

    for item in new_items:
        if item and item not in result:
            result.append(item)

    return result


def extract_ssdp_fingerprint(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return {
            "device_type": "",
            "model_hint": "",
            "os_hint": "",
            "service_hints": [],
        }

    protocol = str(raw.get("protocol", "")).lower()
    if protocol != "ssdp":
        return {
            "device_type": "",
            "model_hint": "",
            "os_hint": "",
            "service_hints": [],
        }

    server = str(raw.get("server", ""))
    st = str(raw.get("st", ""))
    nt = str(raw.get("nt", ""))
    usn = str(raw.get("usn", ""))
    location = str(raw.get("location", ""))

    combined = " ".join([server, st, nt, usn, location]).lower()

    service_hints = ["ssdp", "upnp"]
    device_type = ""
    model_hint = ""
    os_hint = ""

    if "internetgatewaydevice" in combined or "igd.xml" in combined:
        device_type = "router"
        service_hints.append("internet_gateway")
    elif "printer" in combined:
        device_type = "printer"
        service_hints.append("printer")
    elif "camera" in combined:
        device_type = "camera"
        service_hints.append("camera")
    elif "mediarenderer" in combined or "dlna" in combined:
        device_type = "media_device"
        service_hints.append("media_renderer")
    elif "rootdevice" in combined:
        device_type = "upnp_device"

    if server:
        parts = server.split()

        if parts:
            os_hint = parts[0]

        for part in reversed(parts):
            upper = part.upper()
            if (
                "/" in part
                and "UPNP" not in upper
                and not upper.startswith("HTTP")
                and not upper.startswith("TPOS")
            ):
                model_hint = part
                break

        if not model_hint:
            model_hint = server

    return {
        "device_type": device_type,
        "model_hint": model_hint,
        "os_hint": os_hint,
        "service_hints": service_hints,
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
        existing_device_type = existing.get("device_type", "") if existing else ""
        existing_model_hint = existing.get("model_hint", "") if existing else ""
        existing_os_hint = existing.get("os_hint", "") if existing else ""
        existing_service_hints = existing.get("service_hints", []) if existing else []
        existing_sources = existing.get("sources", []) if existing else []
        existing_first_seen = existing.get("first_seen") if existing else None
        existing_last_seen = existing.get("last_seen", "") if existing else ""

        final_ip = existing_ip
        final_hostname = existing_hostname
        final_vendor = existing_vendor
        final_device_type = existing_device_type
        final_model_hint = existing_model_hint
        final_os_hint = existing_os_hint
        final_service_hints = list(existing_service_hints)
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

            if event.vendor and event.vendor != "Unknown":
                final_vendor = event.vendor

            final_sources = merge_sources(final_sources, event.source)

            fingerprint = extract_ssdp_fingerprint(event.raw)

            if fingerprint.get("device_type"):
                final_device_type = fingerprint["device_type"]

            if fingerprint.get("model_hint"):
                final_model_hint = fingerprint["model_hint"]

            if fingerprint.get("os_hint"):
                final_os_hint = fingerprint["os_hint"]

            final_service_hints = merge_unique_list(
                final_service_hints,
                fingerprint.get("service_hints", []),
            )

        if not final_vendor or final_vendor == "Unknown":
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
                "device_type": final_device_type,
                "model_hint": final_model_hint,
                "os_hint": final_os_hint,
                "service_hints": final_service_hints,
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



@app.get("/api/v1/vendors")
def list_vendor_cache(
    limit: int = Query(default=100, ge=1, le=1000),
):
    query = f"""
    SELECT
        prefix,
        vendor,
        source,
        last_checked
    FROM mac_vendor_cache FINAL
    ORDER BY last_checked DESC
    LIMIT {limit}
    FORMAT JSONEachRow
    """

    result = ch_query(query)
    rows = [json.loads(line) for line in result.strip().splitlines() if line]

    return {"total": len(rows), "items": rows}


@app.get("/api/v1/vendors/lookup")
def lookup_vendor_api(mac: str):
    prefix = normalize_oui_prefix(mac)
    vendor = lookup_vendor(mac)

    return {
        "mac": mac,
        "prefix": prefix,
        "vendor": vendor,
    }


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
        device_type,
        model_hint,
        os_hint,
        service_hints,
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
