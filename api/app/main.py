import json
from datetime import datetime
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


def upsert_assets(events: List[AssetEvent]):
    latest = {}

    for event in events:
        current = latest.get(event.asset_id)
        if current is None or event.last_seen > current.last_seen:
            latest[event.asset_id] = event

    rows = []

    for event in latest.values():
        rows.append(
            {
                "asset_id": event.asset_id,
                "ip": event.ip,
                "mac": event.mac,
                "hostname": event.hostname,
                "vendor": event.vendor,
                "sources": [event.source],
                "confidence": event.confidence,
                "first_seen": event.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": event.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "last_source": event.source,
                "updated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    ch_insert_json("assets_latest", rows)


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
        confidence,
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
        confidence,
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
