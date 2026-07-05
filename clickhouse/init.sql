CREATE DATABASE IF NOT EXISTS assetdb;

CREATE TABLE IF NOT EXISTS assetdb.asset_events
(
    event_id String,
    asset_id String,
    ip String,
    mac String,
    hostname String,
    vendor String,
    source String,
    confidence Float32,
    first_seen DateTime,
    last_seen DateTime,
    raw String,
    ingested_at DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toDate(last_seen)
ORDER BY (last_seen, ip, mac, source);

CREATE TABLE IF NOT EXISTS assetdb.assets_latest
(
    asset_id String,
    ip String,
    mac String,
    hostname String,
    vendor String,
    sources Array(String),
    confidence Float32,
    first_seen DateTime,
    last_seen DateTime,
    last_source String,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY asset_id;

CREATE TABLE IF NOT EXISTS asset_alerts
(
    alert_id String,
    alert_type LowCardinality(String),
    severity LowCardinality(String),
    asset_id String,
    ip String,
    mac String,
    source LowCardinality(String),
    message String,
    created_at DateTime
)
ENGINE = MergeTree
ORDER BY (created_at, alert_type, asset_id);
