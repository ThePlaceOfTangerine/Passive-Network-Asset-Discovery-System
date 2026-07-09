# Passive Network Asset Discovery System

## Overview

Passive Network Asset Discovery System is a mini-project for discovering and monitoring network assets in a LAN using a passive approach.

Instead of actively scanning the network, the system listens to existing LAN traffic such as ARP, DHCP and SSDP/UPnP. The collector extracts asset metadata, sends normalized asset events to the backend, stores them in ClickHouse, applies known/unknown asset policy, raises alerts, and displays the current network inventory through a dashboard.

## Main Features

- Passive asset discovery from existing LAN traffic.
- C++ collector using libpcap.
- Multi-protocol parsing:
  - ARP
  - DHCP
  - SSDP/UPnP
- Realtime multi-threaded collector pipeline:
  - Capture thread
  - Raw packet queue
  - Parser worker pool
  - Batch queue
  - Sender thread
- FastAPI backend for event ingestion and query APIs.
- ClickHouse storage for event logs and latest asset state.
- MAC/OUI vendor lookup with cache.
- Alert system:
  - new_asset
  - ip_changed
  - asset_resurfaced
  - unknown_asset
- Known/Unknown Asset Policy using whitelist.
- Streamlit dashboard for monitoring asset inventory, alerts and whitelist.

## System Architecture

```text
Network Traffic
ARP / DHCP / SSDP
        |
        v
C++ Collector
libpcap live capture
        |
        v
Protocol Parsers
ARP / DHCP / SSDP
        |
        v
FastAPI Backend
Ingest + Policy + Alerts
        |
        v
ClickHouse Storage
asset_events / assets_latest / asset_alerts / known_assets
        |
        v
Streamlit Dashboard
Asset inventory / Alerts / Known-Unknown Policy
```

## Collector Pipeline

```text
Main / Capture Thread
libpcap pcap_next_ex()
        |
        v
Raw Packet Queue
thread-safe queue
        |
        v
Parser Worker Pool
ARP / DHCP / SSDP
        |
        v
Batch Queue
AssetEvent batches
        |
        v
Sender Thread
HTTP POST batches
        |
        v
FastAPI API
```

## Project Structure

```text
Passive-Network-Asset-Discovery-System/
├── api/
├── clickhouse/
├── collector/
├── config/
├── dashboard/
├── docs/
├── scripts/
├── docker-compose.yml
├── docker-compose.dashboard.yml
└── README.md
```

## Requirements

Install dependencies:

```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libcurl4-openssl-dev nlohmann-json3-dev jq netcat-openbsd
```

## Start Backend and Dashboard

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.dashboard.yml up -d --build
```

Check backend:

```bash
curl -s http://localhost:8000/health | jq
```

Open dashboard:

```text
http://localhost:8501
```

## Build Collector

```bash
cd collector
cmake -S . -B build
cmake --build build
```

## Run Collector in Realtime Mode

```bash
cd collector

sudo ./build/asset_collector \
  --config ../config/collector.conf \
  --count 0 \
  --duration 0 \
  --batch-size 5 \
  --parser-workers 2
```

Stop collector with:

```text
Ctrl + C
```