# Passive Network Asset Discovery System

A passive network asset discovery system that observes network traffic and identifies active assets in a local network.

The current MVP uses a C++ collector with libpcap to capture real ARP packets from a network interface. It extracts IP/MAC information, sends asset events to a FastAPI backend, stores data in ClickHouse, and exposes query APIs for discovered assets.

## Features

- Live ARP packet capture using C++ and libpcap
- Offline PCAP replay mode for stable demo
- FastAPI backend for asset event ingestion
- ClickHouse storage for raw asset events and latest asset state
- Query APIs for assets, raw asset events, and summary statistics
- Docker Compose deployment for backend services

## Architecture

~~~text
C++ libpcap Collector
        |
        | HTTP POST asset events
        v
FastAPI Ingest API
        |
        v
ClickHouse
        |
        v
Asset Query API
~~~

## Project Structure

~~~text
passive-asset-discovery/
├── api/
│   └── app/
│       ├── main.py
│       ├── db.py
│       └── models.py
├── clickhouse/
│   └── init.sql
├── collector-cpp/
│   ├── include/
│   └── src/
├── docs/
├── samples/
│   └── arp-demo.pcap
└── docker-compose.yml
~~~

## Build and Run

Start backend services:

~~~bash
sudo docker compose up -d --build
~~~

Check health:

~~~bash
curl http://localhost:8000/health
~~~

Build C++ collector:

~~~bash
cd collector-cpp
cmake -S . -B build
cmake --build build
~~~

Run live capture mode:

~~~bash
sudo ./build/asset_collector --mode live --iface wlp3s0 --count 5
~~~

Run offline PCAP mode:

~~~bash
./build/asset_collector --mode pcap --file ../samples/arp-demo.pcap
~~~

Query discovered assets:

~~~bash
curl http://localhost:8000/api/v1/assets | jq
curl http://localhost:8000/api/v1/asset-events | jq
curl http://localhost:8000/api/v1/assets/summary | jq
~~~

## Current Demo Result

The system successfully discovered a real LAN asset from ARP traffic:

~~~json
{
  "asset_id": "30:de:4b:18:f4:50",
  "ip": "192.168.12.67",
  "mac": "30:de:4b:18:f4:50",
  "sources": ["arp"],
  "last_source": "arp"
}
~~~

## Current Limitations

- Only ARP packet parsing is implemented in the current MVP.
- DHCP parsing is planned but not implemented yet.
- Vendor lookup from MAC OUI is not implemented yet.
- Live capture depends on the amount of ARP traffic visible on the selected interface.
