# Demo Guide

This document describes how to run the Passive Network Asset Discovery System demo.

## 1. Start Backend Services

From the `passive-asset-discovery` directory:

~~~bash
sudo docker compose up -d --build
~~~

Check containers:

~~~bash
sudo docker ps --format "table {{.Names}}\t{{.Ports}}"
~~~

Expected services:

~~~text
asset-api
asset-clickhouse
~~~

Check API health:

~~~bash
curl http://localhost:8000/health
~~~

Expected output:

~~~json
{
  "status": "ok",
  "clickhouse": "ok"
}
~~~

## 2. Build C++ Collector

~~~bash
cd collector-cpp
cmake -S . -B build
cmake --build build
~~~

Check usage:

~~~bash
./build/asset_collector
~~~

## 3. Live Capture Demo

Find the active network interface:

~~~bash
ip route | grep default
~~~

Example:

~~~text
default via 192.168.12.67 dev wlp3s0 proto dhcp metric 600
~~~

In this case, the interface is `wlp3s0`.

Run the collector:

~~~bash
sudo ./build/asset_collector --mode live --iface wlp3s0 --count 5
~~~

Generate ARP traffic in another terminal:

~~~bash
ping -c 3 192.168.12.67
~~~

Expected collector output:

~~~text
Listening for ARP packets on interface wlp3s0
Discovered asset ip=192.168.12.67 mac=30:de:4b:18:f4:50 source=arp
Posted 1 asset event(s), status=200
~~~

## 4. Offline PCAP Demo

A sample ARP PCAP file is available at:

~~~text
samples/arp-demo.pcap
~~~

Run collector in PCAP mode:

~~~bash
cd collector-cpp
./build/asset_collector --mode pcap --file ../samples/arp-demo.pcap
~~~

Expected output:

~~~text
Reading ARP packets from pcap file ../samples/arp-demo.pcap
Discovered asset ip=192.168.12.67 mac=30:de:4b:18:f4:50 source=arp
Posted 1 asset event(s), status=200
Collector stopped.
~~~

## 5. Query Results

Query latest discovered assets:

~~~bash
curl http://localhost:8000/api/v1/assets | jq
~~~

Query raw asset events:

~~~bash
curl http://localhost:8000/api/v1/asset-events | jq
~~~

Query summary:

~~~bash
curl http://localhost:8000/api/v1/assets/summary | jq
~~~

Example summary:

~~~json
{
  "total_assets": 1,
  "total_events": 25,
  "unique_ips": 1,
  "unique_macs": 1
}
~~~

## 6. Demo Meaning

The demo proves that the system can:

- Capture real ARP packets from a live network interface
- Extract IP/MAC information from network traffic
- Send asset events from C++ collector to FastAPI backend
- Store asset data in ClickHouse
- Query discovered assets through REST API
- Replay a saved PCAP file for stable demonstration
