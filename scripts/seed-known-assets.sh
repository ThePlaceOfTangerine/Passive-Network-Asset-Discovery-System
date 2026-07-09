#!/usr/bin/env bash
set -euo pipefail

API_BASE_URL="${API_BASE_URL:-http://localhost:8000}"

curl -s -X POST "$API_BASE_URL/api/v1/known-assets" \
  -H "Content-Type: application/json" \
  -d '{
    "mac": "30:de:4b:18:f4:50",
    "label": "Home Router",
    "owner": "Lab",
    "expected_ip": "192.168.12.67",
    "device_type": "router",
    "notes": "TP-Link router"
  }' | jq

curl -s -X POST "$API_BASE_URL/api/v1/known-assets" \
  -H "Content-Type: application/json" \
  -d '{
    "mac": "5c:3a:45:24:02:01",
    "label": "Collector Laptop",
    "owner": "Quang",
    "expected_ip": "192.168.12.108",
    "device_type": "laptop",
    "notes": "Ubuntu collector machine"
  }' | jq

echo "Known assets seeded."
