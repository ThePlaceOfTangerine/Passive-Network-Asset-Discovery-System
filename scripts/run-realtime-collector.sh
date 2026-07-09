#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../collector"

sudo ./build/asset_collector \
  --config ../config/collector.conf \
  --count 0 \
  --duration 0 \
  --batch-size 5 \
  --parser-workers 2
