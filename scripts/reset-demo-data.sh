#!/usr/bin/env bash
set -euo pipefail

sudo docker exec asset-clickhouse clickhouse-client \
  --user asset_user \
  --password asset_pass \
  --database assetdb \
  --multiquery "
TRUNCATE TABLE asset_events;
TRUNCATE TABLE assets_latest;
TRUNCATE TABLE asset_alerts;
"

echo "Demo data reset completed. Vendor cache and known_assets were kept."
