import json
import os
from typing import Any, Dict, List

import requests


CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = os.getenv("CLICKHOUSE_PORT", "8123")
CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "assetdb")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "asset_user")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "asset_pass")

CLICKHOUSE_URL = f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}"


def ch_query(query: str) -> str:
    response = requests.post(
        CLICKHOUSE_URL,
        params={"database": CLICKHOUSE_DATABASE},
        data=query.encode("utf-8"),
        auth=(CLICKHOUSE_USER, CLICKHOUSE_PASSWORD),
        timeout=10,
    )
    response.raise_for_status()
    return response.text


def ch_insert_json(table: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return

    payload = "\n".join(json.dumps(row, default=str) for row in rows)

    response = requests.post(
        CLICKHOUSE_URL,
        params={
            "database": CLICKHOUSE_DATABASE,
            "query": f"INSERT INTO {table} FORMAT JSONEachRow",
        },
        data=payload.encode("utf-8"),
        auth=(CLICKHOUSE_USER, CLICKHOUSE_PASSWORD),
        timeout=10,
    )
    response.raise_for_status()
