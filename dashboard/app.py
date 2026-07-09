import os
import pandas as pd
import requests
import streamlit as st


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")


st.set_page_config(
    page_title="Passive Network Asset Discovery",
    page_icon="🛡️",
    layout="wide",
)


def api_get(path: str):
    url = f"{API_BASE_URL}{path}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        st.error(f"API error: GET {url} - {exc}")
        return None


def api_post(path: str, payload: dict):
    url = f"{API_BASE_URL}{path}"
    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        st.error(f"API error: POST {url} - {exc}")
        return None


def as_items(data):
    if not data:
        return []
    if isinstance(data, dict):
        return data.get("items", [])
    return []


def make_df(items):
    if not items:
        return pd.DataFrame()
    return pd.DataFrame(items)


def normalize_cols(df: pd.DataFrame, cols):
    if df.empty:
        return df
    existing = [col for col in cols if col in df.columns]
    return df[existing]


st.markdown(
    """
    <style>
    .main {
        background-color: #ffffff;
    }
    .metric-card {
        padding: 18px;
        border: 1px solid #eeeeee;
        border-radius: 12px;
        background: #fafafa;
    }
    .small-muted {
        color: #666666;
        font-size: 13px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


st.title("🛡️ Passive Network Asset Discovery Dashboard")



health = api_get("/health")
policy_data = api_get("/api/v1/policy/assets")
alerts_data = api_get("/api/v1/alerts")
known_data = api_get("/api/v1/known-assets")

assets = as_items(policy_data)
alerts = as_items(alerts_data)
known_assets = as_items(known_data)

assets_df = make_df(assets)
alerts_df = make_df(alerts)
known_df = make_df(known_assets)

if health:
    status = health.get("status", "unknown")
    clickhouse_status = health.get("clickhouse", "unknown")
else:
    status = "error"
    clickhouse_status = "unknown"


known_count = 0
unknown_count = 0
active_count = 0

if not assets_df.empty:
    if "is_known" in assets_df.columns:
        known_count = int(assets_df["is_known"].fillna(False).sum())
        unknown_count = int((~assets_df["is_known"].fillna(False)).sum())

    if "status" in assets_df.columns:
        active_count = int((assets_df["status"] == "active").sum())

alert_count = len(alerts)
high_alert_count = 0
if not alerts_df.empty and "severity" in alerts_df.columns:
    high_alert_count = int((alerts_df["severity"] == "high").sum())


st.divider()

m1, m2, m3, m4, m5, m6 = st.columns(6)

m1.metric("API Status", status)
m2.metric("ClickHouse", clickhouse_status)
m3.metric("Total Assets", len(assets))
m4.metric("Known", known_count)
m5.metric("Unknown", unknown_count)
m6.metric("High Alerts", high_alert_count)


st.divider()

tab_assets, tab_alerts, tab_known, tab_add = st.tabs(
    [
        "Asset Policy View",
        "Alerts",
        "Known Assets",
        "Add Whitelist",
    ]
)


with tab_assets:
    st.subheader("Asset Policy View")

    if assets_df.empty:
        st.info("Chưa có asset nào.")
    else:
        filter_col1, filter_col2, filter_col3 = st.columns(3)

        with filter_col1:
            policy_filter = st.selectbox(
                "Policy status",
                ["all", "allowed", "unknown"],
                index=0,
            )

        with filter_col2:
            source_filter = st.text_input("Filter source/vendor/hostname", "")

        with filter_col3:
            show_columns = st.checkbox("Show all columns", value=False)

        view_df = assets_df.copy()

        if policy_filter != "all" and "policy_status" in view_df.columns:
            view_df = view_df[view_df["policy_status"] == policy_filter]

        if source_filter:
            keyword = source_filter.lower()
            search_cols = [
                col for col in ["ip", "mac", "hostname", "vendor", "sources", "known_label", "owner"]
                if col in view_df.columns
            ]

            mask = False
            for col in search_cols:
                mask = mask | view_df[col].astype(str).str.lower().str.contains(keyword, na=False)
            view_df = view_df[mask]

        if not show_columns:
            view_df = normalize_cols(
                view_df,
                [
                    "ip",
                    "mac",
                    "hostname",
                    "vendor",
                    "is_known",
                    "policy_status",
                    "recommended_action",
                    "known_label",
                    "owner",
                    "status",
                    "last_source",
                    "last_seen",
                ],
            )

        st.dataframe(view_df, use_container_width=True, hide_index=True)


with tab_alerts:
    st.subheader("Security Alerts")

    if alerts_df.empty:
        st.success("Chưa có alert.")
    else:
        alert_type = st.selectbox(
            "Alert type",
            ["all"] + sorted(alerts_df["alert_type"].dropna().unique().tolist())
            if "alert_type" in alerts_df.columns
            else ["all"],
        )

        view_df = alerts_df.copy()

        if alert_type != "all" and "alert_type" in view_df.columns:
            view_df = view_df[view_df["alert_type"] == alert_type]

        view_df = normalize_cols(
            view_df,
            [
                "created_at",
                "alert_type",
                "severity",
                "ip",
                "mac",
                "source",
                "message",
            ],
        )

        st.dataframe(view_df, use_container_width=True, hide_index=True)


with tab_known:
    st.subheader("Known Assets / Whitelist")

    if known_df.empty:
        st.info("Whitelist đang rỗng.")
    else:
        view_df = normalize_cols(
            known_df,
            [
                "mac",
                "label",
                "owner",
                "expected_ip",
                "device_type",
                "notes",
                "updated_at",
            ],
        )
        st.dataframe(view_df, use_container_width=True, hide_index=True)


with tab_add:
    st.subheader("Add Asset to Whitelist")

    with st.form("add_known_asset_form"):
        mac = st.text_input("MAC address", placeholder="00:0c:29:52:c9:5c")
        label = st.text_input("Label", placeholder="VM Test Client")
        owner = st.text_input("Owner", placeholder="Lab")
        expected_ip = st.text_input("Expected IP", placeholder="192.168.12.104")
        device_type = st.text_input("Device type", placeholder="virtual_machine")
        notes = st.text_area("Notes", placeholder="VMware internal lab client")

        submitted = st.form_submit_button("Add to whitelist")

        if submitted:
            payload = {
                "mac": mac,
                "label": label,
                "owner": owner,
                "expected_ip": expected_ip,
                "device_type": device_type,
                "notes": notes,
            }

            result = api_post("/api/v1/known-assets", payload)

            if result and result.get("status") == "ok":
                st.success("Added to whitelist.")
                st.json(result)
            else:
                st.error("Failed to add known asset.")
                st.json(result)
