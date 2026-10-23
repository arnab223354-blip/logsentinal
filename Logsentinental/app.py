"""
LogSentinel - Cybersecurity Log Analyzer & Threat Detection Dashboard
Interactive Streamlit application providing real-time log ingestion,
sliding-window heuristic detection, interactive Plotly visualizations,
and forensic database querying.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from database import (
    clear_database,
    get_db_path,
    get_metrics,
    init_db,
    load_alerts,
    load_events,
    save_alerts,
    save_events,
)
from detection import DetectionConfig, detect_threats
from log_parser import parse_log_content, parse_log_file

# Streamlit Page Configuration
st.set_page_config(
    page_title="LogSentinel | SOC Log Analyzer & Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom SOC Dark Cybersecurity Styling
CUSTOM_CSS = """
<style>
    /* Global theme enhancements */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    
    /* Header Container */
    .header-box {
        background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .header-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #58a6ff;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .header-subtitle {
        color: #8b949e;
        font-size: 1.05rem;
        margin-top: 8px;
        margin-bottom: 0;
    }

    /* Metric Cards */
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 18px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.25);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #58a6ff;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        margin-top: 4px;
        font-family: 'JetBrains Mono', monospace, sans-serif;
    }
    .metric-label {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #8b949e;
    }

    /* Severity badges */
    .badge-critical {
        background-color: #da3633;
        color: #ffffff;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
        display: inline-block;
    }
    .badge-high {
        background-color: #d29922;
        color: #ffffff;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
        display: inline-block;
    }
    .badge-medium {
        background-color: #1f6feb;
        color: #ffffff;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        display: inline-block;
    }

    /* Code & Log Mono */
    .mono-text {
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 0.85rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Ensure database is initialized
init_db()
DB_FILE = get_db_path()
SAMPLE_LOG_PATH = Path(__file__).resolve().parent / "data" / "sample_auth.log"


def render_header() -> None:
    """Render top branding banner."""
    st.markdown(
        """
        <div class="header-box">
            <h1 class="header-title">
                <span>🛡️</span> LogSentinel
            </h1>
            <p class="header-subtitle">
                Cybersecurity Log Analyzer & Threat Detection Dashboard —
                Real-time forensic ingestion, sliding-window heuristics, and SIEM event correlation.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def process_and_store_logs(raw_content: str, config: DetectionConfig) -> Tuple[int, int, int]:
    """Parse log content, execute threat rules, and persist results to SQLite."""
    events, errors = parse_log_content(raw_content)

    if errors:
        st.session_state["last_errors"] = errors
    else:
        st.session_state["last_errors"] = []

    if not events:
        return 0, 0, len(errors)

    # Run Threat Detection Engine
    alerts = detect_threats(events, config=config)

    # Save to SQLite
    events_saved = save_events(events)
    alerts_saved = save_alerts(alerts)

    return events_saved, alerts_saved, len(errors)


# ==========================================
# SIDEBAR CONTROLS
# ==========================================
st.sidebar.markdown("## ⚙️ Detection Rules & Heuristics")
st.sidebar.caption("Fine-tune sliding window parameters and threat thresholds.")

failed_thresh = st.sidebar.slider(
    "Rule 1: Failed Login Threshold",
    min_value=2,
    max_value=20,
    value=5,
    help="Number of failed logins from a single IP required to trigger a Brute Force alert.",
)
failed_window = st.sidebar.slider(
    "Rule 1: Failed Login Window (minutes)",
    min_value=1,
    max_value=30,
    value=5,
    help="Sliding time window duration in minutes for counting failed logins.",
)

success_after_fail_thresh = st.sidebar.slider(
    "Rule 2: Failures Before Success",
    min_value=2,
    max_value=10,
    value=3,
    help="Minimum preceding failures required before a success triggers an Account Compromise alert.",
)
success_window = st.sidebar.slider(
    "Rule 2: Correlation Window (minutes)",
    min_value=1,
    max_value=60,
    value=10,
    help="Lookback window in minutes for matching failures to a subsequent success.",
)

active_config = DetectionConfig(
    failed_login_threshold=failed_thresh,
    failed_login_window_minutes=failed_window,
    success_after_failures_threshold=success_after_fail_thresh,
    success_after_failures_window_minutes=success_window,
)

st.sidebar.markdown("---")
st.sidebar.markdown("## 📥 Ingest Logs")

ingest_source = st.sidebar.radio(
    "Select Log Source:",
    options=["Upload Log File (.log, .txt)", "Built-in Sample Log"],
    index=0,
)

uploaded_file = None
if ingest_source == "Upload Log File (.log, .txt)":
    uploaded_file = st.sidebar.file_uploader(
        "Choose an authentication log file",
        type=["log", "txt"],
        help="Upload standard key-value format logs: YYYY-MM-DDTHH:MM:SSZ ip=... user=... event=...",
    )
else:
    st.sidebar.info(f"Using: `data/sample_auth.log` ({SAMPLE_LOG_PATH.name})")

analyze_clicked = st.sidebar.button("🚀 Analyze & Ingest Logs", use_container_width=True, type="primary")

if analyze_clicked:
    raw_content = ""
    if ingest_source == "Built-in Sample Log":
        if SAMPLE_LOG_PATH.exists():
            with open(SAMPLE_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                raw_content = f.read()
        else:
            st.sidebar.error("Sample log file not found at `data/sample_auth.log`.")
    else:
        if uploaded_file is not None:
            raw_bytes = uploaded_file.read()
            raw_content = raw_bytes.decode("utf-8", errors="replace")
        else:
            st.sidebar.warning("Please select or upload a log file first.")

    if raw_content:
        with st.spinner("Parsing logs, evaluating heuristics, and persisting to database..."):
            ev_count, al_count, err_count = process_and_store_logs(raw_content, active_config)
            st.sidebar.success(
                f"Ingested {ev_count} events, flagged {al_count} alerts ({err_count} errors)."
            )

st.sidebar.markdown("---")
st.sidebar.markdown("## 🗄️ Database Management")
st.sidebar.caption(f"Storage: `{DB_FILE.name}`")

confirm_clear = st.sidebar.checkbox("Confirm database reset", value=False)
if st.sidebar.button("🧹 Clear All Stored Data", use_container_width=True, disabled=not confirm_clear):
    clear_database()
    st.session_state["last_errors"] = []
    st.sidebar.success("Database cleared successfully.")
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.caption("LogSentinel SIEM v1.0 • Python & Streamlit")

# ==========================================
# MAIN DASHBOARD AREA
# ==========================================
render_header()

# Display Parsing Errors Expander if any occurred
last_errors = st.session_state.get("last_errors", [])
if last_errors:
    with st.expander(f"⚠️ Parsing Warnings: {len(last_errors)} malformed lines detected", expanded=True):
        st.markdown(
            "The following lines could not be parsed as valid log events and were safely skipped:"
        )
        error_df = pd.DataFrame(last_errors)
        st.dataframe(
            error_df[["line_number", "error", "raw_line"]],
            use_container_width=True,
            hide_index=True,
        )

# Fetch dynamic metrics from SQLite
try:
    metrics = get_metrics()
except Exception as e:
    st.error(f"Failed to query database metrics: {e}")
    metrics = {
        "total_events": 0,
        "failed_logins": 0,
        "successful_logins": 0,
        "high_severity_alerts": 0,
        "total_alerts": 0,
        "unique_ips": 0,
        "unique_users": 0,
    }

total_events = metrics["total_events"]

if total_events == 0:
    # Empty state when database has no events
    st.markdown(
        """
        <div style="background-color: #161b22; border: 1px dashed #30363d; border-radius: 12px; padding: 48px; text-align: center; margin-top: 20px;">
            <div style="font-size: 3.5rem; margin-bottom: 12px;">🛡️</div>
            <h2 style="color: #f0f6fc; margin-bottom: 8px;">No Log Data Analyzed Yet</h2>
            <p style="color: #8b949e; max-width: 600px; margin: 0 auto 24px auto; font-size: 1.05rem;">
                LogSentinel is ready to inspect authentication logs for brute-force attacks, 
                credential stuffing bursts, and suspicious post-failure logins.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col_a, col_b, col_c = st.columns([1, 2, 1])
    with col_b:
        st.write("")
        if st.button("⚡ Click to Ingest & Analyze Built-in Sample Log", type="primary", use_container_width=True):
            if SAMPLE_LOG_PATH.exists():
                with open(SAMPLE_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                ev_count, al_count, err_count = process_and_store_logs(content, active_config)
                st.toast(f"Sample log ingested: {ev_count} events, {al_count} alerts!", icon="🛡️")
                st.rerun()
            else:
                st.error("Sample log file not found.")

    st.stop()

# ------------------------------------------
# 1. METRICS ROW
# ------------------------------------------
mcol1, mcol2, mcol3, mcol4 = st.columns(4)

fail_pct = (metrics["failed_logins"] / total_events * 100) if total_events > 0 else 0
succ_pct = (metrics["successful_logins"] / total_events * 100) if total_events > 0 else 0

with mcol1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Total Ingested Events</div>
            <div class="metric-value" style="color: #58a6ff;">{metrics['total_events']:,}</div>
            <div style="color: #8b949e; font-size: 0.8rem; margin-top: 4px;">Across {metrics['unique_ips']} IPs, {metrics['unique_users']} Users</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with mcol2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Failed Logins</div>
            <div class="metric-value" style="color: #f85149;">{metrics['failed_logins']:,}</div>
            <div style="color: #f85149; font-size: 0.8rem; margin-top: 4px;">{fail_pct:.1f}% failure rate</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with mcol3:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Successful Logins</div>
            <div class="metric-value" style="color: #3fb950;">{metrics['successful_logins']:,}</div>
            <div style="color: #3fb950; font-size: 0.8rem; margin-top: 4px;">{succ_pct:.1f}% of traffic</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with mcol4:
    alert_color = "#da3633" if metrics["high_severity_alerts"] > 0 else "#8b949e"
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">High / Critical Alerts</div>
            <div class="metric-value" style="color: {alert_color};">{metrics['high_severity_alerts']}</div>
            <div style="color: #8b949e; font-size: 0.8rem; margin-top: 4px;">Total Alerts: {metrics['total_alerts']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.write("")

# ------------------------------------------
# 2. CHARTS SECTION
# ------------------------------------------
st.markdown("### 📊 Interactive Forensic Telemetry")
chart_col1, chart_col2 = st.columns(2)

df_all_events = load_events()

with chart_col1:
    if not df_all_events.empty:
        event_counts = df_all_events["event_type"].value_counts().reset_index()
        event_counts.columns = ["event_type", "count"]

        # Color scheme tailored for cybersecurity event types
        event_colors = {
            "login_failed": "#f85149",
            "login_success": "#3fb950",
            "account_locked": "#d29922",
            "logout": "#58a6ff",
        }
        colors = [event_colors.get(et, "#8b949e") for et in event_counts["event_type"]]

        fig_pie = go.Figure(
            data=[
                go.Pie(
                    labels=event_counts["event_type"],
                    values=event_counts["count"],
                    hole=0.55,
                    marker=dict(colors=colors, line=dict(color="#0d1117", width=2)),
                    textinfo="label+percent",
                    hoverinfo="label+value+percent",
                )
            ]
        )
        fig_pie.update_layout(
            title=dict(text="Authentication Event Distribution", font=dict(color="#f0f6fc", size=16)),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=40, b=20, l=20, r=20),
            legend=dict(font=dict(color="#c9d1d9")),
            height=320,
        )
        st.plotly_chart(fig_pie, use_container_width=True)

with chart_col2:
    if not df_all_events.empty:
        # Prepare chronological timeline
        timeline_df = df_all_events.copy()
        timeline_df["timestamp_dt"] = pd.to_datetime(timeline_df["timestamp"])
        timeline_df = timeline_df.sort_values("timestamp_dt")

        # Group by 5-minute intervals or event types over time
        fig_time = px.histogram(
            timeline_df,
            x="timestamp_dt",
            color="event_type",
            color_discrete_map={
                "login_failed": "#f85149",
                "login_success": "#3fb950",
                "account_locked": "#d29922",
                "logout": "#58a6ff",
            },
            title="Event Activity Timeline",
            nbins=30,
        )
        fig_time.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#c9d1d9"),
            margin=dict(t=40, b=20, l=20, r=20),
            xaxis=dict(gridcolor="#21262d", title="Timestamp (UTC)"),
            yaxis=dict(gridcolor="#21262d", title="Event Count"),
            legend=dict(title=dict(text="Event Type"), font=dict(color="#c9d1d9")),
            height=320,
        )
        st.plotly_chart(fig_time, use_container_width=True)

# Secondary row of charts: Targeted Users and IPs
st.write("")
tcol1, tcol2 = st.columns(2)

with tcol1:
    if not df_all_events.empty:
        failed_df = df_all_events[df_all_events["event_type"] == "login_failed"]
        if not failed_df.empty:
            top_failed_ips = failed_df["ip"].value_counts().head(5).reset_index()
            top_failed_ips.columns = ["ip", "failed_count"]

            fig_ip = px.bar(
                top_failed_ips,
                x="failed_count",
                y="ip",
                orientation="h",
                color="failed_count",
                color_continuous_scale="Reds",
                title="Top Source IPs by Failed Logins",
            )
            fig_ip.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#c9d1d9"),
                margin=dict(t=40, b=20, l=20, r=20),
                xaxis=dict(gridcolor="#21262d", title="Failed Attempts"),
                yaxis=dict(categoryorder="total ascending", title="Source IP"),
                coloraxis_showscale=False,
                height=260,
            )
            st.plotly_chart(fig_ip, use_container_width=True)
        else:
            st.info("No failed logins found to graph.")

with tcol2:
    if not df_all_events.empty:
        top_users = df_all_events["user"].value_counts().head(5).reset_index()
        top_users.columns = ["user", "activity_count"]

        fig_user = px.bar(
            top_users,
            x="activity_count",
            y="user",
            orientation="h",
            color="activity_count",
            color_continuous_scale="Blues",
            title="Top Active Target Usernames",
        )
        fig_user.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#c9d1d9"),
            margin=dict(t=40, b=20, l=20, r=20),
            xaxis=dict(gridcolor="#21262d", title="Total Activity Count"),
            yaxis=dict(categoryorder="total ascending", title="Target User"),
            coloraxis_showscale=False,
            height=260,
        )
        st.plotly_chart(fig_user, use_container_width=True)

st.write("")

# ------------------------------------------
# 3. THREAT ALERTS SECTION
# ------------------------------------------
st.markdown("### 🚨 Threat Alerts & Heuristic Detections")

alert_filter_col1, alert_filter_col2, alert_filter_col3 = st.columns([1.5, 2.5, 2])

with alert_filter_col1:
    severity_choice = st.selectbox(
        "Filter by Severity:",
        options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        index=0,
    )

with alert_filter_col2:
    alert_search_query = st.text_input(
        "Search Alerts (IP, User, Rule, or Details):",
        placeholder="e.g. 198.51.100.23 or admin",
    )

with alert_filter_col3:
    st.write("")
    st.caption("Heuristics detect suspicious bursts. Review audit context below.")

df_alerts = load_alerts(
    severity=severity_choice if severity_choice != "All" else None,
    search=alert_search_query if alert_search_query else None,
)

if df_alerts.empty:
    st.success("✅ No threat alerts match the selected criteria.")
else:
    # Render Alerts Table
    display_alerts = df_alerts[["id", "timestamp", "rule_name", "severity", "ip", "user", "explanation"]].copy()
    
    st.dataframe(
        display_alerts,
        use_container_width=True,
        hide_index=True,
        column_config={
            "id": st.column_config.NumberColumn("ID", width="small"),
            "timestamp": st.column_config.TextColumn("Timestamp (UTC)", width="medium"),
            "rule_name": st.column_config.TextColumn("Rule Name", width="medium"),
            "severity": st.column_config.TextColumn("Severity", width="small"),
            "ip": st.column_config.TextColumn("Source IP", width="medium"),
            "user": st.column_config.TextColumn("User", width="medium"),
            "explanation": st.column_config.TextColumn("Heuristic Analysis Explanation", width="large"),
        },
    )

    # Export Buttons for Alerts
    exp_col1, exp_col2, _ = st.columns([1.5, 1.5, 5])
    with exp_col1:
        csv_alerts = df_alerts.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Download Alerts (CSV)",
            data=csv_alerts,
            file_name="logsentinel_threat_alerts.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with exp_col2:
        json_alerts = df_alerts.to_json(orient="records", indent=2).encode("utf-8")
        st.download_button(
            label="📥 Download Alerts (JSON)",
            data=json_alerts,
            file_name="logsentinel_threat_alerts.json",
            mime="application/json",
            use_container_width=True,
        )

st.write("")

# ------------------------------------------
# 4. INGESTED EVENTS EXPLORER
# ------------------------------------------
st.markdown("### 📋 Ingested Event Log Explorer")

efilt_col1, efilt_col2, efilt_col3 = st.columns([1.5, 2.5, 1])

with efilt_col1:
    event_type_filter = st.selectbox(
        "Filter by Event Type:",
        options=["All", "login_failed", "login_success", "logout", "account_locked"],
        index=0,
    )

with efilt_col2:
    event_search_query = st.text_input(
        "Search Events (IP, User, or Raw Text):",
        placeholder="e.g. 192.0.2 or alice",
        key="event_search_input",
    )

with efilt_col3:
    record_limit = st.selectbox("Max Rows:", options=[50, 100, 250, 500, 1000], index=1)

df_events = load_events(
    event_type=event_type_filter if event_type_filter != "All" else None,
    search=event_search_query if event_search_query else None,
    limit=record_limit,
)

if df_events.empty:
    st.info("No events match the search filter.")
else:
    st.dataframe(
        df_events[["id", "timestamp", "ip", "user", "event_type", "raw_line"]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "id": st.column_config.NumberColumn("ID", width="small"),
            "timestamp": st.column_config.TextColumn("Timestamp (UTC)", width="medium"),
            "ip": st.column_config.TextColumn("IP Address", width="medium"),
            "user": st.column_config.TextColumn("User", width="medium"),
            "event_type": st.column_config.TextColumn("Event Type", width="medium"),
            "raw_line": st.column_config.TextColumn("Raw Log Line", width="large"),
        },
    )

    # Export Buttons for Events
    ev_exp_col1, ev_exp_col2, _ = st.columns([1.5, 1.5, 5])
    with ev_exp_col1:
        csv_events = df_events.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Download Events (CSV)",
            data=csv_events,
            file_name="logsentinel_events.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with ev_exp_col2:
        json_events = df_events.to_json(orient="records", indent=2).encode("utf-8")
        st.download_button(
            label="📥 Download Events (JSON)",
            data=json_events,
            file_name="logsentinel_events.json",
            mime="application/json",
            use_container_width=True,
        )

# ------------------------------------------
# 5. SOC EDUCATIONAL NOTES & RULE GUIDANCE
# ------------------------------------------
with st.expander("ℹ️ SIEM Detection Heuristics & Forensic Educational Guide"):
    st.markdown(
        """
        ### About Heuristic Detection
        In modern Security Operations Centers (SOC), deterministic alerts are complemented by 
        **heuristic sliding-window correlation rules**:

        1. **Repeated Failed Logins (Brute Force / Password Spray)**
           - **Heuristic**: Flags high frequencies of authentication rejections originating from a single IP within a short sliding time window.
           - **SOC Context**: Often indicates automated brute force or credential guessing. However, it can also be triggered by a misconfigured scheduled task or forgotten password manager sync.
        
        2. **Successful Login After Repeated Failures (Suspicious Success)**
           - **Heuristic**: Flags when an account suffers repeated authentication rejections followed immediately by a successful authentication within a time window.
           - **SOC Context**: Highly indicative of a successful password guess or brute force completion. Can also occur legitimately when a user attempts variations of a password before remembering the correct one.

        > **Educational Disclaimer**: These rules represent educational heuristics to demonstrate log correlation mechanisms, not absolute proof of malicious compromise. Always perform secondary verification (MFA logs, user behavior analytics) before taking disruptive containment actions.
        """
    )
