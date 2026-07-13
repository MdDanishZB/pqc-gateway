import streamlit as st
import pandas as pd
import sqlite3
import plotly.graph_objects as go
import plotly.express as px
import time
import os

# Set page config for the multi-page app
st.set_page_config(page_title="Live Monitor - PQC Gateway", layout="wide")

# Ensure we can import from the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# Database path
DB_PATH = os.path.join(project_root, "ai_module", "dashboard", "metrics.db")
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(project_root, "metrics.db")

def load_data():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 100", conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Database error: {e}")
        return pd.DataFrame()

def create_gauge(value, title, unit, max_val, color="green"):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={'text': title},
        number={'suffix': unit},
        gauge={
            'axis': {'range': [0, max_val]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, max_val*0.6], 'color': "lightgray"},
                {'range': [max_val*0.6, max_val*0.85], 'color': "gray"},
                {'range': [max_val*0.85, max_val], 'color': "darkgray"}
            ],
        }
    ))
    fig.update_layout(height=250, margin=dict(l=20, r=20, t=50, b=20))
    return fig

st.title("📊 Live Network Monitor")

df = load_data()

if df.empty:
    st.info("Waiting for gateway traffic... (Check if receiver.py and gateway are running)")
    time.sleep(2)
    st.rerun()
else:
    latest = df.iloc[0]
    
    # --- ROW 1: GAUGES ---
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.plotly_chart(create_gauge(latest['latency'], "Latency", "ms", 200, "blue"), key="gauge_latency", width='stretch')
    with col2:
        # Throughput in Kbps/Mbps for better visualization
        tp = latest['throughput'] / 1024.0 # Convert to KB/s
        st.plotly_chart(create_gauge(tp, "Throughput", "KB/s", 1000, "green"), key="gauge_throughput", width='stretch')
    with col3:
        st.plotly_chart(create_gauge(latest['loss'], "Packet Loss", "%", 30, "red"), key="gauge_loss", width='stretch')
    with col4:
        st.plotly_chart(create_gauge(latest['jitter'], "Jitter", "ms", 50, "orange"), key="gauge_jitter", width='stretch')
    
    # --- ROW 2: STATUS & DECISIONS ---
    st.divider()
    col_a, col_b, col_c = st.columns([1, 1, 2])
    
    with col_a:
        st.subheader("🛡️ Security State")
        k_level = str(latest['kyber_level'])
        # Crypto is FLOORED and decoupled from the threat verdict: >= ML-KEM-768 always.
        if "512" in k_level:
            st.error(f"Crypto: {k_level}  ⚠️ below floor")
        else:
            st.success(f"Crypto: {k_level}  🔒 floor")
        st.caption("Set ONLY by data classification (Simulation Control) — floored at "
                   "ML-KEM-768; network/threat/battery never touch it")

        decision = str(latest['ai_decision'])
        color = "red" if decision == "HIGH" else "orange" if decision == "MEDIUM" else "green"
        st.markdown(f"**AI Threat Level:** :{color}[{decision}]")
        # The axis the AI actually drives is TRANSPORT, not crypto.
        action = ("RATE_LIMIT + ALERT" if decision == "HIGH"
                  else "MONITOR" if decision == "MEDIUM" else "NORMAL")
        st.markdown(f"**Transport Action:** `{action}`")
        st.markdown(f"**Active Path:** `{latest['active_path']}`")
    
    with col_b:
        st.subheader("🎯 AI Decision Mix")
        decision_counts = df['ai_decision'].value_counts()
        fig_pie = px.pie(
            values=decision_counts.values, 
            names=decision_counts.index,
            color=decision_counts.index,
            color_discrete_map={'LOW': 'green', 'MEDIUM': 'orange', 'HIGH': 'red'}
        )
        fig_pie.update_layout(height=200, margin=dict(l=0, r=0, t=0, b=0))
        st.plotly_chart(fig_pie, key="pie_decisions", width='stretch')
    
    with col_c:
        st.subheader("📈 Latency Trend")
        trend_df = df.head(50).copy()
        trend_df['timestamp'] = pd.to_datetime(trend_df['timestamp'])
        fig_trend = px.line(trend_df, x='timestamp', y='latency', title=None)
        fig_trend.update_layout(height=200, margin=dict(l=0, r=0, t=0, b=0))
        st.plotly_chart(fig_trend, key="line_latency", width='stretch')

    # --- ROW 3: RECENT SESSIONS ---
    st.subheader("📋 Recent Session Log")
    st.dataframe(
        df[['timestamp', 'session_id', 'kyber_level', 'active_path', 'latency', 'throughput', 'ai_decision']], 
        use_container_width=True,
        hide_index=True
    )

    # Wait 1 second and rerun
    time.sleep(1)
    st.rerun()
