import streamlit as st
import pandas as pd
import sqlite3
import time

DB_PATH = "metrics.db"

st.set_page_config(page_title="PQC Gateway Dashboard", layout="wide")

st.title("🛡️ AI-Optimized Post-Quantum Secure SCTP Gateway")
st.markdown("Real-time monitoring of network conditions, AI security decisions, and SCTP multihoming paths.")

def load_data():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 50", conn)
        conn.close()
        return df
    except Exception as e:
        return pd.DataFrame()

placeholder = st.empty()

while True:
    df = load_data()
    
    with placeholder.container():
        if df.empty:
            st.info("Waiting for gateway traffic...")
        else:
            col1, col2, col3, col4 = st.columns(4)
            latest = df.iloc[0]
            
            col1.metric("Active Path", latest['active_path'])
            col2.metric("Kyber Level", latest['kyber_level'])
            col3.metric("AI Decision", latest['ai_decision'])
            col4.metric("Latency (ms)", f"{latest['latency']:.2f}")
            
            st.subheader("Recent Sessions")
            st.dataframe(df[['timestamp', 'session_id', 'kyber_level', 'active_path', 'latency', 'throughput']], use_container_width=True)
            
            st.subheader("Network Metrics Trend")
            if len(df) > 1:
                chart_data = df[['timestamp', 'latency', 'loss', 'throughput']].copy()
                chart_data['timestamp'] = pd.to_datetime(chart_data['timestamp'])
                chart_data.set_index('timestamp', inplace=True)
                st.line_chart(chart_data)
                
    time.sleep(2)

