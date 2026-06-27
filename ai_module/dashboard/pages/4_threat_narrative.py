import streamlit as st
import pandas as pd
import sqlite3
import os
import time

st.set_page_config(page_title="Threat Narrative - PQC Gateway", layout="wide")

st.title("📜 Live Threat Narrative")
st.markdown("A real-time stream of security events and AI-generated insights.")

# Ensure we can import from the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# Database path
DB_PATH = os.path.join(project_root, "ai_module", "dashboard", "metrics.db")
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(project_root, "metrics.db")

def load_narratives():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM llm_analysis ORDER BY timestamp DESC LIMIT 50", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

df = load_narratives()

if df.empty:
    st.info("Waiting for AI analysis... Ensure llm_advisor.py is running and there is gateway traffic.")
    time.sleep(5)
    st.rerun()
else:
    for _, row in df.iterrows():
        with st.container():
            col_time, col_content = st.columns([1, 4])
            
            with col_time:
                st.caption(f"🕒 {row['timestamp']}")
                level = row['threat_level']
                color = "red" if level == "HIGH" else "orange" if level == "MEDIUM" else "green"
                st.markdown(f"**Threat:** :{color}[{level}]")
                st.markdown(f"**Type:** `{row['attack_type']}`")
            
            with col_content:
                st.markdown(f"### {row['metrics_summary']}")
                st.write(row['explanation'])
                st.info(f"💡 **Recommendation:** {row['recommendation']}")
            
            st.divider()

    time.sleep(5)
    st.rerun()
