import streamlit as st
from streamlit_chat import message
import pandas as pd
import sqlite3
import os
import sys

# Ensure we can import from the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ai_module.llm.llm_engine import PQCSecurityAnalyst

st.set_page_config(page_title="Security Analyst Chat - PQC Gateway", layout="wide")

st.title("🕵️ Security Analyst Chat")
st.markdown("Consult with the AI security analyst about the gateway's state, performance, and threat landscape.")

# --- INITIALIZE SESSION STATE ---
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'analyst' not in st.session_state:
    st.session_state.analyst = PQCSecurityAnalyst()

# --- DATABASE LOADING ---
DB_PATH = os.path.join(project_root, "ai_module", "dashboard", "metrics.db")
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(project_root, "metrics.db")

def get_latest_metrics(limit=10):
    """Return recent decision records as compact JSON — the grounding for the analyst.
    (Structured events, not a raw table dump, so the LLM explains rather than hallucinates.)"""
    import json
    try:
        conn = sqlite3.connect(DB_PATH)
        cols = "timestamp, ai_decision, kyber_level, active_path, latency, loss, throughput"
        df = pd.read_sql_query(
            f"SELECT {cols} FROM metrics ORDER BY timestamp DESC LIMIT {limit}", conn)
        events = df.to_dict(orient="records")
        try:
            pe = pd.read_sql_query(
                "SELECT timestamp, from_path, to_path, reason FROM path_events "
                "ORDER BY timestamp DESC LIMIT 5", conn)
            path_events = pe.to_dict(orient="records")
        except Exception:
            path_events = []
        conn.close()
        return json.dumps({"metrics": events, "path_events": path_events}, default=str)
    except Exception:
        return "No metrics available."

# --- CHAT INTERFACE ---
chat_container = st.container()

with chat_container:
    for i, chat in enumerate(st.session_state.chat_history):
        if chat['role'] == 'user':
            message(chat['text'], is_user=True, key=f"user_{i}")
        else:
            message(chat['text'], key=f"analyst_{i}")

# --- INPUT AREA ---
st.divider()
with st.form(key="chat_form", clear_on_submit=True):
    user_input = st.text_input("Ask the analyst...", placeholder="e.g., Why did we switch to Kyber-1024 recently?")
    submit_button = st.form_submit_button(label="Send")

if submit_button and user_input:
    # 1. Save user message
    st.session_state.chat_history.append({'role': 'user', 'text': user_input})
    
    # 2. Get context
    context = get_latest_metrics()
    
    # 3. Get analyst response
    with st.spinner("Analyst is thinking..."):
        response = st.session_state.analyst.chat(user_input, events=context)
    
    # 4. Save analyst response
    st.session_state.chat_history.append({'role': 'analyst', 'text': response})
    
    # 5. Rerun to display
    st.rerun()

# --- SIDEBAR: HELPFUL QUERIES ---
st.sidebar.header("Quick Inquiries")
example_queries = [
    "Summarize current network health.",
    "Are there any signs of a DDoS attack?",
    "Why is latency high right now?",
    "Explain the benefit of Kyber-1024."
]

for query in example_queries:
    if st.sidebar.button(query):
        st.session_state.chat_history.append({'role': 'user', 'text': query})
        context = get_latest_metrics()
        with st.spinner("Analyst is thinking..."):
            response = st.session_state.analyst.chat(query, events=context)
        st.session_state.chat_history.append({'role': 'analyst', 'text': response})
        st.rerun()

if st.sidebar.button("Clear History"):
    st.session_state.chat_history = []
    st.rerun()
