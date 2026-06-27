import streamlit as st
import time
import os
import sys
import sqlite3
import pandas as pd

# Ensure we can import from the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ai_module.simulator.traffic_generator import TrafficGenerator
from ai_module.simulator.network_conditioner import NetworkConditioner

st.set_page_config(page_title="Demo Scenarios - PQC Gateway", layout="wide")

st.title("🎬 Guided Demo Scenarios")
st.markdown("Run automated end-to-end demonstrations of the PQC Gateway's capabilities.")

# --- INITIALIZE SESSION STATE ---
if 'traffic_gen' not in st.session_state:
    st.session_state.traffic_gen = TrafficGenerator()
if 'network_cond' not in st.session_state:
    st.session_state.network_cond = NetworkConditioner()
if 'demo_running' not in st.session_state:
    st.session_state.demo_running = False
if 'demo_logs' not in st.session_state:
    st.session_state.demo_logs = []

DB_PATH = os.path.join(project_root, "ai_module", "dashboard", "metrics.db")
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(project_root, "metrics.db")

def add_log(msg, type="info"):
    st.session_state.demo_logs.append({"time": time.strftime("%H:%M:%S"), "msg": msg, "type": type})

def get_latest_state():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 1", conn)
        conn.close()
        if not df.empty:
            return df.iloc[0]
        return None
    except Exception:
        return None

# --- SIDEBAR: CONTROLS ---
if st.sidebar.button("🧹 Clear Logs"):
    st.session_state.demo_logs = []
    st.rerun()

# --- MAIN UI ---
col_demos, col_status = st.columns([1, 1])

with col_demos:
    st.subheader("Select a Scenario")
    
    # SCENARIO 1
    with st.expander("🟢 Scenario 1: Normal Operation"):
        st.write("Optimizing for performance under healthy conditions.")
        if st.button("Run Normal Demo", disabled=st.session_state.demo_running):
            st.session_state.demo_running = True
            add_log("Starting Scenario 1: Normal Operation", "info")
            st.session_state.traffic_gen.start(pattern="Normal")
            add_log("Traffic started: Normal (5-20 msg/sec)", "info")
            
            # Wait for some metrics
            time.sleep(3)
            state = get_latest_state()
            if state is not None:
                add_log(f"AI Classification: {state['ai_decision']}", "success")
                add_log(f"Kyber Level: {state['kyber_level']}", "success")
                add_log(f"Active Path: {state['active_path']}", "success")
            
            add_log("Narration: 'Under normal conditions, the AI optimizes for performance by selecting lighter Kyber-512 and utilizing the primary path.'", "narration")
            st.session_state.demo_running = False
            st.rerun()

    # SCENARIO 2
    with st.expander("🔴 Scenario 2: DDoS Attack Detection"):
        st.write("Dynamic hardening and proactive failover during an attack.")
        if st.button("Run DDoS Demo", disabled=st.session_state.demo_running):
            st.session_state.demo_running = True
            add_log("Starting Scenario 2: DDoS Attack Detection", "warning")
            st.session_state.traffic_gen.start(pattern="DDoS")
            add_log("Traffic started: DDoS Burst (< 5ms IAT)", "warning")
            
            # Wait for AI to react
            time.sleep(5)
            state = get_latest_state()
            if state is not None:
                add_log(f"AI Detected Threat: {state['ai_decision']}", "danger")
                add_log(f"Escalating to: {state['kyber_level']}", "danger")
            
            add_log("Narration: 'AI detects volumetric attack patterns and automatically hardens defenses to Kyber-1024 while considering proactive path switching.'", "narration")
            st.session_state.demo_running = False
            st.rerun()

    # SCENARIO 3
    with st.expander("⚙️ Scenario 3: Network Failure & Recovery"):
        st.write("Zero-downtime failover via SCTP multihoming.")
        if st.button("Run Failover Demo", disabled=st.session_state.demo_running):
            st.session_state.demo_running = True
            add_log("Starting Scenario 3: Network Failure & Recovery", "info")
            st.session_state.traffic_gen.start(pattern="Normal")
            st.session_state.network_cond.reset()
            time.sleep(2)
            add_log("Baseline established on Primary Path.", "info")
            
            add_log("ACTION: Killing Primary Path (iptables DROP)...", "danger")
            st.session_state.network_cond.block_path()
            
            add_log("Waiting for SCTP heartbeat to detect failure...", "warning")
            time.sleep(4)
            
            state = get_latest_state()
            if state is not None:
                add_log(f"Failover successful! Active Path: {state['active_path']}", "success")
            
            time.sleep(2)
            add_log("ACTION: Restoring Primary Path...", "info")
            st.session_state.network_cond.unblock_path()
            
            add_log("Waiting for AI to confirm recovery and failback...", "info")
            time.sleep(4)
            
            state = get_latest_state()
            if state is not None:
                add_log(f"Restored to: {state['active_path']}", "success")
                
            add_log("Narration: 'SCTP multihoming combined with AI monitoring ensures zero-downtime communication even during total path failure.'", "narration")
            st.session_state.demo_running = False
            st.rerun()

    # SCENARIO 4
    with st.expander("🌗 Scenario 4: Adaptive Security"):
        st.write("Balancing security and performance in real-time.")
        if st.button("Run Adaptive Demo", disabled=st.session_state.demo_running):
            st.session_state.demo_running = True
            add_log("Starting Scenario 4: Adaptive Security", "info")
            
            patterns = ["Normal", "Congestion", "DDoS", "Normal"]
            for p in patterns:
                add_log(f"Switching pattern to: {p}", "info")
                st.session_state.traffic_gen.start(pattern=p)
                time.sleep(4)
                state = get_latest_state()
                if state is not None:
                    add_log(f"State: {state['ai_decision']} -> {state['kyber_level']}", "info")
            
            add_log("Narration: 'The system continuously balances security strength against performance needs, scaling Kyber levels dynamically.'", "narration")
            st.session_state.demo_running = False
            st.rerun()

with col_status:
    st.subheader("Live Event Log")
    for log in reversed(st.session_state.demo_logs):
        if log['type'] == 'narration':
            st.success(f"🗣️ **{log['time']}**: {log['msg']}")
        elif log['type'] == 'danger':
            st.error(f"🚨 **{log['time']}**: {log['msg']}")
        elif log['type'] == 'warning':
            st.warning(f"⚠️ **{log['time']}**: {log['msg']}")
        elif log['type'] == 'success':
            st.info(f"✅ **{log['time']}**: {log['msg']}")
        else:
            st.write(f"ℹ️ **{log['time']}**: {log['msg']}")

st.divider()
if st.button("⏹️ Stop All Simulation"):
    st.session_state.traffic_gen.stop()
    st.session_state.network_cond.reset()
    st.session_state.network_cond.unblock_path()
    add_log("All simulations stopped and network restored.", "info")
    st.rerun()
