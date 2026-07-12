import streamlit as st
import time
import os
import sys

# Ensure we can import from the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ai_module.simulator.traffic_generator import TrafficGenerator
from ai_module.simulator.network_conditioner import NetworkConditioner
from ai_module.simulator.scenarios import SCENARIOS

st.set_page_config(page_title="Simulation Control - PQC Gateway", layout="wide")

st.title("🎮 Simulation Control Panel")
st.markdown("Manage traffic patterns and network conditions to test gateway adaptation.")

# --- INITIALIZE SESSION STATE ---
if 'traffic_gen' not in st.session_state:
    st.session_state.traffic_gen = TrafficGenerator()
if 'network_cond' not in st.session_state:
    st.session_state.network_cond = NetworkConditioner()
if 'current_scenario' not in st.session_state:
    st.session_state.current_scenario = "Manual"

# --- SIDEBAR: SCENARIOS ---
st.sidebar.header("Scenario Presets")
selected_scenario = st.sidebar.selectbox(
    "Select a Scenario",
    ["Manual"] + list(SCENARIOS.keys())
)

if selected_scenario != st.session_state.current_scenario:
    st.session_state.current_scenario = selected_scenario
    if selected_scenario != "Manual":
        scenario = SCENARIOS[selected_scenario]
        # Apply scenario settings to session state for UI updates
        st.session_state.traffic_pattern = scenario['traffic_pattern']
        st.session_state.loss = scenario['network_conditions']['loss']
        st.session_state.delay = scenario['network_conditions']['delay']
        st.session_state.jitter = scenario['network_conditions']['jitter']
        
        # Automatically apply network conditions
        st.session_state.network_cond.apply_conditions(
            loss=st.session_state.loss,
            delay=st.session_state.delay,
            jitter=st.session_state.jitter
        )
        st.success(f"Applied scenario: {selected_scenario}")

if selected_scenario != "Manual":
    st.sidebar.info(SCENARIOS[selected_scenario]['description'])

# --- MAIN INTERFACE: TWO COLUMNS ---
col_traffic, col_network = st.columns(2)

with col_traffic:
    st.subheader("🚀 Traffic Control")
    
    pattern = st.selectbox(
        "Traffic Pattern",
        ["Normal", "DDoS", "C2 Beacon", "Congestion", "Mixed"],
        key="traffic_pattern" if selected_scenario == "Manual" else None,
        index=["Normal", "DDoS", "C2 Beacon", "Congestion", "Mixed"].index(
            st.session_state.get('traffic_pattern', 'Normal')
        )
    )
    
    rate = st.slider("Rate Scale (%)", 1, 200, 100, help="Adjust simulation intensity")
    
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        if st.button("▶️ Start Traffic", use_container_width=True, type="primary"):
            st.session_state.traffic_gen.start(pattern=pattern)
            st.toast(f"Traffic started: {pattern}")
    with col_t2:
        if st.button("⏹️ Stop Traffic", use_container_width=True):
            st.session_state.traffic_gen.stop()
            st.toast("Traffic stopped")
            
    status_color = "green" if st.session_state.traffic_gen.running else "red"
    st.markdown(f"**Status:** :{status_color}[{'Running' if st.session_state.traffic_gen.running else 'Stopped'}]")
    if st.session_state.traffic_gen.running:
        st.info(f"Active Pattern: {st.session_state.traffic_gen.pattern}")

with col_network:
    st.subheader("🌐 Network Condition Control")
    
    loss = st.slider("Packet Loss (%)", 0, 30, 
                     value=st.session_state.get('loss', 0), 
                     key="loss_slider" if selected_scenario == "Manual" else None)
    delay = st.slider("Latency (ms)", 0, 500, 
                      value=st.session_state.get('delay', 0), 
                      key="delay_slider" if selected_scenario == "Manual" else None)
    jitter = st.slider("Jitter (ms)", 0, 100, 
                       value=st.session_state.get('jitter', 0), 
                       key="jitter_slider" if selected_scenario == "Manual" else None)
    
    col_n1, col_n2 = st.columns(2)
    with col_n1:
        if st.button("🪄 Apply Conditions", use_container_width=True, type="primary"):
            # If manual, we take from sliders directly if they aren't keyed
            l = loss if selected_scenario == "Manual" else st.session_state.loss
            d = delay if selected_scenario == "Manual" else st.session_state.delay
            j = jitter if selected_scenario == "Manual" else st.session_state.jitter
            
            if st.session_state.network_cond.apply_conditions(loss=l, delay=d, jitter=j):
                st.toast("Network conditions applied")
            else:
                st.error("Failed to apply conditions. Check sudo permissions.")
                
    with col_n2:
        if st.button("🔄 Reset Network", use_container_width=True):
            st.session_state.network_cond.reset()
            st.session_state.loss = 0
            st.session_state.delay = 0
            st.session_state.jitter = 0
            st.toast("Network conditions reset")

    st.markdown("**Current Interface Config:**")
    st.code(st.session_state.network_cond.get_status(), language="bash")

# --- SECURITY POSTURE & CRYPTO FLOOR (demo Beat 4 — the headline) ---
st.divider()
st.subheader("🔒 Security Posture & Crypto Floor")
st.caption("The AI drives TRANSPORT (failover / rate-limit); it never weakens crypto. A "
           "battery signal may request cheaper operation but CANNOT push the KEM below the "
           "ML-KEM-768 floor. High-assurance may only RAISE it.")

POSTURE_FILE = os.environ.get("GW_POSTURE_FILE", "/tmp/gw_posture")
colp1, colp2, colp3 = st.columns([1.3, 1, 1.4])

with colp1:
    battery = st.slider("🔋 Battery pressure (%)", 0, 100, 0,
                        help="Simulate a draining or spoofed battery (downgrade attack)")
    high_assurance = st.checkbox("🛡️ High-assurance mode (raise to ML-KEM-1024)")
    if st.button("Apply Posture", type="primary", use_container_width=True):
        try:
            with open(POSTURE_FILE, "w") as f:
                f.write(f"{battery} {1 if high_assurance else 0}\n")
            st.toast(f"Posture applied: battery={battery}%  high_assurance={high_assurance}")
        except Exception as e:
            st.error(f"Could not write posture file {POSTURE_FILE}: {e}")

with colp2:
    try:
        cur = open(POSTURE_FILE).read().strip()
    except Exception:
        cur = "0 0 (default)"
    st.metric("Posture (battery high_assurance)", cur)

with colp3:
    import sqlite3
    _proot = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    _dbp = os.path.join(_proot, "ai_module", "dashboard", "metrics.db")
    if not os.path.exists(_dbp):
        _dbp = os.path.join(_proot, "metrics.db")
    kem = "—"
    try:
        _c = sqlite3.connect(_dbp)
        _r = _c.execute("SELECT kyber_level FROM metrics ORDER BY timestamp DESC LIMIT 1").fetchone()
        _c.close()
        if _r:
            kem = _r[0]
    except Exception:
        pass
    st.metric("Resulting crypto (live)", kem)
    if kem == "—":
        st.info("send traffic → see the negotiated KEM")
    elif "512" not in str(kem):
        st.success("✅ FLOOR HELD (≥ ML-KEM-768)")
    else:
        st.error("⚠️ floor breached")

# --- FOOTER: QUICK ACTIONS ---
st.divider()
st.subheader("🛠️ Quick Actions")
col_q1, col_q2, col_q3 = st.columns(3)

with col_q1:
    if st.button("🚨 Trigger Failover", use_container_width=True, help="Induce 100% loss to force path switch"):
        st.session_state.network_cond.apply_conditions(loss=100)
        st.warning("Failover triggered (100% Loss applied)")

with col_q2:
    if st.button("♻️ Restore Paths", use_container_width=True):
        st.session_state.network_cond.reset()
        st.success("Network restored to normal")

with col_q3:
    if st.button("🧹 Clear All", use_container_width=True):
        st.session_state.traffic_gen.stop()
        st.session_state.network_cond.reset()
        st.info("Simulation cleared")
