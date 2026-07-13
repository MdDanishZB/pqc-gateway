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

# =====================================================================================
#  THE TWO DECOUPLED PIPELINES — the heart of the design, shown side by side.
#  LEFT  : data classification -> crypto strength (policy-only, floored, up-only)
#  RIGHT : network condition (ML-A) -> SCTP transport policy (recommendation by default;
#          ENFORCED when GW_TRANSPORT_ENFORCE=1 over a real multi-path testbed)
#  They never cross: nothing on the right can change the left.
# =====================================================================================
st.divider()

def _live_kem():
    """Most recent negotiated KEM from the metrics DB (what the gateway actually used)."""
    import sqlite3
    _proot = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    _dbp = os.path.join(_proot, "ai_module", "dashboard", "metrics.db")
    if not os.path.exists(_dbp):
        _dbp = os.path.join(_proot, "metrics.db")
    try:
        _c = sqlite3.connect(_dbp)
        _r = _c.execute("SELECT kyber_level FROM metrics ORDER BY timestamp DESC LIMIT 1").fetchone()
        _c.close()
        return _r[0] if _r else "—"
    except Exception:
        return "—"

pipe_sec, pipe_res = st.columns(2)

# ── PIPELINE 1 — SECURITY (data classification → crypto) ────────────────────────────
with pipe_sec:
    st.subheader("🔐 Pipeline 1 — Data Classification → Crypto")
    st.caption("Crypto strength is set ONLY by the data's classification (a policy choice). "
               "ML-KEM-768 is the immovable floor; only CRITICAL data raises it to "
               "ML-KEM-1024. Network conditions, threat level and battery NEVER change it.")

    DATA_CLASS_FILE = os.environ.get("GW_DATA_CLASS_FILE", "/tmp/gw_dataclass")
    cls = st.radio("Data classification (policy input)",
                   ["routine", "sensitive", "critical"], horizontal=True,
                   help="An attribute of the channel — not derived from traffic or any ML model")
    if st.button("Apply Classification", type="primary", use_container_width=True):
        try:
            with open(DATA_CLASS_FILE, "w") as f:
                f.write(cls + "\n")
            st.toast(f"Data classification applied: {cls.upper()}")
        except Exception as e:
            st.error(f"Could not write {DATA_CLASS_FILE}: {e}")

    expected = "ML-KEM-1024" if cls == "critical" else "ML-KEM-768"
    m1, m2 = st.columns(2)
    m1.metric("Policy → KEM", expected, help="floor = ML-KEM-768")
    kem = _live_kem()
    m2.metric("Negotiated (live)", kem)
    if kem == "—":
        st.info("send traffic → see the negotiated KEM")
    elif "512" not in str(kem):
        st.success("✅ FLOOR HELD (≥ ML-KEM-768) — battery / threat cannot lower it")
    else:
        st.error("⚠️ floor breached")

# ── PIPELINE 2 — RESILIENCE (ML-A network condition → transport) ────────────────────
with pipe_res:
    st.subheader("📡 Pipeline 2 — Network Condition (ML-A) → SCTP Transport")
    st.caption("The ML network-condition model reads path-health metrics and recommends an "
               "SCTP transport action. It never touches crypto.")

    # Reflects the ACTUAL gateway mode, not a hardcoded claim. The gateway logs
    # "[NetML] ... [ENFORCED]" or "[... recommendation ...]" per session — this badge
    # mirrors that by reading the SAME env var, passed through by run_demo.sh / the
    # netns runbook. It only means something if this Streamlit process was launched
    # with the SAME GW_TRANSPORT_ENFORCE value as the gateway it's showing.
    _enforced = os.environ.get("GW_TRANSPORT_ENFORCE", "0") not in ("0", "", None)

    NET_POLICY = {
        "STABLE": "NORMAL", "CONGESTED": "CONGESTION_RESPONSE",
        "DEGRADED": "FAILOVER_READY", "UNSTABLE": "PREFER_BACKUP",
        "POSSIBLE_PATH_FAILURE": "FAILOVER",
    }

    def query_netcond(rtt, jitter, loss, thr, cwnd):
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect("/tmp/ai_netcond.sock")
        s.send(f"{rtt:.1f},{jitter:.1f},{loss:.2f},{thr:.1f},{cwnd:.0f}".encode())
        r = s.recv(64).decode().strip()
        s.close()
        return r

    st.caption("Derived from the network sliders above (latency→RTT, jitter, loss).")
    if st.button("Classify Network Condition", use_container_width=True):
        # derive path-health features from the current network sliders
        _rtt = float(delay if selected_scenario == "Manual" else st.session_state.get('delay', 0))
        _jit = float(jitter if selected_scenario == "Manual" else st.session_state.get('jitter', 0))
        _loss = float(loss if selected_scenario == "Manual" else st.session_state.get('loss', 0))
        _thr = max(200.0, 9000.0 * (1.0 - _loss / 100.0))
        _cwnd = max(4.0, 60.0 - _loss)
        try:
            state = query_netcond(_rtt, _jit, _loss, _thr, _cwnd)
            st.session_state["netcond_state"] = state
        except Exception as e:
            st.session_state["netcond_state"] = None
            st.warning(f"ML-A socket not reachable ({e}). Is model_server.py running?")

    state = st.session_state.get("netcond_state")
    if state:
        sev = ["STABLE", "CONGESTED", "DEGRADED", "UNSTABLE", "POSSIBLE_PATH_FAILURE"]
        color = "green" if state == "STABLE" else ("orange" if state in ("CONGESTED", "DEGRADED") else "red")
        n1, n2 = st.columns(2)
        n1.markdown(f"**Network state**\n\n:{color}[{state}]")
        n2.markdown(f"**Transport policy**\n\n{NET_POLICY.get(state, 'NORMAL')}")
        if _enforced:
            st.success("✅ ENFORCED — GW_TRANSPORT_ENFORCE=1: a FAILOVER/PREFER_BACKUP "
                       "recommendation triggers a REAL path switch (proven over a real "
                       "two-path testbed; see scripts/failover_measure.sh)")
        else:
            st.warning("🔸 recommendation — single-path, not enforced "
                       "(set GW_TRANSPORT_ENFORCE=1 on the gateway AND this dashboard "
                       "process, over a real multi-path testbed, to enforce it)")
    else:
        st.info("set the network sliders → click **Classify Network Condition**")
        if _enforced:
            st.caption("GW_TRANSPORT_ENFORCE=1 is set on this dashboard process — "
                      "recommendations below would be ENFORCED.")

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
