import streamlit as st

st.set_page_config(
    page_title="PQC Gateway Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Intelligent Secure Gateway")
st.caption("Legacy TCP device → gateway → secure SCTP tunnel → control center")

st.markdown("""
### Two independent pipelines — this is the whole design

```
Legacy TCP Device
        ↓
Intelligent Secure Gateway
   ├── Data sensitivity ──→ Security Policy Engine ──→ ML-KEM-768 floor
   │                                                    (ML-KEM-1024 only for CRITICAL data)
   ├── Network metrics ───→ ML-A classifier ──→ SCTP transport policy
   │                        (STABLE…POSSIBLE_PATH_FAILURE → recommendation)
   └── ML-KEM → HKDF-SHA-256 → AES-256-GCM ──→ Secure SCTP Tunnel ──→ Control Center
```

**Pipeline 1 (Security):** crypto strength is set *only* by the session's data
classification — a policy choice, never by network conditions, ML verdicts, or battery.
`select_kem()` takes a `DataClassification` and nothing else; that's enforced at compile time.

**Pipeline 2 (Resilience):** a separate ML model reads network-health metrics (RTT, jitter,
loss, throughput) and recommends an SCTP transport action. It never touches crypto, and its
output is a *recommendation* until real multi-path multihoming is wired up.

### Navigation
- **Live Monitor** — real-time metrics, active crypto level, transport action.
- **Simulation Control** — drive traffic, set data classification, classify network condition.
- **PQC & Trust** — hybrid handshake breakdown, ML-DSA authentication, self-test.
- **Evidence** — both models' honest confusion matrices / F1, claims-discipline table.
""")

st.info("👈 Select a page from the sidebar to get started.")

with st.expander("System Status"):
    st.write("**Gateway:** check `.demo_logs/gateway.log` for [Policy] / [NetML] / [PQC] lines")
    st.write("**AI Model Server:** ML-B on `/tmp/ai_gateway.sock`, "
             "ML-A on `/tmp/ai_netcond.sock`")
    st.write("**Metrics DB:** `ai_module/dashboard/metrics.db`")
