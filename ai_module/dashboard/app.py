import streamlit as st

st.set_page_config(
    page_title="PQC Gateway Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ AI-Optimized Post-Quantum SCTP Gateway")

st.markdown("""
### Overview
Welcome to the PQC Gateway Control Center. This dashboard provides real-time monitoring and control over the AI-optimized Post-Quantum Cryptography (PQC) Gateway.

### Navigation
- **Live Monitor**: Real-time visualization of network metrics and security state.
- **Simulation Control**: Manage traffic patterns and network conditions.
- **Security Analyst Chat**: Interactive AI-powered security analysis.
- **PQC Visualizer**: Understand the post-quantum handshake process.
- **Path & Failover**: Monitor SCTP multi-homing and path switches.

### System Architecture
The gateway utilizes a **Hybrid Two-Tier Intelligence** approach:
1. **Real-Time Tier (Random Forest)**: Per-packet classification for sub-5ms path and security level selection.
2. **Analytical Tier (LLM)**: High-level security analysis, threat narrative, and operator assistance.

Use the sidebar to navigate through the different monitoring and control modules.
""")

st.info("👈 Select a page from the sidebar to get started.")

with st.expander("System Status"):
    st.write("**Gateway:** Running")
    st.write("**AI Model Server:** Connected")
    st.write("**LLM Backend:** Ollama (Llama 3.1)")
    st.write("**Metrics DB:** Connected")
