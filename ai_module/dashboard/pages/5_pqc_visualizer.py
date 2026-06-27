import streamlit as st
import pandas as pd
import graphviz
import os
import sys

# Ensure we can import from the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

st.set_page_config(page_title="PQC Handshake - PQC Gateway", layout="wide")

st.title("🔐 PQC Handshake Visualizer")
st.markdown("""
This page explains the **Hybrid Post-Quantum Handshake** used by the gateway to establish secure communication.
The gateway combines classical Diffie-Hellman (X25519) with a Post-Quantum KEM (Kyber) to ensure long-term security.
""")

# --- 1. THE HYBRID CONCEPT ---
st.subheader("🛡️ The Hybrid Concept: Best of Both Worlds")
col1, col2 = st.columns(2)

with col1:
    st.info("""
    **Classical (X25519)**
    - Based on Elliptic Curve Diffie-Hellman.
    - Extremely efficient and well-vetted.
    - Vulnerable to future large-scale Quantum Computers (Shor's Algorithm).
    """)

with col2:
    st.warning("""
    **Post-Quantum (Kyber)**
    - Based on Module Learning-with-Errors (MLWE).
    - Designed to be resistant to both classical and quantum attacks.
    - Newer technology; hybridizing it with classical ensures we don't lose existing security.
    """)

# --- 2. HANDSHAKE FLOW DIAGRAM ---
st.subheader("🔄 Handshake Flow")

dot = graphviz.Digraph(comment='PQC Handshake')
dot.attr(rankdir='LR', size='10,5')

dot.node('C', 'Initiator (Client)', shape='box', style='filled', fillcolor='lightblue')
dot.node('S', 'Responder (Server)', shape='box', style='filled', fillcolor='lightgreen')

# Step 1
dot.edge('C', 'S', label='1. Hello: [KyberLevel, X25519 Pub, Kyber Pub]')
# Step 2
dot.edge('S', 'C', label='2. Response: [X25519 Pub, Kyber Ciphertext]')

# Key Derivation boxes
dot.node('KC', 'Derive Shared Secret\n(X25519 + Kyber)\nHKDF-SHA256', shape='note')
dot.node('KS', 'Derive Shared Secret\n(X25519 + Kyber)\nHKDF-SHA256', shape='note')

dot.edge('C', 'KC', style='dashed')
dot.edge('S', 'KS', style='dashed')

st.graphviz_chart(dot)

# --- 3. STEP-BY-STEP BREAKDOWN ---
with st.expander("🔍 Detailed Handshake Steps"):
    st.markdown("""
    1. **Initiator Hello**:
        - **Kyber Level**: 0, 1, or 2 (512, 768, or 1024) as decided by the AI.
        - **X25519 Public Key**: 32 bytes of classical EC key.
        - **Kyber Public Key**: Varying size (800 - 1568 bytes) based on level.
    
    2. **Responder Response**:
        - **X25519 Public Key**: Server's 32-byte classical key.
        - **Kyber Ciphertext**: The encapsulated PQC secret (768 - 1568 bytes).
    
    3. **Key Derivation (IKM)**:
        - Both sides compute their respective classical shared secret and PQC shared secret.
        - These are concatenated: `IKM = ECDH_Shared || Kyber_Shared`.
    
    4. **Session Key generation**:
        - An AES-256-GCM key is derived using HKDF-SHA256:
        - `Key = HKDF(IKM, salt="pqc-gw", info="session-key", len=32)`
    """)

# --- 4. KYBER LEVELS COMPARISON ---
st.subheader("📊 Kyber Security Levels")

data = {
    "Level": ["Kyber-512", "Kyber-768", "Kyber-1024"],
    "NIST Security Category": ["1 (AES-128 equivalent)", "3 (AES-192 equivalent)", "5 (AES-256 equivalent)"],
    "Public Key Size (Bytes)": [800, 1184, 1568],
    "Ciphertext Size (Bytes)": [768, 1088, 1568],
    "AI Verdict Trigger": ["LOW", "MEDIUM", "HIGH"]
}
df = pd.DataFrame(data)
st.table(df)

# --- 5. WIRE FORMAT VISUALIZER ---
st.subheader("💾 Message Wire Format")

col_init, col_resp = st.columns(2)

with col_init:
    st.markdown("**Initiator Message Structure**")
    st.code("""
[ 1B : Level ]
[ 32B: X25519 Pub ]
[ NB : Kyber Pub  ]
    """, language="text")

with col_resp:
    st.markdown("**Responder Message Structure**")
    st.code("""
[ 32B: X25519 Pub ]
[ MB : Kyber CT   ]
    """, language="text")

st.info("💡 The gateway dynamically switches between these levels based on the real-time AI classification of the network state.")
