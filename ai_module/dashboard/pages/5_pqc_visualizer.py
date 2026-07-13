import streamlit as st
import pandas as pd
import graphviz
import os
import re
import sys
import time
import plotly.express as px

# Ensure we can import from the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

st.set_page_config(page_title="PQC Handshake - PQC Gateway", layout="wide")

# Real per-handshake data comes from the gateway's [Bench] log line.
GW_LOG = os.environ.get("GW_LOG", os.path.join(project_root, ".demo_logs", "gateway.log"))
BENCH_RE = re.compile(
    r"session=(\d+).*?connect=([\d.]+)ms ai_rtt=([\d.]+)ms handshake=([\d.]+)ms "
    r"\[x25519_kg=([\d.]+) kem_kg=([\d.]+) kem_decaps=([\d.]+) net=([\d.]+)\] kem=(\S+)")


def read_handshakes(path, limit=60):
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        with open(path, errors="ignore") as f:
            lines = f.readlines()[-5000:]
    except Exception:
        return pd.DataFrame()
    rows = []
    for ln in lines:
        m = BENCH_RE.search(ln)
        if m:
            g = m.groups()
            rows.append({
                "session": int(g[0]), "connect": float(g[1]), "ai_rtt": float(g[2]),
                "handshake": float(g[3]), "x25519_kg": float(g[4]), "kem_kg": float(g[5]),
                "kem_decaps": float(g[6]), "net": float(g[7]), "kem": g[8],
            })
    return pd.DataFrame(rows[-limit:])


st.title("🔐 PQC Handshake Visualizer")
st.markdown("""
The gateway secures every session with a **hybrid post-quantum handshake** — classical
**X25519** combined with **ML-KEM (Kyber)** — so an attacker must break *both* to recover the
key. Below is **live data from the real handshakes happening right now**, followed by how it works.
""")

# ── LIVE: real handshakes from the gateway ────────────────────────────────
st.subheader("🔴 Live Handshakes (real gateway data)")
auto = st.checkbox("Auto-refresh (2s)", value=True)
hs = read_handshakes(GW_LOG)

if hs.empty:
    st.info(f"No handshakes captured yet — start the stack and send traffic.\n\n"
            f"(reading `{GW_LOG}`; set `GW_LOG` if your gateway logs elsewhere)")
else:
    latest = hs.iloc[-1]
    # Median is robust to the occasional stalled connection under heavy load.
    kem_compute = (hs["kem_kg"] + hs["kem_decaps"]).median()
    med_hs = hs["handshake"].median()
    pct = (100 * kem_compute / med_hs) if med_hs > 0 else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Handshakes observed", len(hs))
    c2.metric("Current KEM", latest["kem"])
    c3.metric("Median handshake", f"{med_hs:.1f} ms")
    c4.metric("ML-KEM compute", f"{kem_compute:.2f} ms", f"{pct:.2f}% of handshake")

    comp = pd.DataFrame({
        "phase": ["X25519 keygen", "ML-KEM keygen", "ML-KEM decaps", "network wait"],
        "ms": [hs["x25519_kg"].median(), hs["kem_kg"].median(),
               hs["kem_decaps"].median(), hs["net"].median()],
        "kind": ["classical", "post-quantum", "post-quantum", "network"],
    })
    fig = px.bar(comp, x="ms", y="phase", orientation="h", color="kind", text="ms",
                 color_discrete_map={"classical": "#4C78A8", "post-quantum": "#54A24B",
                                     "network": "#BAB0AC"})
    fig.update_traces(texttemplate="%{text:.3f} ms")
    fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0),
                      xaxis_title="avg time per handshake phase (ms)", yaxis_title=None)
    st.plotly_chart(fig, use_container_width=True, key="pqc_decomp")
    st.caption("The post-quantum KEM (green) is a **sliver** — the handshake cost is the "
               "network round-trip, not the crypto. This is the measured refutation of "
               "\"post-quantum is too heavy\".")

    st.markdown("**Recent handshakes** (most recent first)")
    st.dataframe(
        hs[["session", "kem", "handshake", "x25519_kg", "kem_kg", "kem_decaps", "net"]]
        .tail(10).iloc[::-1].round(3),
        hide_index=True, use_container_width=True)

st.divider()

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
        - **KEM Level**: set by the session's **data classification** — ML-KEM-768 floor by
          default, ML-KEM-1024 only for CRITICAL data. The AI does **not** choose this.
        - **X25519 Public Key**: 32 bytes of classical EC key.
        - **ML-KEM Public Key**: Varying size (800 - 1568 bytes) based on level.
        - **ML-DSA signature**: the initiator signs the transcript with its pinned identity.

    2. **Responder Response**:
        - **X25519 Public Key**: Server's 32-byte classical key.
        - **Kyber Ciphertext**: The encapsulated PQC secret (768 - 1568 bytes).
        - **ML-DSA signature**: the responder signs the full transcript; each side verifies
          the other against a pinned key, so a man-in-the-middle is rejected.

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
    "Level": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    "NIST Security Category": ["1 (AES-128 equivalent)", "3 (AES-192 equivalent)", "5 (AES-256 equivalent)"],
    "Public Key Size (Bytes)": [800, 1184, 1568],
    "Ciphertext Size (Bytes)": [768, 1088, 1568],
    "Role in this gateway": ["Below floor — never used",
                             "Security FLOOR (ROUTINE / SENSITIVE data)",
                             "CRITICAL data only (raised, never forced down)"]
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
[ 4B : sig length ]
[ LB : ML-DSA sig ]  (over level‖X25519 Pub‖Kyber Pub)
    """, language="text")

with col_resp:
    st.markdown("**Responder Message Structure**")
    st.code("""
[ 32B: X25519 Pub ]
[ MB : Kyber CT   ]
[ 4B : sig length ]
[ LB : ML-DSA sig ]  (over the full transcript)
    """, language="text")

st.info("💡 Crypto strength is set **only by data classification** (ML-KEM-768 floor; "
        "ML-KEM-1024 only for CRITICAL data) — network conditions, threat level and battery "
        "can never change it. The handshake is authenticated with **ML-DSA-65**: each side "
        "verifies the other's signature against a pinned key, so a forged/MitM transcript "
        "is rejected.")

# ── auto-refresh the live section ─────────────────────────────────────────
if auto:
    time.sleep(2)
    st.rerun()
