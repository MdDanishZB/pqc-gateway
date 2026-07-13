"""
4_threat_narrative.py — "Evidence" page.

Replaces the old LLM-narrated "Threat Narrative" (the LLM advisor is parked; that page
depended on it and would sit empty). Shows the honest, measured evidence for both ML
models and the claims-discipline table, so an evaluator can check every claim against a
real artifact instead of a narrated summary.
"""
import json
import os

import streamlit as st

st.set_page_config(page_title="Evidence - PQC Gateway", layout="wide")
st.title("📊 Evidence")
st.caption("Every claim below is backed by a measured artifact — no narrated / LLM-generated "
           "numbers. Two independent models are evaluated separately; neither touches crypto.")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
MODELS = os.path.join(ROOT, "ai_module", "models")

col_b, col_a = st.columns(2)

# ── ML-B: threat detector ─────────────────────────────────────────────────────
with col_b:
    st.subheader("ML-B — Threat Detector (CIC-IDS2017)")
    metrics_path = os.path.join(MODELS, "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            m = json.load(f)
        macro_f1 = m.get("macro_f1") or m.get("rf", {}).get("macro_f1")
        acc = m.get("accuracy") or m.get("rf", {}).get("accuracy")
        if macro_f1 is not None:
            st.metric("macro-F1 (in-distribution)", f"{macro_f1:.3f}")
        if acc is not None:
            st.metric("accuracy", f"{acc:.3f}")
        with st.expander("Full metrics.json"):
            st.json(m)
    else:
        st.info("models/metrics.json not found — run ai_module/train_model.py")

    cm_path = os.path.join(MODELS, "confusion_matrix_strat.png")
    if os.path.exists(cm_path):
        st.image(cm_path, caption="Confusion matrix — held-out CIC-IDS2017 split")
    st.caption("Real, sub-100% number — the earlier separable-by-construction dataset was "
               "replaced with real CIC-IDS2017 flows (see MODEL_CARD.md).")

# ── ML-A: network-condition classifier ──────────────────────────────────────────
with col_a:
    st.subheader("ML-A — Network-Condition Classifier")
    net_metrics_path = os.path.join(MODELS, "netcond_metrics.json")
    if os.path.exists(net_metrics_path):
        with open(net_metrics_path) as f:
            nm = json.load(f)
        rf = nm.get("rf", {})
        base = nm.get("threshold_baseline", {})
        c1, c2 = st.columns(2)
        c1.metric("RF macro-F1", f"{rf.get('macro_f1', 0):.3f}")
        c2.metric("threshold baseline macro-F1", f"{base.get('macro_f1', 0):.3f}",
                  delta=f"{rf.get('macro_f1', 0) - base.get('macro_f1', 0):+.3f}")
        st.caption("The RF must beat a transparent hand-rule baseline to earn its place — "
                   "this is why the states are overlapping/synthetic, not separable.")
        with st.expander("Full netcond_metrics.json"):
            st.json(nm)
    else:
        st.info("models/netcond_metrics.json not found — run "
                "ai_module/netcond_dataset.py then ai_module/train_netcond.py")

    cm2_path = os.path.join(MODELS, "netcond_confusion.png")
    if os.path.exists(cm2_path):
        st.image(cm2_path, caption="Confusion matrix — network-condition states")

st.divider()

# ── Claims discipline ────────────────────────────────────────────────────────────
st.subheader("✅ What we claim now / ⚠️ what's pending")
st.table({
    "Claim": [
        "Quantum-safe confidentiality (hybrid X25519+ML-KEM)",
        "Authenticated handshake (anti-MitM, ML-DSA)",
        "Crypto strength is policy-driven, floored, up-only",
        "ML-A network-condition -> transport recommendations",
        "ML-A -> actual adaptive path switching",
        "ML-B threat detection, honest evaluation",
        "SCTP failover mechanism exists",
        "Real, measured failover timings",
    ],
    "Status": [
        "✅ yes — pqc_selftest, real liboqs ML-KEM-768",
        "✅ yes — pqc_auth_selftest + tests/test_handshake",
        "✅ yes — select_kem() takes ONLY a DataClassification",
        "✅ yes — recommendation-mode, logged as [NetML]",
        "⚠️ not yet — needs a real multi-path testbed (GW_TRANSPORT_ENFORCE)",
        "✅ yes — macro-F1 0.87 in-dist / 0.58 cross-variant, real CIC data",
        "✅ yes — SCTP multihoming code (multihoming.c / path_monitor.c)",
        "⚠️ not yet — current runs are single-host/loopback",
    ],
})
