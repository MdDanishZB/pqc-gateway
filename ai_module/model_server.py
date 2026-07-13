"""
model_server.py — serves BOTH ML models the gateway uses, on two Unix sockets:

  /tmp/ai_gateway.sock   ML-B threat detector (CIC-IDS2017): 6 flow-stat features -> LOW/MEDIUM/HIGH
  /tmp/ai_netcond.sock   ML-A network-condition (net_features): 5 health features -> STATE

The two models are independent (the two-pipeline design): the threat verdict drives the
SECURITY response and the network-condition drives the SCTP TRANSPORT policy. NEITHER selects
the cryptographic strength — that is set solely by data classification (crypto_policy.h).
"""
import os
import socket
import threading

import joblib
import pandas as pd

from features import FEATURES, parse_csv, validate, clip

# ── ML-B: threat detector ─────────────────────────────────────────────────────
model   = joblib.load("models/rf_model.pkl")
encoder = joblib.load("models/label_encoder.pkl")

THREAT_SOCK  = "/tmp/ai_gateway.sock"
NETCOND_SOCK = "/tmp/ai_netcond.sock"

# ── ML-A: network-condition classifier (optional — skip if not trained yet) ───
try:
    import net_features
    net_model   = joblib.load("models/netcond_model.pkl")
    net_encoder = joblib.load("models/netcond_label_encoder.pkl")
except Exception as e:                       # noqa: BLE001
    net_model = None
    print(f"[ML-A] network-condition model unavailable ({e}); "
          f"run: python3 netcond_dataset.py && python3 train_netcond.py")

# ── Threat capture (Workstream E: transfer validation / calibration) ──────────
CAPTURE_CSV        = os.getenv("GW_CAPTURE_CSV")
CAPTURE_LABEL      = os.getenv("GW_CAPTURE_LABEL")
CAPTURE_LABEL_FILE = os.getenv("GW_CAPTURE_LABEL_FILE")
if CAPTURE_CSV and not os.path.exists(CAPTURE_CSV):
    with open(CAPTURE_CSV, "w") as _f:
        _f.write(",".join(FEATURES) + ",severity\n")


def _capture_label():
    if CAPTURE_LABEL_FILE and os.path.exists(CAPTURE_LABEL_FILE):
        try:
            v = open(CAPTURE_LABEL_FILE).read().strip()
            if v:
                return v
        except Exception:
            pass
    return CAPTURE_LABEL


def _serve(path, handler, name):
    """Generic Unix-socket accept loop; each request is one line, one reply."""
    if os.path.exists(path):
        os.remove(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(5)
    print(f"[{name}] serving on {path}")
    while True:
        conn, _ = srv.accept()
        try:
            data = conn.recv(1024).decode().strip()
            if data:
                conn.send(handler(data).encode())
        except Exception as e:                 # noqa: BLE001
            print(f"[{name}] error: {e}")
            try:
                conn.send(b"")
            except Exception:
                pass
        finally:
            conn.close()


def handle_threat(data: str) -> str:
    parts = parse_csv(data)
    warnings = validate(parts)
    if warnings:
        print(f"[ML-B] WARNING — feature skew: {'; '.join(warnings)} (clipping)")
        parts = clip(parts)
    if CAPTURE_CSV:
        lab = _capture_label()
        if lab:
            with open(CAPTURE_CSV, "a") as f:
                f.write(",".join(f"{x:.4f}" for x in parts) + f",{lab}\n")
    input_df = pd.DataFrame([parts], columns=FEATURES)
    result = encoder.inverse_transform(model.predict(input_df))[0]
    print(f"[ML-B] threat={result}  <- {data}")
    return result


def handle_netcond(data: str) -> str:
    parts = net_features.clip(net_features.parse_csv(data))
    input_df = pd.DataFrame([parts], columns=net_features.NET_FEATURES)
    state = net_encoder.inverse_transform(net_model.predict(input_df))[0]
    print(f"[ML-A] net-state={state}  <- {data}")
    return state


if __name__ == "__main__":
    # ML-A on a background thread; ML-B on the main thread (keeps existing behaviour).
    if net_model is not None:
        threading.Thread(
            target=_serve, args=(NETCOND_SOCK, handle_netcond, "ML-A"),
            daemon=True).start()
    print(f"AI Inference Server running (ML-B: {len(FEATURES)} feats"
          f"{', ML-A: %d feats' % len(net_features.NET_FEATURES) if net_model is not None else ''}) ...")
    _serve(THREAT_SOCK, handle_threat, "ML-B")
