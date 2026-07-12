import socket
import os
import joblib
import pandas as pd

from features import FEATURES, parse_csv, validate, clip

model   = joblib.load("models/rf_model.pkl")
encoder = joblib.load("models/label_encoder.pkl")

SOCKET_PATH = "/tmp/ai_gateway.sock"

# ── Phase 3 / Workstream E: optional feature capture ──────────────────────
# Set GW_CAPTURE_CSV=path and GW_CAPTURE_LABEL=LOW|MEDIUM|HIGH to log every
# feature vector the gateway sends (as measured live), tagged with the label of
# the traffic pattern being generated. Feeds eval_transfer.py to test whether the
# CIC-trained model transfers to gateway-measured features.
CAPTURE_CSV   = os.getenv("GW_CAPTURE_CSV")
CAPTURE_LABEL = os.getenv("GW_CAPTURE_LABEL")
if CAPTURE_CSV and not os.path.exists(CAPTURE_CSV):
    with open(CAPTURE_CSV, "w") as _f:
        _f.write(",".join(FEATURES) + ",severity\n")

if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCKET_PATH)
server.listen(5)
print(f"AI Inference Server running ({len(FEATURES)} features)...")

while True:
    conn, _ = server.accept()
    data = conn.recv(1024).decode().strip()

    if not data:
        conn.close()
        continue

    print(f"\n[AI] Metrics: {data}")

    try:
        parts = parse_csv(data)

        # Detect train/serve skew: if the gateway feeds a feature outside the
        # training distribution, surface it loudly and clip so the model never
        # predicts on out-of-distribution garbage (e.g. a cwnd sent as throughput).
        warnings = validate(parts)
        if warnings:
            print(f"[AI] WARNING — feature skew: {'; '.join(warnings)} (clipping)")
            parts = clip(parts)

        # Capture the live feature vector (pre-clip) for transfer validation.
        if CAPTURE_CSV and CAPTURE_LABEL:
            with open(CAPTURE_CSV, "a") as _f:
                _f.write(",".join(f"{x:.4f}" for x in parts) + f",{CAPTURE_LABEL}\n")

        input_df = pd.DataFrame([parts], columns=FEATURES)
        prediction = model.predict(input_df)
        result = encoder.inverse_transform(prediction)[0]

        print(f"[AI] Threat Level: {result}")
        conn.send(result.encode())

    except Exception as e:
        print(f"[AI] Error: {e}")
        conn.send(b"LOW")   # safe default

    conn.close()
