import socket
import os
import joblib
import pandas as pd

from features import FEATURES, parse_csv, validate, clip

model   = joblib.load("models/rf_model.pkl")
encoder = joblib.load("models/label_encoder.pkl")

SOCKET_PATH = "/tmp/ai_gateway.sock"

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

        input_df = pd.DataFrame([parts], columns=FEATURES)
        prediction = model.predict(input_df)
        result = encoder.inverse_transform(prediction)[0]

        print(f"[AI] Threat Level: {result}")
        conn.send(result.encode())

    except Exception as e:
        print(f"[AI] Error: {e}")
        conn.send(b"LOW")   # safe default

    conn.close()
