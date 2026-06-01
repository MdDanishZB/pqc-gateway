import socket
import os
import joblib
import pandas as pd

model   = joblib.load("models/rf_model.pkl")
encoder = joblib.load("models/label_encoder.pkl")

FEATURE_NAMES = [
    "latency",
    "jitter",
    "packet_loss",
    "throughput",
    "inter_arrival",
    "bandwidth_util",
]

SOCKET_PATH = "/tmp/ai_gateway.sock"

if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCKET_PATH)
server.listen(5)
print(f"AI Inference Server running ({len(FEATURE_NAMES)} features)...")

while True:
    conn, _ = server.accept()
    data = conn.recv(1024).decode().strip()

    if not data:
        conn.close()
        continue

    print(f"\n[AI] Metrics: {data}")

    try:
        parts = [float(x) for x in data.split(",")]

        if len(parts) != len(FEATURE_NAMES):
            raise ValueError(
                f"Expected {len(FEATURE_NAMES)} features, got {len(parts)}"
            )

        input_df = pd.DataFrame([parts], columns=FEATURE_NAMES)
        prediction = model.predict(input_df)
        result = encoder.inverse_transform(prediction)[0]

        print(f"[AI] Threat Level: {result}")
        conn.send(result.encode())

    except Exception as e:
        print(f"[AI] Error: {e}")
        conn.send(b"LOW")   # safe default

    conn.close()
