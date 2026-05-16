import socket
import os
import joblib
import pandas as pd

model = joblib.load("models/rf_model.pkl")
encoder = joblib.load("models/label_encoder.pkl")

# Define feature names to match training data
FEATURE_NAMES = ["latency", "jitter", "packet_loss", "throughput"]

SOCKET_PATH = "/tmp/ai_gateway.sock"

if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

server = socket.socket(socket.AF_UNIX,
                       socket.SOCK_STREAM)

server.bind(SOCKET_PATH)

server.listen(5)

print("AI Inference Server Running...")

while True:

    conn, _ = server.accept()

    data = conn.recv(1024).decode()

    if not data:
        conn.close()
        continue

    print("\n[AI] Metrics:", data)

    try:
        parts = data.split(",")
        latency = float(parts[0])
        jitter = float(parts[1])
        packet_loss = float(parts[2])
        throughput = float(parts[3])

        # Create DataFrame with feature names to avoid UserWarning
        input_data = pd.DataFrame([[
            latency,
            jitter,
            packet_loss,
            throughput
        ]], columns=FEATURE_NAMES)

        prediction = model.predict(input_data)
        result = encoder.inverse_transform(prediction)[0]

        print("[AI] Threat Level:", result)
        conn.send(result.encode())

    except Exception as e:
        print(f"[AI] Error processing request: {e}")
        conn.send(b"ERROR")

    conn.close()
