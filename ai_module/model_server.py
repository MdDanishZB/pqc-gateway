import socket
import os

SOCKET_PATH = "/tmp/ai_gateway.sock"

if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

server = socket.socket(socket.AF_UNIX,
                       socket.SOCK_STREAM)

server.bind(SOCKET_PATH)

server.listen(5)

print("AI Model Server Running...")

while True:

    conn, _ = server.accept()

    data = conn.recv(1024).decode()

    print("\n[AI Engine] Metrics Received:")
    print(data)

    decision = "LOW_RISK"

    conn.send(decision.encode())

    conn.close()