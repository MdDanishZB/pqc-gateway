import socket
import time
import random
import threading
import argparse
import sys

class TrafficGenerator:
    def __init__(self, host="127.0.0.1", port=4000):
        self.host = host
        self.port = port
        self.running = False
        self.thread = None
        self.pattern = "Normal"
        self.rate = 10  # msg/sec for certain patterns

    def send_packet(self, payload=None):
        if payload is None:
            payload = f"Generic Payload {random.randint(1000, 9999)}"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                s.connect((self.host, self.port))
                s.sendall(payload.encode())
        except Exception:
            # Silently fail if gateway is not reachable
            pass

    def _worker(self):
        print(f"[*] Traffic Generator started with pattern: {self.pattern}")
        while self.running:
            try:
                if self.pattern == "Normal":
                    # 1–50 msg/sec, realistic payloads (HTTP/IoT telemetry)
                    payloads = [
                        "GET /api/v1/telemetry HTTP/1.1\r\nHost: gateway.local\r\n\r\n",
                        "POST /log HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"temp\": 22.5}",
                        "PUT /config HTTP/1.1\r\n\r\nMODE=ENABLED"
                    ]
                    self.send_packet(random.choice(payloads))
                    time.sleep(1.0 / random.randint(5, 20))
                
                elif self.pattern == "DDoS":
                    # Burst packets, IAT < 10ms, high bandwidth
                    self.send_packet("A" * 500)
                    time.sleep(random.uniform(0.001, 0.005))
                
                elif self.pattern == "C2 Beacon":
                    # Periodic small payloads, IAT 1000–3000ms
                    self.send_packet("HEARTBEAT_ACK_" + hex(random.getrandbits(32)))
                    time.sleep(random.uniform(1.0, 3.0))
                
                elif self.pattern == "Congestion":
                    # Medium latency + moderate loss (handled by network_conditioner)
                    # We send at a moderate rate
                    self.send_packet("DATA_STREAM_CHUNK_" + str(random.randint(0, 1000)))
                    time.sleep(random.uniform(0.01, 0.05))
                
                elif self.pattern == "Mixed":
                    # Random blend cycling through patterns
                    current_sub_pattern = random.choice(["Normal", "DDoS", "C2 Beacon", "Congestion"])
                    duration = random.randint(2, 5)
                    start_time = time.time()
                    while time.time() - start_time < duration and self.running:
                        if current_sub_pattern == "Normal":
                            self.send_packet("MIXED_NORMAL_" + str(random.random()))
                            time.sleep(0.1)
                        elif current_sub_pattern == "DDoS":
                            self.send_packet("MIXED_DDOS_" + "X"*100)
                            time.sleep(0.005)
                        elif current_sub_pattern == "C2 Beacon":
                            self.send_packet("MIXED_C2_" + str(random.getrandbits(16)))
                            time.sleep(1.5)
                        elif current_sub_pattern == "Congestion":
                            self.send_packet("MIXED_CONGESTION_" + str(random.random()))
                            time.sleep(0.02)
                else:
                    time.sleep(1)
            except Exception as e:
                print(f"[!] Error in traffic worker: {e}")
                time.sleep(1)

    def start(self, pattern="Normal"):
        if self.running:
            self.stop()
        self.pattern = pattern
        self.running = True
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        print("[*] Traffic Generator stopped")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Gateway Traffic Simulator")
    parser.add_argument("--pattern", type=str, default="Normal", 
                        choices=["Normal", "DDoS", "C2 Beacon", "Congestion", "Mixed"],
                        help="Traffic pattern to simulate")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Gateway host")
    parser.add_argument("--port", type=int, default=4000, help="Gateway port")
    parser.add_argument("--duration", type=int, default=0, help="Duration in seconds (0 for infinite)")

    args = parser.parse_args()

    gen = TrafficGenerator(args.host, args.port)
    try:
        gen.start(args.pattern)
        if args.duration > 0:
            time.sleep(args.duration)
            gen.stop()
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        gen.stop()
        sys.exit(0)
