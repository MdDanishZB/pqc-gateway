import sqlite3
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

DB_PATH = "metrics.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS metrics (
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id INTEGER,
                    latency REAL,
                    jitter REAL,
                    loss REAL,
                    throughput REAL,
                    ai_decision TEXT,
                    kyber_level TEXT,
                    active_path TEXT,
                    bytes_transferred INTEGER
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS path_events (
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    from_path TEXT,
                    to_path TEXT,
                    reason TEXT
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS llm_analysis (
                    id INTEGER PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    metrics_summary TEXT,
                    threat_level TEXT,
                    attack_type TEXT,
                    confidence REAL,
                    explanation TEXT,
                    recommendation TEXT,
                    inference_time_ms REAL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS chat_history (
                    id INTEGER PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    role TEXT,
                    message TEXT
                )''')
    conn.commit()
    conn.close()

class MetricsHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode('utf-8'))
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            if self.path == '/api/metrics':
                c.execute("INSERT INTO metrics (session_id, latency, jitter, loss, throughput, ai_decision, kyber_level, active_path, bytes_transferred) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (data.get('sessionId'), data.get('latencyMs'), data.get('jitterMs'), data.get('packetLossPct'), data.get('throughputBps'), data.get('aiDecision'), data.get('kyberLevel'), data.get('activePath'), data.get('bytesTransferred')))
            
            elif self.path == '/api/path-event':
                c.execute("INSERT INTO path_events (from_path, to_path, reason) VALUES (?, ?, ?)",
                          (data.get('fromPath'), data.get('toPath'), data.get('reason')))
            
            conn.commit()
            conn.close()
            self.send_response(200)
            self.end_headers()
        except Exception as e:
            print(f"Error parsing request: {e}")
            self.send_response(500)
            self.end_headers()

if __name__ == '__main__':
    init_db()
    server = HTTPServer(('127.0.0.1', 8080), MetricsHandler)
    print("Receiver running on port 8080...")
    server.serve_forever()
