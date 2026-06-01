"""
generate_dataset.py
Generates a 300-row labelled dataset for the PQC gateway AI model.

Features:
  latency          – SCTP connect RTT (ms)
  jitter           – |current_latency - previous_latency| (ms)
  packet_loss      – rolling loss percentage
  throughput       – bytes/sec (gateway session)
  inter_arrival    – inter-packet arrival time (ms)
  bandwidth_util   – EMA throughput as % of 1 MB/s reference link

Label: threat_level ∈ {LOW, MEDIUM, HIGH}

Design rationale
────────────────
LOW    – healthy network; normal IAT; light load
MEDIUM – degraded path; moderate congestion or moderate anomaly
HIGH   – attack pattern (flood: very low IAT + high bw) OR
         C2-beacon pattern (very high IAT + low bw + latency spike)
"""

import csv
import random

random.seed(42)

ROWS_PER_CLASS = 100
OUT_FILE = "dataset.csv"

HEADER = [
    "latency", "jitter", "packet_loss",
    "throughput", "inter_arrival", "bandwidth_util",
    "threat_level",
]


def rnd(lo, hi, decimals=2):
    return round(random.uniform(lo, hi), decimals)


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


rows = []

# ── LOW threat ───────────────────────────────────────────────────────────────
for _ in range(ROWS_PER_CLASS):
    rows.append({
        "latency":        rnd(5,  30),
        "jitter":         rnd(0,  5),
        "packet_loss":    rnd(0,  1),
        "throughput":     rnd(800, 1000),
        "inter_arrival":  rnd(100, 500),   # normal inter-packet spacing
        "bandwidth_util": rnd(5,  30),
        "threat_level":   "LOW",
    })

# ── MEDIUM threat ─────────────────────────────────────────────────────────────
for _ in range(ROWS_PER_CLASS):
    # Two sub-patterns: congested path, or moderately bursty traffic
    if random.random() < 0.5:
        rows.append({
            "latency":        rnd(30,  80),
            "jitter":         rnd(5,   15),
            "packet_loss":    rnd(2,   5),
            "throughput":     rnd(500, 800),
            "inter_arrival":  rnd(50,  150),
            "bandwidth_util": rnd(30,  60),
            "threat_level":   "MEDIUM",
        })
    else:
        rows.append({
            "latency":        rnd(20,  60),
            "jitter":         rnd(8,   20),
            "packet_loss":    rnd(1,   4),
            "throughput":     rnd(400, 750),
            "inter_arrival":  rnd(300, 700),
            "bandwidth_util": rnd(25,  55),
            "threat_level":   "MEDIUM",
        })

# ── HIGH threat ───────────────────────────────────────────────────────────────
for _ in range(ROWS_PER_CLASS):
    # Sub-pattern A: DDoS / flood (very low IAT, high bandwidth, high latency)
    if random.random() < 0.5:
        rows.append({
            "latency":        rnd(80,  200),
            "jitter":         rnd(15,  50),
            "packet_loss":    rnd(5,   20),
            "throughput":     rnd(50,  400),
            "inter_arrival":  rnd(1,   10),    # rapid-fire packets
            "bandwidth_util": rnd(70,  99),
            "threat_level":   "HIGH",
        })
    # Sub-pattern B: C2 beacon / sinkhole (very high IAT, low bw, latency spike)
    else:
        rows.append({
            "latency":        rnd(120, 300),
            "jitter":         rnd(20,  80),
            "packet_loss":    rnd(8,   25),
            "throughput":     rnd(0,   200),
            "inter_arrival":  rnd(1000, 3000),  # slow intermittent beacon
            "bandwidth_util": rnd(0,    5),
            "threat_level":   "HIGH",
        })

random.shuffle(rows)

with open(OUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=HEADER)
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated {len(rows)} rows → {OUT_FILE}")
print("Class distribution:")
for label in ["LOW", "MEDIUM", "HIGH"]:
    count = sum(1 for r in rows if r["threat_level"] == label)
    print(f"  {label}: {count}")
