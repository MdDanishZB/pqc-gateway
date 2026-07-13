"""
ai_module/net_features.py — single source of truth for the NETWORK-CONDITION model (ML-A).

This is a SEPARATE model from the CIC threat detector (features.py / ML-B). ML-A classifies
the health of the SCTP transport path so the gateway can make *resilience* decisions; it never
touches cryptographic strength (that is driven solely by data classification — crypto_policy.h).

Feature vector — network-health signals the gateway/path_monitor genuinely has:
    rtt_ms           round-trip time on the active path (ms)
    jitter_ms        RTT variation (ms)
    loss_pct         send/heartbeat loss (%)
    throughput_kbps  application throughput (kbit/s)
    cwnd             SCTP congestion window (segments)

C ↔ Python contract (order matters), over /tmp/ai_netcond.sock:
    "rtt_ms,jitter_ms,loss_pct,throughput_kbps,cwnd"
Reply: one of STATES below.
"""

NET_FEATURES = ["rtt_ms", "jitter_ms", "loss_pct", "throughput_kbps", "cwnd"]

# Ordered from healthiest to most severe. The transport policy engine maps each to an action.
STATES = ["STABLE", "CONGESTED", "DEGRADED", "UNSTABLE", "POSSIBLE_PATH_FAILURE"]

# Plausible non-negative operating ranges; used to clip out-of-distribution inputs online.
RANGES = {
    "rtt_ms":          (0.0, 2000.0),
    "jitter_ms":       (0.0,  500.0),
    "loss_pct":        (0.0,  100.0),
    "throughput_kbps": (0.0, 100000.0),
    "cwnd":            (0.0,  200.0),
}


def parse_csv(line: str) -> list:
    parts = [float(x) for x in line.strip().split(",")]
    if len(parts) != len(NET_FEATURES):
        raise ValueError(f"expected {len(NET_FEATURES)} features, got {len(parts)}")
    return parts


def clip(values) -> list:
    out = []
    for name, v in zip(NET_FEATURES, values):
        lo, hi = RANGES[name]
        out.append(min(max(v, lo), hi))
    return out
