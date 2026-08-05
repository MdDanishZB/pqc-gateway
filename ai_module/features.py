"""
ai_module/features.py — single source of truth for the gateway's ML feature schema.

Both the OFFLINE path (prepare_dataset.py, train_model.py, evaluate.py) and the ONLINE
path (model_server.py, fed by the C gateway via ai_bridge.c) must agree on this schema.
The C side sends a comma-separated string of these values, in THIS exact order.

Phase 2 schema (real data)
──────────────────────────
The model is trained on CIC-IDS2017 flow statistics. These six features were chosen as
the intersection of (a) columns present in the dataset and (b) quantities the gateway can
compute online over a sliding window of packets — so there is no train/serve semantic gap.
SCTP-only signals (path RTT, send-loss) are deliberately NOT in the model; they stay in the
deterministic transport logic (path_monitor.c) where they belong.

UNITS — read this before touching the C side
─────────────────────────────────────────────
CIC-IDS2017 reports inter-arrival times and flow duration in MICROSECONDS (µs). To avoid a
silent train/serve skew, the ONLINE gateway must emit the same units:
    iat_mean, iat_std, flow_duration  → microseconds (µs)
    pkt_rate                          → packets/second
    byte_rate                         → bytes/second
    mean_pkt_size                     → bytes
If the C gateway computes ms, multiply by 1000 before sending. The C metric-string builders
(sctp_gateway.c, path_monitor.c) MUST match this order and these units.

C ↔ Python contract (order matters):
    "iat_mean,iat_std,pkt_rate,byte_rate,mean_pkt_size,flow_duration"
"""

FEATURES = [
    "iat_mean",       # mean inter-arrival time over the flow/window, µs   (CIC: Flow IAT Mean)
    "iat_std",        # std of inter-arrival time, µs                      (CIC: Flow IAT Std)
    "pkt_rate",       # packets per second                                 (CIC: Flow Packets/s)
    "byte_rate",      # bytes per second                                   (CIC: Flow Bytes/s)
    "mean_pkt_size",  # mean packet size, bytes                            (CIC: Avg Packet Size)
    "flow_duration",  # flow/window span, µs                              (CIC: Flow Duration)
]

# Map from our feature name -> the raw CIC-IDS2017 column name (used by prepare_dataset.py).
CIC_COLUMNS = {
    "iat_mean":      "Flow IAT Mean",
    "iat_std":       "Flow IAT Std",
    "pkt_rate":      "Flow Packets/s",
    "byte_rate":     "Flow Bytes/s",
    "mean_pkt_size": "Avg Packet Size",
    "flow_duration": "Flow Duration",
}

# Plausible NON-NEGATIVE operating ranges, derived from the real CIC-IDS2017 data
# (upper bounds ~ observed max; CIC flow timeout is 120 s = 120_000_000 µs). Used to flag
# and clip out-of-distribution / invalid (e.g. negative) inputs at inference time.
RANGES = {
    "iat_mean":      (0.0, 120_000_000.0),
    "iat_std":       (0.0,  85_000_000.0),
    "pkt_rate":      (0.0,   4_000_000.0),
    "byte_rate":     (0.0,   2_100_000_000.0),
    "mean_pkt_size": (0.0,       4_000.0),
    "flow_duration": (0.0, 120_000_000.0),
}


def parse_csv(line: str) -> list:
    """Parse the C gateway's comma-separated metric string into a float list."""
    parts = [float(x) for x in line.strip().split(",")]
    if len(parts) != len(FEATURES):
        raise ValueError(f"expected {len(FEATURES)} features, got {len(parts)}")
    return parts


def validate(values) -> list:
    """Return a list of skew/range warnings (empty list == in-distribution)."""
    warnings = []
    for name, v in zip(FEATURES, values):
        lo, hi = RANGES[name]
        if v < lo or v > hi:
            warnings.append(f"{name}={v} out of range [{lo}, {hi}]")
    return warnings


def clip(values) -> list:
    """Clamp each feature to its documented range, defending the model from skew."""
    out = []
    for name, v in zip(FEATURES, values):
        lo, hi = RANGES[name]
        out.append(min(max(v, lo), hi))
    return out
