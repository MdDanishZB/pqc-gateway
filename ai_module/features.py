"""
ai_module/features.py — single source of truth for the gateway's ML feature schema.

Both the OFFLINE path (generate_dataset.py, train_model.py) and the ONLINE path
(model_server.py, fed by the C gateway via ai_bridge.c) must agree on this schema.
The C side sends a comma-separated string of these values, in THIS exact order.

C ↔ Python contract
───────────────────
sctp_gateway.c (per session) and path_monitor.c (per poll) build the vector as:

    "latency,jitter,packet_loss,throughput,inter_arrival,bandwidth_util"

Units and sources are documented per-feature below. If you change the order or the
semantics here, you MUST update those C call sites and retrain the model — otherwise
you reintroduce train/serve skew.

NOTE (Phase 1): the model is still trained on synthetic data (generate_dataset.py).
The RANGES below bound that synthetic distribution and are used purely to detect skew
at inference time. Phase 2 replaces the dataset with a real IDS capture and widens
these ranges accordingly.
"""

FEATURES = [
    "latency",         # SCTP connect RTT, milliseconds
    "jitter",          # |latency_t - latency_{t-1}|, milliseconds (RFC-3550 style)
    "packet_loss",     # rolling send-failure percentage, 0..100
    "throughput",      # session payload size, BYTES (not bytes/sec)
    "inter_arrival",   # time since previous arrival, milliseconds
    "bandwidth_util",  # EMA throughput as % of reference link, 0..100
]

# Plausible operating ranges, bounding the synthetic training distribution.
# Used to flag (and optionally clip) out-of-distribution inputs at inference time.
RANGES = {
    "latency":        (0.0, 1000.0),
    "jitter":         (0.0, 500.0),
    "packet_loss":    (0.0, 100.0),
    "throughput":     (0.0, 5000.0),
    "inter_arrival":  (0.0, 60000.0),
    "bandwidth_util": (0.0, 100.0),
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
