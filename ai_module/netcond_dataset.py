"""
netcond_dataset.py — synthesize a labelled NETWORK-CONDITION dataset for ML-A.

Honesty note: real path-health traces on a two-host testbed would be ideal. We don't have
that yet, so we simulate — but *deliberately with overlapping distributions* so the states
blend into one another (a congested path and a degraded path look similar near the boundary).
That overlap is the point: it yields an honest, sub-100% accuracy instead of the separable
toy dataset the original project (rightly) got criticised for. Each state is a mixture of
Gaussians over the five net_features, clipped to physical ranges.

    python3 netcond_dataset.py            # writes data/netcond.csv (default 6000 rows)
"""
import argparse
import os

import numpy as np
import pandas as pd

from net_features import NET_FEATURES, STATES, RANGES

SEED = 42
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# Per-state (mean, std) for each feature. Ranges overlap on purpose (see module docstring).
#                    rtt_ms          jitter_ms       loss_pct        throughput_kbps    cwnd
PROFILES = {
    "STABLE":                [(20,  10), (3,   2), (0.2, 0.3), (9000, 2500), (60, 20)],
    "CONGESTED":             [(70,  25), (12,  6), (1.5, 1.2), (3500, 1800), (28, 12)],
    "DEGRADED":              [(130, 40), (28, 12), (5.0, 3.0), (1500, 900),  (16,  8)],
    "UNSTABLE":              [(120, 60), (55, 25), (9.0, 5.0), (2200, 1600), (20, 14)],
    "POSSIBLE_PATH_FAILURE": [(280, 90), (70, 30), (35,  18), (400,  400),  (5,   4)],
}


def _sample(profile, n, rng):
    cols = []
    for (mean, std), name in zip(profile, NET_FEATURES):
        lo, hi = RANGES[name]
        vals = rng.normal(mean, std, n)
        cols.append(np.clip(vals, lo, hi))
    return np.column_stack(cols)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=6000)
    args = ap.parse_args()

    rng = np.random.default_rng(SEED)
    per_state = args.rows // len(STATES)

    frames = []
    for state in STATES:
        X = _sample(PROFILES[state], per_state, rng)
        df = pd.DataFrame(X, columns=NET_FEATURES)
        df["state"] = state
        frames.append(df)

    data = pd.concat(frames, ignore_index=True).sample(frac=1.0, random_state=SEED)
    os.makedirs(DATA_DIR, exist_ok=True)
    out = os.path.join(DATA_DIR, "netcond.csv")
    data.to_csv(out, index=False)
    print(f"wrote {len(data):,} rows ({per_state}/state) -> {out}")
    print(data["state"].value_counts().to_string())


if __name__ == "__main__":
    main()
