"""
Network-condition model (ML-A) tests. Guards the schema contract, the trained model's
behaviour, and the honesty invariants (real sub-100% F1, beats the threshold baseline).
Run: cd ai_module && python3 tests/test_netcond.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import joblib
import pandas as pd

from net_features import NET_FEATURES, STATES, parse_csv, clip

MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))


def test_schema():
    assert NET_FEATURES == ["rtt_ms", "jitter_ms", "loss_pct", "throughput_kbps", "cwnd"]
    assert STATES[0] == "STABLE" and STATES[-1] == "POSSIBLE_PATH_FAILURE"
    assert len(parse_csv("20,3,0.2,9000,60")) == 5
    # clip clamps out-of-range values
    assert clip([-5, 0, 200, 0, 0])[0] == 0.0 and clip([0, 0, 200, 0, 0])[2] == 100.0


def test_model_predicts_all_states():
    model = joblib.load(os.path.join(MODEL_DIR, "netcond_model.pkl"))
    enc = joblib.load(os.path.join(MODEL_DIR, "netcond_label_encoder.pkl"))
    # Clear archetypes for each state -> the model should recover the label.
    archetypes = {
        "STABLE":                [15,  2, 0.1, 9500, 65],
        "DEGRADED":              [140, 25, 5.5, 1400, 15],
        "POSSIBLE_PATH_FAILURE": [300, 75, 40,  300,  4],
    }
    for want, vec in archetypes.items():
        df = pd.DataFrame([clip(vec)], columns=NET_FEATURES)
        got = enc.inverse_transform(model.predict(df))[0]
        assert got == want, f"expected {want} for {vec}, got {got}"


def test_honest_metrics():
    with open(os.path.join(MODEL_DIR, "netcond_metrics.json")) as f:
        m = json.load(f)
    rf_f1 = m["rf"]["macro_f1"]
    base_f1 = m["threshold_baseline"]["macro_f1"]
    assert 0.5 < rf_f1 < 1.0, f"RF macro-F1 {rf_f1} should be a real sub-100% number"
    assert rf_f1 > base_f1, f"RF ({rf_f1}) must beat the threshold baseline ({base_f1})"


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok  : {name}")
            except AssertionError as e:
                print(f"  FAIL: {name} — {e}")
                fails += 1
    print("\nAll netcond tests passed." if not fails else f"\n{fails} test(s) FAILED.")
    sys.exit(1 if fails else 0)
