"""
Phase 1 feature-schema tests.

Guards the C <-> Python feature contract (ai_module/features.py): correct arity,
out-of-range detection (train/serve skew), and clipping. Run:

    cd ai_module && python3 tests/test_features.py
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from features import FEATURES, RANGES, parse_csv, validate, clip


def test_schema_shape():
    assert len(FEATURES) == 6, "expected 6 features"
    assert set(RANGES.keys()) == set(FEATURES), "RANGES must cover every feature"


def test_parse_csv_arity():
    vec = parse_csv("10,1,0.5,900,200,20")
    assert vec == [10.0, 1.0, 0.5, 900.0, 200.0, 20.0]
    for bad in ("1,2,3", "1,2,3,4,5,6,7"):
        try:
            parse_csv(bad)
            assert False, f"should have rejected {bad!r}"
        except ValueError:
            pass


def test_validate_detects_skew():
    # In-distribution -> clean.
    assert validate([10, 1, 0.5, 900, 200, 20]) == []
    # The original bug: an SCTP cwnd (~14000) sent as "throughput" is out of range.
    warns = validate([10, 1, 0.5, 14000, 200, 20])
    assert any("throughput" in w for w in warns), "cwnd-as-throughput must be flagged"


def test_clip_clamps_to_range():
    clipped = clip([10, 1, 0.5, 14000, 200, 20])
    lo, hi = RANGES["throughput"]
    assert clipped[FEATURES.index("throughput")] == hi
    assert all(RANGES[f][0] <= v <= RANGES[f][1] for f, v in zip(FEATURES, clipped))


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  : {name}")
            passed += 1
    print(f"\nAll {passed} feature tests passed.")
