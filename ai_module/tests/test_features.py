"""
Phase 2 feature-schema tests (D2 / CIC-IDS2017 schema).
Guards the C <-> Python feature contract in ai_module/features.py.
Run: cd ai_module && python3 tests/test_features.py
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from features import FEATURES, RANGES, CIC_COLUMNS, parse_csv, validate, clip


def test_schema_shape():
    assert FEATURES == ["iat_mean", "iat_std", "pkt_rate", "byte_rate",
                        "mean_pkt_size", "flow_duration"]
    assert set(RANGES) == set(FEATURES)
    assert set(CIC_COLUMNS) == set(FEATURES)  # every feature maps to a CIC column


def test_parse_csv_arity():
    vec = parse_csv("28117,17416,61.5,3151,88,64783")
    assert len(vec) == 6 and vec[0] == 28117.0
    for bad in ("1,2,3", "1,2,3,4,5,6,7"):
        try:
            parse_csv(bad)
            assert False, f"should have rejected {bad!r}"
        except ValueError:
            pass


def test_validate_detects_invalid():
    # In-distribution -> clean.
    assert validate([28117, 17416, 61.5, 3151, 88, 64783]) == []
    # Negative IAT is a CIC artifact / impossible live value -> flagged.
    warns = validate([-13, 17416, 61.5, 3151, 88, 64783])
    assert any("iat_mean" in w for w in warns)


def test_clip_clamps_to_range():
    clipped = clip([-13, 17416, 61.5, 3151, 88, 999_999_999])
    assert clipped[FEATURES.index("iat_mean")] == 0.0
    assert all(RANGES[f][0] <= v <= RANGES[f][1] for f, v in zip(FEATURES, clipped))


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  : {name}"); passed += 1
    print(f"\nAll {passed} feature tests passed.")
