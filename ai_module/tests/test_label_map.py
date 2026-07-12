"""
Phase 2 label-map tests. Run: cd ai_module && python3 tests/test_label_map.py
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from label_map import SEVERITIES, known_labels, normalize_label, to_severity


def test_all_known_labels_map():
    for lbl in known_labels():
        assert to_severity(lbl) in SEVERITIES


def test_families():
    assert to_severity("Benign") == "LOW"
    assert to_severity("DDoS") == "HIGH"
    assert to_severity("DoS Hulk") == "HIGH"
    assert to_severity("PortScan") == "MEDIUM"
    assert to_severity("Bot") == "MEDIUM"


def test_mojibake_web_attack():
    # CIC's real label carries the U+FFFD replacement char where an en-dash was.
    assert normalize_label("Web Attack � Brute Force") == "Web Attack Brute Force"
    assert to_severity("Web Attack � Brute Force") == "MEDIUM"
    assert to_severity("Web Attack � XSS") == "MEDIUM"


def test_unknown_raises():
    for bad in ("Totally New Attack", "", "dos hulk"):  # case-sensitive by design
        try:
            to_severity(bad)
            assert False, f"should have raised on {bad!r}"
        except ValueError:
            pass


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  : {name}"); passed += 1
    print(f"\nAll {passed} label-map tests passed.")
