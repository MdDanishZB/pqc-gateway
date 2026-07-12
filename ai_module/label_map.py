"""
ai_module/label_map.py — single source of truth for the CIC-IDS2017 label -> severity map.

The detector's output drives TRANSPORT decisions (failover / rate-limit), so severity is
defined by impact on availability:

    LOW    — benign traffic
    MEDIUM — reconnaissance / brute-force / bot / web / infiltration (targeted, low-volume)
    HIGH   — DoS / DDoS families (volumetric, availability-threatening)

Any label not covered here RAISES — we never silently default an unknown class.
"""
import re

# Severity buckets, keyed by NORMALISED CIC label (see normalize_label).
_HIGH = {
    "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "DDoS",
}
_MEDIUM = {
    "FTP-Patator", "SSH-Patator", "PortScan", "Bot", "Infiltration", "Heartbleed",
    "Web Attack Brute Force", "Web Attack XSS", "Web Attack Sql Injection",
}
_LOW = {
    "Benign",
}

# Flatten to a single lookup: normalised label -> severity.
_LOOKUP = {}
for _lbl in _LOW:
    _LOOKUP[_lbl] = "LOW"
for _lbl in _MEDIUM:
    _LOOKUP[_lbl] = "MEDIUM"
for _lbl in _HIGH:
    _LOOKUP[_lbl] = "HIGH"

SEVERITIES = ["LOW", "MEDIUM", "HIGH"]


def normalize_label(label: str) -> str:
    """
    Normalise a raw CIC label so it matches the lookup keys.

    CIC-IDS2017's "Web Attack" labels contain a mojibake byte (U+FFFD, originally an
    en-dash) — e.g. 'Web Attack � Brute Force'. We strip any non-ASCII character and
    collapse whitespace so it becomes 'Web Attack Brute Force'.
    """
    s = re.sub(r"[^\x00-\x7f]", " ", str(label))   # drop mojibake / non-ASCII
    s = re.sub(r"\s+", " ", s).strip()
    return s


def to_severity(label: str) -> str:
    """Map a raw CIC label to LOW/MEDIUM/HIGH. Raises ValueError on an unknown label."""
    norm = normalize_label(label)
    try:
        return _LOOKUP[norm]
    except KeyError:
        raise ValueError(f"unknown CIC label {label!r} (normalised {norm!r})")


def known_labels() -> set:
    """All raw-normalised labels this map recognises."""
    return set(_LOOKUP.keys())
