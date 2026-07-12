"""
prepare_dataset.py — turn the raw CIC-IDS2017 parquet files into clean, split train/test
sets for the severity detector.

Outputs (git-ignored, under ai_module/data/):
    byday_train.parquet / byday_test.parquet   — leakage-safe split by capture day.
                                                  Trains HIGH on DoS variants, tests on the
                                                  UNSEEN DDoS variant (a real generalization
                                                  test). Also holds out portscan/bot/
                                                  infiltration for MEDIUM.
    strat_train.parquet / strat_test.parquet   — stratified random split (in-distribution
                                                  upper bound).

Cleaning:
  * ±Inf -> NaN, then drop rows with NaN in any model feature.
  * Drop physically-invalid negatives (CIC has negative IAT/duration/rate artifacts).
  * Drop exact duplicate rows (features + label).
Only the 6 model features + a mapped `severity` column are carried forward — nothing leaky.
"""
import glob
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from features import FEATURES, CIC_COLUMNS
from label_map import to_severity

SEED = 42
RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "dataset")
OUT_DIR = os.path.join(os.path.dirname(__file__), "data")

# By-day split (see PHASE2_DATA_PLAN.md §4). Matched by filename substring.
TRAIN_DAYS = ["Benign-Monday", "Bruteforce-Tuesday", "DoS-Wednesday", "WebAttacks-Thursday"]
TEST_DAYS  = ["DDoS-Friday", "Portscan-Friday", "Botnet-Friday", "Infiltration-Thursday"]

# Size caps to keep training fast and memory-sane (attacks kept in full; benign downsampled).
BENIGN_TRAIN_CAP = 250_000
BYDAY_TEST_CAP   = 300_000
STRAT_TOTAL_CAP  = 500_000

CIC_TIME_RATE_COLS = ["iat_mean", "iat_std", "pkt_rate", "byte_rate", "flow_duration"]


def load_and_clean(path):
    """Load one parquet file, select+rename the 6 features, map severity, clean."""
    raw_cols = list(CIC_COLUMNS.values()) + ["Label"]
    df = pd.read_parquet(path, columns=raw_cols)
    df = df.rename(columns={v: k for k, v in CIC_COLUMNS.items()})

    n0 = len(df)
    # ±Inf -> NaN, drop NaN rows.
    df[FEATURES] = df[FEATURES].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=FEATURES)
    n_nan = n0 - len(df)

    # Drop physically-impossible negatives (CIC timestamp artifacts).
    neg_mask = (df[CIC_TIME_RATE_COLS] < 0).any(axis=1)
    n_neg = int(neg_mask.sum())
    df = df[~neg_mask]

    # Map labels -> severity (raises on any unknown label).
    df["severity"] = df["Label"].map(to_severity)
    df = df[FEATURES + ["severity"]]

    # Drop exact duplicates.
    n_pre = len(df)
    df = df.drop_duplicates()
    n_dup = n_pre - len(df)

    print(f"  {os.path.basename(path):45s} kept={len(df):>8d} "
          f"(nan={n_nan}, neg={n_neg}, dup={n_dup})")
    return df


def downsample_benign(df, cap):
    """Cap the LOW (benign) class at `cap`, keep all MEDIUM/HIGH."""
    low = df[df.severity == "LOW"]
    rest = df[df.severity != "LOW"]
    if len(low) > cap:
        low = low.sample(n=cap, random_state=SEED)
    return pd.concat([low, rest], ignore_index=True).sample(frac=1, random_state=SEED)


def stratified_cap(df, cap):
    """Stratified subsample to ~cap rows, preserving class proportions."""
    if len(df) <= cap:
        return df
    frac = cap / len(df)
    return df.groupby("severity", group_keys=False).sample(frac=frac, random_state=SEED)


def dist(df):
    return df.severity.value_counts().to_dict()


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    files = sorted(glob.glob(os.path.join(RAW_DIR, "*.parquet")))
    if not files:
        raise SystemExit(f"No parquet files in {RAW_DIR}")

    print("Loading + cleaning per-file:")
    frames = {os.path.basename(f): load_and_clean(f) for f in files}

    def pick(days):
        return pd.concat(
            [frames[b] for b in frames if any(d in b for d in days)],
            ignore_index=True,
        )

    # ── By-day split ────────────────────────────────────────────────────────
    byday_train = downsample_benign(pick(TRAIN_DAYS), BENIGN_TRAIN_CAP)
    byday_test  = stratified_cap(pick(TEST_DAYS), BYDAY_TEST_CAP)

    # ── Stratified split ────────────────────────────────────────────────────
    full = stratified_cap(pd.concat(frames.values(), ignore_index=True), STRAT_TOTAL_CAP)
    strat_train, strat_test = train_test_split(
        full, test_size=0.3, random_state=SEED, stratify=full.severity)

    for name, df in [("byday_train", byday_train), ("byday_test", byday_test),
                     ("strat_train", strat_train), ("strat_test", strat_test)]:
        df.to_parquet(os.path.join(OUT_DIR, f"{name}.parquet"), index=False)
        print(f"{name:14s} n={len(df):>7d}  {dist(df)}")

    print("\nWrote splits to", OUT_DIR)


if __name__ == "__main__":
    main()
