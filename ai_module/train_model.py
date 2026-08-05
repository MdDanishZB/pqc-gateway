"""
train_model.py — train the severity detector on the real CIC-IDS2017 splits.

Trains a RandomForest for BOTH splits produced by prepare_dataset.py:
  * strat_* (in-distribution)      -> saved as models/rf_strat.pkl AND models/rf_model.pkl
                                      (rf_model.pkl is what model_server.py serves)
  * byday_* (cross-variant/day)    -> saved as models/rf_byday.pkl

Class imbalance (~85% benign) is handled with class_weight="balanced". A shared
LabelEncoder over the fixed severity order is saved once. Honest evaluation (confusion
matrix, per-class P/R/F1, FPR, PR-AUC) lives in evaluate.py.
"""
import os
import shutil

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from features import FEATURES
from label_map import SEVERITIES

SEED = 42
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


def train_split(split, encoder):
    train = pd.read_parquet(os.path.join(DATA_DIR, f"{split}_train.parquet"))
    X = train[FEATURES]
    y = encoder.transform(train["severity"])

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=18,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=SEED,
    )
    model.fit(X, y)

    out = os.path.join(MODEL_DIR, f"rf_{split}.pkl")
    joblib.dump(model, out)
    print(f"[{split}] trained on {len(train):,} rows -> {out}")
    print(f"[{split}] feature importances:")
    for f, imp in sorted(zip(FEATURES, model.feature_importances_),
                         key=lambda t: -t[1]):
        print(f"         {f:14s} {imp:.4f}")
    return model


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Fixed, shared label encoding (LOW/MEDIUM/HIGH order is deterministic).
    encoder = LabelEncoder().fit(SEVERITIES)
    joblib.dump(encoder, os.path.join(MODEL_DIR, "label_encoder.pkl"))

    train_split("strat", encoder)
    train_split("byday", encoder)

    # The in-distribution (strat) model is what the gateway serves.
    shutil.copy(os.path.join(MODEL_DIR, "rf_strat.pkl"),
                os.path.join(MODEL_DIR, "rf_model.pkl"))
    print("\nServing model: models/rf_model.pkl (= rf_strat.pkl)")


if __name__ == "__main__":
    main()
