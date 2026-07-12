"""
retrain_gateway.py — retrain the SERVED detector on features the gateway actually measures.

The Phase-2 model is trained on CICFlowMeter flows; the live gateway computes windowed
features that differ (the CIC->gateway transfer gap). This retrains a RandomForest on a
capture of real gateway features (from run_demo.sh calibrate) and overwrites
models/rf_model.pkl, so the live demo reliably shows Normal->LOW and DDoS->HIGH.

Usage: python3 retrain_gateway.py --capture gateway_capture.csv
"""
import argparse
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from features import FEATURES
from label_map import SEVERITIES

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True)
    args = ap.parse_args()

    df = pd.read_csv(args.capture)
    df = df[df["severity"].isin(SEVERITIES)].dropna(subset=FEATURES)
    if df["severity"].nunique() < 2:
        raise SystemExit(f"capture has <2 classes ({df['severity'].value_counts().to_dict()}) "
                         "— run calibrate with more patterns/traffic")

    print("capture class balance:", df["severity"].value_counts().to_dict())
    X, y_raw = df[FEATURES], df["severity"]

    encoder = LabelEncoder().fit(SEVERITIES)
    y = encoder.transform(y_raw)

    strat = y if pd.Series(y).value_counts().min() >= 2 else None
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=strat)

    model = RandomForestClassifier(n_estimators=120, max_depth=16, min_samples_leaf=3,
                                   class_weight="balanced", n_jobs=-1, random_state=42)
    model.fit(Xtr, ytr)

    print(classification_report(yte, model.predict(Xte),
                                labels=encoder.transform(SEVERITIES),
                                target_names=SEVERITIES, zero_division=0))

    joblib.dump(model, os.path.join(MODEL_DIR, "rf_model.pkl"))
    joblib.dump(encoder, os.path.join(MODEL_DIR, "label_encoder.pkl"))
    print("Served model updated: models/rf_model.pkl (trained on gateway features).")
    print("NOTE: restart model_server so it loads the new model.")


if __name__ == "__main__":
    main()
