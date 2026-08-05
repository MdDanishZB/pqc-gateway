"""
eval_transfer.py — does the CIC-trained detector transfer to GATEWAY-measured features?

Reads a capture CSV produced by model_server.py (GW_CAPTURE_CSV) while labeled traffic was
generated, and evaluates the served model (models/rf_model.pkl) on those *live* feature
vectors — the exact features the gateway computes, not CICFlowMeter flows.

Reports the honest transfer confusion matrix / macro-F1 / FPR, and how many captured rows
fell outside the training range (skew). This closes the train/serve loop opened in Phase 2.

Usage:
    python3 eval_transfer.py --capture capture.csv
"""
import argparse
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (balanced_accuracy_score, classification_report,
                             confusion_matrix, f1_score)

from features import FEATURES, RANGES, clip
from label_map import SEVERITIES

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True, help="CSV from model_server GW_CAPTURE_CSV")
    args = ap.parse_args()

    df = pd.read_parquet(args.capture) if args.capture.endswith(".parquet") \
        else pd.read_csv(args.capture)
    if "severity" not in df.columns:
        raise SystemExit("capture must have a 'severity' column")
    df = df[df["severity"].isin(SEVERITIES)]
    if df.empty:
        raise SystemExit("no rows with a known severity label")

    # Count skew (rows outside the training range) before clipping, exactly as the
    # live server would clip them.
    X = df[FEATURES].to_numpy(dtype=float)
    n_skew = sum(any(v < RANGES[f][0] or v > RANGES[f][1]
                     for f, v in zip(FEATURES, row)) for row in X)
    Xc = np.array([clip(row) for row in X])

    model   = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
    encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))

    y_true = encoder.transform(df["severity"])
    y_pred = model.predict(pd.DataFrame(Xc, columns=FEATURES))

    labels = encoder.transform(SEVERITIES)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    low = encoder.transform(["LOW"])[0]
    benign = y_true == low
    fpr = float((y_pred[benign] != low).mean()) if benign.sum() else float("nan")

    print(f"captured rows: {len(df)}   out-of-range (skew): {n_skew} "
          f"({100*n_skew/len(df):.1f}%)")
    print("label distribution:", df["severity"].value_counts().to_dict())
    print("\nconfusion matrix (rows=true LOW/MEDIUM/HIGH):")
    print(cm)
    print(f"\nmacro-F1 = {f1_score(y_true, y_pred, average='macro', zero_division=0):.4f}"
          f"   balanced-acc = {balanced_accuracy_score(y_true, y_pred):.4f}"
          f"   FPR = {fpr:.4f}")
    print(classification_report(y_true, y_pred, labels=labels,
                                target_names=SEVERITIES, zero_division=0))
    print("NOTE: this is the model on LIVE gateway features. If macro-F1 is much lower than "
          "the Phase-2 in-distribution 0.87, the CIC→gateway transfer is weak — retrain the "
          "served model on this capture (split by session) and report both.")


if __name__ == "__main__":
    main()
