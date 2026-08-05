"""
train_netcond.py — train + honestly evaluate the network-condition classifier (ML-A).

  python3 netcond_dataset.py     # first, to create data/netcond.csv
  python3 train_netcond.py       # trains, evaluates, writes artifacts

Outputs (models/):
  netcond_model.pkl            RandomForest network-condition classifier
  netcond_label_encoder.pkl    LabelEncoder over STATES
  netcond_metrics.json         accuracy, macro-F1, per-class P/R/F1, RF-vs-baseline
  netcond_confusion.png        confusion matrix on the held-out test split

We also report a transparent THRESHOLD baseline (hand rules on loss/rtt/jitter) so the RF
has to earn its place — the contribution is honest evaluation, not model complexity.
"""
import json
import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (confusion_matrix, f1_score,
                             classification_report, accuracy_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from net_features import NET_FEATURES, STATES

SEED = 42
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


def threshold_baseline(row) -> str:
    """Transparent hand-rules — the bar the ML model must beat."""
    rtt, jit, loss = row["rtt_ms"], row["jitter_ms"], row["loss_pct"]
    if loss >= 15 or rtt >= 200:
        return "POSSIBLE_PATH_FAILURE"
    if jit >= 40:
        return "UNSTABLE"
    if loss >= 2.5 or rtt >= 100:
        return "DEGRADED"
    if rtt >= 45 or loss >= 0.8:
        return "CONGESTED"
    return "STABLE"


def main():
    df = pd.read_csv(os.path.join(DATA_DIR, "netcond.csv"))
    encoder = LabelEncoder().fit(STATES)

    X = df[NET_FEATURES]
    y = encoder.transform(df["state"])
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.25, random_state=SEED, stratify=y)

    model = RandomForestClassifier(
        n_estimators=150, max_depth=14, min_samples_leaf=4,
        class_weight="balanced", n_jobs=-1, random_state=SEED)
    model.fit(X_tr, y_tr)

    # ── RF evaluation on the held-out split ──────────────────────────────────
    pred = model.predict(X_te)
    acc = accuracy_score(y_te, pred)
    macro_f1 = f1_score(y_te, pred, average="macro")
    report = classification_report(y_te, pred, target_names=STATES,
                                   output_dict=True, zero_division=0)

    # ── Threshold baseline on the SAME test rows ─────────────────────────────
    te_df = X_te.copy()
    base_pred_labels = te_df.apply(threshold_baseline, axis=1)
    base_pred = encoder.transform(base_pred_labels)
    base_macro_f1 = f1_score(y_te, base_pred, average="macro")
    base_acc = accuracy_score(y_te, base_pred)

    print(f"[netcond] RF       : accuracy={acc:.3f}  macro-F1={macro_f1:.3f}")
    print(f"[netcond] baseline : accuracy={base_acc:.3f}  macro-F1={base_macro_f1:.3f}")
    print(f"[netcond] feature importances:")
    for f, imp in sorted(zip(NET_FEATURES, model.feature_importances_), key=lambda t: -t[1]):
        print(f"          {f:16s} {imp:.4f}")

    # ── Persist artifacts ────────────────────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_DIR, "netcond_model.pkl"))
    joblib.dump(encoder, os.path.join(MODEL_DIR, "netcond_label_encoder.pkl"))

    metrics = {
        "model": "RandomForest",
        "features": NET_FEATURES,
        "states": STATES,
        "n_train": len(X_tr), "n_test": len(X_te),
        "rf": {"accuracy": acc, "macro_f1": macro_f1, "per_class": report},
        "threshold_baseline": {"accuracy": base_acc, "macro_f1": base_macro_f1},
    }
    with open(os.path.join(MODEL_DIR, "netcond_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    # ── Confusion matrix figure ──────────────────────────────────────────────
    cm = confusion_matrix(y_te, pred)
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(STATES))); ax.set_yticks(range(len(STATES)))
    ax.set_xticklabels(STATES, rotation=40, ha="right", fontsize=8)
    ax.set_yticklabels(STATES, fontsize=8)
    ax.set_xlabel("predicted"); ax.set_ylabel("true")
    ax.set_title(f"Network-condition RF — macro-F1 {macro_f1:.2f} "
                 f"(baseline {base_macro_f1:.2f})")
    for i in range(len(STATES)):
        for j in range(len(STATES)):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=8)
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(os.path.join(MODEL_DIR, "netcond_confusion.png"), dpi=130)
    print(f"[netcond] wrote models/netcond_model.pkl, netcond_metrics.json, netcond_confusion.png")


if __name__ == "__main__":
    main()
