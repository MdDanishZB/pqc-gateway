"""
evaluate.py — honest evaluation of the severity detector on held-out test data.

For BOTH splits (strat = in-distribution, byday = cross-variant/day generalization):
  * confusion matrix (counts)
  * per-class precision / recall / F1 + support
  * macro-F1, balanced accuracy, plain accuracy
  * false-positive rate (benign flagged as MEDIUM/HIGH) — the cost that matters, since a
    false HIGH triggers a needless rate-limit/failover
  * PR-AUC (average precision) per class, one-vs-rest
  * single-vector inference latency (keeps the "<5 ms real-time tier" claim honest)
  * baselines: majority-class and logistic regression, for context

Writes models/metrics.json and (if matplotlib is available) confusion-matrix PNGs.
"""
import json
import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                             classification_report, confusion_matrix, f1_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from features import FEATURES
from label_map import SEVERITIES

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


def false_positive_rate(y_true, y_pred, encoder):
    """P(pred != LOW | true == LOW): benign misflagged as an attack."""
    low = encoder.transform(["LOW"])[0]
    benign = y_true == low
    if benign.sum() == 0:
        return None
    return float((y_pred[benign] != low).mean())


def pr_auc_per_class(y_true, proba, encoder):
    # predict_proba columns are ordered by the (sorted) encoded class ints 0..K-1, so the
    # column for severity `s` is exactly its encoded value. Index directly to avoid the
    # column-reordering that label_binarize's sorting would introduce.
    out = {}
    for sev in SEVERITIES:
        c = int(encoder.transform([sev])[0])
        yb = (y_true == c).astype(int)
        out[sev] = (None if yb.sum() == 0
                    else float(average_precision_score(yb, proba[:, c])))
    return out


def inference_latency_ms(model, X, n=300):
    one = X.iloc[[0]]
    model.predict(one)  # warm up
    t0 = time.perf_counter()
    for _ in range(n):
        model.predict(one)
    return (time.perf_counter() - t0) / n * 1000.0


def report(name, y_true, y_pred, encoder):
    rep = classification_report(
        y_true, y_pred, labels=encoder.transform(SEVERITIES),
        target_names=SEVERITIES, output_dict=True, zero_division=0)
    return {
        "accuracy": float((y_true == y_pred).mean()),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "false_positive_rate": false_positive_rate(y_true, y_pred, encoder),
        "per_class": {s: {k: round(rep[s][k], 4) for k in
                          ("precision", "recall", "f1-score", "support")}
                      for s in SEVERITIES},
    }


def save_cm_png(cm, split, encoder):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None
    fig, ax = plt.subplots(figsize=(4.5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(3)); ax.set_yticks(range(3))
    ax.set_xticklabels(SEVERITIES); ax.set_yticklabels(SEVERITIES)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_title(f"Confusion matrix ({split})")
    for i in range(3):
        for j in range(3):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=8)
    fig.colorbar(im, fraction=0.046)
    fig.tight_layout()
    path = os.path.join(MODEL_DIR, f"confusion_matrix_{split}.png")
    fig.savefig(path, dpi=120); plt.close(fig)
    return path


def evaluate_split(split, encoder):
    train = pd.read_parquet(os.path.join(DATA_DIR, f"{split}_train.parquet"))
    test = pd.read_parquet(os.path.join(DATA_DIR, f"{split}_test.parquet"))
    Xtr, ytr = train[FEATURES], encoder.transform(train["severity"])
    Xte, yte = test[FEATURES], encoder.transform(test["severity"])

    model = joblib.load(os.path.join(MODEL_DIR, f"rf_{split}.pkl"))
    ypred = model.predict(Xte)
    proba = model.predict_proba(Xte)

    cm = confusion_matrix(yte, ypred, labels=encoder.transform(SEVERITIES))
    result = report("rf", yte, ypred, encoder)
    result["confusion_matrix"] = {"labels": SEVERITIES, "counts": cm.tolist()}
    result["pr_auc"] = pr_auc_per_class(yte, proba, encoder)
    result["inference_latency_ms"] = round(inference_latency_ms(model, Xte), 4)
    result["test_support"] = int(len(yte))

    # Baselines for context.
    maj = DummyClassifier(strategy="most_frequent").fit(Xtr, ytr)
    logit = make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=200, class_weight="balanced"),
    ).fit(Xtr, ytr)
    result["baselines"] = {
        "majority_class": report("maj", yte, maj.predict(Xte), encoder),
        "logistic_regression": report("logit", yte, logit.predict(Xte), encoder),
    }

    png = save_cm_png(cm, split, encoder)
    print(f"\n===== {split.upper()} =====")
    print(f"accuracy={result['accuracy']:.4f}  balanced_acc={result['balanced_accuracy']:.4f}"
          f"  macro_f1={result['macro_f1']:.4f}  FPR={result['false_positive_rate']:.4f}")
    print("confusion matrix (rows=true LOW/MEDIUM/HIGH):")
    print(cm)
    print(classification_report(yte, ypred, labels=encoder.transform(SEVERITIES),
                                target_names=SEVERITIES, zero_division=0))
    print(f"RF macro-F1 {result['macro_f1']:.3f} vs "
          f"majority {result['baselines']['majority_class']['macro_f1']:.3f} vs "
          f"logistic {result['baselines']['logistic_regression']['macro_f1']:.3f}")
    if png:
        print("wrote", png)
    return result


def main():
    encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
    metrics = {s: evaluate_split(s, encoder) for s in ("strat", "byday")}
    out = os.path.join(MODEL_DIR, "metrics.json")
    with open(out, "w") as f:
        json.dump(metrics, f, indent=2)
    print("\nWrote", out)


if __name__ == "__main__":
    main()
