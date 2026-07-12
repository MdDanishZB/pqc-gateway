# Model Card — PQC Gateway Severity Detector (Phase 2)

## Summary
A RandomForest that classifies a network flow into a **3-level severity** — LOW / MEDIUM /
HIGH — from six flow-statistics features. The severity drives **transport** decisions
(failover / rate-limit) in the gateway, **not** cryptographic strength (crypto is pinned at
a fixed floor — see Phase 1 / `crypto_policy.h`). This replaces the earlier synthetic,
separable-by-construction dataset whose "100% accuracy" was meaningless.

## Data
- **Source:** CIC-IDS2017, cleaned "no-metadata" parquet release (identifier columns — IP,
  port, timestamp, Flow ID — already removed, so no obvious label leakage).
- **Raw:** 2,313,810 flows × 78 columns, single `Label` (15 classes, **85.5% benign**).
- **Cleaning** (`prepare_dataset.py`): ±Inf→NaN then drop; drop physically-invalid
  negatives (CIC timestamp artifacts, ~88 rows); drop exact duplicates (~254k rows).
- **Label mapping → severity** (`label_map.py`, by impact on availability):
  - LOW = Benign
  - MEDIUM = FTP/SSH-Patator, PortScan, Bot, Web Attack (×3), Infiltration, Heartbleed
  - HIGH = DoS Hulk/GoldenEye/slowloris/Slowhttptest, DDoS

## Features (`features.py`, units = **microseconds** for time fields)
`iat_mean, iat_std` (µs) · `pkt_rate` (pkt/s) · `byte_rate` (B/s) · `mean_pkt_size` (B) ·
`flow_duration` (µs). Chosen as the intersection of *present in CIC* ∩ *computable online by
the gateway over a packet window*, to avoid train/serve semantic skew.

## Evaluation — two splits, held-out test data
- **strat** = stratified random 70/30 (in-distribution upper bound).
- **byday** = leakage-safe split by capture day: HIGH trained on DoS variants and tested on
  the **unseen DDoS** variant; MEDIUM trained on brute-force/web and tested on unseen
  portscan/bot/infiltration. This is a real generalization test.

| Metric | strat (in-dist) | byday (cross-variant) |
|---|---|---|
| Accuracy | 0.983 | 0.905 |
| Balanced accuracy | 0.973 | 0.567 |
| **Macro-F1** | **0.874** | **0.575** |
| False-positive rate (benign→attack) | 0.018 | 0.048 |
| F1 — LOW / MEDIUM / HIGH | 0.99 / 0.66 / 0.97 | 0.94 / 0.02 / 0.77 |
| PR-AUC — LOW / MEDIUM / HIGH | 0.999 / 0.929 / 0.983 | 0.989 / 0.031 / 0.78 |

**Baselines (macro-F1):** RF 0.874 / 0.575 vs majority-class 0.30 / 0.30 vs logistic
regression 0.49 / 0.48 — RF clearly justified over trivial and linear baselines.

**Inference latency:** ~**11.6 ms** per single-vector `predict` (Python/sklearn call
overhead dominates, not compute). ⚠️ This is **above** the project's earlier "<5 ms
real-time tier" claim for per-session calls — that claim should be corrected or requalified
(batched inference is far cheaper per row, but the gateway calls one flow at a time).

## Honest findings
- **Not 100%.** The in-distribution macro-F1 is 0.87 — a real, imperfect number.
- **HIGH generalizes; MEDIUM does not.** Trained only on DoS variants, the model still
  detects the unseen DDoS variant (byday HIGH F1 0.77, PR-AUC 0.78) — evidence it learned a
  transferable volumetric signature. MEDIUM collapses across the split (F1 0.02) because
  "targeted low-volume recon" is not one coherent traffic shape (brute-force ≠ portscan ≠
  bot ≠ infiltration). The ~0.30 macro-F1 gap between splits is the point, not a defect.
- **MEDIUM precision is modest even in-distribution** (0.51): some benign flows are flagged
  MEDIUM, which is the main FPR contributor.

## Known limitations & integration status
- ⚠️ **Live inference is not yet wired (train/serve gap open).** The C gateway
  (`sctp_gateway.c`, `path_monitor.c`) still emits the **old** feature vector; `model_server.py`
  now expects the new µs-unit schema. Until the **Phase 2.7 windowed feature computation** in
  C emits `iat_mean,iat_std,pkt_rate,byte_rate,mean_pkt_size,flow_duration` in microseconds,
  the **offline model is validated but the online path would mis-predict.** This is the #1
  follow-up and belongs with the Phase 3 testbed.
- **Transfer to gateway-measured features is unproven.** The model is trained on
  CICFlowMeter flows; whether it holds on the gateway's own windowed features must be shown
  on a real capture (Phase 3), not assumed.
- **MEDIUM class is weak/rare** — treat MEDIUM outputs as low-confidence advisories.
- **No temporal/deployment drift evaluation**; single dataset (UNSW-NB15 cross-dataset check
  is optional future work).

## Reproduce
```bash
cd ai_module && source venv/bin/activate
python3 prepare_dataset.py     # dataset/*.parquet -> data/{strat,byday}_{train,test}.parquet
python3 train_model.py         # -> models/rf_{strat,byday}.pkl, rf_model.pkl, label_encoder.pkl
python3 evaluate.py            # -> models/metrics.json, confusion_matrix_{strat,byday}.png
python3 tests/test_features.py && python3 tests/test_label_map.py
```
Artifacts committed: `models/rf_model.pkl`, `label_encoder.pkl`, `metrics.json`,
`confusion_matrix_*.png`. Raw parquet and `data/` splits are git-ignored.
