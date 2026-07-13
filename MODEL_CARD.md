# Model Card — PQC Gateway ML Models

> Two independent models are documented here: **ML-B**, the threat/severity detector (original
> Phase 2 model, unchanged below), and **ML-A**, the network-condition classifier added when the
> project was redesigned to give ML two real, separate jobs (see `OT_GATEWAY_PLAN.md`). Neither
> model's output ever reaches `crypto_policy.c` — both drive **transport** decisions only.

---

# ML-B — Severity Detector (Phase 2)

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

---

# ML-A — Network-Condition Classifier

## Summary
A RandomForest that classifies live path-health metrics into one of **five network
conditions** — `STABLE / CONGESTED / DEGRADED / UNSTABLE / POSSIBLE_PATH_FAILURE`. The state
drives an **SCTP transport recommendation** (`transport_policy.c:netstate_to_policy()`) — normal
operation, congestion response, raised failover readiness, preferring the backup path, or an
actual failover once `GW_TRANSPORT_ENFORCE=1` is set over a real multi-path testbed. **Its
output never reaches `crypto_policy.c`** — this is a completely separate model from ML-B, with
its own features, socket (`/tmp/ai_netcond.sock`), and training pipeline.

## Data
- **Source:** synthesized (`netcond_dataset.py`) — no real multi-path traffic dataset exists
  publicly for this specific 5-state taxonomy, and (per project scope) no external network
  testbed was available to *capture* one. This is stated plainly rather than hidden.
- **Honesty by construction:** each state is a Gaussian mixture over the five features with
  **deliberately overlapping** ranges (e.g. `CONGESTED` and `DEGRADED` RTT distributions
  intersect) so the classes are *not* separable by construction — the mistake the original
  ML-B redesign was specifically undertaken to correct is not repeated here. 6,000 rows,
  1,200/class, 75/25 stratified train/test split, seed=42.
- **Profiles** (`netcond_dataset.py:PROFILES`, mean±std per feature):

| State | rtt_ms | jitter_ms | loss_pct | throughput_kbps | cwnd |
|---|---|---|---|---|---|
| STABLE | 20±10 | 3±2 | 0.2±0.3 | 9000±2500 | 60±20 |
| CONGESTED | 70±25 | 12±6 | 1.5±1.2 | 3500±1800 | 28±12 |
| DEGRADED | 130±40 | 28±12 | 5.0±3.0 | 1500±900 | 16±8 |
| UNSTABLE | 120±60 | 55±25 | 9.0±5.0 | 2200±1600 | 20±14 |
| POSSIBLE_PATH_FAILURE | 280±90 | 70±30 | 35±18 | 400±400 | 5±4 |

## Features (`net_features.py`)
`rtt_ms, jitter_ms, loss_pct, throughput_kbps, cwnd` — signals the gateway's path monitor
(`path_monitor.c`) genuinely measures per polling interval from the live SCTP association, no
different set from what's fed to the model.

## Evaluation — held-out 25% test split (1,500 rows), vs. a transparent baseline
A hand-written threshold baseline (`train_netcond.py:threshold_baseline()` — simple RTT/loss
cutoffs) is evaluated on the **same** test rows, so the RF has to earn its place rather than
just being assumed better.

| Metric | RF | Threshold baseline |
|---|---|---|
| Accuracy | 0.930 | 0.784 |
| **Macro-F1** | **0.930** | 0.782 |

Per-class F1 (RF): STABLE 0.95 · CONGESTED 0.87 · DEGRADED 0.97 · UNSTABLE 0.99 ·
POSSIBLE_PATH_FAILURE 0.86. `CONGESTED` and `POSSIBLE_PATH_FAILURE` are the weakest classes —
consistent with them sitting at the overlapping boundaries with neighboring states by design.

**Feature importance:** `loss_pct` (0.29) > `jitter_ms` (0.25) > `rtt_ms` (0.24) >
`throughput_kbps` (0.15) > `cwnd` (0.07) — loss and jitter dominate the decision, which matches
intuition (a path degrades primarily through drops and instability before RTT climbs).

## Honest findings
- **Not 100%; beats a real baseline by ~15 points of macro-F1**, not an inflated margin over a
  strawman — the threshold rules are genuinely reasonable, hand-tuned cutoffs.
- **Simulated data is the main limitation.** Unlike ML-B (real CIC-IDS2017 captures), ML-A has
  not been validated against a real multi-path production network. The **real, measured
  artifact that partially validates it in practice** is the netns failover test
  (`scripts/failover_measure.sh`): when the gateway runs with `GW_TRANSPORT_ENFORCE=1` over a
  genuine two-veth testbed, ML-A's `POSSIBLE_PATH_FAILURE`/`UNSTABLE` predictions have been
  observed to trigger real, successful proactive failovers ahead of/alongside the
  threat-driven reactive path — see the failover measurement results (mean ± 95% CI,
  proactive vs. reactive breakdown) for the concrete numbers.
- **No cross-topology validation.** The Gaussian-mixture profiles were authored, not fit to
  observed traffic; different link technologies (satellite vs. fibre vs. cellular) would likely
  need re-profiling.

## Reproduce
```bash
cd ai_module && source venv/bin/activate
python3 netcond_dataset.py     # -> data/netcond.csv (6,000 rows)
python3 train_netcond.py       # -> models/netcond_model.pkl, netcond_label_encoder.pkl,
                                #    netcond_metrics.json, netcond_confusion.png
python3 tests/test_netcond.py  # schema + honest-metrics guard tests
```
Artifacts committed: `models/netcond_model.pkl`, `netcond_label_encoder.pkl`,
`netcond_metrics.json`, `netcond_confusion.png`. `data/netcond.csv` is git-ignored
(regenerate deterministically with the seeded script above).
