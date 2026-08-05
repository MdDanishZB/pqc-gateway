# Phase 2 — Execution Plan (grounded in the real CIC-IDS2017 files)

> This refines `PHASE2_PLAN.md` now that the dataset is in hand. It references the actual
> files, columns, and label counts in `dataset/`, so it is a build sheet, not a strategy doc.

---

## 0. What we actually have

`dataset/` = **CIC-IDS2017, cleaned "no-metadata" release**, 8 per-day parquet files,
**2,313,810 flows × 78 columns**, single `Label` column.

Good news that changes the plan:
- **Leaky identifiers are already gone** (no IP, port, Flow ID, or Timestamp columns). The
  generic "drop leaky columns" step is largely done — just confirm none re-appear.
- The three data-quality columns sampled (`Flow Bytes/s`, `Flow Packets/s`, `Flow IAT Mean`)
  had **0 NaN / 0 Inf** in the DDoS file. Still guard globally (CIC is known for `Inf` in
  `Flow Bytes/s`), but expect light cleaning.
- Files are **per-day / per-attack**, which enables a leakage-safe *by-day* split (§4).
- All six D2 model features exist as columns (§3).

Global label distribution (heavily imbalanced — this is realistic and must be handled):

| Label | Count | % |
|---|---|---|
| Benign | 1,977,318 | 85.46 |
| DoS Hulk | 172,846 | 7.47 |
| DDoS | 128,014 | 5.53 |
| DoS GoldenEye | 10,286 | 0.44 |
| FTP-Patator | 5,931 | 0.26 |
| DoS slowloris | 5,385 | 0.23 |
| DoS Slowhttptest | 5,228 | 0.23 |
| SSH-Patator | 3,219 | 0.14 |
| PortScan | 1,956 | 0.08 |
| Web Attack – Brute Force | 1,470 | 0.06 |
| Bot | 1,437 | 0.06 |
| Web Attack – XSS | 652 | 0.03 |
| Infiltration | 36 | 0.00 |
| Web Attack – SQL Injection | 21 | 0.00 |
| Heartbleed | 11 | 0.00 |

> Note the Web Attack labels contain a mojibake character (`�`) — normalize label strings
> on load (Task 2.1) before mapping.

---

## 1. Column → feature map (D2 schema)

Rename exactly these six CIC columns to the `features.py` schema. No fabrication needed —
every one is a real column, and every one is computable by the gateway over a packet window.

| `features.py` name | CIC column | Unit |
|---|---|---|
| `iat_mean` | `Flow IAT Mean` | µs (CIC) → keep consistent; document |
| `iat_std` | `Flow IAT Std` | µs |
| `pkt_rate` | `Flow Packets/s` | pkts/s |
| `byte_rate` | `Flow Bytes/s` | bytes/s |
| `mean_pkt_size` | `Avg Packet Size` | bytes |
| `flow_duration` | `Flow Duration` | µs |

> Unit caveat: CIC IAT/duration are in **microseconds**. The live gateway computes ms.
> Pick ONE unit in `features.py` and convert on both sides (recommend µs to match the
> training data, converting the C side once). Document it in the `features.py` docstring —
> a silent ms/µs mismatch would be a fresh train/serve skew, exactly what Phase 1 killed.

---

## 2. Label map (15 classes → LOW / MEDIUM / HIGH)

Severity is defined by **impact on availability**, since the detector drives transport
(failover / rate-limit). Put this in a new `ai_module/label_map.py` as the single source.

| Severity | CIC labels |
|---|---|
| **LOW** | Benign |
| **MEDIUM** | FTP-Patator, SSH-Patator, PortScan, Bot, Web Attack (all), Infiltration, Heartbleed |
| **HIGH** | DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, DDoS |

- Any label not in the map must **raise**, never silently default (tested in 2.8).
- Report the resulting 3-class balance; expect ≈ 85% LOW / ~2% MEDIUM / ~13% HIGH.

---

## 3. Cleaning (Task 2.1) — lighter than the generic plan

1. Normalize label strings (fix `�`, strip whitespace) before mapping.
2. Replace `±Inf` → `NaN`, then drop rows with `NaN` in any of the 6 model columns; report
   how many were dropped per file.
3. Drop exact-duplicate rows on the 6 features + label (CIC has known duplicates); report count.
4. Confirm no identifier columns exist (they shouldn't) — assert the 6 selected columns are
   the only ones carried forward, so nothing leaky sneaks in.
5. Keep everything reproducible: fixed seed, write a small sampled working set so iterations
   are fast.

---

## 4. Split strategy — leakage-safe, with a real generalization test

The per-day files let us do something stronger than a random split: **hold out whole days /
attack variants** so the test set contains attack *types the model never saw in training*.

**Primary split (by day — the honest headline):**

| Split | Files | Severity coverage |
|---|---|---|
| **Train** | Benign-Monday, Bruteforce-Tuesday, DoS-Wednesday, WebAttacks-Thursday | LOW; MEDIUM (patator, web); **HIGH = DoS variants only** |
| **Test** | DDoS-Friday, Portscan-Friday, Botnet-Friday, Infiltration-Thursday | LOW; MEDIUM (portscan, bot, infiltration — unseen); **HIGH = DDoS (unseen variant)** |

This asks the real question: *does "HIGH" learned from DoS-Hulk/GoldenEye/slowloris
generalize to DDoS?* and *does MEDIUM learned from brute-force/web generalize to
portscan/bot?* A strong score here is meaningful; a weak one is an honest, reportable finding.

**Secondary split (stratified random 70/30):** report this too, as the "in-distribution"
upper bound. The gap between the two numbers is itself a result worth discussing.

> Benign appears in every file, so LOW is well represented on both sides — good.
> UNSW-NB15 cross-dataset (from `PHASE2_PLAN.md`) is now **optional/future** since only
> CIC-IDS2017 is on disk; the by-day split provides the generalization signal for now.

- Fit any scaler on **train only**. Never let test rows touch `.fit`.
- Imbalance: `class_weight="balanced"` (and/or benign **downsampling on train only**). Never
  resample test.

---

## 5. Scripts to write

| File | Purpose |
|---|---|
| `ai_module/label_map.py` | 15→3 mapping + `to_severity(label)` that raises on unknown |
| `ai_module/features.py` (edit) | replace `FEATURES`/`RANGES` with the D2 schema (§1), fix units, set ranges from observed train min/max |
| `ai_module/prepare_dataset.py` | read parquet → clean (§3) → select+rename 6 cols → apply label map → write `data/train.parquet` + `data/test.parquet` per the by-day split; also emit the stratified split |
| `ai_module/train_model.py` (edit) | train RF (+ logistic-reg & threshold baselines) with `class_weight`; save `models/rf_model.pkl`, `label_encoder.pkl` |
| `ai_module/evaluate.py` | load held-out test → confusion matrix, per-class P/R/F1, macro-F1, balanced acc, **FPR**, PR-AUC, inference latency → write `models/metrics.json` + `models/confusion_matrix.png` |
| `ai_module/tests/test_label_map.py` | every CIC label maps to one severity; unknown raises |
| `MODEL_CARD.md` | data provenance, unit choice, label map, split, metrics, limitations |

Keep raw parquet **out of git** (259 MB) — add `dataset/*.parquet` to `.gitignore`; commit
only scripts, the small derived split, and artifacts.

---

## 6. Evaluation deliverable (Task 2.5)

Report **both** splits, on data the model never trained on:
- Full confusion matrix (counts + row-normalized).
- Per-class precision / recall / F1, macro-F1, balanced accuracy.
- **False-positive rate** (benign flagged HIGH/MEDIUM) — the cost that matters, since a false
  HIGH triggers a needless rate-limit/failover.
- **PR-AUC** per class (imbalance-aware; more honest than ROC-AUC here).
- RF vs baselines — if RF barely beats a threshold rule, say so.
- Inference latency of `predict` on one live-shaped vector (keeps the "<5 ms tier" claim honest).
- Expect a realistic sub-100% number, and a **lower** score on the by-day split than the
  stratified one — that gap is the point.

---

## 7. Re-wire serving (Task 2.6)

- `model_server.py` already pulls `FEATURES`/`validate`/`clip` from `features.py`, so it
  tracks the schema automatically — just confirm the new `RANGES` (from real data) and that
  skew-clip fires on out-of-range live input.
- Update the C metric-string builders (`sctp_gateway.c`, `path_monitor.c`) to emit the D2
  vector **in µs**, in the new order. Full windowed computation in C is Task 2.7 (bridges
  into Phase 3); until then the model is validated offline.

---

## 8. Order & acceptance

**Order:** 2.1 clean/inspect → label_map + features edit → prepare_dataset → train + baselines
→ evaluate → tests → model card. (All offline; C wiring 2.6/2.7 last.)

**Done when:**
- [ ] Training consumes **real CIC-IDS2017**, not synthetic data.
- [ ] `features.py` D2 schema (µs units) is the single source of truth; ranges from real data.
- [ ] `label_map.py` maps all 15 labels; unknown raises; `test_label_map.py` passes.
- [ ] Reported accuracy **< 100%**, with confusion matrix + per-class P/R/F1 + FPR + PR-AUC,
      on **both** the by-day and stratified test sets.
- [ ] By-day (cross-variant) result reported honestly, even if lower than stratified.
- [ ] `MODEL_CARD.md`, `models/metrics.json`, `models/confusion_matrix.png` committed;
      raw parquet git-ignored.

**Out of scope:** C windowed features full integration (Phase 2.7→3), two-laptop testbed
(Phase 3), DTLS/auth (Phase 4), formal proof (Phase 5), UNSW cross-dataset (optional future).

## 9. Risks specific to this data

- **Severe imbalance (85% benign).** Accuracy is meaningless here — lead with macro-F1, FPR,
  PR-AUC. A model predicting "all benign" scores 85% and must be shown to be useless by these.
- **Tiny classes** (Infiltration 36, SQLi 21, Heartbleed 11) — fine once folded into MEDIUM;
  don't try to classify them individually.
- **Unit mismatch (µs vs ms)** is the most likely fresh bug — pin it in `features.py` and add
  it to the C wiring checklist.
- **By-day split may score notably lower** than random — that is the honest signal that CIC
  flow stats partly memorize per-day artifacts; report it rather than hiding behind the
  stratified number.
