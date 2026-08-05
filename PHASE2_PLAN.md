# Phase 2 — Honest ML

> Goal: replace the synthetic, separable-by-construction dataset with a **real labeled
> capture**, and evaluate the detector with a **leakage-safe split and an honest
> (sub-100%) confusion matrix**. After Phase 2, the "100% accuracy" disappears and the
> detector's numbers mean something.
>
> Builds directly on Phase 1: `ai_module/features.py` is already the single source of
> truth, so redefining the feature set propagates cleanly to training, serving, and the
> C contract. The detector now drives **transport** (failover / rate-limit), so its real
> job is **network-anomaly / DDoS detection** — that framing decides everything below.

---

## The crux: three gaps between "what the gateway measures" and "what public datasets contain"

This is the part that makes Phase 2 real work rather than a one-line dataset swap. Do not
paper over these by inventing values — that just re-introduces the dishonesty Phase 1 removed.

| Gap | Gateway today | Public IDS dataset (CIC/UNSW) | Honest resolution |
|---|---|---|---|
| **Feature semantics** | SCTP connect RTT, rolling send-loss %, bandwidth-util vs a 1 MB/s ref | flow duration, Flow IAT mean/std, Flow Bytes/s, pkt counts/sizes | Redefine the schema to the **intersection** of *measurable online* ∩ *present in the dataset* (Decision D2). SCTP-only signals (loss, path RTT) leave the ML model and become deterministic transport inputs. |
| **Granularity** | one snapshot per TCP connection | per-flow aggregate over many packets | Compute features over a **sliding window** of recent arrivals so the live vector matches flow-level stats (Decision D3). |
| **Labels** | LOW / MEDIUM / HIGH severity | BENIGN / DoS / DDoS / PortScan / … | Map dataset classes → severity with a documented rule (Decision D4), keeping the C `transport_policy` contract (LOW/MEDIUM/HIGH) unchanged. |

---

## Design decisions (recommended choice in **bold**)

### D1 — Which dataset
- **Primary: CIC-IDS2017.** Has BENIGN + DoS/DDoS + PortScan, enabling a 3-level severity
  mapping; widely cited; flow features via CICFlowMeter (so the same extractor can later
  run on your own captures, keeping features consistent).
- **Generalization check: UNSW-NB15.** Train on CIC-IDS2017, test on UNSW-NB15 (and vice
  versa). Cross-dataset evaluation is a strong, honest signal that you learned traffic
  structure, not one capture's quirks — reviewers value this far more than a single high score.
- Alternative if you want a pure availability/DDoS stress test: **CIC-DDoS2019**.
- **Known caveat to handle:** CIC-IDS2017 has duplicate flows and some label noise —
  dedupe and document it (Task 2.1).

### D2 — Feature set (the intersection)
Redefine `features.py` to features that are **both** computable by the gateway over a
window **and** present in the public dataset. SCTP-specific signals that have no public
analog (`packet_loss`, path `latency`/RTT) are **removed from the ML model** and instead
consumed directly by the deterministic path logic in `path_monitor.c` (which already reads
true SCTP path state). Proposed model features:

| New feature | Gateway source (windowed) | CIC/UNSW analog |
|---|---|---|
| `iat_mean` | mean inter-arrival over window (ms) | Flow IAT Mean |
| `iat_std` | std of inter-arrival (ms) | Flow IAT Std |
| `pkt_rate` | packets/sec over window | Flow Packets/s |
| `byte_rate` | bytes/sec over window | Flow Bytes/s |
| `mean_pkt_size` | mean payload bytes/packet | Average Packet Size |
| `flow_duration` | window span (ms) | Flow Duration |

This is a **clean separation of concerns**: the ML model detects *traffic-shape* anomalies
from flow stats (trained on public data, no train/serve gap), while *path health*
(loss, RTT, ACTIVE/INACTIVE) stays in deterministic transport logic where it belongs.

> Keep the change surgical: edit `FEATURES` + `RANGES` in `features.py`; everything
> downstream (training, `model_server.py` validation, the C metric string) follows from it.

### D3 — Granularity (windowing)
The live detector computes the D2 features over a **sliding window of the last N arrivals**
(or a T-second window) so the online vector is statistically comparable to a dataset flow.
The offline training rows are CIC/UNSW flows directly. The C-side windowing implementation
is the integration bridge (Task 2.7) and may extend into Phase 3.

### D4 — Output labels
**Keep the 3-level severity output** (LOW/MEDIUM/HIGH) so Phase 1's `transport_policy`
contract is untouched. Map dataset labels with a documented rule, e.g.:

```
BENIGN                              -> LOW
PortScan / probe / low-rate recon   -> MEDIUM
DoS / DDoS / flood families         -> HIGH
```

Alternative (more standard, more churn): emit the real attack classes and update
`decide_transport` to map class→action. Defer unless a reviewer asks.

---

## Tasks

### 2.1 — Data acquisition & cleaning
- Download CIC-IDS2017 (and UNSW-NB15) flow CSVs. Document provenance + version in a
  `data/README.md`. **Do not commit the raw datasets** (large/licensed) — add to
  `.gitignore`; commit only a small sampled/derived split + a fetch script.
- Clean: strip leading/trailing spaces in CIC column names; drop rows with `Inf`/`NaN`
  (CIC has `Flow Bytes/s` infinities); **dedupe** identical flows; drop identifier/leaky
  columns (`Flow ID`, source/dest IP, source/dest **Port**, `Timestamp`).
- Persist a reproducible, sampled working set (class-stratified) so the pipeline runs in
  minutes, not on the full multi-GB capture.

### 2.2 — Feature redefinition + label mapping
- Update `ai_module/features.py`: replace `FEATURES`/`RANGES` with the D2 schema; widen
  `RANGES` to the real data's observed min/max (compute, don't guess).
- New `ai_module/label_map.py`: the D4 mapping `dataset_label -> {LOW,MEDIUM,HIGH}`, plus a
  function to apply it. Single source of truth for label semantics.
- New `ai_module/prepare_dataset.py`: reads raw CIC/UNSW CSVs, selects the D2 feature
  columns (mapping each dataset's column names → our schema), applies the label map, writes
  a unified `dataset.csv` with the **same header** `generate_dataset.py` produced — so
  `train_model.py` needs no structural change.
- Retire `generate_dataset.py` (keep it behind a `--synthetic` flag for smoke tests only,
  clearly labeled "NOT for evaluation").

### 2.3 — Preprocessing & leakage-safe split
- **Split methodology matters more than the model.** Use a split that prevents leakage:
  - Preferred: **by capture day / source file** (train on some attack days, test on others).
  - At minimum: stratified train/val/test (e.g. 60/20/20) + **k-fold CV on train only**.
  - **Cross-dataset**: train CIC → test UNSW as a separate generalization report.
- Fit any scaler/encoder on **train only**; apply to val/test. No test data touches `fit`.
- **Class imbalance:** real IDS data is mostly benign. Use `class_weight="balanced"` (or
  controlled resampling on **train only**). Never resample the test set.

### 2.4 — Train + baselines
- Keep RandomForest as the candidate, but **justify it against a baseline**: a logistic
  regression and a trivial threshold rule. If RF barely beats thresholds, say so — that is
  itself an honest, publishable finding.
- Light hyperparameter search on the **validation** set only.
- Measure and report **inference latency** of `model.predict` on a single live-shaped
  vector (keeps the "<5 ms real-time tier" claim honest).

### 2.5 — Honest evaluation (the deliverable)
Report on the **held-out test set the model never saw**, plus the cross-dataset run:
- Full **confusion matrix** (counts + normalized).
- **Per-class** precision / recall / F1, **macro-F1**, and **balanced accuracy**.
- **False-positive rate** explicitly — a false HIGH triggers a needless rate-limit/failover,
  so FPR is the cost that matters for this control.
- **PR-AUC** (more informative than ROC-AUC under imbalance).
- Feature importances + a leakage sanity check (if one feature trivially separates, suspect
  leakage and investigate).
- Save artifacts: `models/metrics.json`, `models/confusion_matrix.png`,
  the persisted split (indices or seed), and a short **`MODEL_CARD.md`** (data, mapping,
  split, metrics, known limitations). Expect a realistic number well below 100%.

### 2.6 — Re-wire serving to the new schema
- `model_server.py` already imports `FEATURES`/`validate`/`clip` from `features.py`, so it
  follows automatically — just confirm `RANGES` reflect real data and the skew-clip still
  fires on out-of-range live input.
- Confirm the C → Python contract: the gateway/monitor must now emit the **D2** vector in
  order. Update the `snprintf` metric strings (`sctp_gateway.c`, `path_monitor.c`) to the
  new feature set (full computation is Task 2.7).

### 2.7 — (Bridge) C-side windowed features
- Add a small windowed accumulator in `metrics.c` (ring buffer of recent arrival
  timestamps + sizes) exposing `get_window_features(...)` that returns the D2 vector.
- Wire it into the metric string builders. This is the integration that closes the
  train/serve gap for real; if time-boxed, it can spill into the start of Phase 3 (where the
  two-laptop testbed lets you validate transfer on genuinely measured features).

### 2.8 — Tests
- Extend `ai_module/tests/test_features.py` for the new schema (arity, ranges, skew/clip).
- New `test_label_map.py`: every dataset label maps to exactly one severity; unknown label
  raises rather than silently defaulting.
- New `test_no_leakage.py`: assert the dropped-column list excludes IPs/ports/IDs/timestamps
  and that they are absent from the training frame.

---

## Sequencing (~1–2 weeks)

1. **2.1 → 2.2** data + schema/label redefinition (unblocks everything).
2. **2.3 → 2.4 → 2.5** the offline ML pipeline and the honest report (the core deliverable).
3. **2.6** re-wire serving (small, mechanical thanks to Phase 1).
4. **2.7** C windowing — start it; finishing/validating can lean into Phase 3.

## Acceptance criteria (Phase 2 is "done" when all hold)

- [ ] Training data is a **real** capture (CIC-IDS2017); `generate_dataset.py` is no longer
      on the evaluation path.
- [ ] Reported accuracy is **< 100%**, with a full confusion matrix + per-class P/R/F1 + FPR
      on a held-out test set, **plus** a cross-dataset (CIC→UNSW) result.
- [ ] Split is leakage-safe (no IP/port/ID/timestamp features; fit on train only); documented.
- [ ] `features.py` D2 schema is the single source of truth; `model_server.py` validates
      live vectors against it and clips skew.
- [ ] `MODEL_CARD.md` + `metrics.json` + confusion-matrix artifact committed.
- [ ] `python3 tests/test_features.py && python3 tests/test_label_map.py && python3 tests/test_no_leakage.py` pass.

## Explicitly OUT of scope for Phase 2

- Two-laptop testbed / measuring real failover → **Phase 3** (but 2.7 sets it up).
- DTLS-1.3-over-SCTP, ML-DSA authentication → **Phase 4**.
- Formal floor-invariant proof → **Phase 5**.
- LLM repositioning → independent track.

## Risks & honest notes

- **Feature gap is the main risk.** If the D2 intersection turns out too thin to separate
  classes well, that is a *finding*, not a failure — report it and discuss what extra
  online-measurable signal would help. Do not back-fill with fabricated features.
- **CIC-IDS2017 label/duplicate issues** are well documented; dedupe and cite the caveat so
  a reviewer sees you know.
- **Transfer is not guaranteed.** A model trained on CICFlowMeter flows may shift when fed
  the gateway's windowed features; Phase 3's real capture is where you prove (or honestly
  bound) that transfer. Flag this as a stated limitation rather than an assumed result.
