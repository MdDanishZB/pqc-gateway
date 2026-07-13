# Implementation Plan — Features, Visualization & Validation

> Use-case set aside; we just call the source a **legacy device**. This plan is about *building*
> the features below, **surfacing each in the UI + logs**, and **validating** each one.
>
> ```
> Legacy TCP Device
>         ↓
> Intelligent Secure Gateway
>   ├── Data sensitivity ──→ Crypto policy (ML-KEM-768 floor · ML-KEM-1024 for critical)
>   ├── Network metrics ───→ ML classifier ──→ SCTP adaptive networking
>   └── ML-KEM → HKDF → AES-256-GCM ──→ Secure SCTP Tunnel ──→ Control Center
> ```
>
> Each feature below has four parts: **Build · Log · UI · Validate.** Nothing is "done" until all
> four exist. Grounded in the real files in this repo.

---

## Feature 1 — Data-sensitivity → Crypto policy

**Goal:** the KEM level is chosen **only** by data sensitivity. ML-KEM-768 is the immutable floor;
ML-KEM-1024 is used **only** for data classified critical. Network/ML/battery never affect it.

### Build (`gateway/crypto_policy.h/.c`, `sctp_gateway.c`)
- Replace `SecurityPosture{high_assurance, battery_pressure}` with:
  ```c
  typedef enum { CLASS_ROUTINE, CLASS_SENSITIVE, CLASS_CRITICAL } DataClassification;
  MlKemLevel select_kem(DataClassification c);   /* CRITICAL→1024; else 768; never < floor */
  ```
- `select_kem()` takes **only** a `DataClassification` — by its type signature it *cannot* see a
  network metric or ML verdict (this is the invariant, enforced at compile time).
- Read the classification from a **policy source**, not traffic: `GW_DATA_CLASS=routine|sensitive|critical`
  (default `routine`), read per session in `sctp_gateway.c` (same pattern as the old posture file).
- Rename to FIPS names: `KyberLevel→MlKemLevel`, `KYBER_768→ML_KEM_768`, `KYBER_1024→ML_KEM_1024`.
- Keep `#define CRYPTO_FLOOR ML_KEM_768`.

### Log (gateway stdout → `.demo_logs/gateway.log`)
```
[Policy] data-class=CRITICAL  → ML-KEM-1024   (floor=ML-KEM-768)
[Policy] data-class=ROUTINE   → ML-KEM-768    (floor held)
[Policy] battery/threat inputs = IGNORED for crypto (policy-only)
```

### UI (Command Console — Security column)
- **Data classification selector** ROUTINE ▸ SENSITIVE ▸ CRITICAL (writes `GW_DATA_CLASS` file).
- **Resulting KEM** tile + an **immovable floor line** drawn under ML-KEM-768.
- Keep the **battery** and **threat** controls *in this column only to prove they do nothing*: move
  them, the KEM tile does not budge.

### Validate (`gateway/tests/test_crypto_policy.c`)
- `select_kem(ROUTINE)==768`, `select_kem(SENSITIVE)==768`, `select_kem(CRITICAL)==1024`.
- result always `>= ML_KEM_768`.
- Live: set `GW_DATA_CLASS=critical`, send traffic, grep the `[Policy] … ML-KEM-1024` line;
  set battery=100 → KEM line **still** driven by class, not battery.

---

## Feature 2 — Network metrics → ML classifier → SCTP adaptive networking

**Goal:** an ML model classifies live network condition into
`STABLE / CONGESTED / DEGRADED / UNSTABLE / POSSIBLE_PATH_FAILURE`, and that drives **only** the
SCTP transport policy. **Recommendation mode** until real multihoming exists (do not claim live path
switching yet).

### Build — the model (`ai_module/`)
- New dataset `netcond_dataset.py`: synthesize the 5 states from **overlapping** metric ranges
  (states must blend, not be separable) using the existing feature schema in `features.py`
  (latency, jitter, loss, throughput, inter-arrival, bandwidth_util).
- `train_netcond.py` → `models/netcond_model.pkl` + `netcond_label_encoder.pkl`; report confusion
  matrix + macro-F1 + a **threshold baseline** comparison → `models/netcond_metrics.json`,
  `models/netcond_confusion.png`. This is a **separate** model from the CIC threat detector.
- Serve it: extend `model_server.py` with a second reply (or a second socket verb) returning the
  network-condition label, queried the same way as the threat verdict.

### Build — the transport policy (`gateway/transport_policy.h/.c`)
- Extend `decide_transport()` (or add `decide_netpolicy()`) mapping state → recommendation:
  | State | Transport recommendation |
  |---|---|
  | STABLE | normal |
  | CONGESTED | congestion response (rate-limit / pace) |
  | DEGRADED | raise failover readiness; faster monitor |
  | UNSTABLE | prefer backup path (recommendation) |
  | POSSIBLE_PATH_FAILURE | failover (recommendation) |
- **Recommendation vs enforcement flag** `GW_TRANSPORT_ENFORCE` (default 0). At 0, the gateway
  **logs/emits the recommendation only** and does not touch paths. At 1 (after real multihoming),
  wire UNSTABLE/POSSIBLE_PATH_FAILURE to `multihoming.c`/`path_monitor.c`.

### Log
```
[NetML] state=CONGESTED (conf 0.78)  → transport: CONGESTION_RESPONSE  [recommendation]
[NetML] state=POSSIBLE_PATH_FAILURE  → transport: FAILOVER  [recommendation — single-path, not enforced]
```

### UI (Command Console — Resilience column)
- **Network-state tile** (STABLE…POSSIBLE_PATH_FAILURE) with confidence.
- **Transport-policy tile** with a hard **"recommendation — not enforced (single-path)"** badge
  while `GW_TRANSPORT_ENFORCE=0`.
- A small **state timeline** (last N classifications) so the evaluator sees it react to the
  simulator's congestion/degradation sliders.

### Validate
- `ai_module/tests/test_netcond.py`: model loads, predicts all 5 labels, macro-F1 in
  `netcond_metrics.json` is a real sub-100% number, beats the threshold baseline.
- `gateway/tests/test_transport_policy.c`: each of the 5 states maps to the expected recommendation.
- Live: drive congestion via the simulator → watch state flip STABLE→CONGESTED→DEGRADED in the log
  and the UI timeline; confirm crypto tile **unchanged** throughout (cross-pipeline check).

---

## Feature 3 — Secure SCTP tunnel: ML-KEM → HKDF → AES-256-GCM (+ ML-DSA auth)

**Goal:** finish the quantum-safe channel — hybrid ML-KEM confidentiality, ML-DSA authentication,
HKDF-SHA-256 per-session keys, AES-256-GCM over the SCTP association.

### Build
- **Confidentiality (exists, keep):** hybrid X25519+ML-KEM → HKDF-SHA-256 → AES-256-GCM streaming
  relay; `crypto_layer.c` already refuses to run without the PQC-derived key.
- **Authentication (finish R1):** transcript sign/verify with **ML-DSA-65** in `pqc_handshake.c`
  using the already-written `pqc_auth.c/.h`, `pqc_keygen.c`. Verify failure → abort the handshake.
- Add Makefile targets for `pqc_auth.o`, `pqc_keygen`, and link into gateway + sctp_receiver.

### Log
```
[PQC] hybrid: X25519(32B) + ML-KEM-768 pk(1184B) / ct(1088B)
[PQC] auth: ML-DSA-65 — peer signature VERIFIED (identity pinned)
[PQC] auth: ML-DSA-65 — signature INVALID → handshake ABORTED
[Bench] handshake=207.3ms  ML-KEM=0.05ms  ML-DSA=1.1ms  net/setup=206ms
```

### UI (PQC & Trust page)
- **Handshake decomposition** bar (KEM/DSA are a tiny sliver vs network wait) from `[Bench]`.
- **Size fingerprint** (1184B pk / 1088B ct = FIPS 203) + **auth ✔** pill.
- **"Run self-test"** button → `pqc_selftest` output inline.
- **MitM/tamper micro-demo:** corrupt a pinned key → show the handshake **aborts** in the log.

### Validate
- `pqc_selftest` (real ML-KEM-768, sizes, encaps/decaps match, tamper changes secret) — passing.
- Extend it (or add `pqc_auth_selftest`): ML-DSA sign→verify OK; tampered transcript/sig → verify
  fails; wrong pinned key → handshake aborts.
- Live: receiver prints real plaintext (proves both ends derived the identical key).

---

## Cross-cutting A — The UI console (visualize everything)

Consolidate the 6 stale Streamlit pages into **4**, laid out so the two pipelines are visibly
walled off (Security column vs Resilience column). Delete parked LLM pages
(`3_analyst_chat`, old `4_threat_narrative`). Apply a dark ops-console theme
(`.streamlit/config.toml`) + a shared `ui.py` component set + an SVG topology hero
(legacy device → gateway → SCTP → control center).

| Page | Shows |
|---|---|
| **1 · Command Console** | topology hero + Security column (Feature 1) + Resilience column (Feature 2) |
| **2 · Scenario Control** | traffic/attack + congestion sliders + data-classification selector |
| **3 · PQC & Trust** | Feature 3 visuals + self-test + tamper demo |
| **4 · Evidence** | both models' confusion matrices/F1, `[Bench]` numbers, event log, claims table |

---

## Cross-cutting B — Logs (single source of truth)

All decisions emit a tagged line to `.demo_logs/gateway.log`, so the whole story is visible in a
terminal even if the browser fails:
- `[Policy]` crypto decisions · `[NetML]` network state + transport recommendation ·
  `[PQC]`/`[Bench]` handshake + timing · `[Threat]` ML-B verdict + response.
- Use `stdbuf -o0` / line-buffering so logs are readable live (known buffering gotcha).

---

## Cross-cutting C — Validation matrix (what proves each feature)

| Feature | Automated test | Live proof | Honesty note |
|---|---|---|---|
| Crypto policy | `test_crypto_policy`, `test_no_downgrade` | `[Policy]` line; battery/threat don't move KEM | 1024 only for `CLASS_CRITICAL` |
| Net classifier | `test_netcond.py` (F1, baseline) | state flips with congestion sliders; UI timeline | real sub-100% F1 |
| SCTP adaptive | `test_transport_policy.c` | `[NetML] … [recommendation]` line | **recommendation only** until real multihoming |
| PQC tunnel | `pqc_selftest`, auth selftest | receiver decrypts real plaintext; tamper aborts | confidentiality now; auth after R1 |
| Separation | link/grep: classifier has no dep on `crypto_policy` | crypto tile unchanged during attack/congestion | the core invariant |

---

## Build order

1. **Feature 3 auth (finish R1)** — ML-DSA sign/verify + keygen + Makefile + selftest/tamper.
2. **Feature 1** — `DataClassification` refactor, FIPS renames, `GW_DATA_CLASS`, crypto tests.
3. **Feature 2 model** — netcond dataset + train + eval + serve.
4. **Feature 2 transport** — policy mapping + recommendation-mode flag + tests.
5. **Cross-cutting A** — the UI console + theme + topology + page consolidation.
6. **(Later)** enforcement mode once real multihoming/two-path testbed exists.

Each step ends in Build+Log+UI+Validate all present before moving on.
```
