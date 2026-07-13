# Industrial/OT Post-Quantum Resilience Gateway — Build Plan

> **Authoritative spec for the final prototype.** Supersedes the framing choices left open in
> `USE_CASE_AND_UI_PLAN.md`. Locks in: (1) Industrial/OT as the use-case, (2) crypto variation via
> a *strict security-policy model* (never touched by network/ML/battery), (3) an ML
> network-condition classifier whose output drives *only* the SCTP transport policy. Builds on
> `PROJECT_REDESIGN.md` (R1–R4) and `FINAL_PROTOTYPE.md`.

---

## 0. The use-case (fixed)

**A remote industrial site's legacy TCP devices communicate with a central control center through
the secure gateway.** The gateway is transparent to the legacy device (no changes to it) and:

- converts **TCP → SCTP** at the site edge,
- establishes keys with **ML-KEM** (quantum-resistant KEM), authenticated with **ML-DSA**,
- derives per-session keys with **HKDF-SHA-256**,
- encrypts payload with **AES-256-GCM** (authenticated encryption),
- uses an **ML network-condition classifier** to make **SCTP resilience** decisions.

```
  REMOTE INDUSTRIAL SITE                              CONTROL CENTER
 ┌──────────────────────┐         two links        ┌────────────────────┐
 │ legacy PLC / RTU /    │        (when real        │  control-center    │
 │ sensor  (plain TCP) ──┼─►[ OT GATEWAY ]══ path-1 ═══════►│  receiver (SCTP)  │
 │  cannot be modified   │        🔒        ╲ path-2 ═══════►│                    │
 └──────────────────────┘   PQC + AES-GCM   (backup)        └────────────────────┘
```

Why this justifies the whole stack: OT data has a **decades-long confidentiality lifetime**
(harvest-now-decrypt-later is real), the endpoint **cannot be touched or re-certified** (so a
transparent gateway is the only option), and control links have **availability requirements** (so
SCTP multihoming + ML-driven resilience is warranted).

---

## 1. Two strictly-separated pipelines (the core design rule)

These two decision paths **never cross**. This separation is the project's central contribution and
must be enforced in code, not just described.

```
  PIPELINE 1 — SECURITY (confidentiality/integrity)      PIPELINE 2 — RESILIENCE (availability)
  ───────────────────────────────────────────────       ─────────────────────────────────────────
  Data classification                                    Network metrics
        │  (policy attribute of the channel)                   │ (latency, jitter, loss,
        ▼                                                       │  throughput, inter-arrival, …)
  Security Policy Engine                                        ▼
        │                                                 ML Network Classifier
        ▼                                                       │
  ML-KEM-768  ── immutable minimum floor                        ▼   one of:
        or                                                STABLE / CONGESTED / DEGRADED /
  ML-KEM-1024 ── ONLY for critical / high-sensitivity     UNSTABLE / POSSIBLE_PATH_FAILURE
                 data classification                            │
                                                                ▼
                                                         SCTP Transport Policy Engine
                                                                │
                                                                ▼  one of:
                                                         normal / congestion response /
                                                         failover readiness / backup-path
                                                         preference / actual failover
                                                         (only when real multihoming exists)
```

### 1.1 Hard invariants (must be true in code, testable)

- **INV-1 — Immutable floor.** The KEM is **never** below ML-KEM-768. No input can lower it.
- **INV-2 — Crypto is policy-only.** The KEM level is determined **exclusively** by the data
  classification via the Security Policy Engine. **Network conditions, latency, jitter, packet
  loss, throughput, battery state, and every ML network-state prediction are forbidden from
  lowering *or directly determining* the cryptographic level.**
- **INV-3 — Up-only, and only for critical data.** ML-KEM-1024 may be selected **only** for data
  explicitly classified high-sensitivity/critical. Absent that classification, the level is the
  768 floor.
- **INV-4 — ML output is transport-only.** The network classifier's output feeds **only** the SCTP
  Transport Policy Engine. It has **no path** to the crypto selector.

These are enforced by keeping the two engines in **separate modules with no data dependency**
between the classifier and `crypto_policy`, and by a unit test that tries to breach each invariant
and confirms it cannot (see §6).

---

## 2. Pipeline 1 — Security Policy Engine & crypto variation

### 2.1 Model

```
  DataClassification ∈ { ROUTINE, SENSITIVE, CRITICAL }     ← policy input, NOT ML, NOT network
        │
        ▼  Security Policy Engine (pure function, no network/ML/battery inputs)
  select_kem(classification):
        CRITICAL          → ML-KEM-1024
        ROUTINE|SENSITIVE → ML-KEM-768   (the floor)
        always            → max(result, ML-KEM-768)   # floor can only be raised, never lowered
```

- `ROUTINE` and `SENSITIVE` both map to the **768 floor**; only `CRITICAL` (explicit
  high-sensitivity) raises to **1024**. (If you want SENSITIVE to also raise, that's a one-line
  policy change — but the default keeps 1024 reserved for genuinely critical data.)
- **Battery/high-assurance/threat inputs are removed from the crypto decision entirely.** The
  existing `SecurityPosture{high_assurance, battery_pressure}` in `crypto_policy` is replaced by a
  single `DataClassification`. Battery pressure, if kept at all, may influence **transport**
  behaviour only — never crypto.

### 2.2 Code changes (`gateway/crypto_policy.h/.c`)

- Keep `#define CRYPTO_FLOOR ML_KEM_768`.
- Replace `SecurityPosture` with:
  ```c
  typedef enum { CLASS_ROUTINE, CLASS_SENSITIVE, CLASS_CRITICAL } DataClassification;
  MlKemLevel select_kem(DataClassification c);   /* CRITICAL→1024 else 768; never < floor */
  ```
- `select_kem()` takes **only** a `DataClassification` — it is *structurally impossible* for it to
  see a network metric or ML verdict (INV-2 enforced by the type signature).
- The classification is read from a **policy source**, not the detector: a per-session env/config
  (`GW_DATA_CLASS=routine|sensitive|critical`) or a static per-device policy map. The demo control
  writes this file directly (a human/policy act), visibly separate from the ML controls.
- Rename `KyberLevel`→`MlKemLevel`, `KYBER_768`→`ML_KEM_768`, etc. (standardized FIPS 203 names).

### 2.3 Authentication (R1, finish it)

Complete the in-progress ML-DSA-65 handshake authentication (`pqc_auth.c/.h`, `pqc_keygen.c`,
transcript sign/verify in `pqc_handshake.c`). This is orthogonal to the KEM-level policy but part
of Pipeline 1's "quantum-safe channel." Payoff: honest authentication claim + a "MitM/tamper
blocked" demo. Until it lands, keep claiming **confidentiality only**, not MitM resistance.

---

## 3. Pipeline 2 — ML Network Classifier & SCTP Transport Policy

### 3.1 The classifier (new model, R2)

- **Input:** network metrics already available in the gateway's sliding window
  (`gateway/metrics.c` → `get_window_features`): latency/RTT, jitter, packet loss, throughput,
  inter-arrival, bandwidth utilization.
- **Output — one network-condition state:**
  `STABLE / CONGESTED / DEGRADED / UNSTABLE / POSSIBLE_PATH_FAILURE`.
- **Honesty:** train on an **overlapping, non-separable** synthetic-or-real dataset (states are
  *supposed* to blend into each other), report a real confusion matrix + macro-F1, and compare
  against a **threshold baseline** so the model earns its place. This is a *different* model from
  the CIC threat detector (`rf_model.pkl`) — keep them separate:
  - **ML-A (this one):** network condition → transport policy.
  - **ML-B (existing CIC detector):** threat/anomaly → security *response* (rate-limit/alert/log),
    also an availability action — **still never crypto.**
- Artifacts: `ai_module/models/netcond_model.pkl`, `netcond_metrics.json`, confusion matrix PNG.
- Serve it alongside the threat model (extend `model_server.py` or a second endpoint); the gateway
  queries it over the Unix socket the same way it queries ML-B.

### 3.2 SCTP Transport Policy Engine (`gateway/transport_policy.h/.c`, extend)

Map each network-condition state to a **transport recommendation**:

| Network state | Transport policy | Real action available now? |
|---|---|---|
| `STABLE` | normal operation | ✅ |
| `CONGESTED` | congestion response (rate-limit / backpressure / pace sends) | ✅ (rate-limit exists) |
| `DEGRADED` | raise failover readiness; increase path monitoring frequency | ✅ (recommendation + monitor tuning) |
| `UNSTABLE` | prefer backup path; pre-warm secondary | ⚠️ recommendation only until real multihoming |
| `POSSIBLE_PATH_FAILURE` | initiate failover | ⚠️ recommendation only until real multihoming |

### 3.3 Honesty guardrail — recommendation vs. action (CRITICAL)

> **Do NOT claim actual adaptive path switching until SCTP multihoming with multiple *real* paths
> is implemented.** Loopback `127.0.0.1/127.0.0.2` and single-path setups do **not** count.

Two clearly-labeled operating levels, surfaced honestly in the UI and narration:

1. **RECOMMENDATION MODE (now).** The classifier + transport policy emit a **recommendation**
   ("would prefer backup path", "would fail over") and log/visualize it. No claim of live path
   switching. This is fully demoable today on a single host.
2. **ENFORCEMENT MODE (after real multihoming).** Once two **real** paths exist (two-host testbed,
   or netns/veth with independent links torn down for real), wire `POSSIBLE_PATH_FAILURE`/`UNSTABLE`
   to the actual `multihoming.c`/`path_monitor.c` failover and **demonstrate continuity** when one
   uplink degrades or fails (mean ± 95% CI over repeated real link cuts, per `FINAL_PROTOTYPE.md`
   Phase 3).

The UI must **label which mode is active** so an evaluator is never misled. Every recommendation
tile carries a "recommendation — not enforced (single-path)" badge until enforcement mode is on.

---

## 4. Data flow — one OT session's lifecycle

1. Legacy PLC/RTU opens a plain **TCP** connection to the gateway at the site edge.
2. Gateway determines the session's **DataClassification** from policy (device/port/config —
   *not* from traffic). Security Policy Engine → `select_kem()` → ML-KEM-768 (or 1024 if CRITICAL).
3. Handshake: **X25519 + ML-KEM** (hybrid, quantum-safe confidentiality), **ML-DSA-65** transcript
   signatures (authentication), **HKDF-SHA-256** → per-session **AES-256-GCM** key.
4. Gateway relays TCP payload as framed **AES-256-GCM over SCTP** to the control-center receiver.
5. In parallel, the sliding-window metrics feed **ML-A** (network condition) and **ML-B** (threat):
   - ML-A → SCTP Transport Policy (normal / congestion response / failover readiness /
     backup-path preference / — later — real failover).
   - ML-B → security *response* (rate-limit / alert / quarantine). **Neither touches the KEM.**
6. Metrics + decision records POST to the observability stack → SQLite → dashboard.

---

## 5. UI — one OT operations console

Reframe the six disconnected Streamlit pages into a **control-center console** for the OT link,
laid out to make the two-pipeline separation *visible* (per `USE_CASE_AND_UI_PLAN.md` §4):

```
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ OT POST-QUANTUM RESILIENCE GATEWAY · remote site ⇄ control center   ● LIVE     │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ HERO: link topology — PLC ─►[GW]══path-1(active)══►control center              │
 │                                  ╲ path-2(backup) [recommendation-mode badge]  │
 │        auth ML-DSA-65 ✔   KEM ML-KEM-768 🔒   AES-256-GCM   HKDF-SHA-256        │
 ├───────────────────────────────────────┬────────────────────────────────────────┤
 │ SECURITY POLICY (Pipeline 1)          │ RESILIENCE (Pipeline 2)                │
 │ Data classification: [ROUTINE▸CRIT]   │ ML-A network state: STABLE/CONGESTED/… │
 │ Resulting KEM: ML-KEM-768             │ Transport policy:  normal / prefer-bkp │
 │ ▓▓▓ floor = ML-KEM-768 (immovable) ▓▓ │  (badge: recommendation, not enforced) │
 │ battery=100% → still 768 ✅            │ ML-B threat: LOW → RATE_LIMIT/ALERT    │
 │ threat=HIGH → KEM UNCHANGED ✅         │ path events / failover log             │
 ├───────────────────────────────────────┴────────────────────────────────────────┤
 │ EVIDENCE: [Run PQC self-test]  KEM≈0.05ms/handshake  ML-A F1=…  ML-B F1=0.87    │
 └──────────────────────────────────────────────────────────────────────────────┘
```

- **Left column = Pipeline 1:** the Data Classification selector (ROUTINE→SENSITIVE→CRITICAL) is
  the *only* thing that moves the KEM, and only upward from the immovable 768 floor line. Battery
  and threat controls sit here only to *prove they do nothing* to crypto.
- **Right column = Pipeline 2:** ML-A network state + transport policy (with the honest
  recommendation/enforcement badge), and ML-B threat response. Clearly walled off from the left.
- Consolidate pages 6→4 (Command Console, Scenario Control, PQC & Trust, Evidence); **delete** the
  parked LLM `3_analyst_chat` and old `4_threat_narrative` framing; apply a dark ops-console theme
  and an SVG topology hero.

---

## 6. Tests that enforce the invariants

- `test_crypto_policy` — `select_kem(ROUTINE|SENSITIVE)=768`, `select_kem(CRITICAL)=1024`, and the
  result is **always ≥ 768**. Type signature makes network/ML inputs impossible (compile-time INV-2).
- `test_no_downgrade` — attempt to force sub-floor via every removed lever (battery, spoofed
  verdict); confirm it stays ≥ 768 (INV-1).
- `test_pipeline_separation` — the network classifier module has **no symbol dependency** on
  `crypto_policy` and vice-versa (INV-4); a grep/link test.
- `test_transport_policy` — each of the 5 network states maps to the expected transport
  recommendation.
- `pqc_selftest` — real ML-KEM-768 (already passing); add ML-DSA sign/verify + tamper-abort.

---

## 7. Build order

1. **R1 — finish ML-DSA authentication** (in progress): transcript sign/verify in
   `pqc_handshake.c`, `pqc_keygen`, Makefile targets, selftest + tamper-abort demo.
2. **Security Policy Engine refactor** (§2): replace `SecurityPosture` with `DataClassification`;
   rename to FIPS 203/204 names; wire `GW_DATA_CLASS`; add `test_crypto_policy`/`test_no_downgrade`.
3. **ML-A network classifier** (§3.1, R2): dataset (overlapping states), train, evaluate vs
   threshold baseline, serve alongside ML-B.
4. **SCTP Transport Policy** (§3.2–3.3, R3): map states → recommendations; **recommendation mode**
   only; badge everything honestly.
5. **UI console** (§5, R4): consolidate pages, two-pipeline layout, classification selector, theme,
   topology hero; delete dead LLM pages.
6. **Real multihoming → enforcement mode** (Phase 3, when a real two-path testbed exists): connect
   `POSSIBLE_PATH_FAILURE`/`UNSTABLE` to actual failover; demonstrate continuity under real link
   loss with mean ± 95% CI. **Only then** claim adaptive path switching.

Each step ends in something visible/testable; nothing is left mid-refactor.

---

## 8. Claims discipline (what you may and may not say)

| May claim now | May NOT claim until… |
|---|---|
| Quantum-safe **confidentiality** (hybrid X25519+ML-KEM, real liboqs, self-test) | — |
| **Authenticated** handshake (anti-MitM) | …R1 (ML-DSA) lands |
| Crypto strength is **policy-driven, floored, up-only**; ML/battery/network never lower it | — (enforced by design) |
| ML-A classifies network condition; produces **transport recommendations** | **actual adaptive path switching** — until real multihoming with multiple real paths |
| ML-B detects threats honestly (macro-F1 0.87, real CIC data) | 100% / separable-by-construction numbers (never) |
| Failover **mechanism** exists (SCTP multihoming code) | real failover *timings* — until a real two-path testbed |
```
