# The Final Prototype — End Goal, Architecture & Expected Results

> What this project becomes once all phases land. This is the target the phase plans build
> toward; read it to understand *why* each phase exists. It supersedes the original
> "AI picks the Kyber strength" framing, which was a category error (see `IMPROVEMENT_PLAN.md`).

---

## 1. One sentence

**A transparent, transport-hardening gateway that re-originates legacy TCP traffic as an
authenticated, hybrid post-quantum DTLS-1.3-over-SCTP association with autonomous
multihoming failover — governed by a controller whose cryptographic strength has a
*provable security floor* that a battery-drain / downgrade adversary cannot push below, and
whose ML network-anomaly detector steers *transport resilience* rather than crypto strength.**

## 2. The problem it solves

Legacy clients speak plain TCP with classical (quantum-breakable) crypto or none at all.
Three real gaps, none covered together by existing products:

- **Harvest-now-decrypt-later (HNDL):** today's recorded traffic is decryptable by a future
  quantum computer. Commercial PQC proxies (IBM, Palo Alto, Zscaler) exist — but all
  terminate to **TLS over TCP**. None upgrade into a **multihomed SCTP association**.
- **Availability under attack / link failure:** a single-path TLS/TCP session dies when its
  path dies. SCTP multihoming survives it — but nobody drives that failover from live threat
  state.
- **Adaptive-crypto is a downgrade hole:** "weaken crypto to save power" lets an attacker who
  drains/spoofs the battery force the weakest mode. The fix is an asymmetric **floor**.

The gap this fills — *transport-upgrading + provable floor + threat-driven resilience* — is
unclaimed and defensible.

## 3. Full architecture (end state)

```
                         LAPTOP A — GATEWAY (C)                              LAPTOP B — RECEIVER (C)
 ┌──────────────────────────────────────────────────────────────┐     ┌────────────────────────────────┐
 │                                                                │     │                                │
 │  legacy TCP client ─► accept()                                 │     │  sctp_receiver                 │
 │        │                                                       │     │   • binds 2 local IPs          │
 │        ▼  recv() ──────────► WINDOW ACCUMULATOR (metrics.c)    │     │   • DTLS1.3/hybrid handshake   │
 │        │                      ring buffer (ts_us,size)         │     │   • ML-DSA auth (Phase 4)      │
 │        │                          │ get_window_features[µs]    │     │   • AES-256-GCM decrypt        │
 │        │                          ▼                            │PATH1│                                │
 │        │      Unix sock ─► model_server (RandomForest)         │═eth═►│                                │
 │        │                          │  LOW / MEDIUM / HIGH       │     │                                │
 │        │            ┌─────────────┴─────────────┐             │PATH2│  (both paths kept ACTIVE by    │
 │        │            ▼ TRANSPORT axis            ▼ CRYPTO axis  │═wifi═►│   SCTP heartbeat; autonomous  │
 │        │   transport_policy:              crypto_policy:       │     │   failover on link cut)        │
 │        │   • failover (path down)         • ML-KEM-768 FLOOR   │     └────────────────────────────────┘
 │        │   • rate-limit (flood)           • never weakened     │
 │        │   • rekey cadence                • ↑only (high-assur) │              ▲
 │        ▼                                  • floor enforced     │              │ severing PATH1
 │   hybrid handshake ─► HKDF ─► AES-256-GCM ─► SCTP send ────────┼──────────────┘  triggers failover
 │        │                                                       │
 │        └── metrics HTTP POST ─────────────────────────────────┼───► receiver.py ─► SQLite
 └──────────────────────────────────────────────────────────────┘                        │
                                                                                           ▼
                                              Streamlit dashboard  +  grounded LLM analyst (explains,
                                              (live monitor, sim,      NEVER decides; answers only from
                                               PQC visualizer)         recorded events)
```

### The two decoupled control axes (the heart of the design)

```
   ML detector verdict (LOW/MEDIUM/HIGH)                 device/threat posture
              │                                                   │
              ▼                                                   ▼
   ┌────────────────────────┐                       ┌──────────────────────────────┐
   │  TRANSPORT axis         │                       │  CRYPTO axis                  │
   │  failover / rate-limit  │   ✗ NEVER crosses ✗   │  ML-KEM-768 floor (fixed)     │
   │  rekey cadence / alert  │◄─────────────────────►│  high-assurance may RAISE     │
   │                         │                       │  battery may NOT lower        │
   └────────────────────────┘                       └──────────────────────────────┘
     availability & resilience                         confidentiality & integrity
```

The single most important property: **a network anomaly can never change cryptographic
strength, and a battery signal can never breach the floor.** Threat may only *escalate*
crypto; battery may only request cheaper *transport/operational* behavior.

## 4. How it works — one request's lifecycle

1. Legacy TCP client connects; the gateway accepts and begins relaying.
2. Each received packet feeds a sliding-window accumulator → 6 flow-statistics features (µs).
3. The RF detector returns LOW/MEDIUM/HIGH — a **network-anomaly** verdict.
4. `crypto_policy.select_kem()` picks the KEM: **always ≥ ML-KEM-768 floor**, independent of
   the verdict; the DTLS-1.3/hybrid handshake authenticates (ML-DSA) and derives an
   AES-256-GCM key via HKDF over `X25519 ‖ ML-KEM` secrets.
5. `transport_policy` maps the verdict to a transport action: primary down → **failover**;
   flood → **rate-limit + alert**; threat clears → **restore primary**; plus rekey cadence.
6. Payload is encrypted and sent over the multihomed SCTP association; a background monitor
   keeps both paths healthy and fails over autonomously if one dies.
7. Session metrics are POSTed to the observability stack; the LLM analyst can *explain* any
   decision from the recorded event log (it never makes one).

## 5. Feature list (what the finished prototype does)

- **Transparent protocol upgrade:** plain TCP in → authenticated hybrid-PQC SCTP out, no
  client changes.
- **Hybrid post-quantum key exchange:** X25519 + ML-KEM (FIPS 203), HKDF-SHA256, AES-256-GCM.
- **Authenticated handshake:** ML-DSA (FIPS 204) signatures over the transcript / DTLS-1.3
  (Phase 4) — real MitM resistance, not asserted.
- **Provable security floor:** downgrade-resistant crypto policy; battery/load can't weaken it.
- **SCTP multihoming + autonomous failover** across two real paths, sub-second, lossless-ish.
- **ML network-anomaly detector** (RandomForest) trained/validated on real data, driving
  transport resilience — with honest, reported accuracy (not 100%).
- **Adaptive transport response:** failover, rate-limiting, rekey cadence keyed to threat.
- **Full observability:** Streamlit live dashboard, traffic simulator, PQC handshake
  visualizer, and a **grounded** LLM security analyst.

## 6. Security & correctness properties (what will be *true*, not asserted)

| Property | Guaranteed by | Verified by |
|---|---|---|
| HNDL resistance | hybrid X25519+ML-KEM; key secure if *either* holds | handshake tests; correct combiner framing |
| No crypto downgrade below floor | `crypto_policy` invariant; responder rejects sub-floor | `test_floor_invariant` (passing) + Phase 5 Tamarin/ProVerif proof |
| Battery can't weaken crypto | asymmetric policy (battery→transport only) | floor test with max battery pressure (passing) |
| Authenticated key exchange (anti-MitM) | ML-DSA / DTLS-1.3 transcript binding | Phase 4 |
| Availability under path loss | SCTP multihoming + monitor | Phase 3 real link-cut, mean ± 95% CI |
| Threat detection is honest | real dataset, leakage-safe split | Phase 2 done: macro-F1 0.87 in-dist / 0.58 cross-variant |

## 7. Expected results (the evaluation we will report — honestly)

Some already measured (Phase 2); the rest are Phase 3–5 targets, reported with CIs and real
baselines. **No fabricated numbers, no 100%, no strawman comparison tables.**

| Result | Status | Value / target |
|---|---|---|
| Detector macro-F1 (in-distribution) | ✅ measured | **0.874** (accuracy 98.3%, FPR 1.8%) |
| Detector macro-F1 (cross-attack-variant) | ✅ measured | **0.575** — HIGH transfers, MEDIUM doesn't (honest gap) |
| RF vs baselines (macro-F1) | ✅ measured | 0.87/0.58 vs majority 0.30, logistic 0.48 |
| Single-vector inference latency | ✅ measured | ~11.6 ms (⚠️ corrects the old "<5 ms" claim) |
| Live transfer on gateway features | Phase 3 | measured on real capture; retrain if weak |
| Real failover time / loss | Phase 3 | mean ± 95% CI over ≥20 physical link cuts |
| Handshake latency decomposition | Phase 3 | KEM shown to be a *small* fraction (corrects "32%") |
| Crypto overhead vs no-crypto / classical | Phase 3 | interpretable overhead with real baselines |
| Floor-invariant / downgrade resistance | Phase 5 | mechanized proof (Tamarin/ProVerif) |
| CPU energy per handshake (optional) | Phase 3 | RAPL proxy (host CPU, NOT battery) |

## 8. Why it's novel / defensible

- **Transport context nobody else occupies:** legacy → authenticated hybrid-PQC **SCTP**
  association with multihoming, not TLS-over-TCP.
- **The floor invariant** as a named, *provable* defense against the battery-drain/downgrade
  adversary — an actual theorem, not a feature bullet.
- **Correct separation of concerns:** ML drives *availability*; crypto strength is floored and
  policy-driven — fixing the original category error and the HNDL own-goal.
- **Honesty as a feature:** real dataset, leakage-safe evaluation, real testbed, corrected
  claims — the opposite of the desk-reject risks flagged in review.

## 9. How the phases build to it

```
 Phase 1 ✅  Coherence      decouple crypto⇄detector; ML-KEM-768 floor + downgrade test;
                            transport_policy; shared feature schema (train/serve skew fixed)
 Phase 2 ✅  Honest ML      real CIC-IDS2017; leakage-safe split; confusion matrix, FPR,
                            PR-AUC; the "100%" is gone; MODEL_CARD
 Phase 3 ▶   Real testbed   two laptops, two paths; C windowed features (live gap closed);
                            real failover + latency decomposition; transfer-validate/retrain
 Phase 4 ○   Real security  DTLS-1.3-over-SCTP + ML-DSA auth → genuine MitM/downgrade resistance
 Phase 5 ○   Formal proof   mechanize the floor invariant (Tamarin/ProVerif); optional RAPL energy
                            └────────────────────────►  publishable prototype
```

## 10. Non-goals & honest limitations (stated, not hidden)

- **Not a constrained-device deployment:** no MCU/power monitor on hand, so **no IoT
  battery-life claims** — CPU-energy (RAPL) proxy only, clearly scoped.
- **Not line-rate / production-hardened:** it is a research prototype; the AI Unix-socket
  round-trip, not the crypto, dominates per-session latency.
- **MEDIUM-severity detection is weak** and doesn't generalize across attack types — reported
  as a low-confidence advisory, not a strong claim.
- **Single dataset** (CIC-IDS2017) + one real capture; cross-dataset (UNSW-NB15) is future work.
- **Venue calibration:** honest capstone / IEEE Access after Phase 3; mid-tier conference after
  Phase 4; journal (TNSM/TIFS/TDSC) after the Phase 5 proof — not IoT-J (needs device energy).
```
