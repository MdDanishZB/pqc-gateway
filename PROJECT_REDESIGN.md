# Project Redesign — Making ML, PQC, and SCTP Each Meaningful

> Your instinct is correct. The project felt pointless because it **forced three unrelated
> technologies through one control signal** ("AI picks the crypto strength"). That coupling was
> never real. The fix is to stop forcing them together and instead let **each of the three do
> the job it's actually good at**, integrated in one gateway. This document refines **ML** and
> **PQC** into independently-defensible, individually-visible contributions.

---

## 1. Why it felt pointless (the honest diagnosis)

- **PQC** was being *driven by the AI* — but a network threat has nothing to do with whether a
  key is quantum-safe. So PQC looked like a passenger with no real job.
- **ML** was classifying "threat level" only to pick a Kyber size — a decision that shouldn't
  depend on ML at all. So ML looked decorative.
- **SCTP** was there but barely used by the intelligence.

Three technologies, one fake link between them. Remove the fake link and give each a real job.

## 2. The reframe: three independent legs, one gateway

> **New thesis:** *An intelligent gateway that (1) secures legacy traffic with **post-quantum
> authenticated encryption**, (2) uses **ML to keep the SCTP transport resilient**, and (3) uses
> **ML to detect threats/anomalies** — three capabilities that each stand alone but compose
> naturally in one system.*

```
                         TCP client (legacy)
                                │
                     ┌──────────▼───────────┐
                     │  Intelligent Gateway │
                     │  Metrics Collector   │
                     └─────┬──────────┬─────┘
             ┌─────────────┘          └──────────────┐
             ▼                                        ▼
   ML-A: Network-Condition model          ML-B: Threat / Anomaly model
   STABLE / CONGESTED /                    NORMAL / SUSPICIOUS /
   DEGRADED / UNSTABLE / PRE_FAILURE       ANOMALOUS / HIGH_RISK
             │                                        │
             ▼                                        ▼
     SCTP Policy Engine                       Security Policy Engine
     • proactive path failover               • log / alert / rate-limit
     • path & stream selection                • quarantine severe anomalies
     • monitor-frequency tuning
             └─────────────┬──────────────────────────┘
                           ▼
       ┌─────────────────────────────────────────────┐
       │  SECURITY LAYER (independent of the ML)       │
       │  PQC-authenticated key exchange:              │
       │    X25519 + ML-KEM (confidentiality)          │
       │    + ML-DSA signatures (authentication)       │
       │  → AES-256-GCM → SCTP multihomed transport    │
       └─────────────────────────────────────────────┘
                           ▼
                     Remote receiver
```

**The crucial change:** the two ML models drive **networking and security policy**. Neither
touches the crypto. The crypto is a **fixed, strong, always-on security layer** — its job is
quantum-safe confidentiality + authentication, justified entirely by the quantum threat, not by
ML. That's why each leg now makes sense on its own.

---

## 3. Refining PQC — from "a passenger" to a complete post-quantum secure channel

**The point of PQC (independent justification):** classical encryption (RSA/ECDH) will be broken
by quantum computers via Shor's algorithm. An attacker can **record encrypted traffic today and
decrypt it later** ("harvest-now-decrypt-later"). PQC makes today's traffic safe against that
future. This is real and needs no ML to justify.

**What you already have (keep):** hybrid X25519 + ML-KEM-768 → HKDF → AES-256-GCM, proven real by
`pqc_selftest` (correct FIPS 203 sizes, encaps/decaps agree, tamper-sensitive).

**The one big refinement — add post-quantum AUTHENTICATION (ML-DSA).** Today the handshake has a
hole: it's **unauthenticated**, so a man-in-the-middle can defeat it, and you (correctly) can't
claim MitM resistance. Fix it:
- Give each side a long-term **ML-DSA (FIPS 204 / Dilithium)** signing keypair — a post-quantum
  *identity*. liboqs provides `OQS_SIG` for this.
- During the handshake, each side **signs the transcript** (the exchanged public keys) with its
  ML-DSA key; the peer **verifies** the signature against a **pinned/known public key**.
- Now it's a complete **post-quantum *authenticated* key exchange**: X25519+ML-KEM for
  confidentiality, ML-DSA for identity. This closes the hole and lets you honestly claim MitM
  resistance.

**Why this is the right PQC refinement:** it turns PQC from "we encrypt with a PQ algorithm" into
"we have a *full* post-quantum secure channel (confidentiality **and** authentication)" — a
complete, standalone security contribution. And it gives you a **killer live demo** (§6).

**Secondary PQC refinements (nice-to-have, visible):**
- **PQC characterization**: benchmark ML-KEM-512/768/1024 **and** classical ECDH side by side —
  handshake time, key/ciphertext sizes, bandwidth. A clean table/chart proving you understand the
  cost/security tradeoff (and that PQC compute is cheap; the cost is payload size).
- **Crypto-agility note**: the code already supports 512/768/1024 + ML-DSA — mention it can move
  to a stronger set if one is weakened. Good security-engineering practice.

---

## 4. Refining ML — two models that are genuinely necessary (not if/else)

You get ML right by using it **where thresholds fail**: decisions that depend on **combinations
of weak signals, learned baselines, or trajectories**. You proposed both models — build both.

### ML-A: Network-Condition model → SCTP adaptation (the NEW, unique contribution)
- **Inputs (a window of):** latency/RTT, RTT variation (jitter), packet loss, throughput,
  retransmissions, cwnd, path-state flaps, congestion indicators. *(Simulated metrics are fine —
  §5 explains how to keep that honest.)*
- **Output:** `STABLE / CONGESTED / DEGRADED / UNSTABLE / PRE_FAILURE`.
- **Action (SCTP Policy Engine):** prefer the healthier path; **fail over proactively**; adjust
  stream allocation; raise monitoring frequency when unstable.
- **Why ML, not if/else — the honest argument (make it empirical):** no *single* metric decides
  it. "Latency slightly up + jitter rising + cwnd shrinking + intermittent loss + short sessions"
  can mean *imminent path failure* even though **no single feature crosses a threshold**. The
  headline value is **predictive/proactive failover** — switching *before* the path hard-fails,
  which reactive threshold logic can't do. Prove it: show that thresholding any one feature
  misclassifies the overlapping cases, but the model using the combination gets them right.

### ML-B: Threat / Anomaly model → security policy (the STRONGER-justified leg you already have)
- **Reuse your Phase-2 CIC-IDS2017 model**, reframed as the anomaly/threat detector.
- **Inputs:** flow statistics (connection rate, bytes, durations, packet sizes, reconnects,
  baseline deviation).
- **Output:** `NORMAL / SUSPICIOUS / ANOMALOUS / HIGH_RISK`.
- **Action (Security Policy Engine):** log/alert, rate-limit the source, quarantine severe
  anomalies. **It does NOT change the crypto** — it changes *security operations*.
- **Why ML here:** intrusion patterns are multi-feature and deviate from a learned baseline; you
  already evaluated it honestly on real data (macro-F1 0.87, not a fake 100%).

> Clean separation: **ML-A answers "is the *network* healthy?" → transport actions. ML-B answers
> "is the *traffic* malicious?" → security actions.** Two different questions, two models, zero
> overlap with crypto.

---

## 5. "Simulated metrics are fine" — how to do it WITHOUT repeating the old sin

The earlier mistake was synthetic data with **non-overlapping ranges** → trivially separable →
meaningless 100% accuracy. Simulate honestly instead:

1. **Overlap the classes.** Draw each feature from distributions that **overlap** across classes,
   with **noise** and **correlations**, so **no single feature separates them**. (E.g. DEGRADED
   and UNSTABLE share latency ranges; only the *combination* with jitter+loss+cwnd distinguishes.)
2. **Report honest metrics.** Held-out test set, confusion matrix, per-class F1, expect a
   realistic **sub-100%** number.
3. **Prove ML is needed on this data.** Add a **single-threshold baseline** and show it does
   **worse** than the model — because the classes overlap in every single dimension. *This is the
   empirical proof that ML earns its place*, and it's honest even on simulated data.
4. **State it as a limitation** and leave a hook: the same pipeline can later ingest **real SCTP
   path metrics** from the netns testbed (`get_path_status` already exposes RTT/cwnd/state).

---

## 6. The three visible, unique results (one per leg — this is what you demo)

| Leg | Visible unique result | Why it lands |
|---|---|---|
| **PQC** | **Live MitM demo**: without ML-DSA a man-in-the-middle succeeds; with ML-DSA the signature fails to verify and the session is rejected. Plus `./pqc_selftest`. | Shows a *complete* post-quantum secure channel defeating a real attack |
| **ML-A + SCTP** | **Proactive vs reactive failover**: the model predicts PRE_FAILURE and switches early → measurably **fewer lost packets** during transition than threshold-based reactive failover. | ML + SCTP doing something if/else *cannot*; a measured improvement |
| **ML-B** | **Anomaly caught by combination**: a crafted attack where no single metric is alarming, but the model flags HIGH_RISK; a single-threshold baseline misses it. | Proves ML beats rules; real-dataset-trained |

Each is independently impressive; together they tell one coherent story.

---

## 7. What to reuse / build / drop

**Reuse (already done, still valid):**
- PQC hybrid handshake + `pqc_selftest`, AES-GCM, streaming relay, SCTP multihoming/failover,
  netns testbed, the CIC-IDS2017 anomaly model (becomes ML-B), the dashboard + live PQC view.

**Build (the refinement work):**
- **PQC:** ML-DSA authentication in the handshake (`OQS_SIG`), pinned-key verification, + the
  MitM demo. (Optional: the KEM-vs-classical benchmark chart.)
- **ML-A:** a network-condition dataset generator (honest/overlapping), a trained model, and a
  **SCTP Policy Engine** that turns its verdict into path/stream/failover actions.
- **Wiring:** feed ML-A from the path monitor's live metrics; drive proactive failover from it.
- **Dashboard:** a "Network Condition" panel (ML-A) alongside the existing threat panel (ML-B),
  and a "PQC authentication" indicator.

**Drop / de-emphasize:**
- The "AI picks the crypto level" idea — gone for good.
- The battery/floor "adaptive crypto" narrative as the *headline*. Keep "ML never weakens crypto"
  as a one-line **design principle**, but it's no longer the centerpiece — the three legs are.

---

## 8. Phased plan

| Phase | Work | Outcome |
|---|---|---|
| **R1 — PQC authentication** | add ML-DSA sign/verify to the handshake; pinned keys; MitM demo | complete PQ-authenticated channel; MitM claim becomes true |
| **R2 — ML-A model** | honest overlapping network-condition dataset; train + evaluate; baseline comparison | a *justified* ML model with real metrics |
| **R3 — SCTP Policy Engine** | verdict → proactive failover / path & stream selection; wire to path monitor | ML actually drives SCTP; proactive-failover result |
| **R4 — Integration & dashboard** | two-panel dashboard (network + threat), PQC-auth indicator; end-to-end demo | one coherent, visible story |
| **R5 — (optional) real metrics** | swap ML-A's simulated features for live SCTP metrics from netns | removes the "simulated" caveat |

Suggested order: **R1 → R2 → R3 → R4** (R5 later). R1 (PQC auth) is the highest-value single
change — it makes the security real and gives you the strongest demo moment.

---

## 9. Honest scoping & risks

- **ML-DSA authentication** with pinned keys is very achievable (liboqs `OQS_SIG` mirrors the KEM
  API you already use). Full PKI/certificates are out of scope — pinned keys are enough to defeat
  MitM and to demo it.
- **Simulated network data** is acceptable *if* you follow §5 (overlap + honest eval + baseline
  comparison). Do **not** ship separable synthetic data again.
- **Proactive failover** is the boldest claim — scope it as "acts on early degradation
  (DEGRADED/UNSTABLE/PRE_FAILURE) before the SCTP stack marks the path INACTIVE," and measure the
  packet-loss difference. That's honest and demonstrable without needing a perfect predictor.
- Keep the naming standard: **ML-KEM (FIPS 203)** and **ML-DSA (FIPS 204)**.

---

## 10. What this means for your viva

You can now answer the three questions cleanly:
- **"What's the point of PQC?"** → Quantum-safe confidentiality **and** authentication for legacy
  traffic — defends harvest-now-decrypt-later and MitM. *(Run `pqc_selftest`; show the MitM demo.)*
- **"What's the point of ML?"** → Two jobs thresholds can't do: classify network condition to
  drive **proactive SCTP resilience**, and detect **multi-feature anomalies**. *(Show ML beating
  the threshold baseline on overlapping data.)*
- **"Why together?"** → A gateway that's simultaneously **secure (PQC), resilient (ML+SCTP), and
  watchful (ML)** — three independent guarantees composed in one place, not one forced knob.
