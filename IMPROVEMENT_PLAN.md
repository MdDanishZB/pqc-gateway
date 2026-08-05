# PQC Gateway — Diagnosis and Improvement Plan

> Purpose: turn this from a working-but-incoherent demo into a project that solves a
> real, well-defined problem and survives technical scrutiny. This document is written
> against the actual code in this repo, not the README's aspirational description.

---

## 0. TL;DR — the one sentence that fixes everything

**Stop using the AI to choose the cryptographic strength. The two things you coupled —
"how anomalous is the network" and "how quantum-resistant is the key exchange" — are
unrelated axes, and coupling them is what makes the project feel pointless.**

Once you decouple them, you have *two* individually-defensible systems and a novel
combination:

- **Security axis (crypto):** always-on strong floor. Never weakened by traffic or
  battery. Adaptation may only *raise* cost, never lower it below the floor.
- **Operations axis (detection + transport):** the ML detector classifies network
  conditions and drives **transport resilience** (SCTP failover, multistreaming,
  rate-limiting, rekey cadence, alerting) — **not** key strength.

Everything below builds on that single decoupling.

---

## 1. Honest diagnosis — answering your own three doubts

You asked whether the problem is (a) the idea itself, (b) an overfitted model, or
(c) a misused LLM. The answer is: **all three, plus a fourth you didn't name (the
security claims are unfounded).** Here is each, grounded in the code.

### 1.1 "Is the idea itself unsuitable?" — Partly. The *framing* is broken, the *substrate* is good.

The core mechanism is a **category error**:

- `sctp_gateway.c` reads an AI verdict (LOW/MEDIUM/HIGH) and selects Kyber-512/768/1024.
- ML-KEM parameter sets defend against a **cryptanalytic/quantum adversary**. A DDoS
  (high bandwidth, low inter-arrival time) does not make Kyber-512 breakable, and a
  bigger KEM does nothing to stop a DDoS. The two are orthogonal.
- It is actively *harmful* under your own Harvest-Now-Decrypt-Later (HNDL) threat model:
  an attacker harvests **all** traffic, including the LOW-threat baseline that is the
  bulk of what gets recorded. You are encrypting the most-harvested data with your
  **weakest** key and the rare bursts with your strongest. That is an own-goal against
  the exact threat you claim to defend.

**But** the substrate — a C gateway doing TCP→SCTP re-origination with a real hybrid
X25519+ML-KEM handshake, liboqs, lksctp, a path monitor, and an observability stack —
is genuinely substantial. You do not throw this away. You **re-aim** it. See §2.

### 1.2 "Is the model overfitted?" — Yes, and worse than ordinary overfitting.

Two distinct problems:

1. **The dataset is separable by construction.** `generate_dataset.py` draws each class
   from non-overlapping uniform ranges (LOW latency 5–30, HIGH 80–300; LOW IAT 100–500,
   HIGH-flood IAT 1–10). `train_model.py` then "achieves" ~100% accuracy — it has merely
   re-learned the boundaries you hand-coded. This number means nothing about real threats
   and a reviewer spots it instantly.
2. **Train/serve skew (a real bug).** The model trains on `throughput` ∈ ~[0,1000] bytes/s
   and `jitter` = |latencyₜ − latencyₜ₋₁|. But at inference `path_monitor.c:69-78` feeds
   it `primary_ps.cwnd` (a congestion window, totally different units/scale) as
   "throughput" and the **RTT difference between the two paths** as "jitter." The model
   is being queried with out-of-distribution garbage, so the monitor's verdicts are
   effectively arbitrary. Even a perfect model would misbehave here.

### 1.3 "Is the LLM misused or mis-prompted?" — Both.

- **Misused (architecture):** `3_analyst_chat.py` and `llm_advisor.py` ask the LLM to
  *classify threats* from a raw `df.to_string()` dump of recent rows. That re-derives
  what the RF already does, ungrounded, which is precisely the task LLMs hallucinate on.
  The LLM is sitting *in* the security decision path, where it must never be.
- **Mis-prompted (execution):** generic system prompt, no schema, raw table dump as
  context, no instruction to refuse when the data doesn't support an answer. It will
  confidently invent DDoS findings.
- **Config incoherence:** `app.py` hardcodes the status text "LLM Backend: Ollama
  (Llama 3.1)", `llm_config.py` defaults to `ollama`, but the checked-in `.env` sets
  `LLM_BACKEND=gemini`. Pick one story.

The fix is not "prompt harder." It is to **move the LLM out of the decision loop** and
give it a grounded *explanation* job. See §5.

### 1.4 The unnamed fourth problem: the security claims are unfounded.

- **The handshake is unauthenticated.** `pqc_handshake.h` documents raw ephemeral
  X25519 + Kyber public keys with **no signature, certificate, PSK, or identity binding**.
  This is an unauthenticated key exchange; a real active man-in-the-middle defeats it by
  running two half-handshakes. Any "MitM resistance" result was not testing a real MitM.
  You must either add authentication or delete every MitM/HNDL-mitigation claim.
- **Everything runs on loopback.** "Primary" `127.0.0.1` and "secondary" `127.0.0.2` are
  the same host. Multihoming bind time, failover time, and "zero-loss path transition"
  are measured with no real interfaces, RTT, or link failure. None of the resilience
  numbers are credible yet.
- **The hybrid math is wrong.** `Pr(compromise) ≤ Pr(break X25519) × Pr(break Kyber)`
  implies independence and "must break both." The correct statement: the combined key is
  secure if **at least one** component is secure. Drop the product formula.

---

## 2. The reframe — what this project should actually be

> **A transparent transport-hardening gateway that re-originates legacy TCP traffic as an
> *authenticated*, hybrid post-quantum **DTLS-1.3-over-SCTP** association, governed by a
> policy controller with a *provable security floor* that a battery-drain / downgrade
> adversary cannot push below.**

Why this is real and unclaimed:

- Commercial "crypto-translator" proxies (IBM Quantum Safe Remediator, Palo Alto,
  Zscaler) all terminate to **TLS over TCP**. Nobody re-originates legacy traffic into a
  **multihomed/multistreamed SCTP association**. That transport context is the gap.
- The **security-floor invariant** (threat may escalate strength; battery/load may never
  drop below a fixed floor) is a clean, named defense against **downgrade attacks** and is
  a genuine contribution you can state formally and even mechanize (Tamarin/ProVerif).
- Running hybrid groups inside **DTLS 1.3 over SCTP** (per `draft-ietf-tsvwg-dtls-over-sctp-bis`)
  lets you **inherit** the IETF hybrid-KEX security proof and get authentication + replay
  protection, instead of inventing an unproven concatenate-then-HKDF combiner. This single
  change fixes §1.4's authentication hole *and* the wrong combiner framing at once.

### Two coherent control axes (the heart of the redesign)

| Axis | Driven by | Acts on | Floor |
|---|---|---|---|
| **Security (crypto)** | fixed policy | hybrid KEM + signature auth + AES-GCM | **always ≥ floor** (e.g. hybrid X25519+ML-KEM-768 + ML-DSA). Threat may raise to ML-KEM-1024 / faster rekey; nothing lowers it below floor. |
| **Operations (resilience)** | ML anomaly detector | SCTP path failover, multistreaming, rate-limit/backpressure, **rekey cadence**, alerting | n/a |

The ML detector keeps its job — **detecting bad network conditions** — but now drives
*availability/transport* responses, which is what anomaly detection is actually for. The
crypto strength is decoupled and floored.

> **Energy story — deferred (no constrained hardware available).** You have a second
> laptop but no MCU or power monitor, so an *embedded* energy-adaptive narrative can't be
> measured and should not be the headline. Keep the spine on the **security-floor /
> downgrade-resistance** contribution, which needs no special hardware. If you want any
> energy figure at all, use the **Intel RAPL CPU-energy proxy** on the laptops (see §6.4),
> clearly scoped as host-CPU energy — not IoT battery life. Note: lattice KEMs are already
> *cheaper* than the classical ECDH you pair them with, so "weaken the KEM to save energy"
> was never the right lever anyway.

---

## 3. Workstream A — Crypto & protocol correctness

Goal: make the security claims true and standards-grounded.

1. **Add authentication.** Preferred: migrate the bespoke handshake to **DTLS 1.3 over
   SCTP** with hybrid groups, so you inherit auth, replay protection, and the hybrid
   proof. If you must keep the bespoke handshake short-term: sign the **full handshake
   transcript** with **ML-DSA (FIPS 204)** and bind certificates/identities into the
   HKDF `info`. Until one of these exists, remove all MitM/HNDL claims from any writeup.
2. **Set and enforce the floor invariant.** Define `FLOOR = hybrid(X25519, ML-KEM-768) +
   ML-DSA-65`. The controller may select ≥ FLOOR only. Add an assertion in
   `sctp_gateway.c` that refuses to start a session below FLOOR, and a unit test that
   tries to force a downgrade (spoofed low-battery / forged verdict) and confirms it
   cannot drop below it. This test *is* your contribution made tangible.
3. **Fix naming.** Use **ML-KEM (FIPS 203)** and **ML-DSA (FIPS 204)** as primary names;
   mention "formerly Kyber/Dilithium" once. Reviewers in 2026 expect standardized names.
   Rename `KyberLevel` → `MlKemLevel` etc. for consistency.
4. **Fix the hybrid framing.** Replace the product formula with: *the session key is
   secure as long as at least one of {X25519, ML-KEM} is unbroken* and cite an actual KEM
   combiner result. Delete "provably stronger" unless you cite the proof you inherit.

## 4. Workstream B — The detector (make the ML honest and correct)

Goal: a network-anomaly detector evaluated on data it did not author, with no train/serve
skew, driving transport (not crypto).

1. **Train on a real labeled dataset.** Use **CIC-IDS2017**, **CIC-DDoS2019**, or
   **UNSW-NB15**. Map their flow features onto your schema (or expand the schema). Report
   an honest **confusion matrix**, precision/recall/F1 **per class**, and **false-positive
   rate** — a realistic sub-100% number. Use a **temporal or grouped split** so flows from
   one capture session don't leak across train/test.
2. **Kill train/serve skew with a single shared feature module.** Create
   `ai_module/features.py` defining the canonical 6 (or N) features, their units, and
   their computation. *Both* `generate_dataset.py`/training *and* the online path
   (`ai_bridge.c` → `model_server.py`, and whatever `path_monitor.c` feeds) must produce
   features through the same definition. Fix `path_monitor.c:69-78`: stop sending `cwnd`
   as "throughput" and path-RTT-delta as "jitter." Add range/scale validation in
   `model_server.py` that rejects or clips out-of-distribution inputs.
3. **Justify the model choice.** For flow-stat DDoS detection a small RF or even tuned
   thresholds may suffice — say so and show the trade-off. The contribution is *honest
   evaluation*, not model complexity. Persist the train/test split and a `metrics.json`
   (accuracy, CM, ROC-AUC) as an artifact.
4. **Re-target the output.** The verdict now selects a **transport action** (failover /
   rate-limit / rekey-now / alert), not a Kyber level. Update `path_monitor.c`'s decision
   block accordingly: HIGH ⇒ rate-limit + alert + (if path degraded) failover; it must
   **not** change crypto strength.

## 5. Workstream C — The LLM (reposition or cut)

Goal: the LLM is a **grounded explanation / operator-assist layer, strictly outside the
security decision loop.** It explains decisions the deterministic system already made; it
never makes them.

1. **Remove it from the decision path.** Delete `llm_advisor.py`'s role of producing
   `threat_level`/`attack_type` that could feed anything. The RF/controller decides; the
   LLM only narrates.
2. **Ground every answer in structured decision records, not raw dumps.** Replace
   `df.to_string()` context with a compact JSON of *actual events*: `{timestamp, rf_verdict,
   controller_action, active_path, kyber_level, path_event, key_metrics}`. The LLM's job is
   "explain why the system did X," answerable from that record.
3. **Constrain the prompt.** System prompt: role + the schema of the record + a hard rule
   *"Answer only from the provided events; if the data does not support an answer, say so.
   Never assert an attack the records don't show."* This is what stops hallucination — not
   a longer prompt.
4. **Pick one backend and tell the truth about it.** Make `app.py`'s status line read
   from `llm_config`. Reconcile the `.env` (`gemini`) vs default (`ollama`) vs UI text.
5. **For a paper: consider cutting the LLM** or scoping it explicitly as a
   non-security-critical UX aid. Framed as "doing security," it is a reviewer liability.

## 6. Workstream D — A real testbed & honest evaluation

Goal: numbers a reviewer believes.

1. **Two real paths (you have the hardware for the strong version — use it).** With a
   second laptop, build a genuine **two-host testbed** instead of the netns fallback:
   - Give each laptop **two independent links** to the other — e.g. an Ethernet cable
     (USB-Ethernet adapter if needed) as **path 1** and Wi-Fi (or a second adapter) as
     **path 2**. Each host now has two IPs, which is what real SCTP multihoming needs.
   - Apply `tc netem` per-interface for impairment, and **physically unplug / `ip link set
     <if> down`** one link to measure *real* failover — not an iptables DROP on loopback.
   - This directly retires the §1.4 loopback problem and makes the multihoming/failover
     numbers credible. Loopback `127.0.0.1/127.0.0.2` does not count.
   - (Fallback only if a link is unavailable: two **network namespaces** + **veth pairs**
     with independent `tc netem`, tearing one down for real.)
2. **Real baselines.** Measure (a) no-crypto passthrough, (b) classical DTLS/TLS, (c) your
   hybrid — so overhead is interpretable. Report **mean ± 95% CI over many runs**; drop
   false precision like "238.825 ms."
3. **Decompose handshake latency.** Separate KEM compute vs the Python AI round-trip over
   the Unix socket vs setup/polling. You will likely find the KEM is a small fraction of
   the ~238 ms — which honestly *refutes* the old "32% crypto-time reduction" claim. State
   that. Don't compare handshake-limited "125 B/s throughput" against a raw AES-NI
   "2.4 GB/s" CPU benchmark; that's apples-to-oranges.
4. **Energy: drop battery claims; optionally report a CPU-energy *proxy*.** You have **no
   MCU and no power monitor**, so **embedded/IoT battery-life claims are off the table —
   remove them entirely.** If you still want a scoped, honest energy figure, the laptops'
   x86 CPUs expose **Intel RAPL** (read via `perf stat -e power/energy-pkg/ ...` or
   `/sys/class/powercap/intel-rapl/.../energy_uj`): report **CPU-package energy in
   joules/mJ per handshake, per rekey, and per MB encrypted**, with the explicit caveat
   that this is *host CPU energy, not constrained-device battery energy*. This is enough
   to compare crypto variants honestly (and will show the KEM is cheap relative to the
   classical ECDH + AI round-trip) without claiming IoT battery life you can't measure.
5. **Replace the strawman comparison table.** A 9-criteria table where you get ✓ on
   everything and all prior work gets ✗ reads as overclaiming (several of your ✓'s are the
   broken items). Make it narrow and honest.

## 7. Workstream E — Reference integrity (do this first, it's an emergency)

External review flagged that several load-bearing citations **may not exist** (e.g. the
"conveniently matches our design" [12], [15], [16] — a classic LLM-fabrication signature).

1. **Verify every reference by DOI** on IEEE Xplore / the publisher. Delete any that don't
   resolve. Never trust an LLM-suggested citation without opening it.
2. **Rebuild the bibliography only from papers you have actually read.** Real anchors to
   start from: Paquin et al. (PQCrypto 2020), the IETF hybrid-KEX drafts,
   `draft-ietf-tsvwg-dtls-over-sctp-bis`, FIPS 203/204, and your chosen IDS dataset paper.
3. Submitting fabricated citations is research misconduct and editors run automated
   checks. This is the single fastest way to a desk-reject + reputational damage. Treat it
   as priority zero.

## 8. Workstream F — Code structure & reproducibility (lighter, but do it)

1. **Add `requirements.txt`** (there is none; only an `ai_module/venv`). Pin versions.
2. **Single source of truth for the feature schema** (`ai_module/features.py`, §4.2).
3. **Resolve the duplicated `metrics.db`** (root vs `ai_module/dashboard/`). One canonical
   path in config; `receiver.py` currently writes wherever its cwd is.
4. **Add tests:** the floor-invariant downgrade test (§3.2), a handshake round-trip test,
   a feature-parity test (offline vs online features agree on the same input).
5. **Provide a launcher** and a README "how to reproduce every figure" section. Keep the
   real secrets out — `.env` with `GEMINI_API_KEY` is currently untracked; add it to
   `.gitignore` so it stays that way.

---

## 9. Phased execution plan

**Phase 0 — Stop the bleeding (days, do immediately)**
- Verify/replace all references (§7).
- Remove or soften every claim the current system can't back: MitM resistance, HNDL
  mitigation, energy/battery savings, 100% accuracy as a result, the product formula.
- Decide scope: capstone-honest (Phases 1–3) vs publishable (add Phases 4–5).

**Phase 1 — Coherence (1–2 weeks)**
- Decouple crypto from the detector; set the floor invariant + downgrade test (§3.2).
- Re-target the detector output to transport actions (§4.4).
- Fix train/serve skew via the shared feature module (§4.2).

**Phase 2 — Honest ML (1–2 weeks)**
- Retrain/evaluate on a real dataset with a proper split and confusion matrix (§4.1).

**Phase 3 — Honest measurement (1–2 weeks)**
- Netns/veth or two-host testbed; real baselines; latency decomposition; CIs (§6.1–6.3).
- Reposition the LLM as grounded explainer or cut it (§5).

**Phase 4 — Real security (2–4 weeks, for publication)**
- DTLS-1.3-over-SCTP with hybrid groups + ML-DSA auth (§3.1). Now MitM/HNDL claims are
  legitimately back on the table.

**Phase 5 — The contribution made formal (2–4 weeks, for a top venue)**
- Mechanize the floor-invariant / downgrade-resistance in Tamarin or ProVerif. This is
  **software-only** — fully achievable with your current hardware and is the real
  journal-tier differentiator.
- (Optional) RAPL CPU-energy proxy on the laptops (§6.4). Constrained-device battery
  energy is **out of scope** — no MCU/power monitor available.

---

## 10. Scope tiers — be calibrated about the target

| Target | Needs | Realistic with |
|---|---|---|
| **Honest, defensible capstone / IEEE Access** | Phases 0–3 | reframe + real data + netns testbed + honest numbers |
| **Mid-tier security/networking conference** | + Phase 4 | DTLS-over-SCTP authentication + **two-laptop testbed (you have this)** |
| **Journal (TNSM / TIFS / TDSC)** | + Phase 5 | formal floor proof (+ optional RAPL CPU-energy). **Note:** IoT-J specifically expects a constrained-device energy story you can't currently measure — aim TNSM/TIFS/TDSC instead. |

This is currently a strong *undergraduate systems build* with *unsound claims*. The build
is an asset; the claims are the liability. Phases 0–3 alone convert it from "impressive but
desk-rejectable" to "honest and useful." Everything past that buys venue tier.

> Watch out for predatory venues: "Post-Quantum + AI + IEEE" keywords attract fake
> fast-acceptance-for-a-fee journals. An acceptance there is worse than none.

---

## 11. The honesty checklist (paste into your manuscript review)

- [ ] Every reference resolves to a real DOI I have opened.
- [ ] No claim that the AI improves cryptographic security (it improves *resilience*).
- [ ] Crypto floor stated; downgrade test passes; battery can't drop below floor.
- [ ] Handshake is authenticated, or all MitM/HNDL claims are removed.
- [ ] ML evaluated on external data with a real (sub-100%) confusion matrix + FPR.
- [ ] Offline and online features are computed by the same code (no skew).
- [ ] Results from ≥2 real network paths; failover measured by severing a real link.
- [ ] Baselines (no-crypto / classical / hybrid) reported with mean ± CI.
- [ ] Handshake latency decomposed; KEM's true fraction shown.
- [ ] Energy measured on real hardware, or no energy claims at all.
- [ ] LLM is outside the security decision loop and grounded in event records.
- [ ] Standardized names (ML-KEM / ML-DSA) used throughout.
- [ ] Comparison table is narrow and honest, not all-✓.
```
