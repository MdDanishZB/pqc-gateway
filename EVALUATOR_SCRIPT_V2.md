# Evaluator Demo Script v2 (Read-and-Speak)

> Supersedes `EVALUATOR_SCRIPT.md`, which still walks through a battery-posture slider and pages
> that no longer exist (`3_analyst_chat.py`, `8_demo_scenarios.py`). This version matches the
> current dashboard (Live Monitor, Simulation Control's two-pipeline panels, PQC & Trust,
> Evidence) and the now-proven real-failover capability. `EVALUATOR_SCRIPT.md` is left in place
> for history; use this one. **[DO]** = click/type · **[SAY]** = speak · **[POINT]** = show ·
> **[INFER]** = the conclusion to state.

---

## Before the evaluator arrives (5-minute checklist)

**If demoing Mode A (loopback, safe default):**
```bash
cd ~/project-root
(cd gateway && make)
./scripts/run_demo.sh reset
./scripts/run_demo.sh start          # -> http://localhost:8501
./scripts/run_demo.sh seed
```
Open two windows: the **browser** at `localhost:8501`, and a **terminal** running
`tail -f ~/project-root/.demo_logs/gateway.log`.

**If demoing Mode B (real two-path failover — the stronger version):** follow the full runbook
in `DEMO_PLAN_V2.md` §5b. The critical thing to verify before the evaluator sits down: **both**
the gateway terminal and the receiver terminal print
`[PQC] Authentication: ML-DSA-65 (identity pinned)` — if either shows a "keys not loaded"
warning, the demo will misbehave (handshakes will abort). Fix: relaunch both `gateway` and
`sctp_receiver` from inside the `gateway/` directory.

Verify: the browser's Live Monitor shows data; the terminal shows `[Policy]`/`[PQC]`/`[Bench]`
lines. Keep **Simulation Control** open in the browser — it's where you'll drive everything.

---

## 0. Opening (30 seconds)

**[SAY]** "This is a security gateway for legacy TCP traffic. It transparently upgrades that
traffic to post-quantum, authenticated encryption, sends it over a connection that can survive a
broken network path, and uses two separate AI models — one for threats, one for network health.
The core design rule is that neither AI is ever allowed to touch the encryption strength; that's
decided purely by a policy choice about the data itself. Let me show it running live."

---

## 1. It's really running, and it's really authenticated (1 min)

**[DO]** Point to the terminal with the live gateway log scrolling.
**[SAY]** "Every line here is a real session being secured right now."
**[POINT]** `[PQC] Hybrid handshake — initiator — ML-KEM-768` then
`[PQC] Authentication: ML-DSA-65 (identity pinned)` then
`[PQC] auth: responder — ML-DSA-65 signature VERIFIED`.
**[SAY]** "Each session does a hybrid handshake — classical X25519 and post-quantum ML-KEM
together — and now, each side also signs the handshake with a pinned post-quantum identity.
If someone tried to sit in the middle without the right key, the signature check fails and the
handshake is aborted outright — I can show that failing on purpose if you'd like."
**[INFER]** "This isn't just confidential; it's authenticated. A man-in-the-middle is defeated,
not just theorized about."

---

## 2. Normal traffic → the threat model reads it (1 min)

**[DO]** Browser → **Simulation Control** → Traffic Pattern = **Normal** → **Start Traffic**.
**[DO]** Switch to **Live Monitor**.
**[SAY]** "I'm sending normal traffic."
**[POINT]** **AI Threat Level** → **LOW**. **Crypto** line → **ML-KEM-768**.
**[INFER]** "The threat model reads it as ordinary. Encryption sits at its floor level."

---

## 3. Attack → the threat model reacts, crypto does not (2 min)

**[DO]** Simulation Control → Traffic Pattern = **DDoS** → **Start Traffic**. Back to **Live
Monitor**.
**[SAY]** "Now a flood — a denial-of-service pattern."
**[POINT]** **AI Threat Level** → **HIGH**; **Transport Action** → **RATE_LIMIT / ALERT**.
**[SAY]** "It reacted — but watch the crypto line."
**[POINT]** Still **ML-KEM-768**.
**[INFER]** "The reaction happened entirely on the network side. A flood doesn't make encryption
weaker and stronger encryption doesn't stop a flood, so those two jobs stay separate."

---

## 4. THE HEADLINE — crypto strength is a policy decision, not a network one (2.5 min)

**[DO]** Simulation Control → **Pipeline 1 — Data Classification → Crypto** panel.
**[SAY]** "Here's the core idea. Encryption strength should track how sensitive the data is —
not how the network is behaving. Watch."
**[DO]** Select **critical** → **Apply Classification**. Send a message.
**[POINT]** **Negotiated (live)** → **ML-KEM-1024**, ✅ FLOOR HELD.
**[SAY]** "Marking the data as critical raised the encryption strength — a deliberate,
explainable policy decision."
**[DO]** Select **routine** → **Apply Classification** — while the DDoS from step 3 is still
flagged HIGH. Send another message.
**[POINT]** **Negotiated (live)** drops back to **ML-KEM-768** immediately.
**[INFER]** "It fell straight back to the floor — the ongoing attack never had any influence on
it in either direction. The *only* thing that moves crypto strength is an explicit
classification of the data, and it can only ever rise above the floor, never fall below it.
That decoupling — and the fact it's provable by watching the log, not just claimed — is the
project's central contribution."

---

## 5. A second, independent AI drives resilience — and it's proven with a real cut (2.5 min)

**[DO]** Simulation Control → **Pipeline 2 — Network Condition (ML-A) → SCTP Transport** panel.
**[SAY]** "There's a second AI model here, completely separate from the threat detector — it
has never seen threat data, it only reads network health: latency, jitter, loss, throughput."
**[DO]** Move the loss/jitter sliders up → **Classify Network Condition**.
**[POINT]** The state (e.g. **DEGRADED**) and the recommended transport policy
(**FAILOVER_READY**).

**[If Mode A / loopback]**
**[POINT]** The badge: *"recommendation — single-path, not enforced."*
**[SAY]** "On this single-path demo it's a recommendation only — I'm being precise about what's
proven versus what's asserted."

**[If Mode B / real two-path testbed]**
**[POINT]** The badge: *"✅ ENFORCED."*
**[DO]** Sever the second link live (`sudo ./scripts/setup_netns.sh cut`) or narrate the
pre-recorded run.
**[POINT]** The gateway log's failover line, and the pre-captured `failover_measure.sh`
mean ± 95% CI.
**[SAY]** "That failover is real — a physical link was severed, twenty times, and this is the
measured average time to switch, not a single lucky anecdote."

**[INFER]** "Two AI models, two jobs, one wall between them and the crypto."

---

## 6. Are the numbers honest? (2 min)

**[DO]** Browser → **Evidence** page.
**[POINT]** ML-B's confusion matrix and macro-F1 (**0.87**, real CIC-IDS2017 data).
**[POINT]** ML-A's confusion matrix and macro-F1 (**0.93**) next to its threshold baseline
(**0.78**).
**[INFER]** "Neither model reports a suspicious 100% — that would mean the data was separable by
construction, which was an actual mistake in an earlier version of this project that I
corrected. ML-A specifically has to beat a transparent, hand-written baseline to justify using
a model at all — it does, by about 15 points of macro-F1."
**[DO]** (Optional) Point to the `[Bench]` line: *"ML-KEM compute is about 0.05 milliseconds of
a roughly 200-millisecond handshake — negligible."*

---

## 7. Close (30 seconds)

**[SAY]** "To summarize: legacy traffic goes in, comes out authenticated and post-quantum
encrypted over a resilient connection. Encryption strength is a policy decision about the data,
provably decoupled from both AI models and from network conditions. Resilience is driven by a
second, independently-evaluated AI model, and — on the real two-path setup — that resilience
claim is backed by a measured, repeated failover, not just a mechanism that exists on paper."

---

## Anticipated questions (crisp answers)

**Q: Is this quantum-safe today?**
A: The key exchange is — hybrid X25519 + ML-KEM (FIPS 203) — defending against harvest-now,
decrypt-later. The handshake is now also authenticated with ML-DSA (FIPS 204), so it resists
man-in-the-middle, not just eavesdropping.

**Q: Why does data classification pick the crypto level instead of the AI?**
A: Because crypto strength should reflect how sensitive the data is, which is a policy fact
about the data — not a property of current network conditions or detected threats. Coupling
crypto to a threat verdict was the original design's mistake: a DDoS doesn't make a key
breakable, and a bigger key doesn't stop a DDoS. This version fixes that by construction —
`select_kem()` in the code literally cannot receive anything except the data classification.

**Q: What do the two AI models actually do, concretely?**
A: ML-B reads six flow statistics and flags LOW/MEDIUM/HIGH threat, driving rate-limiting and
alerts. ML-A reads five network-health metrics (RTT, jitter, loss, throughput, congestion
window) and predicts one of five conditions, driving SCTP transport policy — up to and including
a real failover when enforcement is enabled over a genuine second path.

**Q: Is the failover real, or simulated?**
A: Both claims exist and I'm precise about which is which. The mechanism (SCTP multihoming,
`multihoming.c`) is always real code. Whether a *given demo run* proves it depends on the
network: on loopback it's a recommendation only (the UI says so explicitly); on the two-veth
testbed with a link actually taken down via `ip link set down`, it's a real, measured failover —
20 trials, mean ± 95% CI, reported honestly as "netns-emulated" pending a genuine two-host run.

**Q: The AI models are only ~87–93% accurate — isn't that low?**
A: It's honest. Perfect scores usually mean the training data was separable by construction —
exactly the mistake an earlier version of this project made and that I corrected. Both models
here are compared against real baselines (majority-class/logistic for ML-B, a hand-written
threshold rule for ML-A) and clearly beat them without claiming perfection.

**Q: What's the actual novelty?**
A: Three things combined: (1) legacy traffic upgraded into an *authenticated, hybrid
post-quantum, multihomed SCTP* tunnel — not TLS-over-TCP like commercial products; (2) a
provably decoupled security-policy engine where crypto strength is structurally unreachable by
any ML or network signal; (3) two independently-evaluated ML models each doing one real job
(threat response, network resilience) instead of one model overloaded to do everything.

---

## If something breaks (stay calm)

- **Charts empty / no data:** `./scripts/run_demo.sh seed`, wait 5 seconds, refresh.
- **Handshake aborts / "keys not loaded" warning:** you're not launching `gateway`/
  `sctp_receiver` from inside `gateway/` — see the checklist above.
- **A page errors:** switch to the terminal and narrate the live `[Policy]`/`[PQC]`/`[NetML]`
  lines — the whole story is visible there without the browser.
- **Total failure:** play the recorded backup run and narrate. Never debug live.

> Golden rule: if the browser misbehaves, the **terminal log tells the entire story**. Keep it
> visible throughout.
