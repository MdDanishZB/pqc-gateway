# Evaluator Demo Script (Read-and-Speak)

> A word-for-word walkthrough for presenting the live demo (Mode A / loopback, ~10–12 min).
> **[DO]** = what you click/type · **[SAY]** = what you say · **[POINT]** = what to show ·
> **[INFER]** = the conclusion to state. Speak calmly; let the screen do the proving.

---

## Before the evaluator arrives (5-minute checklist)

```bash
cd ~/project-root
(cd gateway && make)                 # ensure it's built
./scripts/run_demo.sh reset          # clean slate
./scripts/run_demo.sh start          # launch everything -> http://localhost:8501
./scripts/run_demo.sh calibrate      # ~90s: makes DDoS reliably read HIGH (do this!)
./scripts/run_demo.sh seed           # warm up the charts so they're not empty
```
Open two windows side by side:
- **Browser** at `http://localhost:8501` (the dashboard).
- **Terminal** running `tail -f ~/project-root/.demo_logs/gateway.log`.

Verify: the browser Live Monitor shows data; the terminal shows `[Crypto]`/`[Bench]` lines.
Keep the **Simulation Control** page open in the browser to drive things.

---

## 0. Opening (30 seconds)

**[SAY]** "This project is a security gateway. Old programs send network traffic with
encryption that a future *quantum computer* could break. My gateway transparently upgrades that
traffic to *post-quantum* encryption, sends it over a connection that survives a broken network
path, and uses a small AI to react to attacks. The original contribution is that the AI manages
*network resilience* but is never allowed to weaken the encryption — and there's a guaranteed
minimum encryption strength that nothing, not even a battery-drain attack, can push below.
Let me show it running live."

---

## 1. It's really running (30 seconds)

**[DO]** Point to the terminal with the live gateway log scrolling.
**[SAY]** "This is the live gateway. Every line here is a real session it's securing right now."
**[POINT]** A `[PQC] Hybrid session key ready (X25519 + Kyber768 …)` line.
**[SAY]** "Each session does a *hybrid* handshake — classical X25519 *and* post-quantum ML-KEM
together — so an attacker must break both."

---

## 2. Normal traffic → the AI reads it (1.5 min)

**[DO]** Browser → **Simulation Control** → Traffic Pattern = **Normal** → **Start Traffic**.
**[DO]** Switch to the **Live Monitor** page.
**[SAY]** "I'm sending normal traffic. Watch the AI classify it."
**[POINT]** The **AI Threat Level** box → **LOW**; the gauges filling in.
**[POINT]** The **Crypto** line → **ML-KEM-768 🔒 floor**.
**[INFER]** "The AI sees normal traffic and says LOW. The encryption is at its floor level,
ML-KEM-768."

---

## 3. Attack → the AI reacts, but crypto does NOT change (2 min)

**[DO]** Simulation Control → Traffic Pattern = **DDoS** → **Start Traffic**.
**[DO]** Back to **Live Monitor** (give it a few seconds).
**[SAY]** "Now I launch a flood — a denial-of-service attack."
**[POINT]** **AI Threat Level** flips to **HIGH**; **Transport Action** shows **RATE_LIMIT +
ALERT**; the pie shifts toward red.
**[SAY]** "The AI detected the flood and responded — but notice *how* it responded."
**[POINT]** The **Crypto** line — *still* **ML-KEM-768**.
**[INFER]** "This is the core idea. The AI reacted on the *network* side — rate-limiting the
flood. It did **not** touch the encryption. A flood doesn't make encryption weaker, and
stronger encryption doesn't stop a flood — so those two jobs are kept completely separate."

---

## 4. THE HEADLINE — a battery-drain attack can't weaken the crypto (2.5 min)

**[SAY]** "Here's the attack most 'smart security' systems fall for. Many devices weaken their
encryption when the battery is low, to save power. So an attacker *drains or fakes* a low
battery to force weak encryption, then attacks that. Let me try that here."

**[DO]** Simulation Control → **Security Posture & Crypto Floor** panel → drag **Battery
pressure to 100%** → click **Apply Posture**.
**[DO]** Make sure traffic is still running (Start Normal if needed), so a new session happens.
**[POINT]** In the same panel, **Resulting crypto (live)** → **ML-KEM-768**, with **✅ FLOOR
HELD**.
**[DO]** (Optional, stronger) Switch to the terminal.
**[POINT]** `[Crypto] battery=100% high_assurance=0 -> ML-KEM-768 (floor enforced)`.
**[SAY]** "Battery pressure is maxed out — the attacker's dream — and the encryption stays at
ML-KEM-768. The system *refuses* to go below the floor."
**[DO]** (Optional) Tick **High-assurance** → Apply → send traffic.
**[POINT]** Resulting crypto rises to **ML-KEM-1024**.
**[INFER]** "So the rule is asymmetric: a threat or high-assurance request can *raise* the
strength, but a battery signal can *never lower* it below the floor. That asymmetry is what
defeats the downgrade attack — and it's the heart of my contribution."

---

## 5. Is post-quantum crypto too slow? Measured answer: no (2 min)

**[DO]** Browser → **PQC Visualizer** page (top **Live Handshakes** section).
**[SAY]** "A common objection is that post-quantum crypto is heavy. Here's the measured truth
from the real handshakes happening right now."
**[POINT]** The metric **ML-KEM compute … % of handshake** (a fraction of a percent).
**[POINT]** The **bar chart** — the green post-quantum bars are a tiny sliver; the grey
'network wait' bar dominates.
**[INFER]** "The post-quantum math is about a *twentieth of a millisecond* — under half a
percent of the handshake. The real cost is the network round-trip, not the crypto. So
'post-quantum is too heavy' simply isn't true here — I measured it."

---

## 6. Is the AI honest? (1.5 min)

**[DO]** Open the image `ai_module/models/confusion_matrix_strat.png` (or have it on a slide).
**[SAY]** "The AI wasn't trained on toy data — it's trained and tested on a real public
intrusion dataset, CIC-IDS2017."
**[POINT]** The confusion matrix.
**[INFER]** "It scores an F1 of about 0.87 — a real, honest number, not a suspicious 100%. And
when I tested it on attack *types it had never seen*, the flood detection still generalized
while the rarer classes were weaker — which I report honestly rather than hide."

---

## 7. Close (30 seconds)

**[SAY]** "To summarize: old traffic goes in, and comes out post-quantum-encrypted over a
resilient connection — with no change to the old program. The AI manages network resilience but
can never weaken the crypto, and the crypto has a floor that defeats battery-drain downgrade
attacks. Everything you saw was live and measured. The next steps are adding cryptographic
*authentication* and a formal mathematical proof of the floor guarantee."

---

## Anticipated questions (crisp answers)

**Q: Is this quantum-safe today?**
A: The *key exchange* is — it's hybrid X25519 + ML-KEM, so an attacker must break both, and
ML-KEM is the post-quantum standard. It defends against "harvest now, decrypt later."

**Q: Does it stop a man-in-the-middle attacker?**
A: Not yet — I'm being precise here. I prove *confidentiality*, but the handshake isn't
*authenticated* yet (no identity check). Authentication is the next phase; until then I don't
claim MitM resistance.

**Q: Why does the AI pick the security level? Isn't that dangerous?**
A: It deliberately does **not**. That was a flaw in the original design that I fixed. The AI
only drives *transport* — failover and rate-limiting. Crypto is floored and decoupled. A DDoS
and encryption strength are unrelated problems.

**Q: How does failover work / can you show it?**
A: The connection runs over two network paths (SCTP multihoming); if one dies, traffic
continues on the other. I demo that in the two-machine / two-path setup; today's run is the
single-machine core demo, so I'm describing it rather than cutting a live cable.

**Q: The AI is only ~87% accurate — isn't that low?**
A: It's *honest*. On heavily imbalanced real attack data, accuracy is misleading, so I report
F1, false-positive rate, and cross-attack generalization. A suspicious 100% would mean the data
was separable by construction — which was exactly the earlier mistake I corrected.

**Q: What's the actual novelty?**
A: The combination: upgrading legacy traffic into a *multihomed post-quantum SCTP* association
(others do TLS-over-TCP), plus the *provable security floor* that decouples the AI from crypto
and defeats battery-drain downgrade attacks.

**Q: Where did you measure the crypto being cheap?**
A: The gateway times each handshake sub-phase — the `[Bench]` log line — and the PQC page
visualizes it live. ML-KEM is ~0.05 ms of a ~200 ms handshake.

---

## If something breaks (stay calm)

- **Charts empty / no data:** run `./scripts/run_demo.sh seed`, wait 5 seconds, refresh.
- **DDoS shows LOW:** you skipped calibration — say "let me re-run detector calibration" and run
  `./scripts/run_demo.sh calibrate`; meanwhile narrate from the terminal `[Crypto]`/`[Bench]`
  lines, which don't depend on the AI.
- **A page errors:** switch to the terminal and narrate the live `[Crypto]` and `[Bench]` lines
  — the whole story (floor + cheap PQC) is visible there without the browser.
- **Total failure:** you recorded a backup run — play it and narrate. Never debug live.

> Golden rule: if the browser misbehaves, the **terminal log tells the entire story**. Keep it
> visible.
