# The Project, Explained From Zero (Plain Language)

> Read this once slowly. By the end you'll understand *what* this is, *why* it matters, *how*
> it works, and *how to read every screen and log line* in the demo. No prior knowledge assumed.

---

## 1. The one-paragraph version

This project is a **security gateway** — a piece of software that sits between an old, insecure
program and the network. Old programs send data with encryption that a future **quantum
computer** could break. Our gateway **transparently upgrades** that traffic: it re-wraps it in
**post-quantum encryption** (encryption even a quantum computer can't crack), sends it over a
**resilient network connection that survives a broken cable**, and uses a small **AI** to watch
for attacks and react. The clever part — our main original idea — is that the AI controls
*network resilience* but is **never allowed to weaken the encryption**, and there's a
guaranteed **minimum encryption strength ("the floor") that nothing can push below** — not an
attacker, not a dying battery.

---

## 2. The problem, told as a story

Imagine an old factory sensor that speaks a simple, outdated network language (plain **TCP**)
with weak or no encryption. You can't rewrite the sensor. But its data still travels across
networks where attackers lurk. Three real dangers:

1. **The quantum threat ("harvest now, decrypt later").** An attacker can *record* the
   encrypted traffic **today**, store it, and wait. When quantum computers mature, they'll
   crack today's encryption and read everything retroactively. So "it's encrypted" isn't
   enough — it must be encrypted in a way quantum computers *can't* break.

2. **Attacks and overload.** Someone floods the link (a **DDoS** — denial of service), or a
   cable/path fails. The connection dies; the sensor goes dark.

3. **The "downgrade" trick.** Many systems save power by using weaker encryption when the
   battery is low. A clever attacker *drains or fakes a low battery* to force the device into
   its weakest mode — then attacks that weak mode. "Adapt security to battery" is a trap.

Our gateway is the answer to all three, without touching the old sensor.

---

## 3. The building blocks (each explained with a simple analogy)

### 3a. Post-Quantum Cryptography (PQC)
**Encryption** = scrambling data so only the intended receiver can unscramble it, using a
secret **key**. Today's common encryption relies on math that **quantum computers will break**.
**Post-quantum cryptography** uses *different* math (based on hard lattice problems) that
quantum computers are **not** expected to break. The standard we use is called **ML-KEM**
(formerly "Kyber").

> Analogy: today's locks can be picked by a future master-key machine. PQC is a new kind of
> lock that machine can't pick.

### 3b. Hybrid encryption (belt *and* suspenders)
We don't fully trust the new lock alone (it's newer). So we use **two** key-exchanges at once:
a classical one (**X25519**) *and* the post-quantum one (**ML-KEM**), and mathematically
combine them. **An attacker must break BOTH to get in.** If either survives, you're safe.

> Analogy: two locks from two different makers on the same door. The burglar must defeat both.

The final data is scrambled with **AES-256-GCM** — fast, strong, standard encryption — using
the key produced by that hybrid exchange.

### 3c. The gateway (a transparent upgrader)
A **gateway** is a middleman. Old program → speaks plain TCP → **our gateway** catches it,
wraps it in the hybrid post-quantum encryption, and forwards it. The receiver on the other end
unwraps it. **The old program never changes** — it thinks it's just talking normally.

> Analogy: a valet who takes your ordinary car and, before it hits the highway, silently
> installs armor and unbreakable locks — you didn't have to do anything.

### 3d. SCTP + multihoming (two roads, automatic detour)
Normal internet connections (**TCP**) use **one path**. If that path breaks, the connection
dies. We use **SCTP**, a transport that supports **multihoming** — the same connection can run
over **two network paths at once** (e.g., a cable *and* Wi-Fi). If one path dies, traffic
**automatically continues on the other** without dropping the session. This is called
**failover**.

> Analogy: two roads to the same destination. If one is blocked, your car reroutes to the
> other automatically, mid-journey, without stopping.

### 3e. The AI detector (a traffic-pattern guard)
A small **machine-learning model** (a "Random Forest") looks at the *shape* of the traffic —
how fast packets arrive, how big they are, how bursty it is — and classifies the situation as
**LOW** (normal), **MEDIUM** (suspicious), or **HIGH** (attack, e.g., a flood). It was trained
on a real public dataset of network attacks (**CIC-IDS2017**).

> Analogy: a security guard who doesn't read the letters (can't — they're encrypted) but
> watches the *flow* of people and spots a stampede (a flood/DDoS).

---

## 4. THE BIG IDEA (this is your project's original contribution — memorize it)

Most "smart security" projects make a mistake: they let the AI/battery **change the encryption
strength**. That's wrong for two reasons:

- **It's a category error.** A traffic flood (DDoS) does *not* make your encryption easier to
  crack, and stronger encryption does *not* stop a flood. They're unrelated problems.
- **It's a security hole.** If a low battery weakens encryption, an attacker just drains the
  battery to force weak encryption.

**Our fix — two separate control knobs that never touch each other:**

```
   The AI verdict (LOW/MEDIUM/HIGH)              The device's battery / posture
             │                                              │
             ▼                                              ▼
   ┌───────────────────────┐                  ┌──────────────────────────────┐
   │  TRANSPORT knob         │   never cross    │  CRYPTO knob                  │
   │  failover, rate-limit   │◄───── ✗ ─────►  │  ALWAYS ≥ ML-KEM-768 (floor)  │
   │  (network resilience)   │                  │  battery can NEVER lower it   │
   └───────────────────────┘                  └──────────────────────────────┘
```

- **The AI only adjusts the network** (fail over to the other path, rate-limit a flood). It
  **cannot** weaken the encryption.
- **The encryption has a floor** (ML-KEM-768). A battery/attacker signal can *ask* to save
  power, but the system **refuses to go below the floor**. Only an explicit "high-assurance"
  request may *raise* it (to ML-KEM-1024). **Threat can strengthen; nothing can weaken below the
  floor.**

> One sentence to say out loud: *"The AI manages availability; the crypto is floored and
> can't be weakened — and those two jobs never cross."*

---

## 5. How one message flows through the system (start to finish)

1. Old program sends a plain-TCP message → the **gateway** catches it.
2. The gateway measures the recent **traffic pattern** and asks the **AI**: LOW/MEDIUM/HIGH?
   (This drives *network* decisions, not crypto.)
3. The gateway picks the encryption level from the **crypto floor** (always ML-KEM-768; battery
   can't lower it). It does a **hybrid handshake** (X25519 + ML-KEM) with the receiver and
   derives an AES-256-GCM key.
4. The gateway **encrypts** the message and sends it over the **multihomed SCTP** connection
   (two paths). A background **monitor** keeps both paths healthy; if one dies, it **fails over**.
5. The receiver **decrypts** and delivers the message.
6. Stats (latency, verdict, KEM level, path) are sent to a **dashboard** so you can *watch*
   everything happening live.

---

## 6. What's actually running during the demo (the moving parts)

When you run `./scripts/run_demo.sh start`, five programs start:

| Program | Plain-language job |
|---|---|
| **model_server** | the AI — answers LOW/MEDIUM/HIGH when the gateway asks |
| **receiver.py** | collects live stats into a database the dashboard reads |
| **sctp_receiver** | the "other end" — receives and decrypts the upgraded traffic |
| **gateway** | the star — upgrades TCP → post-quantum SCTP, runs the crypto floor + AI |
| **streamlit** | the **dashboard UI** in your browser (http://localhost:8501) |

You then generate traffic (normal or attack) from the dashboard and **watch the effects**.

---

## 7. The UI, page by page — what you see and what it MEANS

Open **http://localhost:8501**. Pages are in the left sidebar.

### Home
A summary + system status (which backend, etc.). Just an intro slide — say one line and move on.

### 📊 Live Monitor — *"the vital signs"*
Shows live gauges (latency, throughput, loss, jitter) and a **Security State** box:
- **Crypto: ML-KEM-768 🔒 floor** — the *current* encryption strength. **Inference to state:**
  "It stays at the floor no matter what the AI says — crypto is decoupled."
- **AI Threat Level: LOW/MEDIUM/HIGH** — the AI's current read of the traffic.
- **Transport Action: NORMAL / RATE_LIMIT+ALERT** — what the AI does *on the network* (not
  crypto).
- **AI Decision Mix (pie)** — the spread of verdicts over recent traffic.
- **Latency trend + session log** — the raw evidence.

> What to conclude: when you switch to attack traffic, the **AI Threat Level** flips to HIGH
> and the **Transport Action** changes — but the **Crypto** line **stays ML-KEM-768**. That
> visual *is* the big idea.

### 🎮 Simulation Control — *"the control panel"*
This is where **you drive the demo**:
- **Traffic Control**: pick a pattern (**Normal**, **DDoS**, C2 Beacon…) and **Start/Stop**.
  This sends real traffic to the gateway. Normal → AI reads LOW; DDoS → AI reads HIGH.
- **Network Condition Control**: sliders to inject packet loss / delay (simulate a bad link).
- **🔒 Security Posture & Crypto Floor** (the headline panel):
  - **Battery pressure slider** — simulate a draining/spoofed battery (a downgrade attack).
  - **High-assurance checkbox** — request maximum crypto.
  - **Apply Posture** → writes the setting the gateway reads.
  - **Resulting crypto (live)** → reads back what the gateway actually used, with a
    **✅ FLOOR HELD** badge.

> What to conclude: set **battery = 100%**, Apply, send traffic → the **Resulting crypto stays
> ML-KEM-768**. You just showed that a battery-drain attacker **cannot** weaken the encryption.
> That's the downgrade-attack defense, demonstrated live.

### 🔐 PQC Visualizer — *"how the post-quantum crypto works, live"*
Top = **live handshake data from the real gateway**:
- **Median handshake time**, **current KEM**, and **ML-KEM compute as a % of the handshake**.
- A **bar chart** splitting each handshake into: X25519 keygen, ML-KEM keygen, ML-KEM decaps,
  and **network wait**. The post-quantum bars are a **tiny sliver**; network dominates.
- A live feed of recent handshakes.

Below = an **explainer**: the two-lock hybrid concept, the message flow diagram, key sizes,
and the wire format.

> What to conclude: **"Post-quantum crypto is essentially free."** The ML-KEM math is ~0.05 ms
> — a fraction of a percent of the handshake; the real cost is the network, not the crypto.
> This kills the common objection that "post-quantum is too heavy."

### (Other pages) Threat Narrative / Demo Scenarios
Nice-to-have. The **Analyst Chat** page uses an optional AI-language-model helper that you've
**parked** — don't open it in the demo.

---

## 8. The logs — what each line means (watch `tail -f .demo_logs/gateway.log`)

The gateway prints, per session, lines you can read out loud:

- `[AI] verdict=LOW ai_rtt=38ms` — the AI was asked and answered LOW; it took 38 ms to answer.
- `[Crypto] battery=100% high_assurance=0 -> ML-KEM-768 (floor=ML-KEM-768 enforced)` — **the
  money line.** Even at 100% battery pressure, the chosen crypto is ML-KEM-768. The floor held.
- `[PQC] Hybrid session key ready (X25519 + Kyber768 → HKDF-SHA256)` — the two-lock hybrid key
  was successfully created for this session.
- `[Bench] session=1 connect=0.2ms ai_rtt=38ms handshake=207ms [x25519_kg=1.3 kem_kg=0.2
  kem_decaps=0.04 net=205] kem=ML-KEM-768` — the **latency breakdown**. Notice `kem_kg` +
  `kem_decaps` ≈ **0.24 ms** out of a 207 ms handshake: **the post-quantum crypto is
  negligible; the 205 ms is network.**
- `[Monitor] ...` (only in the two-path testbed) — the background path watcher; it prints
  failover events like `*** PRIMARY PATH DOWN — emergency failover ***`.

On the **receiver** side: `[Receiver] msg 3 (13 B): ...` — it received and **decrypted** a
message, proving the end-to-end secure channel works.

---

## 9. The results and what they prove (your "findings")

| What you observe | What it proves |
|---|---|
| `[Crypto] battery=100% -> ML-KEM-768` | Battery/downgrade attacker **cannot weaken crypto** (the floor invariant) |
| AI flips LOW→HIGH on DDoS, but Crypto stays 768 | Crypto and threat are **decoupled** (the core design fix) |
| `[Bench]` ML-KEM ≈ 0.05 ms of ~200 ms | Post-quantum crypto is **cheap**; cost is the network |
| Receiver decrypts messages | The **end-to-end hybrid-PQC channel works** |
| Detector macro-F1 **0.87** (not 100%) on real data | The AI is **honestly evaluated**, not faked (`models/confusion_matrix_strat.png`) |
| (Two-path mode) traffic survives a cut path | **Multihoming failover** works |

---

## 10. Honest limits (say these if asked — they build trust)

- **Encryption is on, but the handshake is not yet *authenticated*.** We prove *confidentiality*
  (nobody can read it, even with a quantum computer later), but we don't yet verify *identity*.
  So **don't claim "man-in-the-middle resistance"** — that's the next phase (authentication).
- **The failover numbers are from an emulated two-path setup on one laptop.** The *mechanism* is
  real; the exact millisecond figures need two physical machines to confirm.
- **The AI's "MEDIUM" class is weak** and doesn't generalize across attack types — we report
  that honestly rather than hide it.
- **This is a research prototype**, not a hardened product. The main per-message delay is the
  AI round-trip and network, not the crypto.

> Calibrated honesty is a *strength* in a viva. Overclaiming is the fastest way to get caught.

---

## 11. If you remember only five sentences

1. It's a gateway that upgrades old traffic to **post-quantum encryption** without changing the
   old program.
2. It sends that traffic over a **two-path connection that survives a broken link** (SCTP
   multihoming + failover).
3. A small **AI** watches traffic and reacts on the **network** (failover/rate-limit) — it
   **never weakens the encryption**.
4. The encryption has a **floor** nothing can push below — defeating **battery-drain/downgrade
   attacks**; only high-assurance can *raise* it.
5. We measured everything honestly: the **post-quantum crypto is basically free** (~0.05 ms),
   and the **AI detector scores 0.87** on real attack data.
