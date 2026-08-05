# Live Demo & Presentation Plan

> Goal: run the whole prototype live, drive it through a UI, and visualize everything as it
> happens — normal traffic, a simulated attack, the AI reacting, the **security floor holding**,
> autonomous **failover**, and honest **measurements** — as a guided walkthrough for an evaluator.

---

## 1. The story you're telling (6 beats)

Every click should prove one of the project's real contributions. Structure the demo as a
narrative, not a feature tour:

| Beat | What the evaluator sees | The point it proves |
|---|---|---|
| **1. Transparent PQC upgrade** | a plain TCP message goes in, comes out the other side hybrid-PQC encrypted over SCTP | legacy traffic is upgraded with no client changes |
| **2. AI sees the traffic** | send "Normal" traffic → dashboard shows verdict **LOW** | the ML detector classifies live flows |
| **3. Attack detected** | switch to **DDoS** → verdict flips to **HIGH**, transport **rate-limits/alerts** | detection drives *availability* response |
| **4. The security floor (headline)** | under attack **and** a simulated "low battery", crypto **never drops below ML-KEM-768** | the novel, downgrade-proof contribution |
| **5. Autonomous failover** | cut a network path mid-stream → traffic keeps flowing on the 2nd path | SCTP multihoming + autonomous monitor |
| **6. Honest numbers** | show the `[Bench]` line (KEM ≈ 0.3 ms) + the real confusion matrix (macro-F1 0.87) | crypto is cheap; results aren't faked |

> The spine to say out loud: **"The AI controls *availability*; the crypto is *floored* and
> can't be weakened. Those two axes never cross — that's the core of the design."**

---

## 2. Two demo modes — pick based on risk tolerance

```
  MODE A — CORE (loopback, low-risk)              MODE B — FULL (netns, adds failover)
  ┌───────────────────────────────┐              ┌───────────────────────────────────┐
  │ all components on 127.0.0.1    │              │ two REAL veth paths on one laptop  │
  │ beats 1,2,3,4,6                │   +failover  │ = beats 1–6 including live cut     │
  │ no sudo needed for core        │  ───────────►│ needs sudo (netns + tc)            │
  │ zero chance of network hiccup  │              │ the "wow" moment, slightly riskier │
  └───────────────────────────────┘              └───────────────────────────────────┘
```

Recommendation: **rehearse Mode B, but keep Mode A as the guaranteed fallback.** If netns
misbehaves on the day, you still deliver 5 of 6 beats flawlessly on loopback.

---

## 3. Prep tasks (do these BEFORE demo day)

These make the demo smooth and let the UI tell the *current* (post-refactor) story. Each is
small; I can implement them on request.

1. **One-click launcher `scripts/run_demo.sh`** — starts, in order: `model_server`,
   `receiver.py`, `sctp_receiver`, `gateway`, `streamlit`; tails the gateway log to a visible
   pane. A `--netns` flag brings up the two-path testbed first. A `stop`/`reset` subcommand
   kills everything and clears `metrics.db`.
2. **Expose the security posture as env vars (critical for Beat 4).** The gateway currently
   hardcodes `{high_assurance:0, battery_pressure:0}`. Make it read `GW_BATTERY_PRESSURE` and
   `GW_HIGH_ASSURANCE` so you can, live, crank "battery pressure" to 100 and **show the KEM
   stays at ML-KEM-768** — the floor invariant made visible. (Small change in `sctp_gateway.c`.)
3. **Align the dashboard with the new narrative.** A few pages predate Phase 1–3 and still
   imply "Kyber scales with threat." Update them so they show the truth:
   - **Live Monitor**: add a **Security Floor** tile (current KEM level, with "floor = ML-KEM-768,
     battery can't lower it") and a **Transport Action** tile (NORMAL / RATE_LIMIT / FAILOVER).
   - **Threat Narrative**: repoint from the (parked) LLM to the **RF verdicts + path events**
     already in SQLite, so it reads live without the LLM.
   - **Simulation Control**: verify it targets the gateway at `127.0.0.1:4000` and that
     traffic patterns + `tc netem` sliders work.
4. **Add a Path & Failover view** (new page or panel): a small topology (PRIMARY / SECONDARY)
   with the **active path highlighted** and a live table of `path_events` (from/to/reason).
5. **Surface the latency decomposition** (Beat 6): simplest is a visible terminal pane showing
   the gateway's `[Bench]` line; optionally add a small bar in the UI.
6. **Warm-up + reset**: a script to pre-send a little traffic so charts aren't empty when you
   start, and a reset to clear `metrics.db` between rehearsal runs.
7. **Rehearse twice end-to-end** and screen-record a backup (see §7).

---

## 4. Screen layout for the demo

```
 ┌──────────────────────────────┬─────────────────────────────┐
 │  BROWSER — Streamlit dashboard │  TERMINAL — gateway log      │
 │  (your primary UI)             │  (live [Monitor]/[Bench])    │
 │  • Live Monitor (charts)       │  shows failover + latency    │
 │  • Simulation Control          │  decomposition as it happens │
 │  • Path & Failover             ├─────────────────────────────┤
 │  • PQC Visualizer              │  small TERMINAL — controls   │
 │                                │  (traffic gen / path cut)    │
 └──────────────────────────────┴─────────────────────────────┘
```

Keep the browser front-and-center; use the terminal panes to reveal the "under the hood"
moments (failover log line, the `[Bench]` KEM timing) that make it feel real.

---

## 5. Launch runbook (Mode B — full)

```bash
# 0) (once) build + model ready
cd gateway && make && cd ..
#    model artifacts already committed (rf_model.pkl, label_encoder.pkl)

# 1) bring up the two-path testbed
sudo ./scripts/setup_netns.sh up --netem

# 2) start the stack (each in its own pane; run_demo.sh will automate this)
cd ai_module && source venv/bin/activate
python3 model_server.py                     # AI detector (Unix socket)
python3 dashboard/receiver.py               # metrics -> SQLite
sudo ip netns exec ns_rx env GW_LOCAL_PRIMARY=10.0.0.2 GW_LOCAL_SECONDARY=10.0.1.2 \
     ../gateway/sctp_receiver                # receiver in the 2nd namespace
GW_PEER_PRIMARY=10.0.0.2 GW_PEER_SECONDARY=10.0.1.2 GW_LOCAL_PRIMARY=10.0.0.1 \
     GW_LOCAL_SECONDARY=10.0.1.1 stdbuf -o0 ../gateway/gateway    # gateway
streamlit run dashboard/app.py              # the UI -> http://localhost:8501

# 3) (Mode A fallback) skip step 1 and the GW_* vars — everything defaults to loopback
```

Drive traffic/attacks from the **Simulation Control** page (or the CLI):
```bash
# sustained normal / attack streams (keep ONE association alive)
./gateway/tcp_client "normal"  0 200     # ~5 msg/s
./gateway/tcp_client "flood"   0 2       # ~500 msg/s (DDoS-like)
# cut / restore a path mid-stream (Beat 5)
sudo ./scripts/setup_netns.sh cut
sudo ./scripts/setup_netns.sh restore
```

---

## 5b. Mode A quick-start (IMPLEMENTED & smoke-tested)

Everything for the loopback demo is built. One launcher runs it all:

```bash
cd ~/project-root
(cd gateway && make)                 # build once

./scripts/run_demo.sh start          # launches: model_server, receiver, sctp_receiver,
                                     #           gateway, streamlit  (http://localhost:8501)
./scripts/run_demo.sh seed           # optional: warm up the charts with a little traffic
./scripts/run_demo.sh calibrate      # optional but RECOMMENDED: retrains the detector on
                                     #   real gateway features so DDoS reliably reads HIGH
watch: tail -f .demo_logs/gateway.log   # live [Crypto]/[Bench]/[Monitor] lines

./scripts/run_demo.sh reset          # wipe metrics.db + posture between rehearsals
./scripts/run_demo.sh stop           # stop everything
```

Drive the demo from the browser (**Simulation Control** page: Start Normal / DDoS traffic,
the **Security Posture & Crypto Floor** panel for Beat 4) and watch the **Live Monitor**.

Verified headless already:
- Battery pressure = 100 → `[Crypto] battery=100% → ML-KEM-768 (floor enforced)` (Beat 4 ✅)
- `[Bench]` shows ML-KEM compute ≈ 0.26 ms of a ~207 ms handshake (Beat 6 ✅)
- metrics land in `metrics.db` and render on the Live Monitor (Beats 2/3 ✅)

Beat-4 live control: the **Security Posture** panel writes `/tmp/gw_posture`; the gateway
re-reads it every flow (no restart), so moving the battery slider to 100 and re-sending
traffic shows the KEM stay at ML-KEM-768.

## 6. The walkthrough (talk track — ~10–12 min)

**Intro (30s):** "This is a transparent gateway that upgrades legacy TCP traffic to
post-quantum-secured SCTP, with an AI that manages resilience — and a crypto floor an
attacker can't push through. Let me show it live."

1. **PQC upgrade (1 min).** Open **PQC Visualizer**; send one message with `tcp_client`.
   Point to the receiver pane decrypting it. *"Plain TCP in, hybrid X25519+ML-KEM out — the
   client changed nothing."*
2. **Normal traffic (1 min).** Simulation → **Normal** → Start. Live Monitor fills in;
   verdict **LOW**, path PRIMARY, crypto **ML-KEM-768**. *"The AI is classifying every flow."*
3. **Attack (2 min).** Switch to **DDoS**. Watch the verdict flip to **HIGH**, the
   Transport Action tile go **RATE_LIMIT/ALERT**. *"It detected a flood and responded on the
   availability axis."* Then the key line: *"Notice the crypto level — still ML-KEM-768."*
4. **The floor (2 min — the headline).** Crank **battery pressure to 100** (env/control).
   *"Now the device is 'dying' and an attacker would love to force weak crypto."* Show the KEM
   **stays at ML-KEM-768**. Optionally set high-assurance → it **rises to 1024** but never
   falls. *"Battery can only lower cost on the transport side; it can never breach the crypto
   floor. That asymmetry is the core contribution."*
5. **Failover (2 min).** With traffic streaming, run `setup_netns.sh cut`. In the gateway
   pane: `[Monitor] *** PRIMARY PATH DOWN — emergency failover ***`; the Path view flips the
   active path to SECONDARY; traffic keeps flowing. `restore` to fail back. *"One association,
   two real paths, autonomous switchover — no dropped session."*
6. **Honest numbers (2 min).** Point to the `[Bench]` line: *"The post-quantum crypto is
   about 0.3 ms of the handshake — negligible; the cost is the network, not the KEM."* Then
   show `models/confusion_matrix_strat.png`: *"On real CIC-IDS2017 data the detector is
   macro-F1 0.87 — a real number, not a suspicious 100%."*

**Close (30s):** the two-axis diagram from `FINAL_PROTOTYPE.md` + one line on what's next
(Phase 4 authentication, Phase 5 proof).

---

## 7. Robustness & fallbacks (protect the demo)

- **Screen-record a full clean run** beforehand. If anything hangs live, play the clip and
  narrate — never debug in front of the evaluator.
- **`reset` between rehearsals** (clear `metrics.db`) so charts start clean.
- **Pre-flight checklist** (run 10 min before): `make` is current; model files present;
  ports 8080/8501 free; `setup_netns.sh up` succeeds and both paths show **ACTIVE** in the
  gateway log; a warm-up burst has populated the charts.
- **Common gotchas:** sudo password prompt for `tc`/netns (run one sudo command first to
  cache it); `metrics.db` locked (only one `receiver.py`); empty charts (warm-up first);
  SCTP path stuck UNCONFIRMED (wait one heartbeat interval before cutting).
- **Keep Mode A ready** as the no-network-risk fallback for beats 1–4 and 6.
- **Don't run the LLM** (parked) — skip the Analyst Chat page so nothing depends on it.

---

## 8. Honesty guardrails (say these — evaluators trust calibrated claims)

- Say "hybrid post-quantum **encrypted**", **not** "authenticated / MitM-resistant" — that's
  Phase 4. Overclaiming here is the easiest way to lose credibility.
- Call the failover numbers **"namespace-emulated on one host; absolute latency pending a
  two-host run"** — the mechanism is real, the millisecond figure is optimistic.
- Present the detector's cross-attack result honestly (HIGH transfers, MEDIUM is weak) if
  asked — it shows you understand your own system.

---

## 9. What I can build next (pick any)

- `scripts/run_demo.sh` (+ `stop`/`reset`) — one-command launch.
- Env-driven security posture in `sctp_gateway.c` (so Beat 4 is a live toggle).
- Dashboard updates: Security-Floor tile, Transport-Action tile, Path & Failover page,
  LLM-free Threat Narrative.
- A warm-up/seed script for non-empty charts.

Suggested order: **run_demo.sh → posture env vars → dashboard tiles/failover page → warm-up.**
That sequence gets you to a fully rehearsable demo the fastest.
