# Live Demo & Presentation Plan (v2 — post-redesign)

> Supersedes `DEMO_PLAN.md`, which still narrates the old battery-posture Beat 4 and references
> pages that no longer exist. This version reflects the current architecture: two independent
> ML models, each driving one axis, with the wall between them made **visible** in the UI.
> `DEMO_PLAN.md` is left in place for history; use this one.

---

## 1. The story you're telling (6 beats)

| Beat | What the evaluator sees | The point it proves |
|---|---|---|
| **1. Transparent PQC upgrade + real authentication** | a plain TCP message goes in, comes out hybrid-PQC encrypted over SCTP; both terminals show `ML-DSA-65 signature VERIFIED` | legacy traffic is upgraded with no client changes, AND the handshake is genuinely authenticated (anti-MitM) — not just confidential |
| **2. ML-B sees the traffic** | send "Normal" traffic → dashboard shows verdict **LOW** | the threat detector classifies live flows |
| **3. Attack detected** | switch to **DDoS** → verdict flips to **HIGH**, transport **rate-limits/alerts** | detection drives *availability* response |
| **4. THE FLOOR (headline)** | crank **Data Classification → CRITICAL** → KEM rises to ML-KEM-1024; set it back to ROUTINE while HIGH threat is active → KEM stays at ML-KEM-768 regardless | crypto strength is a **policy decision about the data**, not a network/threat decision — the two axes never cross |
| **5. ML-A sees the network, not the traffic** | congestion/loss sliders → **Classify Network Condition** → STABLE/CONGESTED/.../POSSIBLE_PATH_FAILURE → a transport recommendation; on a real two-path testbed with `GW_TRANSPORT_ENFORCE=1`, an actual failover | a **second**, independent ML model drives *resilience*, proven with a real severed link, not just a slider |
| **6. Honest numbers** | `[Bench]` line (KEM ≈ 0.05 ms), ML-B confusion matrix (macro-F1 0.87), ML-A confusion matrix vs. threshold baseline (0.93 vs 0.78), and the real failover mean ± 95% CI | crypto is cheap, both models are honestly evaluated, failover is *measured*, not asserted |

> The spine to say out loud: **"Two ML models, two separate jobs. One reads traffic and flags
> threats. One reads the network and recommends resilience actions. Neither one is allowed
> anywhere near the encryption — that's decided by data classification alone, and it can only
> go up from a floor that nothing else can move."**

---

## 2. Two demo modes — pick based on risk tolerance

```
  MODE A — CORE (loopback, low-risk)              MODE B — FULL (netns, real 2nd path)
  ┌───────────────────────────────┐              ┌───────────────────────────────────┐
  │ all components on 127.0.0.1    │              │ two REAL veth links (10.0.0.x/     │
  │ beats 1,2,3,4,6                │   +failover  │ 10.0.1.x) on one laptop            │
  │ ML-A is RECOMMENDATION-only    │  ───────────►│ = beats 1–6 including a REAL,      │
  │ no sudo needed for core        │              │ measured failover (severed link)   │
  │ zero chance of network hiccup  │              │ needs sudo (netns); the "wow" beat │
  └───────────────────────────────┘              └───────────────────────────────────┘
```

Recommendation: **rehearse Mode B, but keep Mode A as the guaranteed fallback.** Mode A alone is
still a complete, honest 5-of-6-beat demo; Mode B adds the one beat (real failover) that most
distinguishes this project.

---

## 3. Prep tasks (do these BEFORE demo day)

1. **Build + verify everything is real (2 min).**
   ```bash
   cd gateway && make
   make pqc_selftest      && ./pqc_selftest        # real ML-KEM-768
   make pqc_keygen        && ./pqc_keygen           # generates keys/*.bin (git-ignored)
   make pqc_auth_selftest && ./pqc_auth_selftest    # real ML-DSA-65
   make test                                        # crypto/transport policy unit tests
   ```
2. **Train ML-A if you haven't already** (`run_demo.sh start` does this automatically on first
   run, but do it once ahead of time so demo day has no surprises):
   ```bash
   cd ai_module && source venv/bin/activate
   python3 netcond_dataset.py && python3 train_netcond.py
   ```
3. **Rehearse Mode A** with `scripts/run_demo.sh` (see §5).
4. **Rehearse Mode B** with `scripts/setup_netns.sh` + `scripts/failover_measure.sh`
   (see §5b) — **critical gotcha**: both `gateway` and `sctp_receiver` must be launched with
   `cwd = gateway/`, or ML-DSA keys silently fail to load on one side, and the *other* side
   (which does have keys) will abort every handshake demanding a signature that never
   arrives. Confirm **both** terminals print `[PQC] Authentication: ML-DSA-65 (identity
   pinned)` before trusting anything downstream.
5. **Capture the real failover numbers once**, ahead of time, so you have them ready to quote
   even if you don't re-run the live cut on stage:
   ```bash
   sudo ./scripts/failover_measure.sh gw_netns.log 20
   ```
   Write the resulting `mean ± CI` (and proactive/reactive split) into your notes — don't
   improvise a number live.
6. **Screen-record a full clean run of Mode B** as a backup (see §7).

---

## 4. Screen layout for the demo

```
 ┌──────────────────────────────┬─────────────────────────────┐
 │  BROWSER — Streamlit dashboard │  TERMINAL — gateway log      │
 │  (your primary UI)             │  (live [Policy]/[NetML]/     │
 │  • Live Monitor                │   [PQC]/[Bench]/[Monitor])   │
 │  • Simulation Control          │  shows the ACTUAL decisions  │
 │    (two-pipeline panels)       │  as they happen, unfiltered  │
 │  • PQC & Trust                 ├─────────────────────────────┤
 │  • Evidence                    │  small TERMINAL — controls   │
 │                                │  (tcp_client / netns cut)    │
 └──────────────────────────────┴─────────────────────────────┘
```

Keep the browser front-and-center for the story; the terminal is your proof when someone asks
"is that really happening or is it a mock?"

---

## 5. Launch runbook — Mode A (loopback)

```bash
cd ~/project-root
(cd gateway && make)

./scripts/run_demo.sh start      # -> http://localhost:8501; trains ML-A / generates keys
                                  #    automatically on first run if missing
./scripts/run_demo.sh seed       # warm up the charts
tail -f .demo_logs/gateway.log   # watch [Policy]/[NetML]/[PQC]/[Bench]/[Monitor] live
```

Beat 4 live control (Data Classification):
```bash
echo critical > .demo_dataclass   # KEM -> ML-KEM-1024
echo routine  > .demo_dataclass   # back to the floor
```
Beat 5 in Mode A is **recommendation-only** — the UI's badge will correctly say so (it reads the
same `GW_TRANSPORT_ENFORCE` the gateway does, defaulted off by `run_demo.sh`). That's the honest
state; don't claim real failover here.

```bash
./scripts/run_demo.sh reset      # wipe metrics.db between rehearsals
./scripts/run_demo.sh stop
```

---

## 5b. Launch runbook — Mode B (real two-path failover)

**Terminal 1** — build the two real veth links:
```bash
sudo ./scripts/setup_netns.sh up --netem
```

**Terminal 2** — AI model server (loopback, no netns needed):
```bash
cd ~/project-root/ai_module && source venv/bin/activate && python3 model_server.py
```

**Terminal 3** — metrics receiver:
```bash
cd ~/project-root/ai_module && source venv/bin/activate && python3 dashboard/receiver.py
```

**Terminal 4** — SCTP receiver, inside `ns_rx`, **launched from `gateway/`**:
```bash
cd ~/project-root/gateway
sudo ip netns exec ns_rx env GW_LOCAL_PRIMARY=10.0.0.2 GW_LOCAL_SECONDARY=10.0.1.2 \
     GW_SCTP_PORT=5000 ./sctp_receiver
```

**Terminal 5** — the gateway, **launched from `gateway/`**, enforcement ON:
```bash
cd ~/project-root/gateway
GW_PEER_PRIMARY=10.0.0.2 GW_PEER_SECONDARY=10.0.1.2 \
     GW_LOCAL_PRIMARY=10.0.0.1 GW_LOCAL_SECONDARY=10.0.1.1 GW_SCTP_PORT=5000 \
     GW_TRANSPORT_ENFORCE=1 \
     stdbuf -o0 ./gateway 2>&1 | tee ../gw_netns.log
```
Confirm both Terminal 4 and Terminal 5 show `[PQC] Authentication: ML-DSA-65 (identity
pinned)` before proceeding — if either shows the "keys not loaded" warning, you're not in
`gateway/`.

**Terminal 6** — sanity-check one session, then either drive it live or run the batch:
```bash
cd ~/project-root
./gateway/tcp_client "demo-check" 0 1        # confirm a clean handshake first

# live, narrated cut/restore:
./gateway/tcp_client "demo-stream" 0 200 &
sudo ./scripts/setup_netns.sh cut            # watch Terminal 5 for the failover line
sudo ./scripts/setup_netns.sh restore

# OR the honest, repeatable measurement:
sudo ./scripts/failover_measure.sh gw_netns.log 20
```

Tear down when done:
```bash
sudo ./scripts/setup_netns.sh down
```

---

## 6. The walkthrough (talk track — ~11–13 min)

**Intro (30s):** "This gateway transparently upgrades legacy TCP traffic into an authenticated,
post-quantum-secured SCTP tunnel. Two independent AI models watch it — one for threats, one for
network health — and neither one is allowed to touch the encryption. Let me show it live."

1. **PQC upgrade + authentication (1.5 min).** Open **PQC & Trust**; send one message.
   *"Hybrid X25519 + ML-KEM-768, and — new — each side signs the handshake with a pinned
   ML-DSA-65 identity. If I swap in the wrong key here [optional: show the tamper/forgery
   test], the handshake aborts instead of silently succeeding. That's real MitM resistance,
   not just confidentiality."*
2. **Normal traffic (1 min).** Simulation Control → Normal → Start. *"ML-B reads the flow,
   says LOW."*
3. **Attack (2 min).** Switch to DDoS. *"Verdict flips to HIGH, transport rate-limits. Now
   look at the crypto column next to it — unchanged."*
4. **The floor (2.5 min — headline).** Simulation Control, Pipeline 1 panel. Set Data
   Classification → CRITICAL → Apply. *"KEM rises to ML-KEM-1024 — a policy decision about
   the data, not the network."* Set it back to ROUTINE while the DDoS from step 3 is still
   flagged HIGH. *"KEM drops back to the floor and stays there — threat level never moved it
   in the first place. The only thing that can raise crypto strength is an explicit
   classification. Nothing can lower it below the floor."*
5. **ML-A and resilience (2.5 min).** Pipeline 2 panel. Nudge the loss/jitter sliders,
   click Classify Network Condition. *"A second, completely separate model — different
   features, different socket, different training data from ML-B — reads network health and
   recommends a transport action."* **[Mode B]** *"And on a real second link — not loopback —
   that recommendation becomes a real failover."* Cut the link (live or narrate the recorded
   backup) and show the gateway log's failover line, plus the measured `mean ± CI` from your
   pre-captured run.
6. **Honest numbers (2 min).** `[Bench]` line: *"ML-KEM is about 0.05 ms of the handshake —
   negligible."* Evidence page: ML-B confusion matrix (macro-F1 0.87, real CIC-IDS2017), ML-A
   confusion matrix (macro-F1 0.93 vs. a 0.78 threshold baseline — it has to earn its place).
   *"No 100%, nothing asserted without a number behind it."*

**Close (30s):** the two-pipeline diagram + one line on what's next (real-topology validation,
formal floor proof).

---

## 7. Robustness & fallbacks

- **Screen-record a full clean Mode B run** beforehand, including a successful
  `failover_measure.sh` batch. If netns misbehaves live, play the recording and narrate.
- **Pre-flight checklist:** `make` current; both ML-DSA identities generated; ML-A trained;
  ports 8080/8501 free (`./scripts/run_demo.sh stop` + `rm -f /tmp/ai_*.sock` if in doubt);
  `setup_netns.sh up` succeeds; both terminals show the ML-DSA VERIFIED line, not the warning.
- **Common gotchas:** launching the C binaries from the wrong directory (breaks auth — see §3);
  a stale demo stack from `run_demo.sh` still holding port 8080 when you try to start the netns
  processes manually; sticky path preference making repeated manual cuts inconsistent (use
  `failover_measure.sh`, which resets it automatically, rather than hand-cutting many times).
- **Keep Mode A ready** as the no-sudo, no-network-risk fallback for beats 1–4 and 6.
- **Don't open the Analyst Chat page** — it was removed; if asked, say the LLM is deliberately
  kept outside the decision loop and isn't part of the current demo.

---

## 8. Honesty guardrails (say these — evaluators trust calibrated claims)

- Only claim "real, measured failover" for **Mode B with `GW_TRANSPORT_ENFORCE=1` over the
  netns testbed** — label the numbers "netns-emulated" (shared CPU/kernel; a two-*host* run
  would be the next rigor step) rather than absolute production latency.
- In Mode A, say "recommendation" for ML-A, not "failover" — the UI badge will already say this
  correctly, don't contradict it verbally.
- Present ML-A's honest limitation if asked: its training data is synthesized with deliberately
  overlapping state boundaries (not a real network capture) — the netns failover test is the
  closest thing to real-world validation it currently has.
- Present ML-B's cross-attack-variant result honestly if asked (HIGH transfers, MEDIUM is weak).
