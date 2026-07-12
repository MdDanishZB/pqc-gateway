# Phase 3 — Real Testbed & Honest Measurement

> Goal: move the system off loopback onto a **genuine two-host, two-path testbed** (your two
> laptops), close the **live train/serve gap** left open in Phase 2 (the C side still emits
> the old feature vector), and produce **honest, CI-backed measurements** — real failover,
> real baselines, decomposed latency, and a model evaluated on the *actual features it
> serves*. This is the phase that produces your paper's evaluation section.
>
> Hardware fit: needs only the two laptops (+ one Ethernet cable / USB-Ethernet adapter). No
> MCU/power monitor — embedded energy stays out; a RAPL CPU-energy proxy is optional (§D).

---

## What Phase 3 must prove (and what it retires)

| Claim currently unfounded | Retired by |
|---|---|
| Multihoming/failover numbers (measured on `127.0.0.1`/`127.0.0.2`) | §A real two-path testbed + §C real link cut |
| The Phase 2 model works live (C still emits old features; µs schema mismatch) | §B windowed features + §E transfer validation |
| "<5 ms inference" / "32% crypto-time reduction" | §D latency decomposition + baselines |
| Detector transfers from CICFlowMeter flows to gateway traffic (assumed) | §E capture + evaluate on gateway features |

### Phase 3 at a glance (the live system, end of phase)

```
        LAPTOP A  (gateway)                                  LAPTOP B (receiver)
 ┌─────────────────────────────────────────┐          ┌──────────────────────────┐
 │ TCP client                               │          │                          │
 │   │                                      │  PATH 1  │  sctp_receiver           │
 │   ▼ recv() ─► window accumulator ────────┼══(eth)══►│   hybrid PQC handshake   │
 │            (metrics.c ring buffer)        │          │   AES-256-GCM decrypt    │
 │   │                                      │  PATH 2  │                          │
 │   ▼ get_window_features()  [µs, D2]       ┼══(wifi)═►│  (both paths ACTIVE via  │
 │   │                                      │          │   SCTP heartbeat)        │
 │   ├─► Unix socket ─► model_server (RF) ──► LOW/MED/HIGH └──────────────────────┘
 │   │                         │                        ▲
 │   │        ┌────────────────┴───────────────┐        │ failover on real link cut
 │   ▼        ▼ transport_policy               ▼ crypto_policy
 │  encrypt   failover / rate-limit / rekey    ML-KEM-768 FLOOR (never weakened)
 └─────────────────────────────────────────┘
        ▲                                   observability
        └── metrics HTTP POST ─► receiver.py ─► SQLite ─► Streamlit + grounded LLM
```

The detector output steers the **left/transport** path only; the **right/crypto** path is
floored and decoupled — the Phase-1 invariant, now exercised on real hardware.

---

## Prerequisite: the physical topology

Two real network paths between the two laptops so a path can be **physically severed**:

```
        Laptop A (gateway)                         Laptop B (sctp_receiver)
   ┌───────────────────────┐                  ┌───────────────────────┐
   │ eth0  10.0.0.1/24 ─────┼──── cable ───────┼─ eth0  10.0.0.2/24    │  PATH 1 (primary)
   │ wlan0 192.168.1.10 ────┼──── Wi-Fi/AP ─────┼─ wlan0 192.168.1.11   │  PATH 2 (secondary)
   └───────────────────────┘                  └───────────────────────┘
```

- **Path 1** = direct Ethernet cable, static IPs `10.0.0.0/24` — the one you physically unplug.
- **Path 2** = both laptops on the same Wi-Fi/LAN — survives the unplug.
- SCTP multihoming binds/​connects across both address pairs; heartbeats already probe both.
- Impairment via `tc netem` per interface; failure via unplug or `ip link set eth0 down`.

---

## Workstream A — Make the gateway testbed-configurable (kill loopback hardcoding)

**Files:** `gateway/multihoming.h`, `sctp_gateway.c`, `sctp_receiver.c`, `path_monitor.c`,
new `scripts/setup_testbed.sh`.

1. `PRIMARY_IP`/`SECONDARY_IP` are compile-time `#define`s in `multihoming.h` (loopback).
   Replace with **runtime config** read once at startup from env vars, with the loopback
   values as defaults so single-host dev still works:
   ```
   GW_PRIMARY_IP   (default 127.0.0.1)   GW_SECONDARY_IP (default 127.0.0.2)
   GW_PEER_PRIMARY GW_PEER_SECONDARY     GW_SCTP_PORT    (default 5000)
   ```
   Provide a small `net_config.{h,c}` (or extend `multihoming`) exposing getters; replace the
   ~10 `PRIMARY_IP`/`SECONDARY_IP`/`5000` references found in `sctp_gateway.c`,
   `path_monitor.c`, `sctp_receiver.c`. Also fix the hardcoded `strcpy(session.client_ip,
   "127.0.0.1")` in `sctp_gateway.c:54`.
2. The gateway (client) and receiver (server) now bind/connect to **their own two local IPs**
   and (client) `sctp_connectx` to the **peer's two IPs**. Confirm `multihome_server_create`
   binds both local addrs (it already `sctp_bindx`es the secondary).
3. `scripts/setup_testbed.sh <role>` — sets the static Ethernet IP, verifies Wi-Fi
   reachability, prints the env-var block to export on each laptop. Replaces the loopback
   alias step in `setup_net.sh` for the two-host case.
4. Smoke test: run receiver on B, gateway on A, send one message across the real link.

## Workstream B — C windowed features (the deferred Task 2.7 — closes the live gap)

**Files:** `gateway/metrics.c`/`.h`, `sctp_gateway.c`, `path_monitor.c`.

The Phase 2 model expects `iat_mean,iat_std,pkt_rate,byte_rate,mean_pkt_size,flow_duration`
in **microseconds**; the gateway still emits the old vector. Implement the real computation:

```
 recv() events over time  ──►  ring buffer  (last N=256 arrivals / last T=2 s)
   pkt1  pkt2  pkt3 ... pktN        (ts_us, size_bytes)  [mutex-guarded]
                                          │
                                          ▼  get_window_features(out[6])
        ┌───────────────┬───────────────┬───────────────┬───────────────┬───────────────┐
        │ iat_mean (µs) │ iat_std (µs)  │ pkt_rate (/s) │ byte_rate(/s) │ mean_pkt_size │  flow_duration(µs)
        └───────────────┴───────────────┴───────────────┴───────────────┴───────────────┘
                                          │
                     "iat_mean,iat_std,pkt_rate,byte_rate,mean_pkt_size,flow_duration"
                                          │  Unix socket  (SAME contract, NEW vector)
                                          ▼
                                    model_server (RF)  ─►  LOW / MEDIUM / HIGH
```


1. Add a **sliding-window accumulator** in `metrics.c`: a mutex-guarded ring buffer of recent
   packet events `(timestamp_us, size_bytes)` over a fixed horizon (e.g. last N=256 arrivals
   or a T=2 s window). Expose `get_window_features(double out[6])` returning the 6 features in
   the exact `features.py` order and **µs** units:
   - `iat_mean`, `iat_std` = mean/std of consecutive arrival gaps (µs)
   - `pkt_rate` = count / window_span_seconds
   - `byte_rate` = total_bytes / window_span_seconds
   - `mean_pkt_size` = total_bytes / count
   - `flow_duration` = last_ts − first_ts (µs)
2. Feed every `recv()` in `handle_client` (and any relayed packet) into the accumulator.
3. Replace the metric-string builders in `sctp_gateway.c` and `path_monitor.c` with
   `get_window_features()` output (drop the old latency/jitter/loss/throughput string).
4. Update `features.py` docstring's C-contract note to point at `get_window_features`.
   **Guard the units** — the single most likely bug is emitting ms where the model expects µs.

> **Design note / honesty:** CIC features are *per-flow*; this window is *aggregate recent
> traffic*. They are not identical. That mismatch is exactly what §E measures — do not assume
> the CIC-trained model transfers; prove it, and retrain on gateway features if it doesn't.

## Workstream C — Real failover & resilience measurement

**Files:** new `scripts/failover_measure.sh`, reuse `path_monitor.c` logs.

```
 t0            t1: cut          t2: detect         t3: on path2       t4: restore
 │──steady────►│ unplug eth0    │ path_monitor     │ traffic flowing  │ path1 back,
 │  (path1)    │ (PATH1 down)   │ sees INACTIVE    │ over wifi        │ failback
 ═════════════╪════════════════╪══════════════════╪══════════════════╪═══════════►  t
              │                                    │
              │◄────── failover time = t3 − t1 ───►│      ← measure ≥20× →
              │         packets lost in (t1,t3)    │        mean ± 95% CI
```

1. Establish an association, start steady traffic, then **cut path 1** (unplug cable or
   `ip link set eth0 down`) and later restore it.
2. Measure, over **≥ 20 trials**: time-to-failover (cut → traffic flowing on path 2),
   packets/bytes lost during transition, time-to-failback. Timestamp from `path_monitor`
   detection and from received-sequence gaps on the receiver.
3. Report **mean ± 95% CI**, not a single loopback number. Compare SCTP-native failover vs a
   TCP baseline that simply breaks (illustrates the multihoming benefit).

## Workstream D — Baselines & latency decomposition

**Files:** new `scripts/bench.sh`, small timing hooks in `pqc_handshake.c`, `sctp_gateway.c`.

```
 total handshake ≈ 238 ms  ──decompose──►   (illustrative shape; measure the real split)
   X25519 keygen+derive   ▓                    small
   ML-KEM keygen/encaps    ▓▓                   small   ◄─ refutes "32% crypto-time reduction"
   SCTP connect/setup      ▓▓▓
   AI Unix-socket round-trip ▓▓▓▓▓▓▓▓▓▓▓▓▓       likely DOMINATES the 238 ms
                           └────────────────────────────►  report mean ± 95% CI
```

1. **Baselines** for interpretable overhead: (a) no-crypto SCTP passthrough, (b) classical
   TLS/DTLS or X25519-only, (c) the hybrid. Report handshake time + steady throughput for each.
2. **Decompose the handshake latency** into: X25519 keygen/derive, ML-KEM keygen/encaps/decaps,
   SCTP setup, and the **AI Unix-socket round-trip**. This will show the KEM is a small
   fraction of the ~238 ms — which **refutes the old "32% crypto-time reduction"** claim.
   State the corrected breakdown.
3. Confirm/correct the **inference-latency** claim (Phase 2 measured ~11.6 ms single-vector,
   *above* "<5 ms"). Report the real number with CI.
4. All timings: **mean ± 95% CI over many runs**; drop false precision like "238.825 ms".
   Don't compare handshake-limited throughput against a raw AES-NI CPU benchmark.

## Workstream E — Model transfer validation (closes Phase 2's open risk)

**Files:** new `ai_module/capture_gateway_features.py`, `ai_module/eval_transfer.py`;
reuse `ai_module/simulator/traffic_generator.py`.

```
 traffic_generator ──(knows pattern = ground-truth label)──┐
   benign / DDoS / recon                                    │
        │  real traffic through the LIVE gateway            │
        ▼                                                   ▼
   get_window_features()  ─────────►  capture.csv (features + label)
                                             │
                        ┌────────────────────┴────────────────────┐
                        ▼                                          ▼
            eval CIC-trained model                     if transfer weak:
            on gateway features                        retrain RF on capture
            (honest confusion matrix,                  (split by session)
             macro-F1, FPR)                                    │
                        └───────────────► TRANSFER REPORT ◄─────┘
                                     update MODEL_CARD + rf_model.pkl
```

1. Drive **labeled real traffic** through the live gateway: benign (iperf / real requests),
   flood/DDoS (`hping3`, the traffic generator's DDoS mode), recon. The generator already
   knows which pattern it runs → that is the ground-truth label.
2. **Log the gateway's own `get_window_features` vectors** (from §B) alongside the label into
   a CSV — features measured exactly as served.
3. **Evaluate the Phase 2 CIC-trained model** on this gateway-feature capture. Report the
   honest transfer confusion matrix / macro-F1 / FPR.
4. **If transfer is weak (expected, given the per-flow vs window mismatch):** retrain / fine-
   tune the RF on the gateway-feature capture (train/test split by capture session) and report
   that model too. The deployed model is then validated on the *exact* features it serves —
   finally closing the train/serve loop. Update `MODEL_CARD.md` + `models/rf_model.pkl`.
   > Honest framing: CIC-IDS2017 gave the methodology and an in-lab number; the **gateway
   > capture is the real deployment dataset**. Report both; don't hide a transfer drop.

## Workstream F — LLM repositioning (from IMPROVEMENT_PLAN §5; independent track)

**Files:** `ai_module/llm/llm_advisor.py`, `dashboard/pages/3_analyst_chat.py`, `app.py`.

1. Remove the LLM from any decision role — it must not emit `threat_level`/`attack_type` that
   could feed control. The RF/controller decides; the LLM only **explains**.
2. Ground it: replace the raw `df.to_string()` context with a compact JSON of **actual events**
   (`{timestamp, rf_verdict, transport_action, active_path, kem_level, path_event}`) and a
   system prompt that says *"answer only from these events; if unsupported, say you don't
   know."* This is what stops hallucination.
3. Reconcile the backend story (`app.py` says Ollama; `.env` says Gemini) — read from
   `llm_config`. For the paper, scope the LLM explicitly as a non-security-critical aid.

---

## Sequencing (~2 weeks)

1. **A** testbed config + wiring (unblocks everything real).
2. **B** windowed features (makes live inference meaningful).
3. **E** capture + transfer eval + (likely) retrain — the key ML honesty step.
4. **C** and **D** measurement campaigns (parallelizable once A/B land).
5. **F** LLM repositioning (independent; do anytime).

## Acceptance criteria

- [ ] Gateway runs across **two physical hosts on two real paths**; loopback constants gone
      (env-configurable, loopback only as default).
- [ ] Live gateway emits the **µs D2 feature vector** via `get_window_features`; a live capture
      shows `model_server` logging **zero** skew-clip warnings under normal traffic.
- [ ] Failover measured on a **physically cut link**: mean ± 95% CI over ≥20 trials.
- [ ] Baselines (no-crypto / classical / hybrid) + **decomposed handshake latency** reported;
      the KEM's true (small) fraction shown; old "32% crypto-time" and "<5 ms" claims corrected.
- [ ] Phase 2 model evaluated on **gateway-measured features**; transfer reported honestly, and
      the served model retrained on gateway data if transfer is weak. `MODEL_CARD.md` updated.
- [ ] LLM is outside the decision loop, grounded in event records; backend story reconciled.

## Out of scope (later phases)

- DTLS-1.3-over-SCTP, ML-DSA authentication, full on-wire MitM/downgrade resistance → **Phase 4**.
- Formal floor-invariant proof (Tamarin/ProVerif) → **Phase 5**.
- Constrained-device battery energy → not available (no MCU); RAPL CPU-energy proxy optional.

## Risks

- **SCTP multihoming across two subnets can be finicky** (routing, `rp_filter`, firewalls). Budget
  time for `sysctl net.ipv4.conf.*.rp_filter=0` and route setup; verify both paths show ACTIVE
  in `get_path_status` before trusting failover numbers.
- **Transfer drop is likely, not a failure** — the per-flow → window mismatch is real; the plan
  already routes around it by retraining on gateway captures. Report the drop.
- **Unit (µs/ms) skew** in §B is the highest-probability regression — assert it with a live
  capture check, not just a unit test.
- **Wi-Fi variance** inflates latency CIs; run enough trials and report the spread honestly.
