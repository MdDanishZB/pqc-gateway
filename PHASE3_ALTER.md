# Phase 3 (Alternate) — Single-Laptop Testbed via Network Namespaces

> You don't have the second laptop yet. This plan does **as much of Phase 3 as can be done
> honestly on one machine**, using Linux **network namespaces + veth pairs** instead of the
> two-host wiring. It replaces only the *substrate* in `PHASE3_PLAN.md` — Workstreams B, D,
> E, F are done in full now; Workstream C (failover) is done for real *mechanically*, with
> its absolute timing clearly labeled as emulation until the second laptop confirms it.

---

## TL;DR — what changes and what doesn't

| Workstream | On one laptop (netns)? | Notes |
|---|---|---|
| **A** config (kill loopback hardcoding) | ✅ full | point at namespace IPs instead of loopback |
| **B** C windowed features (µs schema) | ✅ full | pure code — no network dependency |
| **C** real failover | ⚠️ mechanism real, timing emulated | `ip link set … down` = a **real** link failure; add `tc netem` for realistic RTT. Absolute ms numbers are optimistic (shared CPU/kernel) — re-confirm on 2 laptops. |
| **D** baselines + latency decomposition | ✅ full | crypto/AI timing, not network |
| **E** model transfer validation (+ retrain) | ✅ full | **the most valuable ML-honesty step — needs no 2nd machine** |
| **F** LLM repositioning | ✅ full | independent of hardware |

**Bottom line:** you can finish ~90% of Phase 3 now. Only the *headline absolute failover
latency / throughput numbers* need the real two-laptop run later. Everything you build here
(config, windowing, capture/retrain, measurement scripts) carries over unchanged.

## Why netns/veth is honest (and loopback aliases are not)

- `127.0.0.1` + `127.0.0.2` are the **same** interface talking to itself — no separate link
  state, so you can't actually "fail" a path (the old test faked it with `iptables DROP`).
- **veth pairs** are real virtual Ethernet links with independent state. `ip link set
  veth-gw1 down` is a genuine link-down event the SCTP stack sees and fails over from — the
  same code path a physical unplug would exercise.
- Each veth can carry its own `tc netem` delay/loss/jitter, so you can give the two paths
  *different, realistic* characteristics (e.g. 10 ms cable vs 30 ms Wi-Fi).

## Topology (one laptop)

Gateway + AI + dashboard stay in the **default** namespace (so the Unix socket to
`model_server` and the metrics POST to `receiver.py` keep working). The **receiver** runs in
its own namespace, reachable only over **two veth links** = two SCTP paths.

```
        DEFAULT namespace (gateway + model_server + receiver.py + Streamlit)
   ┌──────────────────────────────────────────────────────────┐
   │  gateway  ── Unix sock ──► model_server (RF)              │
   │     │  ── HTTP 8080 ──► receiver.py ─► SQLite ─► dashboard │
   │     │                                                     │
   │  veth-gw1 10.0.0.1/24 ●───────────┐   PATH 1 (primary)    │
   │  veth-gw2 10.0.1.1/24 ●─────────┐ │                       │
   └─────────────────────────────────┼─┼───────────────────────┘
                                     │ │
                          veth pair 2│ │veth pair 1
                                     │ │
   ┌─────────────────────────────────┼─┼───────────────────────┐
   │  veth-rx2 10.0.1.2/24 ●─────────┘ │   ns_rx namespace      │
   │  veth-rx1 10.0.0.2/24 ●───────────┘   (sctp_receiver)      │
   │                                                            │
   │  sctp_receiver  binds 10.0.0.2 + 10.0.1.2 (multihomed)     │
   └────────────────────────────────────────────────────────────┘

   Fail a path for real:   ip link set veth-gw1 down     (PATH 1 dies → SCTP uses PATH 2)
   Make it realistic:      tc qdisc add dev veth-gw1 root netem delay 10ms
                           tc qdisc add dev veth-gw2 root netem delay 30ms
```

## Setup script (new `scripts/setup_netns.sh`)

Creates the namespace, both veth pairs, assigns IPs, disables reverse-path filtering
(required for multihoming across two subnets), and optionally applies `tc netem`.

```bash
#!/usr/bin/env bash
set -e
RX=ns_rx
sudo ip netns add $RX

# Two veth pairs = two paths
sudo ip link add veth-gw1 type veth peer name veth-rx1
sudo ip link add veth-gw2 type veth peer name veth-rx2
sudo ip link set veth-rx1 netns $RX
sudo ip link set veth-rx2 netns $RX

# Addresses: path1 = 10.0.0.0/24, path2 = 10.0.1.0/24
sudo ip addr add 10.0.0.1/24 dev veth-gw1
sudo ip addr add 10.0.1.1/24 dev veth-gw2
sudo ip link set veth-gw1 up; sudo ip link set veth-gw2 up
sudo ip netns exec $RX ip addr add 10.0.0.2/24 dev veth-rx1
sudo ip netns exec $RX ip addr add 10.0.1.2/24 dev veth-rx2
sudo ip netns exec $RX ip link set veth-rx1 up
sudo ip netns exec $RX ip link set veth-rx2 up
sudo ip netns exec $RX ip link set lo up

# Multihoming across subnets needs rp_filter off
for i in all default veth-gw1 veth-gw2; do
  sudo sysctl -qw net.ipv4.conf.$i.rp_filter=0 || true
done
sudo ip netns exec $RX sysctl -qw net.ipv4.conf.all.rp_filter=0

# Optional realistic path conditions
# sudo tc qdisc add dev veth-gw1 root netem delay 10ms
# sudo tc qdisc add dev veth-gw2 root netem delay 30ms 5ms
echo "netns testbed up. Run receiver with:  sudo ip netns exec $RX ./sctp_receiver"
```

Teardown: `sudo ip netns del ns_rx && sudo ip link del veth-gw1 2>/dev/null; sudo ip link del veth-gw2 2>/dev/null`.

## Running the system on the netns testbed

```
Terminal 1  model_server        (default ns) — cd ai_module && python3 model_server.py
Terminal 2  receiver.py         (default ns) — cd ai_module && python3 dashboard/receiver.py
Terminal 3  sctp_receiver       (ns_rx)      — sudo ip netns exec ns_rx ./sctp_receiver
Terminal 4  gateway             (default ns) — GW_PRIMARY_IP=10.0.0.1 GW_SECONDARY_IP=10.0.1.1 \
                                               GW_PEER_PRIMARY=10.0.0.2 GW_PEER_SECONDARY=10.0.1.2 ./gateway
Terminal 5  fail a path         — sudo ip link set veth-gw1 down    (watch failover)
```

(The env-var config is Workstream A from `PHASE3_PLAN.md` — needed here too, since the
loopback `#define`s must become runtime values.)

## What each workstream looks like on one laptop

- **A / B / F** — identical to `PHASE3_PLAN.md`; no change.
- **C (failover):** drive steady traffic, `ip link set veth-gw1 down`, measure detect→failover
  time from `path_monitor` logs and receiver sequence gaps, `up` again for failback. Run ≥20×,
  report mean ± 95% CI. **Add `tc netem delay` so the paths have non-zero RTT** — otherwise the
  timing is unrealistically fast. Label these as *namespace-emulated*; the real absolute
  numbers come from the two-laptop run later.
- **D (latency/baselines):** unchanged and fully valid — this measures crypto + AI-round-trip
  time, which is independent of whether the network is real or emulated.
- **E (transfer validation) — do this now, it's the big win:** run
  `traffic_generator.py` (benign / DDoS / recon) through the live gateway on the netns
  testbed, log the gateway's `get_window_features` vectors + the generator's ground-truth
  label, evaluate the Phase-2 model on them, and retrain on the capture if transfer is weak.
  This closes the train/serve loop and needs only one machine.

## Simulating the "data" (your question, directly)

Two different things get simulated — keep them separate and honest:

1. **Network conditions** — `tc netem` on the veths gives real loss/delay/jitter. This is
   legitimate emulation, standard in networking papers.
2. **Traffic + labels for the ML** — `ai_module/simulator/traffic_generator.py` produces
   benign/DDoS/C2/congestion patterns; it *knows which pattern it emits*, so that is the
   ground-truth label for Workstream E. This is how you "make the data and make it work"
   without a second machine — you generate labeled traffic, push it through the real gateway,
   and measure what the gateway actually computes.

> Honesty guardrail: simulated **traffic** driving a **real gateway** measuring **real
> features** is fair evidence. What you must NOT do is go back to hand-drawn feature ranges
> (the Phase-1/2 sin) — the features must be computed by the live gateway from actual packets.

## Acceptance criteria (single-laptop phase)

- [ ] Gateway + receiver run in **separate network namespaces over two veth paths**; loopback
      `#define`s replaced by env config (Workstream A).
- [ ] Live gateway emits the **µs D2 feature vector** via `get_window_features`; `model_server`
      logs **zero** skew warnings on normal traffic (Workstream B).
- [ ] Failover triggered by a **real `ip link down`** (not iptables), measured ≥20× with
      `tc netem` RTT, reported mean ± 95% CI and **labeled "netns-emulated."**
- [ ] Handshake latency decomposed; KEM shown to be a small fraction (Workstream D).
- [ ] Phase-2 model evaluated on **gateway-measured features** from live simulated traffic;
      transfer reported honestly; model retrained on the capture if weak (Workstream E).
- [ ] LLM out of the decision loop, grounded in event records (Workstream F).

## What still needs the second laptop (defer, don't fake)

- **Absolute** failover latency, throughput, and jitter under real propagation and a real
  radio (Wi-Fi) — the netns numbers are optimistic because both ends share one CPU/kernel.
- Physical-unplug transients and link-layer behavior.
- → When the laptop arrives: re-run **only C and D** on real hardware and swap those numbers
  in. Everything else (A, B, E, F, all scripts and code) carries over unchanged.

## Writeup wording (so a reviewer trusts it)

State plainly: *"Evaluation was performed on a single-host testbed using Linux network
namespaces connected by two veth links with `tc netem` path emulation; link failure was
induced by administratively downing an interface. Absolute failover latencies are therefore
lower bounds pending a two-host validation."* That sentence is the difference between honest
emulation and overclaiming.
```
