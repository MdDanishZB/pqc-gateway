# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An **Intelligent Secure Gateway**: a research prototype that transparently upgrades legacy TCP
traffic into an authenticated, hybrid post-quantum SCTP tunnel, with **two independent ML
models** driving two separate control axes. The design's core invariant — and the thing every
change must preserve — is that these two axes **never cross**:

```
Legacy TCP Device
        |
Intelligent Secure Gateway
        |
        +-- Data sensitivity --> Security Policy Engine --> ML-KEM-768 floor
        |                                                    (ML-KEM-1024 only if CRITICAL)
        |
        +-- Network metrics ---> ML-A classifier ----------> SCTP transport policy
        |                        (STABLE...POSSIBLE_PATH_FAILURE)  (recommendation, or
        |                                                           ENFORCED with a real
        |                                                           multi-path testbed)
        |
        +-- ML-KEM -> HKDF-SHA-256 -> AES-256-GCM --> Secure SCTP Tunnel --> Control Center
```

`select_kem()` in `gateway/crypto_policy.c` takes **only** a `DataClassification` argument —
by its type signature it is structurally impossible for a network metric, an ML verdict, or a
battery signal to reach it. Never change that signature to accept anything else; that's the
whole point (see `IMPLEMENTATION_PLAN.md` and `OT_GATEWAY_PLAN.md` for the full rationale —
an earlier version of this project let the threat detector pick the KEM level, which was a
category error: a DDoS doesn't make a key breakable, and a bigger key doesn't stop a DDoS).

The runtimes (C gateway + C receiver, two Python ML servers, Streamlit dashboard) communicate
over **process boundaries**, not function calls — the wire contracts below matter more than any
single file.

## Wire contracts

- **C gateway <-> ML-B (threat detector)**: 6-field CSV over Unix socket
  `/tmp/ai_gateway.sock` (`gateway/ai_bridge.c:query_ai()` <-> `ai_module/model_server.py`).
  Feature order is fixed (`ai_module/features.py`):
  `iat_mean, iat_std, pkt_rate, byte_rate, mean_pkt_size, flow_duration` (µs for time fields).
  Reply is the literal `LOW`/`MEDIUM`/`HIGH`. Drives **transport response** (rate-limit/alert)
  via `transport_policy.c` — never crypto.
- **C gateway <-> ML-A (network-condition classifier)**: 5-field CSV over Unix socket
  `/tmp/ai_netcond.sock` (`gateway/ai_bridge.c:query_netcond()` <-> `ai_module/model_server.py`,
  served on a background thread). Feature order (`ai_module/net_features.py`):
  `rtt_ms, jitter_ms, loss_pct, throughput_kbps, cwnd`. Reply is one of
  `STABLE/CONGESTED/DEGRADED/UNSTABLE/POSSIBLE_PATH_FAILURE`. Mapped to a transport
  recommendation by `transport_policy.c:netstate_to_policy()`. **This is a separate model from
  ML-B** — don't conflate their sockets, features, or training data.
- **C gateway -> metrics sink**: raw HTTP/1.1 `POST /api/metrics` and `/api/path-event` to
  `127.0.0.1:8080` (`gateway/metrics_reporter.c`), hand-written, no libcurl. JSON keys are
  camelCase and must match the parser in `ai_module/dashboard/receiver.py`.
- **Data classification -> KEM level**: `gateway/crypto_policy.c:select_kem()`.
  `CLASS_CRITICAL -> ML-KEM-1024`; `CLASS_ROUTINE`/`CLASS_SENSITIVE -> ML-KEM-768` (the
  immutable floor). Read once per session in `sctp_gateway.c` from `GW_DATA_CLASS_FILE`
  (default `/tmp/gw_dataclass`, re-read every session so the dashboard can change it live) or
  `GW_DATA_CLASS` env, defaulting to `routine`.
- **Handshake wire format**: `gateway/pqc_handshake.h`. Initiator sends
  `[1B level][32B X25519 pub][NB ML-KEM pub][4B siglen][ML-DSA sig]`; responder replies
  `[32B X25519 pub][MB ML-KEM ct][4B siglen][ML-DSA sig]`. Each side verifies the other's
  signature against a **pinned** public key (`gateway/pqc_auth.c`); a missing or invalid
  signature aborts the handshake (downgrade/MitM defense). `AES-256-GCM` key =
  `HKDF-SHA256(X25519_secret || ML-KEM_secret)`.

## Post-quantum authentication (ML-DSA) — the #1 footgun

`pqc_auth.c` loads long-term ML-DSA-65 identities from **relative paths**:
`keys/gateway_sk.bin`, `keys/receiver_pk.bin` (initiator) and `keys/receiver_sk.bin`,
`keys/gateway_pk.bin` (responder), resolved from `keys/` under **whatever directory the process
was launched from** — not the binary's location. Both `gateway` and `sctp_receiver` **must be
launched with cwd = `gateway/`**, or they silently fall back to unauthenticated (printing a
`[PQC] WARNING: ML-DSA keys not loaded` line) — and if only *one* side falls back, the other
side (which does have its keys) will **abort every handshake** with
`auth: ... sent NO signature but auth is required -> ABORT`. This has bitten real test runs
twice; when a handshake mysteriously fails/aborts on a fresh terminal, check `pwd` first.

Generate the identities once (git-ignored, `gateway/keys/`):
```bash
cd gateway && make pqc_keygen && ./pqc_keygen
```
Override paths with `GW_INIT_SK`/`GW_RESP_PK` (initiator) or `GW_RESP_SK`/`GW_INIT_PK`
(responder) env vars if you need absolute paths instead.

## The two-pipeline invariant (read before touching crypto_policy.c or transport_policy.c)

| Axis | Input | Function | Output |
|---|---|---|---|
| **Security** | `DataClassification` (policy, not traffic) | `crypto_policy.c:select_kem()` | ML-KEM level, floor-enforced |
| **Resilience** | ML-A network state | `transport_policy.c:netstate_to_policy()` | transport recommendation/action |
| **Security response** | ML-B threat verdict | `transport_policy.c:decide_transport()` | transport action (rate-limit/failover) — still never crypto |

Both ML models are wired **only** into transport (`path_monitor.c`). If you ever find yourself
passing an ML verdict, a network metric, or a battery reading into anything in
`crypto_policy.c`, stop — that's the exact regression this project was rebuilt to eliminate.

## Failover: recommendation vs. enforced

`GW_TRANSPORT_ENFORCE` (env var, default unset/0) gates whether ML-A's `POSSIBLE_PATH_FAILURE`/
`UNSTABLE` predictions trigger a **real** proactive path switch (`path_monitor.c`) or stay a
logged recommendation only. **Only claim "enforced/real failover" when this is `1` AND the
gateway is running over a genuine multi-path link** (`scripts/setup_netns.sh`, real veth pairs
severed with `ip link down` — not loopback). The Streamlit "ENFORCED" badge
(`2_simulation.py`) reads this same env var from its own process, so pass it consistently to
both the gateway and Streamlit (`scripts/run_demo.sh` does this via `GW_TRANSPORT_ENFORCE`).

Path-preference stickiness: once a session fails over, `path_monitor.c` remembers and prefers
the healthy path for *new* sessions too (intentional — don't blindly retry a path that just
died). For repeatable failover measurement trials that all cut the same physical link, this
memory needs resetting between trials: touch `GW_PATH_RESET_FILE` (default
`/tmp/gw_path_reset`); the gateway consumes it once at the start of the next session.
`scripts/failover_measure.sh` already does this automatically.

## Two dashboards exist — Streamlit is current

**Use the Streamlit one** (`ai_module/dashboard/`); the Java Maven stack under `java_dashboard/`
is the older Spring Boot + JavaFX implementation and is effectively superseded — don't add new
features there. `README.md` documents the original C+Java architecture and is still accurate for
low-level gateway internals (SCTP/multihoming mechanics), but its framing of "AI picks the Kyber
level" and its "how to run" section are both outdated; trust this file and
`ai_module/dashboard/` over it.

Current pages (`ai_module/dashboard/pages/`):
- `1_live_monitor.py` — live metrics, active KEM, transport action.
- `2_simulation.py` — traffic/network sliders, the two-pipeline panels (data classification ->
  crypto; ML-A network condition -> transport recommendation/enforced).
- `4_threat_narrative.py` — now an **Evidence** page: both models' confusion matrices/F1 and a
  claims-discipline table (despite the filename, it no longer narrates via LLM).
- `5_pqc_visualizer.py` — handshake decomposition, ML-DSA auth status, self-test.

The LLM advisor (`llm_advisor.py`, `llm/`) is **parked** — deliberately kept outside the
decision loop and out of the current dashboard nav (`3_analyst_chat.py` and the old
`8_demo_scenarios.py`, which narrated the pre-redesign "AI escalates to Kyber-1024" story, were
both deleted for actively contradicting the current design). Don't re-wire the LLM into any
decision path; if resurrected, it must only explain already-made deterministic decisions.

## Build & run

### C gateway
```bash
cd gateway
make            # builds: gateway, sctp_receiver, tcp_client
make clean
```
The Makefile hardcodes a **locally-built liboqs** at `/home/danish/liboqs/install/usr/local/`
(include + lib paths). If liboqs lives elsewhere, edit `CFLAGS`/`LIBS` in `gateway/Makefile`.
Build liboqs from the vendored `liboqs/` source:
```bash
cd liboqs && mkdir -p build && cd build
cmake -DOQS_DIST_BUILD=ON .. && make -j$(nproc)
make install DESTDIR=/home/danish/liboqs/install
```
Link deps: `-lsctp -lpthread -lssl -lcrypto -loqs -lm` (needs `libsctp-dev`, OpenSSL 3+, liboqs).

Standalone proofs (run these before claiming anything is "real"):
```bash
make pqc_selftest      && ./pqc_selftest       # real ML-KEM-768: sizes, encaps/decaps, tamper-sensitive
make pqc_auth_selftest && ./pqc_auth_selftest  # real ML-DSA-65: sign/verify, tamper + wrong-key rejection
make tests/test_handshake && ./tests/test_handshake   # end-to-end authenticated handshake + forgery rejection
make test              # crypto policy, transport policy, netstate mapping, window features
```

### Python AI / dashboard
A venv already exists at `ai_module/venv` (there is **no requirements.txt** — install into that
venv directly). Key packages: `streamlit`, `pandas`, `plotly`, `scikit-learn`, `joblib`,
`requests`. Always `source ai_module/venv/bin/activate` first.

Retrain ML-B, the threat detector (regenerates `ai_module/models/rf_model.pkl` +
`label_encoder.pkl`, trained on real CIC-IDS2017 — see `MODEL_CARD.md`):
```bash
cd ai_module && source venv/bin/activate
python3 prepare_dataset.py    # dataset/*.parquet -> data/{strat,byday}_{train,test}.parquet
python3 train_model.py        # trains RandomForest, both splits
python3 evaluate.py           # -> models/metrics.json, confusion_matrix_*.png
```
(`generate_dataset.py` is the older, separable-by-construction synthetic generator kept only
for historical reference — do not use it to retrain the served model.)

Retrain ML-A, the network-condition classifier (regenerates
`ai_module/models/netcond_model.pkl`):
```bash
python3 netcond_dataset.py    # synthesizes overlapping STABLE..POSSIBLE_PATH_FAILURE states
python3 train_netcond.py      # -> models/netcond_model.pkl, netcond_metrics.json, confusion PNG
```
Both models are served together by `model_server.py` (run from `ai_module/`), on the two
sockets described above.

### Java dashboard (legacy)
```bash
cd java_dashboard && mvn package      # builds all three modules
```

## Running the full system

`model_server.py` and `receiver.py` both **load files by relative path**, so they must be
launched from the directory below (and the C binaries need `cwd = gateway/`, see the ML-DSA
section above):
- `model_server.py` does `joblib.load("models/rf_model.pkl")` -> run from `ai_module/`.
- `receiver.py` writes `metrics.db` in its cwd -> run from `ai_module/dashboard/` (per
  `scripts/run_demo.sh`) so it matches where the dashboard looks. A second, older `metrics.db`
  path may exist at the repo root from earlier runs; don't run two receivers at once.

**Fastest path — one-command launcher (loopback, Mode A):**
```bash
cd gateway && make && cd ..
./scripts/run_demo.sh start      # http://localhost:8501
./scripts/run_demo.sh seed       # warm up the charts
./scripts/run_demo.sh reset      # wipe metrics.db + reset data-classification between runs
./scripts/run_demo.sh stop
```
This trains ML-A and generates ML-DSA keys automatically on first run if missing.

**Manual order** (all AI/C processes, then the dashboard last):
AI model server -> metrics receiver -> `sctp_receiver` -> `gateway` -> `streamlit run
dashboard/app.py`.

## Real two-path testbed (netns) — for a genuine failover claim

`scripts/setup_netns.sh up --netem` builds two real veth links between the default namespace
(gateway) and `ns_rx` (receiver) — `ip link set ... down` severs a link for real, unlike a
loopback/iptables fake. `scripts/failover_measure.sh <gateway.log> [trials]` automates
cut/restore over N trials and reports mean +/- 95% CI, split by **proactive** (ML-A,
`GW_TRANSPORT_ENFORCE=1`) vs **reactive** (threat-driven, always on) trigger. Read the script
headers before running — both the gateway and `sctp_receiver` must be launched with
`cwd = gateway/` (see the ML-DSA footgun above) or the handshake will fail before there's
anything to fail over.

## SCTP dual-path convention

Default (loopback demo): primary `127.0.0.1:5000`, secondary `127.0.0.2:5000` — the secondary
alias must be added first (`scripts/setup_net.sh`, or `run_demo.sh start` does it). Real testbed
(netns): `10.0.0.x` / `10.0.1.x`, see above. All IPs are env-overridable via
`GW_LOCAL_PRIMARY`/`GW_LOCAL_SECONDARY`/`GW_PEER_PRIMARY`/`GW_PEER_SECONDARY`/`GW_SCTP_PORT`
(`gateway/net_config.c`). Failover mechanics live in `gateway/multihoming.c` (SCTP
setsockopt-level path control) and `gateway/path_monitor.c` (the autonomous poll loop that
queries both ML models and decides transport action). The liboqs `Kyber` API name in code is
OQS's ML-KEM equivalent; `OQS_SIG_alg_ml_dsa_65` is the ML-DSA-65 equivalent.
