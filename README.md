# AI-Optimized Post-Quantum SCTP Association Gateway

A research-grade network gateway that combines **post-quantum cryptography**, **AI-driven threat classification**, and **SCTP multihoming** into a single, observable system.

```
TCP Client → [Gateway] → PQC Handshake → AES-256-GCM → SCTP → Receiver
                 ↕                               ↕
           AI Model Server              Path Monitor Thread
                 ↕                               ↕
          Unix Domain Socket             HTTP POST (Python)
                                               ↕
                                        Streamlit Live Dashboard
```

---

## What Is Built

| Layer | Component | Status |
|---|---|---|
| **Transport** | SCTP multihoming (primary + secondary path) | Done |
| **Crypto** | Hybrid X25519 + Kyber KEM → HKDF → AES-256-GCM | Done |
| **AI** | Random Forest threat classifier (6 features) | Done |
| **Path Monitor** | Autonomous AI-driven failover background thread | Done |
| **Metrics** | Latency, jitter, packet loss, throughput, IAT, bandwidth | Done |
| **Dashboard** | Spring Boot REST + JavaFX live charts | Done |
| **Scripts** | VM setup, loss simulation, failover test | Done |

---

## Architecture — How It All Fits Together

### 1. Gateway (C) — `gateway/`

The gateway is a multi-threaded TCP→SCTP proxy. Each incoming TCP connection spawns a thread that runs this pipeline:

```
recv TCP data
    → measure inter-arrival time (IAT)
    → collect prior-session metrics (latency, jitter, loss, throughput, IAT, bw_util)
    → query AI model via Unix socket  →  LOW / MEDIUM / HIGH
    → select Kyber level (512 / 768 / 1024) based on AI verdict
    → multihome_client_connect() — SCTP with dual-path (127.0.0.1 + 127.0.0.2)
    → enable SCTP heartbeat (1 s interval)
    → path_monitor_register() — background thread watches this fd
    → pqc_initiator_handshake() — hybrid key exchange
    → encrypt_data_gcm() — AES-256-GCM with PQC-derived key
    → send encrypted payload over SCTP
    → record_send_result() + update_bandwidth_ema()
    → path_monitor_unregister() + close fds
    → report_session_metrics() → Spring Boot REST API
```

#### Key source files

| File | Purpose |
|---|---|
| [`sctp_gateway.c`](gateway/sctp_gateway.c) | Main orchestration — TCP accept loop + per-connection pipeline |
| [`pqc_handshake.c`](gateway/pqc_handshake.c) | Hybrid X25519+Kyber handshake, HKDF key derivation |
| [`pqc_handshake.h`](gateway/pqc_handshake.h) | Wire format documentation + public API |
| [`crypto_layer.c`](gateway/crypto_layer.c) | AES-256-GCM encrypt/decrypt (OpenSSL EVP) |
| [`multihoming.c`](gateway/multihoming.c) | SCTP dual-path connect, heartbeat, path query, failover |
| [`multihoming.h`](gateway/multihoming.h) | PathStatus, PathState, public API |
| [`path_monitor.c`](gateway/path_monitor.c) | AI-driven background monitor thread |
| [`path_monitor.h`](gateway/path_monitor.h) | Monitor lifecycle API |
| [`metrics.c`](gateway/metrics.c) | Jitter, loss window, IAT, bandwidth EMA |
| [`metrics.h`](gateway/metrics.h) | Metrics public API |
| [`ai_bridge.c`](gateway/ai_bridge.c) | Unix socket client → Python AI server |
| [`metrics_reporter.c`](gateway/metrics_reporter.c) | Raw HTTP/1.1 POST → Spring Boot |
| [`sctp_receiver.c`](gateway/sctp_receiver.c) | Receiving side: multihomed listen, PQC handshake, GCM decrypt |
| [`tcp_client.c`](gateway/tcp_client.c) | Test client — sends a message to the gateway TCP port |
| [`Makefile`](gateway/Makefile) | Builds `gateway`, `sctp_receiver`, `tcp_client` |

---

### 2. Post-Quantum Cryptography — Hybrid Handshake

The PQC handshake combines a **classical** and a **post-quantum** key exchange so that both must be broken simultaneously to compromise the session key.

```
Initiator → Responder
  [1 byte  : KyberLevel (0/1/2 = Kyber-512/768/1024)]
  [32 bytes : X25519 public key]
  [N bytes  : Kyber public key]     (800 / 1184 / 1568 B)

Responder → Initiator
  [32 bytes : X25519 public key]
  [M bytes  : Kyber ciphertext]     (768 / 1088 / 1568 B)

Both sides derive:
  ikm     = X25519_shared_secret (32 B) ‖ Kyber_shared_secret (32 B)
  aes_key = HKDF-SHA256(ikm, salt="pqc-gw", info="session-key", len=32)
```

**Kyber level selection** is driven by the AI:

| AI Verdict | Kyber Level | Key Size | Use Case |
|---|---|---|---|
| LOW | Kyber-512 | NIST Level 1 | Normal traffic |
| MEDIUM | Kyber-768 | NIST Level 3 | Moderate threat |
| HIGH | Kyber-1024 | NIST Level 5 | Active attack / DDoS |

---

### 3. AI Threat Classifier — `ai_module/`

A **Random Forest** classifier trained on 6 real-time network metrics.

#### Features

| Feature | Source | Description |
|---|---|---|
| `latency` | `timed_connect()` | SCTP connect RTT (ms) |
| `jitter` | `update_jitter()` | RFC-3550 `|current − previous|` (ms) |
| `packet_loss` | `get_packet_loss_pct()` | Rolling 100-sample window (%) |
| `throughput` | bytes received | Payload size per session (bytes) |
| `inter_arrival` | `measure_iat_ms()` | Time since previous TCP arrival (ms) |
| `bandwidth_util` | `get_bandwidth_util_pct()` | EMA throughput as % of 1 MB/s ref link |

#### Training labels (300 rows, 100 per class)

| Class | Pattern |
|---|---|
| **LOW** | Healthy: low latency (5–30 ms), low jitter, <1% loss, normal IAT (100–500 ms) |
| **MEDIUM** | Degraded: congested path OR bursty traffic (moderate IAT shifts) |
| **HIGH** | DDoS flood (IAT 1–10 ms, BW 70–99%) or C2 beacon (IAT 1000–3000 ms, BW <5%) |

#### Files

| File | Purpose |
|---|---|
| [`generate_dataset.py`](ai_module/generate_dataset.py) | Generates `dataset.csv` with realistic feature distributions |
| [`train_model.py`](ai_module/train_model.py) | Trains Random Forest, prints accuracy + feature importances, saves `.pkl` |
| [`model_server.py`](ai_module/model_server.py) | Unix socket server — receives CSV metrics string, returns LOW/MEDIUM/HIGH |

The C gateway sends metrics as a comma-separated string over `/tmp/ai_gateway.sock`. The Python server wraps it in a `pandas.DataFrame` and runs `model.predict()`.

---

### 4. SCTP Multihoming — Dual-Path Transport

The gateway uses two loopback addresses to simulate dual-homed SCTP:

- **Primary path**: `127.0.0.1:5000`
- **Secondary path**: `127.0.0.2:5000`

**Server side** (`sctp_receiver`): binds to primary with `bind()`, then calls `sctp_bindx(SCTP_BINDX_ADD_ADDR)` to add the secondary address. Both paths are active from the first handshake.

**Client side** (`gateway`): creates a `SOCK_SEQPACKET / IPPROTO_SCTP` socket and calls `sctp_connectx()` with both addresses so the SCTP association knows both paths from the start.

**Heartbeats**: enabled via `SCTP_PEER_ADDR_PARAMS` at 1-second intervals. The kernel probes both paths and marks inactive ones.

**Path info**: queried via `SCTP_GET_PEER_ADDR_INFO` to get per-path RTT, cwnd, and state.

**Failover**: performed via `SCTP_PRIMARY_ADDR` setsockopt — changes which path carries traffic without tearing down the association.

---

### 5. Path Monitor Thread — `path_monitor.c`

A background `pthread` that runs for the lifetime of the gateway and makes autonomous path decisions every 2 seconds.

```
Every 2 s:
  get_path_status(fd, PRIMARY_IP)    → PathStatus { state, rtt_ms, cwnd }
  get_path_status(fd, SECONDARY_IP)  → PathStatus
  build 6-value metrics string
  query_ai()  → LOW / MEDIUM / HIGH

  Decision logic:
    If on primary AND secondary available:
      primary DOWN                 → emergency failover to secondary
      AI == HIGH                   → autonomous changeover to secondary
    If on secondary AND AI == LOW AND primary active:
      → restore primary (threat cleared)
```

The monitor's preferred-path decision is persistent: `path_monitor_preferred_primary()` is called by each new connection to pick the right path immediately.

---

### 6. Real-Time Metrics — `metrics.c`

All metrics are thread-safe with dedicated mutexes.

| Function | Algorithm |
|---|---|
| `update_jitter(ms)` | RFC-3550: running `|current − previous|` |
| `get_last_latency_ms()` | Returns the latency stored by the most recent `timed_connect()` call |
| `record_send_result(ok)` | Pushes 0/1 into a circular buffer of 100 entries |
| `get_packet_loss_pct()` | Counts 0s in the circular buffer |
| `measure_iat_ms()` | `clock_gettime(CLOCK_MONOTONIC)` delta since previous call |
| `update_bandwidth_ema(bytes, ms)` | EMA with α=0.3; reference bandwidth 1 MB/s |
| `get_bandwidth_util_pct()` | `ema_bps / 1_000_000 × 100`, capped at 100 |

**Bootstrapping**: on the very first session, `get_last_latency_ms()` returns 0. Jitter and bandwidth update after the SCTP connect so subsequent sessions have real data.

---

### 7. Java Dashboard — `java_dashboard/`

A three-module Maven project:

```
java_dashboard/
├── pom.xml                    (parent)
├── spring-server/             (Spring Boot 3.2 — REST API + in-memory store)
├── analytics-engine/          (shared library — aggregation + log parsing)
└── dashboard-ui/              (JavaFX 21 — live charts + status panel)
```

#### Spring Boot server (`spring-server`)

Runs on port 8080. Three REST endpoints consumed by the C gateway and the JavaFX UI:

| Method | Path | Called by | Purpose |
|---|---|---|---|
| `POST` | `/api/metrics` | C gateway (`metrics_reporter.c`) | Store per-session metrics |
| `POST` | `/api/path-event` | C gateway | Store path failover events |
| `GET` | `/api/metrics/recent?n=N` | JavaFX | Last N session records |
| `GET` | `/api/path-events/recent?n=N` | JavaFX | Last N path events |
| `GET` | `/api/status` | JavaFX | Aggregate summary |

The C metrics reporter posts a raw HTTP/1.1 request over a plain TCP socket — no libcurl required. If Spring Boot is not running, the call returns silently within 1 second.

#### Analytics engine (`analytics-engine`)

Shared JAR depended on by both `spring-server` and `dashboard-ui`.

- `MetricsAggregator` — computes `avgLatency`, `maxLatency`, `avgThroughput`, `dominantAiMode` from a list of sessions via the `MetricsSummary` interface.
- `LogParser` — regex parser for gateway stdout (useful for offline analysis).

#### JavaFX dashboard (`dashboard-ui`)

Polls `/api/status`, `/api/metrics/recent`, `/api/path-events/recent` every 2 seconds.

- **Three live `LineChart`s**: latency (ms), throughput (B/s), packet loss (%).
- **Status panel**: current AI threat level (colour-coded: green/orange/red), Kyber level, active path, aggregate stats.
- **Path events table**: timestamped log of every failover with from/to/reason.

---

## How to Run

### Prerequisites (Ubuntu VM)

Run once after cloning:

```bash
chmod +x scripts/setup_net.sh
./scripts/setup_net.sh
# Manually build liboqs from source if not already installed system-wide:
# cd liboqs && mkdir -p build && cd build && cmake -DOQS_DIST_BUILD=ON .. && make -j$(nproc) && make install DESTDIR=/home/danish/liboqs/install
```

This installs: `libsctp-dev`, `libssl-dev`, `iproute2`, `iptables`, `python3-pip`, `default-jdk`, `maven`. Adds `127.0.0.2` to the loopback interface, builds the gateway, and trains the AI model.

### Run order (4 terminals + Streamlit Dashboard)

```
Terminal 1  — AI model server
  cd ai_module && source venv/bin/activate && python3 model_server.py

Terminal 2  — Streamlit Dashboard Receiver (HTTP listener on 8080)
  cd ai_module/dashboard && source ../venv/bin/activate && python3 receiver.py

Terminal 3  — SCTP receiver (the backend the gateway forwards to)
  cd gateway && ./sctp_receiver

Terminal 4  — Gateway
  cd gateway && ./gateway

Terminal 5  — Streamlit Dashboard App (Open http://127.0.0.1:8501 in your browser)
  cd ai_module/dashboard && source ../venv/bin/activate && streamlit run app.py --server.port 8501 --server.headless true
```

Optional: Send a test message
```
Terminal 6  — Send a test message
  cd gateway && ./tcp_client "Hello PQC Gateway!"
```

---

## Testing

### Simulate network degradation

```bash
# Apply 5% loss, 50 ms delay, 10 ms jitter (default)
./scripts/simulate_loss.sh

# Custom: 15% loss, 100 ms delay, 20 ms jitter
./scripts/simulate_loss.sh 15 100 20

# Remove all rules
./scripts/simulate_loss.sh reset
```

The AI model will escalate from LOW → MEDIUM → HIGH as conditions worsen. Watch the gateway terminal for Kyber level changes.

### Autonomous failover test

```bash
# Requires: sctp_receiver, gateway, and model_server all running
./scripts/failover_test.sh
```

The script:
1. Sends a baseline message (primary path, expected LOW/MEDIUM).
2. Blocks `127.0.0.1:5000` with iptables DROP rules.
3. Waits 3 s for the path monitor to detect failure.
4. Sends a second message — gateway routes via `127.0.0.2`.
5. Restores primary path and confirms failback.

Watch the gateway terminal for:
```
[Monitor] *** PRIMARY PATH DOWN — emergency failover ***
[Monitor] *** Threat cleared — switching back to primary ***
```

---

## Build

```bash
cd gateway

# Build all binaries
make

# Clean
make clean
```

Compiler flags: `-Wall -Wextra`
Link flags: `-lsctp -lpthread -lssl -lcrypto -loqs`

**Dependencies**: `libsctp-dev`, `libssl-dev` (OpenSSL 3+), `liboqs-dev` (Open Quantum Safe).

---

## Directory Layout

```
pqc-gateway/
├── gateway/                    C gateway (TCP→SCTP proxy + PQC + metrics)
│   ├── sctp_gateway.c          Main orchestration
│   ├── pqc_handshake.c/h       Hybrid X25519 + Kyber KEM handshake
│   ├── crypto_layer.c          AES-256-GCM encrypt/decrypt
│   ├── multihoming.c/h         SCTP dual-path connect + failover
│   ├── path_monitor.c/h        AI-driven background monitor thread
│   ├── metrics.c/h             Jitter, loss, IAT, bandwidth EMA
│   ├── metrics_reporter.c/h    HTTP POST → Spring Boot
│   ├── ai_bridge.c             Unix socket → Python AI server
│   ├── sctp_receiver.c         Receiving side
│   ├── tcp_client.c            Test sender
│   └── Makefile
│
├── ai_module/                  Python AI inference layer
│   ├── generate_dataset.py     Generates 300-row training dataset
│   ├── train_model.py          Trains + saves Random Forest model
│   ├── model_server.py         Unix socket server (real-time inference)
│   └── models/                 rf_model.pkl + label_encoder.pkl (generated)
│
├── java_dashboard/             Java observability layer
│   ├── spring-server/          Spring Boot 3.2 REST API
│   ├── analytics-engine/       Shared aggregation + log parsing library
│   ├── dashboard-ui/           JavaFX 21 live dashboard
│   └── pom.xml                 Parent POM
│
└── scripts/
    ├── setup_net.sh            One-time VM bootstrap
    ├── simulate_loss.sh        tc netem — inject loss/delay/jitter
    └── failover_test.sh        Automated iptables failover test
```

---

## Security Properties

- **Harvest-now-decrypt-later defence**: even if a future quantum computer breaks X25519, the Kyber KEM remains unbroken, and vice versa. Both must be broken simultaneously to recover the session key.
- **Adaptive key strength**: the AI selects Kyber-512, 768, or 1024 based on observed traffic anomalies — higher CPU cost only when the threat warrants it.
- **Authenticated encryption**: AES-256-GCM provides both confidentiality and integrity. A tampered ciphertext is rejected at `EVP_DecryptFinal_ex()` before any plaintext is exposed.
- **Ephemeral keys**: X25519 and Kyber keypairs are generated fresh per session. Secrets are wiped from the stack with `memset()` immediately after the HKDF derivation.
