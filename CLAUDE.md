# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An **AI-Optimized Post-Quantum SCTP Association Gateway**: a research prototype that chains
post-quantum crypto, an ML threat classifier, and SCTP multihoming into one observable
TCP→SCTP proxy. Data flow:

```
TCP client → [C gateway] → AI verdict picks Kyber level → hybrid X25519+Kyber handshake
           → AES-256-GCM → SCTP (dual-path) → sctp_receiver
                    │                                  │
              Unix socket to                    background path_monitor
              Python AI server                  thread (autonomous failover)
                    │
              HTTP POST session metrics → receiver.py → SQLite → Streamlit dashboard + LLM advisor
```

The three runtimes (C, Python, optional Java) communicate over **process boundaries**, not
function calls — understanding the wire contracts between them matters more than any single file:

- **C gateway ↔ Python AI**: a 6-field CSV string over the Unix socket `/tmp/ai_gateway.sock`,
  reply is the literal `LOW`/`MEDIUM`/`HIGH`. Feature order is fixed and must match on both sides
  (`gateway/ai_bridge.c` and `FEATURE_NAMES` in `ai_module/model_server.py`):
  `latency, jitter, packet_loss, throughput, inter_arrival, bandwidth_util`.
- **C gateway → metrics sink**: raw HTTP/1.1 `POST /api/metrics` and `/api/path-event` to
  `127.0.0.1:8080` (`gateway/metrics_reporter.c`), hand-written with no libcurl. JSON keys are
  camelCase (`latencyMs`, `aiDecision`, …) and must match the parser in `ai_module/dashboard/receiver.py`.
- **AI verdict → Kyber level**: LOW→Kyber-512, MEDIUM→Kyber-768, HIGH→Kyber-1024, selected per
  session in `sctp_gateway.c` and encoded as the first handshake byte (see `pqc_handshake.h` for
  the wire format).

## Two dashboards exist — Streamlit is current

There are two observability layers. **Use the Streamlit one** (`ai_module/dashboard/`, see
`RUN_GUIDE.md`); the Java Maven stack under `java_dashboard/` is the older Spring Boot + JavaFX
implementation described in `README.md` and is effectively superseded. Both consume the same
`127.0.0.1:8080` metrics POSTs — only one sink should run at a time. `README.md` documents the
original C+Java architecture in depth and is still accurate for the gateway internals; treat its
"how to run" section as outdated relative to `RUN_GUIDE.md`.

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
Link deps: `-lsctp -lpthread -lssl -lcrypto -loqs` (needs `libsctp-dev`, OpenSSL 3+, liboqs).

### Python AI / dashboard
A venv already exists at `ai_module/venv` (there is **no requirements.txt** — install into that
venv directly). Key packages: `streamlit`, `pandas`, `plotly`, `scikit-learn`, `joblib`,
`requests`, `google-genai`, `python-dotenv`. Always `source ai_module/venv/bin/activate` first.

Retrain the model (regenerates `ai_module/models/rf_model.pkl` + `label_encoder.pkl`):
```bash
cd ai_module && source venv/bin/activate
python3 generate_dataset.py   # writes dataset.csv (300 rows, 100/class)
python3 train_model.py        # trains Random Forest, prints accuracy + feature importances
```

### Java dashboard (legacy)
```bash
cd java_dashboard && mvn package      # builds all three modules
```

## Running the full system

`RUN_GUIDE.md` is the authoritative run order. `model_server.py` and `receiver.py` both
**load files by relative path**, so they must be launched from the directory the guide specifies:
- `model_server.py` does `joblib.load("models/rf_model.pkl")` → run from `ai_module/`.
- `receiver.py` writes `metrics.db` in its cwd → run from `ai_module/` (per the guide) so it
  matches where the dashboard/advisor look. Note a second copy lives at
  `ai_module/dashboard/metrics.db`; `llm_advisor.py` prefers that path and falls back to the root
  copy. Keep a single receiver running and be deliberate about cwd to avoid split DBs.

Typical order: AI model server → metrics receiver → (optional) LLM advisor → `sctp_receiver`
→ `gateway` → `streamlit run dashboard/app.py`.

## LLM backend

`ai_module/llm/llm_config.py` selects the backend via the `LLM_BACKEND` env var (default
`ollama`; the checked-in `.env` sets `gemini`). Ollama runs `llama3.1` locally at
`localhost:11434`; Gemini uses `gemini-2.0-flash` and needs `GEMINI_API_KEY` in `.env`. The
abstraction is in `llm_engine.py` (`PQCSecurityAnalyst`) — both backends are interchangeable, so
keep new code backend-agnostic and route through that class rather than calling a provider directly.

## Testing & simulation

There is no unit-test suite. "Testing" here means driving the live system:
```bash
./scripts/simulate_loss.sh [loss% delay_ms jitter_ms]   # tc netem on lo; `reset` to clear
./scripts/failover_test.sh                              # iptables DROP on 127.0.0.1, checks failover
```
The newer Streamlit **Simulation Control** page replaces the manual `tcp_client` / shell scripts:
`ai_module/simulator/traffic_generator.py` synthesizes Normal/DDoS/C2/Congestion/Mixed traffic and
`network_conditioner.py` wraps `sudo tc netem`. Both `tc` and `iptables` paths need sudo — the
Streamlit process may prompt for a password in its launching terminal.

## SCTP dual-path convention

Primary path is `127.0.0.1:5000`, secondary is `127.0.0.2:5000`. The secondary loopback alias
must be added before anything works (`scripts/setup_net.sh` does this). Failover logic lives in
`gateway/multihoming.c` (SCTP setsockopt-level path control) and `gateway/path_monitor.c` (the
autonomous 2-second decision loop that also queries the AI). The liboqs `Kyber` API name in code
is OQS's ML-KEM equivalent.
