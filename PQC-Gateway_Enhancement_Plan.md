# PQC Gateway Enhancement Plan (Final)

## Goal

Transform the project from a terminal-only C program into a fully interactive prototype with:

- Multi-page Streamlit dashboard (control + visualization)
- Traffic simulation engine (no more manual terminal commands)
- LLM-powered security analyst (Ollama local / Gemini API)
- Guided demo scenarios that run themselves

---

## Architecture: Hybrid Two-Tier Intelligence

```text
STREAMLIT DASHBOARD
├── Live Metrics (from RF)
├── Simulation Control (traffic + network)
├── Analyst Chat (from LLM)
└── Demos

            SQLite                    LLM API
               |                         |
               v                         v
      +----------------+      +------------------+
      | Metrics DB     |----->| LLM Advisor      |
      | (receiver.py)  |      | (llm_engine.py)  |
      +----------------+      | - Analyzes every 5s
               ^              | - Generates alerts
               |              | - Answers chat
           HTTP POST          +------------------+
               ^                         |
               |                   Ollama/Gemini
      +----------------+                |
      | C Gateway      |----------------+
      | (sctp_gateway) |
      +----------------+
               |
               v
      +----------------+
      | RF Model Server|
      | <5ms inference |
      +----------------+
```

Tier 1 (Real-Time): Random Forest per-packet (<5ms), drives Kyber level + path selection.  
Tier 2 (Analytical): LLM every 5s on batched metrics, provides explanations, predictions, chat, and narrative.

---

## LLM Backend Configuration

| Backend | Model | Latency | Setup |
|----------|--------|----------|--------|
| Ollama (offline) | Llama 3.1 8B / Phi-3 Mini | 200-500ms | `ollama pull llama3.1` |
| Gemini API (cloud) | Gemini 2.0 Flash | 300-800ms | API key in `.env` |

Both backends are interchangeable via a config flag.

---

# Phase 1: Traffic Simulation Engine

### `ai_module/simulator/traffic_generator.py`

Python-based traffic simulator replacing manual `tcp_client`:

- Normal: 1–50 msg/sec, realistic payloads (HTTP/IoT telemetry)
- DDoS: Burst packets, IAT < 10ms, high bandwidth → HIGH
- C2 Beacon: Periodic small payloads, IAT 1000–3000ms → HIGH
- Congestion: Medium latency + moderate loss → MEDIUM
- Mixed: Random blend cycling through all patterns

### `ai_module/simulator/network_conditioner.py`

Wraps `tc netem` for UI-controlled impairment:

- Latency (0–500ms)
- Loss (0–30%)
- Jitter (0–100ms)
- Callable from Streamlit sliders

---

# Phase 2: Multi-Page Streamlit Dashboard

## Page 1: Live Monitor

- Real-time gauges: latency, throughput, loss %, jitter
- Path status indicators (green/yellow/red for both SCTP paths)
- AI decision distribution pie chart
- Kyber level currently active
- Auto-refresh every 1 second

## Page 2: Simulation Control Panel

- Traffic pattern dropdown (Normal/DDoS/C2/Congestion/Mixed)
- Start/Stop buttons + rate slider
- Network condition sliders
- Failover trigger button
- Restore button
- One-click scenario presets

## Page 3: Security Analyst Chat (Flagship Feature)

- Interactive chat with the LLM about gateway state
- Example: “Why did you switch to Kyber-1024?”
- Metric-backed reasoning
- Context-aware access to metrics and history

## Page 4: Live Threat Narrative

Example:

```text
[14:32:15] Detecting anomalous traffic.
IAT dropped from 340ms to 4ms.
Resembles volumetric flood.
Escalating to Kyber-1024.
```

Replaces raw logs with human-readable commentary.

## Page 5: PQC Handshake Visualizer

1. Client generates X25519 + Kyber keypairs
2. Client sends public keys
3. Server responds with X25519 pubkey + Kyber ciphertext
4. Both derive: `IKM = X25519_shared || Kyber_shared`
5. HKDF → 32-byte AES-256-GCM key

Also includes:

- Kyber level comparison table
- Classical vs PQC explanation

## Page 6: Path & Failover Visualization

- Network topology diagram
- Active path highlighted
- Failover event timeline
- Demo failover button

## Page 7: AI & LLM Analytics

- RF decision history
- Feature importance chart
- LLM analysis log
- Prediction accuracy tracker
- Confidence scores

## Page 8: Guided Demo Scenarios

1. Normal Operation
2. DDoS Detection
3. Network Failure & Recovery
4. Adaptive Security

---

# Phase 3: LLM Integration

### `ai_module/llm/llm_engine.py`

```python
class PQCSecurityAnalyst:

    def analyze_metrics(self, metrics_window):
        pass

    def explain_decision(self, session_id):
        pass

    def predict_next_threat(self, history):
        pass

    def generate_narrative(self, event):
        pass

    def chat(self, operator_message, context):
        pass
```

### `ai_module/llm/llm_config.py`

```python
LLM_BACKEND = "ollama"  # or "gemini"
OLLAMA_MODEL = "llama3.1"
OLLAMA_URL = "http://localhost:11434"
GEMINI_MODEL = "gemini-2.0-flash"

ANALYSIS_INTERVAL_SEC = 5
METRICS_WINDOW_SIZE = 20
```

### `ai_module/llm/llm_advisor.py`

Background service:

- Polls SQLite every 5 seconds
- Sends windowed data to LLM
- Stores analysis in `llm_analysis`
- Can override RF decisions

---

# Phase 4: Supporting Changes

## Database Schema Additions

```sql
CREATE TABLE llm_analysis (
    id INTEGER PRIMARY KEY,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    metrics_summary TEXT,
    threat_level TEXT,
    attack_type TEXT,
    confidence REAL,
    explanation TEXT,
    recommendation TEXT,
    inference_time_ms REAL
);

CREATE TABLE chat_history (
    id INTEGER PRIMARY KEY,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    role TEXT,
    message TEXT
);
```

Enhanced metrics:

- handshake_duration_ms
- ai_inference_ms
- path_rtt_primary
- path_rtt_secondary

---

## C Gateway Metrics Enhancement

Add to `metrics_reporter.c`:

- Handshake duration
- AI inference latency
- Path RTT for both SCTP paths

---

## Single Launcher: `run_demo.sh`

```bash
#!/bin/bash

ollama serve &
python3 ai_module/model_server.py &
python3 ai_module/llm/llm_advisor.py &
python3 ai_module/dashboard/receiver.py &

./gateway/sctp_receiver &
./gateway/gateway &

streamlit run ai_module/dashboard/app.py
```

---

# Final File Structure

```text
ai_module/
├── llm/
│   ├── llm_engine.py
│   ├── llm_prompts.py
│   ├── llm_config.py
│   ├── llm_advisor.py
│   └── scenario_generator.py
├── simulator/
│   ├── traffic_generator.py
│   ├── network_conditioner.py
│   └── scenarios.py
├── dashboard/
│   ├── app.py
│   ├── receiver.py
│   └── pages/
│       ├── 1_live_monitor.py
│       ├── 2_simulation.py
│       ├── 3_analyst_chat.py
│       ├── 4_threat_narrative.py
│       ├── 5_pqc_visualizer.py
│       ├── 6_path_failover.py
│       ├── 7_ai_analytics.py
│       └── 8_demo_scenarios.py
├── metrics.db
├── model_server.py
├── generate_dataset.py
├── train_model.py
└── models/
    ├── rf_model.pkl
    └── label_encoder.pkl
```

---

# Implementation Order

| # | Task |
|---|------|
| 1 | Traffic Simulator |
| 2 | Enhanced Live Monitor |
| 3 | Simulation Control Panel |
| 4 | LLM Engine |
| 5 | Security Analyst Chat |
| 6 | Live Threat Narrative |
| 7 | PQC Handshake Visualizer |
| 8 | Path Failover Visualization |
| 9 | Guided Demo Scenarios |
| 10 | LLM Advisor Background Service |
| 11 | AI Analytics Page |
| 12 | Launcher Script |

---

# Dependencies

```txt
streamlit>=1.30
pandas
plotly
scikit-learn
requests
google-genai
graphviz
streamlit-chat
```

System: Ollama installed + model pulled:

```bash
ollama pull llama3.1
```

---

# End Result

The prototype demonstrates:

1. Post-Quantum Cryptography (Kyber + X25519)
2. SCTP Multihoming
3. ML Threat Classification
4. LLM Security Analysis
5. Adaptive Security
