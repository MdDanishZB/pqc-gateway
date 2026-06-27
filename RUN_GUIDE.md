# PQC Gateway Run Guide

This guide provides instructions for running the AI-Optimized Post-Quantum SCTP Gateway project, including the new simulation and dashboard features.

## Prerequisites

- **Python 3.14+** with `venv`
- **C Compiler (gcc)** with `libsctp-dev`, `libssl-dev`, and `liboqs-dev`
- **Sudo privileges** (for `tc` network conditioning)
- **Gemini API Key** (for the Security Analyst Chat)

---

## Initial Setup

1. **Environment Variables**:
   Create a `.env` file in the root directory and add your Gemini API key:
   ```text
   GEMINI_API_KEY=your_actual_api_key_here
   LLM_BACKEND=gemini
   ```

2. **Network Setup**:
   Run the setup script to configure loopback aliases and install dependencies:
   ```bash
   sudo ./scripts/setup_net.sh
   ```

3. **Build the Gateway**:
   ```bash
   cd gateway && make clean all && cd ..
   ```

---

## Running the Complete System

To run the full prototype, you need to start several components. It is recommended to use separate terminal windows for each.

### 1. Start Backend Infrastructure

**Terminal 1: AI Model Server**
Provides real-time per-packet threat classification.
```bash
cd ai_module && source venv/bin/activate
python3 model_server.py
```

**Terminal 2: Metrics Receiver**
Collects session metrics into the SQLite database.
```bash
cd ai_module && source venv/bin/activate
python3 dashboard/receiver.py
```

**Terminal 3: LLM Advisor**
Provides high-level security analysis and threat narratives using the Gemini API.
```bash
cd ai_module && source venv/bin/activate
python3 llm/llm_advisor.py
```

### 2. Start the Gateway & Receiver

**Terminal 4: SCTP Receiver**
The destination for all forwarded and encrypted traffic.
```bash
cd gateway
./sctp_receiver
```

**Terminal 5: PQC Gateway**
The main proxy server.
```bash
cd gateway
./gateway
```

### 3. Start the Dashboard

**Terminal 6: Streamlit Dashboard**
The central control and visualization UI.
```bash
source ai_module/venv/bin/activate
streamlit run ai_module/dashboard/app.py
```
*Access the dashboard at `http://localhost:8501` (or the port specified in the terminal).*

---

## Using the Simulation Features

Once the system is running, navigate to the **Simulation Control** page in the dashboard:

1. **Start Traffic**: Choose a pattern (e.g., "Normal" or "DDoS") and click "Start Traffic".
2. **Apply Network Conditions**: Use the sliders to inject loss or latency, then click "Apply Conditions".
3. **Preset Scenarios**: Use the sidebar to quickly apply a complex scenario (e.g., "Severe Congestion").
4. **Observe**: Switch to the **Live Monitor** or **Live Threat Narrative** pages to see how the AI adapts security levels and paths in response to your changes.

---

## Troubleshooting

- **Sudo Password**: The "Network Condition Control" uses `sudo tc`. You might need to enter your password in the terminal where Streamlit is running if prompted.
- **Database Locked**: If you see SQLite locking errors, ensure only one instance of `receiver.py` is running.
- **Port Conflicts**: If port 8080 (Receiver) or 8501 (Streamlit) are occupied, the services will fail to start.
