#!/usr/bin/env bash
# setup_net.sh — one-time VM setup for pqc-gateway
# Run as a normal user; sudo is called internally where needed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PRIMARY_IP="127.0.0.1"
SECONDARY_IP="127.0.0.2"

banner() { echo; echo "──── $* ────"; }

# ── 1. Kernel modules ────────────────────────────────────────────────────────
banner "Loading SCTP kernel module"
if lsmod | grep -q '^sctp '; then
    echo "  sctp already loaded"
else
    sudo modprobe sctp
    echo "  sctp loaded"
fi

# ── 2. Secondary loopback alias ──────────────────────────────────────────────
banner "Configuring secondary loopback ($SECONDARY_IP)"
if ip addr show lo | grep -q "$SECONDARY_IP"; then
    echo "  $SECONDARY_IP already present on lo"
else
    sudo ip addr add "$SECONDARY_IP/8" dev lo
    echo "  Added $SECONDARY_IP to lo"
fi

# ── 3. System packages ───────────────────────────────────────────────────────
banner "Installing system packages"
sudo apt-get update -qq
sudo apt-get install -y \
    libsctp-dev \
    libssl-dev \
    liboqs-dev \
    iproute2 \
    iptables \
    python3-pip \
    default-jdk \
    maven

# ── 4. Python packages ───────────────────────────────────────────────────────
banner "Installing Python packages"
pip3 install --quiet scikit-learn pandas joblib

# ── 5. Build gateway ─────────────────────────────────────────────────────────
banner "Building gateway"
make -C "$REPO_ROOT/gateway" clean all

# ── 6. Train AI model ────────────────────────────────────────────────────────
banner "Generating dataset and training AI model"
(cd "$REPO_ROOT/ai_module" && python3 generate_dataset.py && python3 train_model.py)

banner "Setup complete"
echo
echo "  Run order:"
echo "    Terminal 1:  cd ai_module  && python3 model_server.py"
echo "    Terminal 2:  cd gateway    && ./sctp_receiver"
echo "    Terminal 3:  cd gateway    && ./gateway"
echo "    Terminal 4:  cd gateway    && ./tcp_client"
echo
