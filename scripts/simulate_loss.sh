#!/usr/bin/env bash
# simulate_loss.sh — inject packet loss / latency on loopback via tc netem
#
# Usage:
#   ./simulate_loss.sh                     # defaults: 5% loss, 50ms delay, 10ms jitter
#   ./simulate_loss.sh <loss%> <delay_ms> <jitter_ms>
#   ./simulate_loss.sh reset               # remove all netem rules
#
# The AI model will adapt its threat level as conditions change.
# Watch the gateway terminal to see Kyber level and failover decisions respond.

set -euo pipefail

IFACE="lo"

reset_netem() {
    sudo tc qdisc del dev "$IFACE" root 2>/dev/null && \
        echo "[Sim] netem rules cleared on $IFACE" || \
        echo "[Sim] No netem rules to clear"
}

if [ "${1:-}" = "reset" ]; then
    reset_netem
    exit 0
fi

LOSS="${1:-5}"
DELAY="${2:-50}"
JITTER="${3:-10}"

echo "[Sim] Applying on $IFACE:"
echo "      packet loss : ${LOSS}%"
echo "      delay       : ${DELAY}ms ± ${JITTER}ms jitter"

# Remove any existing root qdisc first
reset_netem 2>/dev/null || true

sudo tc qdisc add dev "$IFACE" root netem \
    loss "${LOSS}%" \
    delay "${DELAY}ms" "${JITTER}ms" \
    distribution normal

echo "[Sim] Rules applied. Gateway AI should escalate threat level."
echo "      Run './simulate_loss.sh reset' to restore normal conditions."
echo
echo "      To verify:"
echo "        sudo tc qdisc show dev $IFACE"
