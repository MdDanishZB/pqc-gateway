#!/usr/bin/env bash
# failover_test.sh — verify AI-driven autonomous SCTP path failover
#
# What this test does:
#   1. Sends a baseline message (primary path, expect LOW/MEDIUM threat)
#   2. Blocks primary path using iptables DROP rules
#   3. Waits for the path monitor to detect failure and switch to secondary
#   4. Sends a second message (should route via secondary 127.0.0.2)
#   5. Restores primary path and sends a final message (expect failback)
#
# Prerequisites:
#   - sctp_receiver running  (Terminal 2)
#   - gateway running        (Terminal 3)
#   - AI model_server running (Terminal 1)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATEWAY_DIR="$REPO_ROOT/gateway"

PRIMARY_IP="127.0.0.1"
SECONDARY_IP="127.0.0.2"
SCTP_PORT="5000"

MONITOR_POLL_S=3   # path_monitor polls every 2s; give it 3s margin

banner() { echo; echo "══════════════════════════════════════════════"; echo "  $*"; echo "══════════════════════════════════════════════"; }
step()   { echo; echo "  ── $* ──"; }

block_primary() {
    sudo iptables -I INPUT  1 -s "$PRIMARY_IP" -p sctp --dport "$SCTP_PORT" -j DROP
    sudo iptables -I OUTPUT 1 -d "$PRIMARY_IP" -p sctp --dport "$SCTP_PORT" -j DROP
    echo "  [iptables] PRIMARY path BLOCKED ($PRIMARY_IP:$SCTP_PORT)"
}

unblock_primary() {
    sudo iptables -D INPUT  -s "$PRIMARY_IP" -p sctp --dport "$SCTP_PORT" -j DROP 2>/dev/null || true
    sudo iptables -D OUTPUT -d "$PRIMARY_IP" -p sctp --dport "$SCTP_PORT" -j DROP 2>/dev/null || true
    echo "  [iptables] PRIMARY path RESTORED ($PRIMARY_IP:$SCTP_PORT)"
}

# Clean up iptables rules on exit (even on error)
trap unblock_primary EXIT

banner "PQC Gateway — Autonomous Failover Test"

# ── Phase 1: baseline ────────────────────────────────────────────────────────
step "Phase 1: Baseline message (primary path)"
"$GATEWAY_DIR/tcp_client"
echo "  ✓ Baseline sent"

sleep 1

# ── Phase 2: block primary ───────────────────────────────────────────────────
step "Phase 2: Blocking primary path ($PRIMARY_IP)"
block_primary

echo "  Waiting ${MONITOR_POLL_S}s for path monitor to detect failure..."
sleep "$MONITOR_POLL_S"

# ── Phase 3: send via secondary ──────────────────────────────────────────────
step "Phase 3: Message while primary is down (expect secondary path)"
"$GATEWAY_DIR/tcp_client"
echo "  ✓ Message sent — check gateway log for '[Monitor] *** PRIMARY PATH DOWN'"

sleep 1

# ── Phase 4: restore primary ─────────────────────────────────────────────────
step "Phase 4: Restoring primary path"
unblock_primary
trap - EXIT   # cancel the trap; we already cleaned up

echo "  Waiting ${MONITOR_POLL_S}s for path monitor to detect recovery..."
sleep "$MONITOR_POLL_S"

# ── Phase 5: confirm failback ────────────────────────────────────────────────
step "Phase 5: Message after recovery (expect failback to primary)"
"$GATEWAY_DIR/tcp_client"
echo "  ✓ Message sent — check gateway log for '[Monitor] *** Threat cleared'"

banner "Failover test complete"
echo
echo "  What to look for in the gateway terminal:"
echo "    [Monitor] *** PRIMARY PATH DOWN — emergency failover ***"
echo "    [Monitor] Primary path switched to $SECONDARY_IP:$SCTP_PORT"
echo "    [Monitor] *** Threat cleared — switching back to primary ***"
echo "    [Monitor] Primary path switched to $PRIMARY_IP:$SCTP_PORT"
echo
