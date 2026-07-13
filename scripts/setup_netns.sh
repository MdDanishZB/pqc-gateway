#!/usr/bin/env bash
#
# setup_netns.sh — single-laptop two-path SCTP testbed via network namespaces.
# See PHASE3_ALTER.md. Gives two REAL veth links (two SCTP paths) so a path can be
# failed for real with `ip link set ... down` (not an iptables fake on loopback).
#
#   Default ns: gateway + model_server + receiver.py + Streamlit
#     veth-gw1 10.0.0.1/24  (PATH 1, primary)     veth-gw2 10.0.1.1/24 (PATH 2)
#   ns_rx:      sctp_receiver
#     veth-rx1 10.0.0.2/24                          veth-rx2 10.0.1.2/24
#
# Usage:
#   sudo ./scripts/setup_netns.sh up            # create testbed
#   sudo ./scripts/setup_netns.sh up --netem     # + realistic per-path delay/jitter
#   sudo ./scripts/setup_netns.sh down           # tear down
#   sudo ./scripts/setup_netns.sh cut            # fail PATH 1 (down primary link)
#   sudo ./scripts/setup_netns.sh restore        # bring PATH 1 back
set -euo pipefail

RX=ns_rx
PORT=5000

require_root() { [ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }; }

up() {
  require_root
  ip netns add $RX 2>/dev/null || { echo "$RX exists; run 'down' first"; exit 1; }

  ip link add veth-gw1 type veth peer name veth-rx1
  ip link add veth-gw2 type veth peer name veth-rx2
  ip link set veth-rx1 netns $RX
  ip link set veth-rx2 netns $RX

  ip addr add 10.0.0.1/24 dev veth-gw1
  ip addr add 10.0.1.1/24 dev veth-gw2
  ip link set veth-gw1 up
  ip link set veth-gw2 up

  ip netns exec $RX ip addr add 10.0.0.2/24 dev veth-rx1
  ip netns exec $RX ip addr add 10.0.1.2/24 dev veth-rx2
  ip netns exec $RX ip link set veth-rx1 up
  ip netns exec $RX ip link set veth-rx2 up
  ip netns exec $RX ip link set lo up

  # Multihoming across two subnets needs reverse-path filtering disabled.
  for i in all default veth-gw1 veth-gw2; do
    sysctl -qw net.ipv4.conf.$i.rp_filter=0 2>/dev/null || true
  done
  ip netns exec $RX sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null || true

  if [ "${1:-}" = "--netem" ]; then
    tc qdisc add dev veth-gw1 root netem delay 10ms 2>/dev/null || true
    tc qdisc add dev veth-gw2 root netem delay 30ms 5ms 2>/dev/null || true
    echo "[netem] PATH1=10ms  PATH2=30ms±5ms"
  fi

  cat <<EOF
netns testbed UP.

Run the stack (each in its own terminal):
  1) cd ai_module && source venv/bin/activate && python3 model_server.py
  2) cd ai_module && source venv/bin/activate && python3 dashboard/receiver.py
  3) cd gateway   # IMPORTANT: both sctp_receiver and gateway load their ML-DSA keys
                  #  from the RELATIVE path keys/*.bin — you MUST launch them with
                  #  cwd=gateway/, or the handshake will be UNAUTHENTICATED (or the
                  #  gateway will ABORT expecting a signature the receiver never sends).
     sudo ip netns exec $RX env GW_LOCAL_PRIMARY=10.0.0.2 GW_LOCAL_SECONDARY=10.0.1.2 \\
         GW_SCTP_PORT=$PORT ./sctp_receiver
  4) (from gateway/ again, a different terminal)
     GW_PEER_PRIMARY=10.0.0.2 GW_PEER_SECONDARY=10.0.1.2 \\
         GW_LOCAL_PRIMARY=10.0.0.1 GW_LOCAL_SECONDARY=10.0.1.1 GW_SCTP_PORT=$PORT \\
         GW_TRANSPORT_ENFORCE=1 \\
         stdbuf -o0 ./gateway 2>&1 | tee ../gw_netns.log

     GW_TRANSPORT_ENFORCE=1 lets the ML-A network-condition classifier PROACTIVELY fail
     over on a predicted POSSIBLE_PATH_FAILURE/UNSTABLE state (logged "[NetML] *** proactive
     failover ***"), in addition to the existing threat-driven reactive failover (logged
     "[Monitor] *** PRIMARY PATH DOWN ***"). Omit it to keep ML-A recommendation-only.

  Check BOTH sides log "[PQC] Authentication: ML-DSA-65 (identity pinned)" — NOT the
  "keys not loaded" warning — before trusting any failover measurement below.

Fail / restore PATH 1:  sudo ./scripts/setup_netns.sh cut   |   restore
Measure it honestly:    sudo ./scripts/failover_measure.sh gw_netns.log 20
                         (run from ~/project-root, one level above gateway/)
EOF
}

down() {
  require_root
  ip netns del $RX 2>/dev/null || true
  ip link del veth-gw1 2>/dev/null || true
  ip link del veth-gw2 2>/dev/null || true
  echo "netns testbed DOWN."
}

cut()     { require_root; ip link set veth-gw1 down; echo "PATH 1 (veth-gw1) DOWN — expect failover to PATH 2"; }
restore() { require_root; ip link set veth-gw1 up;   echo "PATH 1 (veth-gw1) UP — expect failback"; }

case "${1:-}" in
  up)      shift; up "${1:-}";;
  down)    down;;
  cut)     cut;;
  restore) restore;;
  *) echo "usage: $0 {up [--netem]|down|cut|restore}"; exit 1;;
esac
