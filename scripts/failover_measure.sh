#!/usr/bin/env bash
#
# failover_measure.sh — measure SCTP failover on the netns testbed (Phase 3 / Workstream C).
#
# Requires the streaming relay (a long-lived association) so failover can be exercised while
# traffic flows. Preconditions:
#   1) sudo ./scripts/setup_netns.sh up --netem
#   2) receiver + gateway running per setup_netns.sh, with the GATEWAY stdout captured
#      UNBUFFERED to a log file, e.g.:
#         stdbuf -o0 env GW_PEER_PRIMARY=10.0.0.2 GW_PEER_SECONDARY=10.0.1.2 \
#            GW_LOCAL_PRIMARY=10.0.0.1 GW_LOCAL_SECONDARY=10.0.1.1 ./gateway/gateway >gw.log 2>&1 &
#
# What it measures: wall time from cutting PATH 1 to the path monitor reporting the primary
# INACTIVE / emergency failover. Granularity is bounded by the monitor poll interval
# (MONITOR_INTERVAL_MS, default 2000 ms) and, on netns, absolute numbers are optimistic
# (shared CPU/kernel) — label results "netns-emulated" until a two-host run confirms them.
#
# Usage: sudo ./scripts/failover_measure.sh <gateway.log> [trials] [stream_interval_ms]
set -uo pipefail

GWLOG="${1:?usage: failover_measure.sh <gateway.log> [trials] [interval_ms]}"
TRIALS="${2:-20}"
INTERVAL_MS="${3:-50}"
CLIENT=./gateway/tcp_client
NETNS=./scripts/setup_netns.sh
MARKER="PRIMARY PATH DOWN"

command -v bc >/dev/null || { echo "needs 'bc'"; exit 1; }
[ -f "$GWLOG" ] || { echo "gateway log $GWLOG not found (is the gateway running?)"; exit 1; }

results=()
for t in $(seq 1 "$TRIALS"); do
  sudo "$NETNS" restore >/dev/null 2>&1
  sleep 2

  # Long-lived stream keeps ONE association alive at the gateway.
  "$CLIENT" "failover-probe" 0 "$INTERVAL_MS" >/dev/null 2>&1 &
  CLPID=$!
  sleep 2                                   # let the association + monitor settle

  base=$(grep -c "$MARKER" "$GWLOG")        # failover markers seen before the cut
  t_cut=$(date +%s.%N)
  sudo "$NETNS" cut >/dev/null 2>&1

  # Poll the gateway log until a NEW failover marker appears (timeout 10 s).
  t_detect=""
  for _ in $(seq 1 200); do
    now=$(grep -c "$MARKER" "$GWLOG")
    if [ "$now" -gt "$base" ]; then t_detect=$(date +%s.%N); break; fi
    sleep 0.05
  done

  kill "$CLPID" 2>/dev/null; wait "$CLPID" 2>/dev/null
  if [ -n "$t_detect" ]; then
    ms=$(echo "($t_detect - $t_cut) * 1000" | bc -l)
    printf "trial %2d: failover detected in %.1f ms\n" "$t" "$ms"
    results+=("$ms")
  else
    printf "trial %2d: NO failover detected within 10 s\n" "$t"
  fi
done

sudo "$NETNS" restore >/dev/null 2>&1

# mean ± 95% CI
n=${#results[@]}
[ "$n" -gt 0 ] || { echo "no successful trials"; exit 1; }
mean=$(printf '%s\n' "${results[@]}" | awk '{s+=$1} END{print s/NR}')
sd=$(printf '%s\n' "${results[@]}" | awk -v m="$mean" '{d=$1-m; s+=d*d} END{print (NR>1)?sqrt(s/(NR-1)):0}')
ci=$(echo "1.96 * $sd / sqrt($n)" | bc -l)
echo "-------------------------------------------------------"
printf "failover: mean %.1f ms  ± %.1f (95%% CI)  over %d trials  [netns-emulated]\n" \
       "$mean" "$ci" "$n"
echo "NOTE: granularity is bounded by MONITOR_INTERVAL_MS; re-confirm on two hosts."
