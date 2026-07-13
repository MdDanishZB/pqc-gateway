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
#            GW_LOCAL_PRIMARY=10.0.0.1 GW_LOCAL_SECONDARY=10.0.1.1 \
#            GW_TRANSPORT_ENFORCE=1 ./gateway/gateway >gw.log 2>&1 &
#
# What it measures: wall time from cutting PATH 1 to a failover being triggered. Two
# independent triggers now exist and are reported SEPARATELY:
#   REACTIVE  — the threat-driven path monitor sees the primary go INACTIVE and fails over
#               unconditionally ("[Monitor] *** PRIMARY PATH DOWN ***"). Always active.
#   PROACTIVE — the ML-A network-condition classifier predicts POSSIBLE_PATH_FAILURE /
#               UNSTABLE and fails over BEFORE (or without waiting for) the hard-down
#               detection ("[NetML] *** proactive failover ***"). Only fires if the
#               gateway was started with GW_TRANSPORT_ENFORCE=1.
# Whichever marker appears FIRST in a trial is the one counted for that trial's latency.
# Granularity is bounded by the monitor poll interval (MONITOR_INTERVAL_MS, default 2000 ms)
# and, on netns, absolute numbers are optimistic (shared CPU/kernel) — label results
# "netns-emulated" until a two-host run confirms them.
#
# Usage: sudo ./scripts/failover_measure.sh <gateway.log> [trials] [stream_interval_ms]
set -uo pipefail

GWLOG="${1:?usage: failover_measure.sh <gateway.log> [trials] [interval_ms]}"
TRIALS="${2:-20}"
INTERVAL_MS="${3:-50}"
CLIENT=./gateway/tcp_client
NETNS=./scripts/setup_netns.sh
MARKER_REACTIVE="PRIMARY PATH DOWN"
MARKER_PROACTIVE="proactive failover"
PATH_RESET_FILE="${GW_PATH_RESET_FILE:-/tmp/gw_path_reset}"

command -v bc >/dev/null || { echo "needs 'bc'"; exit 1; }
[ -f "$GWLOG" ] || { echo "gateway log $GWLOG not found (is the gateway running?)"; exit 1; }

results=()
kinds=()
for t in $(seq 1 "$TRIALS"); do
  sudo "$NETNS" restore >/dev/null 2>&1

  # Failover stickiness is intentional (path_monitor.h): once a session fails over, new
  # sessions prefer the healthy path rather than blindly retrying the one that just died.
  # For repeatable trials that all cut the SAME physical link, forget that memory so each
  # trial's new session starts fresh on the configured primary.
  touch "$PATH_RESET_FILE"
  sleep 2

  # Long-lived stream keeps ONE association alive at the gateway.
  "$CLIENT" "failover-probe" 0 "$INTERVAL_MS" >/dev/null 2>&1 &
  CLPID=$!
  sleep 2                                   # let the association + monitor settle

  base_r=$(grep -c "$MARKER_REACTIVE"  "$GWLOG")
  base_p=$(grep -c "$MARKER_PROACTIVE" "$GWLOG")
  t_cut=$(date +%s.%N)
  sudo "$NETNS" cut >/dev/null 2>&1

  # Poll the gateway log until a NEW marker of EITHER kind appears (timeout 10 s).
  t_detect="" ; kind=""
  for _ in $(seq 1 200); do
    now_r=$(grep -c "$MARKER_REACTIVE"  "$GWLOG")
    now_p=$(grep -c "$MARKER_PROACTIVE" "$GWLOG")
    if [ "$now_p" -gt "$base_p" ]; then t_detect=$(date +%s.%N); kind="proactive"; break; fi
    if [ "$now_r" -gt "$base_r" ]; then t_detect=$(date +%s.%N); kind="reactive";  break; fi
    sleep 0.05
  done

  kill "$CLPID" 2>/dev/null; wait "$CLPID" 2>/dev/null
  if [ -n "$t_detect" ]; then
    ms=$(echo "($t_detect - $t_cut) * 1000" | bc -l)
    printf "trial %2d: %-9s failover detected in %.1f ms\n" "$t" "$kind" "$ms"
    results+=("$ms")
    kinds+=("$kind")
  else
    printf "trial %2d: NO failover detected within 10 s\n" "$t"
  fi
done

sudo "$NETNS" restore >/dev/null 2>&1

# mean ± 95% CI (all trials, either kind)
n=${#results[@]}
[ "$n" -gt 0 ] || { echo "no successful trials"; exit 1; }
mean=$(printf '%s\n' "${results[@]}" | awk '{s+=$1} END{print s/NR}')
sd=$(printf '%s\n' "${results[@]}" | awk -v m="$mean" '{d=$1-m; s+=d*d} END{print (NR>1)?sqrt(s/(NR-1)):0}')
ci=$(echo "1.96 * $sd / sqrt($n)" | bc -l)
n_proactive=$(printf '%s\n' "${kinds[@]}" | grep -c proactive || true)
n_reactive=$(printf '%s\n' "${kinds[@]}" | grep -c reactive || true)
echo "-------------------------------------------------------"
printf "failover: mean %.1f ms  ± %.1f (95%% CI)  over %d trials  [netns-emulated]\n" \
       "$mean" "$ci" "$n"
printf "  proactive (ML-A, GW_TRANSPORT_ENFORCE=1): %d trials\n" "$n_proactive"
printf "  reactive  (threat-driven, always on):     %d trials\n" "$n_reactive"
echo "NOTE: granularity is bounded by MONITOR_INTERVAL_MS; re-confirm on two hosts."
