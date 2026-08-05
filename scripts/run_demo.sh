#!/usr/bin/env bash
#
# run_demo.sh — one-command launcher for the Mode A (loopback) live demo.
# See DEMO_PLAN.md.
#
#   ./scripts/run_demo.sh start      # launch the whole stack (loopback)
#   ./scripts/run_demo.sh seed       # send a short normal-traffic burst (warm up charts)
#   ./scripts/run_demo.sh stop       # stop everything
#   ./scripts/run_demo.sh reset      # stop + wipe metrics.db + reset posture
#   ./scripts/run_demo.sh calibrate  # (optional) retrain the detector on real gateway
#                                     #  features so Normal->LOW / DDoS->HIGH is reliable
#   ./scripts/run_demo.sh status     # what's running
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GW="$ROOT/gateway"
AI="$ROOT/ai_module"
VENV="$AI/venv/bin/activate"
DB="$AI/dashboard/metrics.db"
DATACLASS="$ROOT/.demo_dataclass"
CAP="$AI/gateway_capture.csv"
LOGS="$ROOT/.demo_logs"
PIDF="$ROOT/.demo_pids"
mkdir -p "$LOGS"

py() { ( cd "$AI" && source "$VENV" && "$@" ); }
save_pid() { printf '%s %s\n' "$1" "$2" >> "$PIDF"; }
run_bg() {
    local log_file="$1"
    shift
    nohup "$@" >"$log_file" 2>&1 &
    echo $!
}

start_core() {
    [ -f "$VENV" ] || { echo "venv missing at $VENV"; exit 1; }
    [ -x "$GW/gateway" ] || { echo "build first: (cd gateway && make)"; exit 1; }
    stop_all >/dev/null 2>&1 || true
    rm -f "$PIDF" "$LOGS"/model_server.log "$LOGS"/receiver.log "$LOGS"/sctp_receiver.log "$LOGS"/gateway.log "$LOGS"/streamlit.log
    : > "$PIDF"
    echo "routine" > "$DATACLASS"                 # data classification -> ML-KEM-768 floor
    sudo ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true

    # Off by default: this is the loopback demo (Mode A), not a real multi-path testbed, so
    # ML-A's failover recommendations stay advisory. Pass GW_TRANSPORT_ENFORCE=1 in your own
    # environment before calling this script ONLY if you're running against a real two-path
    # setup (see scripts/setup_netns.sh) — the gateway and this dashboard must agree, or the
    # UI's ENFORCED badge would lie about what the gateway is actually doing.
    ENFORCE="${GW_TRANSPORT_ENFORCE:-0}"

    # One-time assets: ML-DSA identities (handshake auth) + ML-A network-condition model.
    if [ ! -f "$GW/keys/gateway_sk.bin" ]; then
        echo "[0/5] generating ML-DSA identities (keys/)..."
        ( cd "$GW" && make pqc_keygen >/dev/null 2>&1 && ./pqc_keygen >/dev/null 2>&1 ) || \
            echo "  (warning: keygen failed — handshake will be UNAUTHENTICATED)"
    fi
    if [ ! -f "$AI/models/netcond_model.pkl" ]; then
        echo "[0/5] training ML-A network-condition model..."
        py python3 netcond_dataset.py >/dev/null 2>&1 && py python3 train_netcond.py >/dev/null 2>&1 || \
            echo "  (warning: ML-A training failed — network-condition panel will be inert)"
    fi

    echo "[1/5] AI model server..."
    save_pid model_server "$(run_bg "$LOGS/model_server.log" bash -c "cd '$AI' && . '$VENV' && stdbuf -o0 python3 model_server.py")"
    sleep 1.5

    echo "[2/5] metrics receiver..."
    save_pid receiver "$(run_bg "$LOGS/receiver.log" bash -c "cd '$AI/dashboard' && . '$VENV' && stdbuf -o0 python3 receiver.py")"
    sleep 1

    echo "[3/5] SCTP receiver..."
    save_pid sctp_receiver "$(run_bg "$LOGS/sctp_receiver.log" bash -c "cd '$GW' && stdbuf -o0 ./sctp_receiver")"
    sleep 0.8

    echo "[4/5] gateway (watch $LOGS/gateway.log for [Bench]/[Monitor]/[Policy]/[NetML])..."
    save_pid gateway "$(run_bg "$LOGS/gateway.log" bash -c "cd '$GW' && GW_DATA_CLASS_FILE='$DATACLASS' GW_TRANSPORT_ENFORCE='$ENFORCE' stdbuf -o0 ./gateway")"
    sleep 0.8

    echo "[5/5] Streamlit dashboard -> http://localhost:8501"
    # Pass the SAME data-classification file + gateway-log path + enforcement flag the
    # gateway uses, so the UI's classification control, PQC live view, and the ENFORCED/
    # recommendation badge all agree with what the gateway is actually doing.
    save_pid streamlit "$(run_bg "$LOGS/streamlit.log" bash -c "cd '$AI' && . '$VENV' && GW_DATA_CLASS_FILE='$DATACLASS' GW_LOG='$LOGS/gateway.log' GW_TRANSPORT_ENFORCE='$ENFORCE' streamlit run dashboard/app.py --server.port 8501 --server.headless true")"

    echo
    echo "Stack up. Dashboard: http://localhost:8501"
    echo "Live gateway log:    tail -f $LOGS/gateway.log"
    echo "Crypto policy:       echo 'critical' > $DATACLASS   (CRITICAL data -> ML-KEM-1024)"
    if [ "$ENFORCE" = "1" ]; then
        echo "Transport policy:    ENFORCED (GW_TRANSPORT_ENFORCE=1) — only meaningful over a real multi-path testbed"
    else
        echo "Transport policy:    recommendation-only (loopback demo — set GW_TRANSPORT_ENFORCE=1 for a real testbed)"
    fi
}

seed() {
    echo "seeding warm-up traffic..."
    "$GW/tcp_client" "warmup"  20 150 >/dev/null 2>&1 || true
    echo "done."
}

stop_all() {
    if [ -f "$PIDF" ]; then
        while read -r name pid; do
            [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null && echo "stopped $name ($pid)"
        done < "$PIDF"
        rm -f "$PIDF"
    fi
    pkill -f 'model_server.py' 2>/dev/null || true
    pkill -f 'dashboard/receiver.py' 2>/dev/null || true
    pkill -f 'receiver.py' 2>/dev/null || true
    pkill -f 'sctp_receiver' 2>/dev/null || true
    pkill -f '(^|/)gateway($| )' 2>/dev/null || true
    pkill -f 'streamlit' 2>/dev/null || true
    echo "all stopped."
}

reset_all() {
    stop_all
    rm -f "$DB" "$AI/metrics.db" "$ROOT/metrics.db" "$AI/dashboard/metrics.db" 2>/dev/null || true
    mkdir -p "$ROOT/.demo_logs"
    echo "routine" > "$DATACLASS"
    echo "metrics.db wiped, data classification reset to routine."
}

status() {
    [ -f "$PIDF" ] || { echo "not started"; return; }
    while read -r name pid; do
        if kill -0 "$pid" 2>/dev/null; then echo "UP    $name ($pid)"; else echo "DOWN  $name"; fi
    done < "$PIDF"
}

calibrate() {
    # Retrain the served detector on features the gateway ACTUALLY measures, so the
    # demo reliably shows Normal->LOW and DDoS->HIGH (closes the CIC->gateway gap).
    # Requires the core stack running. Restarts model_server with capture enabled.
    echo "== calibrate: capturing gateway features per pattern =="
    pkill -f 'model_server.py' 2>/dev/null; sleep 1
    rm -f "$CAP"
    ( cd "$AI" && source "$VENV" && GW_CAPTURE_CSV="$CAP" \
        GW_CAPTURE_LABEL_FILE=/tmp/gw_caplabel stdbuf -o0 python3 model_server.py ) \
        >"$LOGS/model_server.log" 2>&1 & save_pid model_server $!
    sleep 1.5
    declare -A P=( [Normal]=LOW [DDoS]=HIGH ["C2 Beacon"]=MEDIUM )
    for pat in "Normal" "DDoS" "C2 Beacon"; do
        echo "  capturing '$pat' -> ${P[$pat]} (25s)"
        echo "${P[$pat]}" > /tmp/gw_caplabel
        py python3 capture_gateway_features.py --pattern "$pat" --duration 25 >/dev/null 2>&1 || true
    done
    echo "== retraining served model on $CAP =="
    py python3 retrain_gateway.py --capture "$CAP"
    echo "== restarting model_server with the calibrated model =="
    pkill -f 'model_server.py' 2>/dev/null; sleep 1
    ( cd "$AI" && source "$VENV" && stdbuf -o0 python3 model_server.py ) \
        >"$LOGS/model_server.log" 2>&1 & save_pid model_server $!
    echo "calibrate done."
}

case "${1:-}" in
    start)     start_core;;
    seed)      seed;;
    stop)      stop_all;;
    reset)     reset_all;;
    status)    status;;
    calibrate) calibrate;;
    *) echo "usage: $0 {start|seed|stop|reset|status|calibrate}"; exit 1;;
esac
