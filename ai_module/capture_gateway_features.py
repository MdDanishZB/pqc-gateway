"""
capture_gateway_features.py — drive one labeled traffic pattern through the LIVE gateway so
model_server.py can log the gateway-measured feature vectors (Phase 3 / Workstream E).

Workflow (each pattern captured separately, one label at a time):

  1) Start the stack (model_server with capture enabled), e.g.:
       GW_CAPTURE_CSV=cap_high.csv GW_CAPTURE_LABEL=HIGH python3 model_server.py
     ...plus receiver.py, sctp_receiver, gateway (see setup_netns.sh).

  2) Drive traffic of the matching pattern for a while:
       python3 capture_gateway_features.py --pattern DDoS --duration 60

  3) Repeat for other patterns with a fresh GW_CAPTURE_LABEL, then concatenate the CSVs and:
       python3 eval_transfer.py --capture cap_all.csv

Pattern -> severity label (keep GW_CAPTURE_LABEL consistent with --pattern):
    Normal     -> LOW
    Congestion -> LOW      (benign traffic under a degraded link)
    C2 Beacon  -> MEDIUM   (botnet-style beaconing)
    DDoS       -> HIGH
"""
import argparse
import time

from simulator.traffic_generator import TrafficGenerator

PATTERN_LABEL = {"Normal": "LOW", "Congestion": "LOW", "C2 Beacon": "MEDIUM", "DDoS": "HIGH"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pattern", required=True, choices=list(PATTERN_LABEL))
    ap.add_argument("--duration", type=int, default=60, help="seconds")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4000)
    args = ap.parse_args()

    print(f"[capture] pattern={args.pattern} (label {PATTERN_LABEL[args.pattern]}) "
          f"for {args.duration}s -> gateway {args.host}:{args.port}")
    print("[capture] ensure model_server was started with "
          f"GW_CAPTURE_LABEL={PATTERN_LABEL[args.pattern]} and GW_CAPTURE_CSV set.")

    gen = TrafficGenerator(host=args.host, port=args.port)
    gen.pattern = args.pattern
    gen.running = True
    import threading
    t = threading.Thread(target=gen._worker, daemon=True)
    t.start()
    time.sleep(args.duration)
    gen.running = False
    time.sleep(1)
    print("[capture] done.")


if __name__ == "__main__":
    main()
