# ai_module/simulator/scenarios.py

SCENARIOS = {
    "Normal Operation": {
        "traffic_pattern": "Normal",
        "network_conditions": {"loss": 0, "delay": 0, "jitter": 0},
        "description": "System operating under normal conditions with standard traffic."
    },
    "DDoS Attack": {
        "traffic_pattern": "DDoS",
        "network_conditions": {"loss": 2, "delay": 50, "jitter": 10},
        "description": "Simulated volumetric flood causing slight network degradation."
    },
    "C2 Beaconing": {
        "traffic_pattern": "C2 Beacon",
        "network_conditions": {"loss": 0, "delay": 0, "jitter": 0},
        "description": "Stealthy periodic communication typical of compromised hosts."
    },
    "Severe Congestion": {
        "traffic_pattern": "Congestion",
        "network_conditions": {"loss": 15, "delay": 200, "jitter": 50},
        "description": "High packet loss and latency, testing failover and adaptation."
    }
}
