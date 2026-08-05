import time
import sqlite3
import pandas as pd
import os
import sys
import json

# Ensure we can import from the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ai_module.llm.llm_engine import PQCSecurityAnalyst
from ai_module.llm.llm_config import ANALYSIS_INTERVAL_SEC, METRICS_WINDOW_SIZE

DB_PATH = os.path.join(project_root, "ai_module", "dashboard", "metrics.db")
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(project_root, "metrics.db")

class LLMAdvisor:
    def __init__(self):
        self.analyst = PQCSecurityAnalyst()
        self.last_analyzed_id = 0

    def get_new_metrics(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            # Get metrics that haven't been analyzed yet
            df = pd.read_sql_query(
                f"SELECT * FROM metrics WHERE rowid > {self.last_analyzed_id} ORDER BY rowid DESC LIMIT {METRICS_WINDOW_SIZE}", 
                conn
            )
            if not df.empty:
                self.last_analyzed_id = pd.read_sql_query("SELECT MAX(rowid) FROM metrics", conn).iloc[0,0]
            conn.close()
            return df
        except Exception as e:
            print(f"Error fetching metrics: {e}")
            return pd.DataFrame()

    @staticmethod
    def _events_json(df):
        """Compact, authoritative decision records for grounding the LLM."""
        cols = [c for c in ("timestamp", "ai_decision", "kyber_level", "active_path",
                            "latency", "loss", "throughput") if c in df.columns]
        return json.dumps(df[cols].to_dict(orient="records"), default=str)

    @staticmethod
    def _dominant_verdict(df):
        """Echo the RF's own verdict — the LLM never (re)classifies threats."""
        if "ai_decision" in df.columns and not df["ai_decision"].dropna().empty:
            return df["ai_decision"].mode().iloc[0]
        return None

    def run(self):
        print(f"[*] LLM Advisor started (EXPLANATION only, out of the decision loop). "
              f"Polling every {ANALYSIS_INTERVAL_SEC}s...")
        while True:
            df = self.get_new_metrics()
            if not df.empty:
                print(f"[*] Explaining {len(df)} new event(s)...")
                events = self._events_json(df)

                # The LLM only NARRATES what the system already decided (grounded, refuses
                # when unsupported). It does not produce a threat classification.
                explanation = self.analyst.explain_events(events)

                # threat_level is the RF's OWN dominant verdict, echoed — not LLM-derived.
                verdict = self._dominant_verdict(df)
                summary = f"{len(df)} events; RF dominant verdict={verdict}"

                try:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute(
                        "INSERT INTO llm_analysis (metrics_summary, threat_level, "
                        "attack_type, confidence, explanation, recommendation) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (summary, verdict, "n/a (LLM does not classify)", None,
                         explanation, "See explanation; controls are automatic."))
                    conn.commit()
                    conn.close()
                    print("[+] Grounded explanation stored.")
                except Exception as e:
                    print(f"[!] DB store error: {e}")

            time.sleep(ANALYSIS_INTERVAL_SEC)

if __name__ == "__main__":
    advisor = LLMAdvisor()
    try:
        advisor.run()
    except KeyboardInterrupt:
        print("[*] LLM Advisor stopped.")
