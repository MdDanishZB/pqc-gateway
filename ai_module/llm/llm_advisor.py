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

    def run(self):
        print(f"[*] LLM Advisor started. Polling every {ANALYSIS_INTERVAL_SEC}s...")
        while True:
            df = self.get_new_metrics()
            if not df.empty:
                print(f"[*] Analyzing {len(df)} new metrics...")
                metrics_str = df.to_string()
                
                # We ask the LLM for a structured analysis
                prompt = (
                    f"Analyze these PQC Gateway metrics:\n{metrics_str}\n\n"
                    "Provide a JSON response with these fields:\n"
                    "metrics_summary (short string),\n"
                    "threat_level (LOW, MEDIUM, or HIGH),\n"
                    "attack_type (e.g., None, DDoS, C2),\n"
                    "confidence (0.0 to 1.0),\n"
                    "explanation (human readable reasoning),\n"
                    "recommendation (actionable advice)\n"
                    "Return ONLY valid JSON."
                )
                
                raw_response = self.analyst.chat(prompt)
                
                try:
                    # Try to extract JSON from the response (sometimes LLMs wrap it in markdown)
                    json_str = raw_response
                    if "```json" in raw_response:
                        json_str = raw_response.split("```json")[1].split("```")[0].strip()
                    elif "```" in raw_response:
                        json_str = raw_response.split("```")[1].split("```")[0].strip()
                    
                    analysis = json.loads(json_str)
                    
                    # Store in DB
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute(
                        "INSERT INTO llm_analysis (metrics_summary, threat_level, attack_type, confidence, explanation, recommendation) VALUES (?, ?, ?, ?, ?, ?)",
                        (analysis.get('metrics_summary'), analysis.get('threat_level'), analysis.get('attack_type'), 
                         analysis.get('confidence'), analysis.get('explanation'), analysis.get('recommendation'))
                    )
                    conn.commit()
                    conn.close()
                    print("[+] Analysis stored in database.")
                    
                except Exception as e:
                    print(f"[!] Error parsing LLM response or storing in DB: {e}")
                    print(f"Raw response was: {raw_response[:200]}...")

            time.sleep(ANALYSIS_INTERVAL_SEC)

if __name__ == "__main__":
    advisor = LLMAdvisor()
    try:
        advisor.run()
    except KeyboardInterrupt:
        print("[*] LLM Advisor stopped.")
