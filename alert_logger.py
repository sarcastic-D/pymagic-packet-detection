import json
import os
from datetime import datetime

class AlertLogger:
    def __init__(self, outdir="output_v2"):
        self.path = os.path.join(outdir, "alerts_v2.json")
        if not os.path.exists(outdir): os.makedirs(outdir)
    
    def log(self, norm_pkt, rule_id, rule_meta, score, explanation):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "rule_id": rule_id,
            "risk_score": score,
            "explanation": explanation,
            "rule_meta": rule_meta,
            "packet_meta": {
                "src": norm_pkt.get("ip_src"),
                "dst": norm_pkt.get("ip_dst"),
                "proto": norm_pkt.get("protocol")
            }
        }
        print(f"[ALERT] Rule: {rule_id} | Score: {score} | {explanation}")
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")