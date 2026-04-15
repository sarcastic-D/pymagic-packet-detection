import json
import os
import logging
from datetime import datetime

class AlertLogger:
    def __init__(self, outdir="output_v2"):
        self.path = os.path.join(outdir, "alerts_v2.json")
        if not os.path.exists(outdir): os.makedirs(outdir)
        
        # --- [NEW] SYSLOG INTEGRATION ---
        self.syslog = logging.getLogger("SentinelForge")
        self.syslog.setLevel(logging.WARNING)
        
        # We write to a local file which can be tailed by the SIEM agent
        syslog_path = os.path.join(outdir, "sentinel_forge_syslog.log")
        handler = logging.FileHandler(syslog_path)
        
        # Standard RFC-like format for SIEM ingestion
        formatter = logging.Formatter('%(asctime)s SENTINEL_FORGE %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        
        # Prevent adding multiple handlers if logger is instantiated multiple times
        if not self.syslog.handlers:
            self.syslog.addHandler(handler)
        # --------------------------------
    
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
        
        # 1. Output JSON alert
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
            
        # 2. Output Syslog for SIEM (Wazuh, Splunk, Sentinel)
        syslog_msg = (f"msg=\"Threat Detected\" rule=\"{rule_id}\" score={score} "
                      f"src_ip={norm_pkt.get('ip_src')} dst_ip={norm_pkt.get('ip_dst')} "
                      f"protocol={norm_pkt.get('protocol')} reason=\"{explanation}\"")
        self.syslog.warning(syslog_msg)