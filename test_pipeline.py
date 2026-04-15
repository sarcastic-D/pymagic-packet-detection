"""
Sentinel Forge - Full Pipeline Test (PCAP Mode)
=================================================
Runs the entire detection pipeline on synthetic_malware_v2.pcap
Demonstrates: ML Triage → Defragmentation → Decoding → Entropy → Matching → Alerts
"""
from dynamic_analyzer import run_analysis
from common_utilities import load_config
import os
import json
import time

config = load_config()
pcap_path = config.get("PCAP_MALWARE_FILE", "synthetic_malware_v2.pcap")

print("=" * 55)
print("  SENTINEL FORGE: FULL PIPELINE TEST (PCAP MODE)")
print("=" * 55)
print(f"[*] Input PCAP: {pcap_path}")
print(f"[*] ML Pre-Filter: {'LOADED' if os.path.exists('ml_prefilter.joblib') else 'NOT FOUND'}")
print(f"[*] Anti-Evasion: Base64 + Hex + XOR Decoding")
print(f"[*] Shannon Entropy Threshold: {config.get('ENTROPY_THRESHOLD', 7.5)}")
print(f"[*] Webhook: HMAC-SHA256 Signed")
print()

# Run the full analysis pipeline
start_time = time.perf_counter()
alerts = run_analysis(pcap_path, mode='live')
elapsed = (time.perf_counter() - start_time) * 1000

# Wait for async webhook threads
time.sleep(2)

print()
print("=" * 55)
print("  RESULTS SUMMARY")
print("=" * 55)
print(f"[+] Total Alerts Triggered: {len(alerts)}")
print(f"[+] Total Pipeline Time: {elapsed:.2f} ms")
print()

# Show alert details
alerts_file = os.path.join(config.get("OUTPUT_DIR", "output_v2"), "alerts_v2.json")
if os.path.exists(alerts_file):
    print("[+] Alert Details (from alerts_v2.json):")
    print("-" * 55)
    with open(alerts_file, 'r') as f:
        for i, line in enumerate(f):
            try:
                alert = json.loads(line.strip())
                print(f"  Alert #{i+1}:")
                print(f"    Rule:    {alert.get('rule_id', 'N/A')}")
                print(f"    Score:   {alert.get('risk_score', 'N/A')}")
                print(f"    Source:  {alert.get('ip_src', 'N/A')}")
                print(f"    Reasons: {alert.get('reasons', 'N/A')}")
                print()
            except:
                pass

# Check syslog
syslog_file = os.path.join(config.get("OUTPUT_DIR", "output_v2"), "sentinel_forge_syslog.log")
if os.path.exists(syslog_file):
    with open(syslog_file, 'r') as f:
        lines = f.readlines()
    print(f"[+] Syslog entries written: {len(lines)}")

print("[+] Pipeline test complete.")
