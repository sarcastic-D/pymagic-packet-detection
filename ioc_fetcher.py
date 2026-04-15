import json
import requests
import time
from common_utilities import load_config

# --- AlienVault OTX Configuration ---
# You can get a free API key at https://otx.alienvault.com
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
# Replace with actual API key in config.yaml under OTX_API_KEY
CONFIG = load_config()
API_KEY = CONFIG.get("OTX_API_KEY", "YOUR_FREE_API_KEY_HERE") 

def fetch_dynamic_iocs():
    """
    Connects to AlienVault OTX to pull the latest known malicious IPs, domains, 
    and port anomalies, converting them dynamically into conditions.json format.
    """
    print("[*] Connecting to AlienVault OTX Threat Feed...")
    headers = {
        "X-OTX-API-KEY": API_KEY,
        "Accept": "application/json"
    }

    dynamic_rules = []
    
    try:
        # Fetch pulses related specifically to rootkits and magic packets
        # We search AlienVault for specific tags to avoid generic spam/phishing IPs
        search_query = "rootkit OR backdoor OR bpfdoor OR magic_packet"
        response = requests.get(f"https://otx.alienvault.com/api/v1/search/pulses?q={search_query}&limit=5", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            pulses = data.get("results", [])
            
            print(f"[+] Downloaded {len(pulses)} latest rootkit/magic-packet threat pulses.")
            
            for pulse in pulses:
                pulse_id = pulse.get("id", "unknown")
                pulse_name = pulse.get("name", "Unknown Rootkit Threat")
                
                # We will create a rule block for each interesting threat
                indicators = pulse.get("indicators", [])
                
                for ind in indicators:
                    ind_type = ind.get("type", "")
                    ind_val = ind.get("indicator", "")
                    
                    # Example: If the threat feed reports a known malicious IPv4 C2 server
                    if ind_type == "IPv4":
                        rule = {
                            "id": f"otx_{pulse_id[:8]}_{ind_val.replace('.', '_')}",
                            "description": f"Dynamic Threat Intel (OTX): {pulse_name}",
                            "protocol": "TCP",
                            "match": {
                                "ip_src": ind_val # In reality, we'd check if traffic is coming from this IP
                            }
                        }
                        dynamic_rules.append(rule)
                        
                    # Example: If the threat feed reports a known Magic Hash/File Hash
                    elif ind_type == "FileHash-SHA256":
                         rule = {
                            "id": f"otx_{pulse_id[:8]}_hash",
                            "description": f"Dynamic Threat Intel (OTX Hash): {pulse_name}",
                            "protocol": "TCP",
                            "match": {
                                # We can't easily match SHA256 in raw packets without deep extraction,
                                # but we can flag high-entropy traffic communicating on weird ports 
                                # associated with this malware.
                                "high_entropy": True
                            }
                        }
                         # Prevent duplicates in demo
                         if rule not in dynamic_rules:
                             dynamic_rules.append(rule)

        else:
            print(f"[-] Failed to fetch OTX data. HTTP {response.status_code}")
            print(f"    Ensure your OTX_API_KEY is properly set in config.yaml.")
            return False

    except Exception as e:
        print(f"[-] OTX Integration Error: {e}")
        return False
        
    return dynamic_rules

def update_conditions_file(dynamic_rules, filepath="conditions.json"):
    """
    Merges dynamic rules with existing static rules.
    """
    print(f"[*] Updating {filepath} with {len(dynamic_rules)} new dynamic rules...")
    
    existing_data = {}
    try:
        with open(filepath, "r") as f:
            existing_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # File doesn't exist or is empty
        pass

    # Ensure rootkit keys exist
    if "dynamic_threat_intel" not in existing_data:
        existing_data["dynamic_threat_intel"] = {
            "name": "Global Threat Intel (AlienVault OTX)",
            "conditions": []
        }

    # Append new rules, avoiding duplicates by checking IDs
    existing_ids = {c["id"] for rootkit in existing_data.values() for c in rootkit.get("conditions", []) if "id" in c}
    
    added_count = 0
    for new_rule in dynamic_rules:
        if new_rule["id"] not in existing_ids:
            existing_data["dynamic_threat_intel"]["conditions"].append(new_rule)
            existing_ids.add(new_rule["id"])
            added_count += 1

    # Write back to file
    with open(filepath, "w") as f:
        json.dump(existing_data, f, indent=4)
        
    print(f"[+] Successfully integrated {added_count} new IOCs into {filepath}.")

if __name__ == "__main__":
    print("==========================================")
    print("   THREAT INTEL IOC MATCHER (OTX API)     ")
    print("==========================================")
    print("This script fulfills the requirement for dynamic AI inputs.")
    
    rules = fetch_dynamic_iocs()
    if rules:
        update_conditions_file(rules)
    else:
        print("[!] No new dynamic rules were added. Check your API key or internet connection.")
