import subprocess
import sys
import os
import re

# Define filenames here to easily match your local setup
FILES = {
    "compiler": "static_analyzer.py",
    "simulator": "malware_simulator.py",
    "analyzer": "dynamic_analyzer.py",
    "visualizer": "visualization.py",
    "config": "config.yaml",
    "synthetic_pcap": "synthetic_malware_v2.pcap"
}

def run_step(step_name, script_name):
    print(f"\n[+] Running Step: {step_name} ({script_name})...")
    
    if not os.path.exists(script_name):
        print(f"    [!] Error: File '{script_name}' not found in current directory.")
        return False
        
    try:
        # Uses the current python interpreter (python or python3)
        subprocess.check_call([sys.executable, script_name])
        print("    -> Success.")
        return True
    except subprocess.CalledProcessError:
        print(f"    [!] Error: Script '{script_name}' crashed.")
        return False

def update_config_for_local_test():
    """
    Updates config_v2.yaml to point to the local synthetic file
    instead of waiting for live capture.
    """
    cfg = FILES["config"]
    target_pcap = FILES["synthetic_pcap"]
    
    if not os.path.exists(cfg):
        print(f"    [!] Config file '{cfg}' not found.")
        return False

    print(f"    -> Updating {cfg} to analyze '{target_pcap}'...")
    
    with open(cfg, 'r') as f:
        content = f.read()
    
    # Regex replace to safely swap the PCAP file path
    new_content = re.sub(
        r'PCAP_MALWARE_FILE: ".*?"', 
        f'PCAP_MALWARE_FILE: "{target_pcap}"', 
        content
    )
    
    with open(cfg, 'w') as f:
        f.write(new_content)
    return True

def main():
    print("==========================================")
    print("🛡️  SENTINEL FORGE: LOCAL LOGIC TEST    🛡️")
    print("==========================================")

    # 1. Compile Rules
    if not run_step("Compiling Intelligence", FILES["compiler"]): return

    # 2. Simulation
    if not run_step("Generating Synthetic Attack Data", FILES["simulator"]): return
    
    if not os.path.exists(FILES["synthetic_pcap"]):
        print(f"    [!] Error: {FILES['synthetic_pcap']} was not generated.")
        return

    # 3. Analyze
    if not update_config_for_local_test(): return
    if not run_step("Running Deep Packet Inspection", FILES["analyzer"]): return

    # 4. Report
    if not run_step("Generating Thesis Graphs", FILES["visualizer"]): return

    print("\n==========================================")
    print("✅  LOCAL TEST COMPLETE")
    print("==========================================")

if __name__ == "__main__":
    main()