import multiprocessing
import time
import subprocess
import os
import sys

def start_agent():
    subprocess.call([sys.executable, "agent_core.py"])

if __name__ == '__main__':
    print("[*] Starting Agent Core in background...")
    agent_process = multiprocessing.Process(target=start_agent)
    agent_process.start()
    
    # Wait for flask to spin up
    time.sleep(3)
    
    print("[*] Running Sentinel Forge logic test with active response...")
    subprocess.call([sys.executable, "run.py"])
    
    print("[*] Shutting down background Agent Core...")
    agent_process.terminate()
    print("[+] Done.")
