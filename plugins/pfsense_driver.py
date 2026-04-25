"""
Occult Tracer - pfSense SSH Driver Plugin
==========================================
Uses paramiko to SSH into a pfSense firewall and execute
the 'easyrule' command to dynamically block malicious IPs.

Usage:
    In config.yaml, set FIREWALL_TYPE: "pfsense" and configure:
        PFSENSE_HOST, PFSENSE_PORT, PFSENSE_USER, PFSENSE_PASSWORD
"""

import paramiko
from common_utilities import load_config

# Load pfSense connection settings from config.yaml
_CONFIG = load_config()

PFSENSE_HOST = _CONFIG.get("PFSENSE_HOST", "192.168.1.1")
PFSENSE_PORT = _CONFIG.get("PFSENSE_PORT", 22)
PFSENSE_USER = _CONFIG.get("PFSENSE_USER", "admin")
PFSENSE_PASSWORD = _CONFIG.get("PFSENSE_PASSWORD", "pfsense")
PFSENSE_WAN_INTERFACE = _CONFIG.get("PFSENSE_WAN_INTERFACE", "wan")


def block_ip(target_ip: str) -> bool:
    """
    SSHs into pfSense and executes:
        easyrule block <interface> <ip>
    
    This permanently adds a firewall block rule on the WAN interface.
    Returns True on success, False on failure.
    """
    command = f"easyrule block {PFSENSE_WAN_INTERFACE} {target_ip}"
    
    print(f"[pfSense Driver] Connecting to {PFSENSE_HOST}:{PFSENSE_PORT}...")
    
    try:
        # Create SSH client with auto host-key acceptance
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to pfSense
        client.connect(
            hostname=PFSENSE_HOST,
            port=PFSENSE_PORT,
            username=PFSENSE_USER,
            password=PFSENSE_PASSWORD,
            timeout=10
        )
        
        # Execute the easyrule block command
        stdin, stdout, stderr = client.exec_command(command)
        
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        
        client.close()
        
        if error:
            print(f"[pfSense Driver] Error: {error}")
            return False
        
        print(f"[pfSense Driver] SUCCESS: {command}")
        if output:
            print(f"    -> pfSense Response: {output}")
        
        return True
        
    except paramiko.AuthenticationException:
        print(f"[pfSense Driver] Authentication failed. Check PFSENSE_USER/PASSWORD in config.yaml.")
        return False
    except paramiko.SSHException as e:
        print(f"[pfSense Driver] SSH Error: {e}")
        return False
    except Exception as e:
        print(f"[pfSense Driver] Connection Error: {e}")
        return False
