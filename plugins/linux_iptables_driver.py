"""
Occult Tracer - Linux iptables Driver Plugin
==============================================
Uses subprocess to execute iptables commands on a local Linux host
to dynamically block malicious IPs.

Usage:
    In config.yaml, set FIREWALL_TYPE: "linux"
    Requires: sudo privileges or running as root.
"""

import subprocess


def block_ip(target_ip: str) -> bool:
    """
    Executes a local iptables DROP rule:
        sudo iptables -A INPUT -s <ip> -j DROP
    
    Returns True on success, False on failure.
    """
    command = ["sudo", "iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"]
    
    print(f"[Linux Driver] Executing: {' '.join(command)}")
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print(f"[Linux Driver] SUCCESS: iptables rule added for {target_ip}")
            return True
        else:
            print(f"[Linux Driver] Error: {result.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"[Linux Driver] Timeout: iptables command took too long.")
        return False
    except FileNotFoundError:
        print(f"[Linux Driver] Error: iptables not found. Is this a Linux system?")
        return False
    except Exception as e:
        print(f"[Linux Driver] Error: {e}")
        return False
