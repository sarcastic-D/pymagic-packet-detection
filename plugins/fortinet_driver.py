"""
Fortinet (FortiOS) Firewall Driver Plugin

This plugin connects to a FortiGate firewall via its REST API (FortiOS API).
It adds the malicious IP to an Address Object group that is pre-configured
in a Deny policy on the firewall.
"""

import os
import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def block_ip(ip: str):
    """
    Executes a block against the specified IP on a Fortinet firewall.
    Expects environment variables or config files for credentials.
    """
    fw_ip   = os.getenv("FORTINET_IP", "192.168.1.1")
    api_key = os.getenv("FORTINET_API_KEY", "dummy_token_for_thesis")
    group   = os.getenv("FORTINET_BLOCK_GROUP", "Occult_Tracer_Blocklist")

    print(f"[Fortinet Driver] Authenticating to FortiOS REST API at {fw_ip}...")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    # Step 1: Create the address object for the IP
    print(f"[Fortinet Driver] Creating Address Object for IP: {ip}")
    addr_payload = {
        "name": f"OT_BLOCK_{ip}",
        "type": "ipmask",
        "subnet": f"{ip} 255.255.255.255"
    }
    
    # Step 2: Add the newly created address object to the Blocklist Group
    print(f"[Fortinet Driver] Appending Address Object to Block Group: {group}")
    group_payload = {
        "name": group,
        "member": [{"name": f"OT_BLOCK_{ip}"}]
    }

    # Simulating API execution for thesis purposes
    # requests.post(f"https://{fw_ip}/api/v2/cmdb/firewall/address", json=addr_payload, headers=headers, verify=False)
    # requests.put(f"https://{fw_ip}/api/v2/cmdb/firewall/addrgrp/{group}", json=group_payload, headers=headers, verify=False)
    
    success = True

    if success:
        print(f"[+] Fortinet: Successfully created rule and added {ip} to FortiGate drop policy.")
    else:
        print(f"[-] Fortinet: API constraint failed for {ip}.")
