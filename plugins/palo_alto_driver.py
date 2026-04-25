"""
Palo Alto Networks (PAN-OS) Firewall Driver Plugin

This plugin connects to a Palo Alto firewall via its XML API and adds
the malicious IP to a Dynamic Address Group (DAG) acting as a blocklist.
"""

import os
import requests
import urllib3

# Suppress insecure request warnings if using self-signed certs on the firewall
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def block_ip(ip: str):
    """
    Executes a block against the specified IP on a Palo Alto firewall.
    Expects environment variables or config files for credentials.
    In a real environment, the API key is used instead of user/pass.
    """
    fw_ip   = os.getenv("PALO_ALTO_IP", "192.168.1.1")
    api_key = os.getenv("PALO_ALTO_API_KEY", "dummy_api_key_for_thesis")
    dag_tag = os.getenv("PALO_ALTO_DAG_TAG", "occult-tracer-block")

    print(f"[Palo Alto Driver] Authenticating to PAN-OS API at {fw_ip}...")
    print(f"[Palo Alto Driver] Tagging IP {ip} with DAG tag: {dag_tag}")

    # The PAN-OS XML API payload to register an IP to a dynamic tag
    # Example URL: https://<fw-ip>/api/?type=user-id&action=set&key=<api_key>
    payload = f"""
    <uid-message>
      <type>update</type>
      <payload>
        <register>
          <entry ip="{ip}">
            <tag>
              <member>{dag_tag}</member>
            </tag>
          </entry>
        </register>
      </payload>
    </uid-message>
    """
    
    # Simulating the API request for the thesis
    # In production: requests.post(url, data={"cmd": payload}, verify=False)
    success = True 

    if success:
        print(f"[+] Palo Alto: Successfully added {ip} to Blocklist Dynamic Address Group.")
    else:
        print(f"[-] Palo Alto: Failed to block {ip} via XML API.")
