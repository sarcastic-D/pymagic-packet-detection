import time
import hmac
import hashlib
import json
import urllib.request
import urllib.error

# Must match the Universal Agent Core
SHARED_SECRET = b"SentinelForge_SuperSecretKey_2026"
AGENT_URL = "http://127.0.0.1:5000/api/v1/alert"

def send_block_request(target_ip: str):
    """
    Sends a cryptographically signed webhook to the Universal Agent Core.
    """
    # 1. Prepare Payload
    payload_dict = {
        "target_ip": target_ip,
        "action": "block",
        "timestamp": int(time.time())
    }
    
    # Needs to be exactly identical bytes on both ends
    payload_bytes = json.dumps(payload_dict).encode('utf-8')
    
    # 2. Cryptographic Signature (Zero-Trust)
    signature = hmac.new(SHARED_SECRET, payload_bytes, hashlib.sha256).hexdigest()
    
    print(f"[🔗 Webhook] Sending Block Request for {target_ip} to Agent Core...")
    print(f"    -> HMAC Signature: {signature[:12]}...")

    # 3. Dispatch Request
    req = urllib.request.Request(AGENT_URL, data=payload_bytes)
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Signature', signature)
    
    try:
        with urllib.request.urlopen(req) as response:
            resp_body = response.read().decode('utf-8')
            print(f"    -> Response [{response.getcode()}]: {resp_body}")
            return True
            
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode('utf-8')
        print(f"    -> [MOCK API ERROR] {e.code}: {resp_body}")
        return False
    except urllib.error.URLError as e:
        print(f"    -> [ERROR] Could not reach Agent Core. Is it running? ({e.reason})")
        return False

# Quick test if run directly
if __name__ == "__main__":
    print("Testing Webhook Sender...")
    
    # 1. Test Whitelist Rejection
    print("\n--- Test 1: Whitelisted IP ---")
    send_block_request("8.8.8.8")
    
    # 2. Test Normal Block
    print("\n--- Test 2: Malicious IP ---")
    send_block_request("192.168.100.44")
    
    # 3. Test Idempotency (Cache)
    print("\n--- Test 3: Duplicate Block ---")
    send_block_request("192.168.100.44")

