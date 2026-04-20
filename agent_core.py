import time
import hmac
import hashlib
import sqlite3
import importlib
from flask import Flask, request, jsonify
from common_utilities import load_config

app = Flask(__name__)

# --- CONFIGURATION ---
CONFIG = load_config()
SHARED_SECRET = CONFIG.get("SHARED_SECRET", "SentinelForge_SuperSecretKey_2026").encode()

# IP Whitelist — only localhost. All other protections are handled dynamically
# in dynamic_analyzer.py via hostname -I to prevent false positives.
IP_WHITELIST = {
    "127.0.0.1",  # Localhost (the agent itself)
}

# --- DATABASE SETUP (Idempotency Cache) ---
DB_PATH = "agent_cache.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# --- PLUGIN ARCHITECTURE ---
# Dynamically load the correct firewall driver based on config.yaml
FIREWALL_DRIVER = None

def load_firewall_driver():
    """
    Reads FIREWALL_TYPE from config.yaml and dynamically imports
    the corresponding plugin module from the plugins/ directory.
    Each plugin must implement: block_ip(target_ip) -> bool
    """
    global FIREWALL_DRIVER
    fw_type = CONFIG.get("FIREWALL_TYPE", "mock")
    
    DRIVER_MAP = {
        "pfsense": "plugins.pfsense_driver",
        "linux":   "plugins.linux_iptables_driver",
    }
    
    if fw_type in DRIVER_MAP:
        try:
            FIREWALL_DRIVER = importlib.import_module(DRIVER_MAP[fw_type])
            print(f"[+] Plugin Loaded: {DRIVER_MAP[fw_type]} ({fw_type})")
        except ImportError as e:
            print(f"[!] Failed to load plugin '{fw_type}': {e}")
            print("[!] Falling back to Mock Driver.")
            FIREWALL_DRIVER = None
    else:
        print(f"[+] Using Mock Driver (FIREWALL_TYPE='{fw_type}')")
        FIREWALL_DRIVER = None

# --- SECURITY UTILS ---
def verify_signature(payload_body: bytes, provided_signature: str) -> bool:
    """
    Verifies the HMAC-SHA256 signature attached to the webhook.
    """
    if not provided_signature:
        return False
        
    expected_hmac = hmac.new(SHARED_SECRET, payload_body, hashlib.sha256).hexdigest()
    
    # Use hmac.compare_digest to prevent timing attacks
    return hmac.compare_digest(expected_hmac, provided_signature)

# --- CORE LOGIC (Universal Enforcement) ---
def enforce_block(target_ip: str) -> str:
    """
    Universal enforcement logic with plugin support.
    Checks whitelist and idempotency, then delegates to the loaded driver.
    """
    # Defensive Check 1: Whitelist Safety
    if target_ip in IP_WHITELIST:
        print(f"[Safety Lock] Ignoring block request for whitelisted IP: {target_ip}")
        return "whitelisted"

    # Defensive Check 2: Idempotency Cache
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip FROM blocked_ips WHERE ip = ?", (target_ip,))
    if c.fetchone():
        conn.close()
        print(f"[Cache Hit] IP {target_ip} is already blocked. Skipping.")
        return "already_blocked"

    # Action: Execute via Plugin or Mock
    if FIREWALL_DRIVER is not None:
        # Real Plugin Driver (pfSense, Linux, etc.)
        print(f"\n[PLUGIN DRIVER] Executing block via {CONFIG.get('FIREWALL_TYPE', 'unknown')}...")
        success = FIREWALL_DRIVER.block_ip(target_ip)
        if not success:
            conn.close()
            return "driver_error"
    else:
        # Mock Driver (Simulation Mode)
        print(f"\n[MOCK FIREWALL] Executing block...")
        print(f"    -> iptables -A INPUT -s {target_ip} -j DROP")
        print(f"    -> Windows Firewall Rule added for {target_ip}\n")
    
    # Store in cache
    c.execute("INSERT INTO blocked_ips (ip) VALUES (?)", (target_ip,))
    conn.commit()
    conn.close()

    return "blocked"

# --- FLASK ENDPOINTS ---
@app.route('/api/v1/alert', methods=['POST'])
def receive_alert():
    """
    Webhook receiver endpoint for Sentinel Forge.
    Expected JSON: {"target_ip": "1.2.3.4", "action": "block", "timestamp": <unix>}
    Headers must include: X-Signature
    """
    # 1. Zero-Trust Handshake Authentication
    signature = request.headers.get('X-Signature')
    payload_raw = request.get_data()

    if not verify_signature(payload_raw, signature):
        print(f"[UNAUTHORIZED] Rejecting unauthorized request from {request.remote_addr}.")
        return jsonify({"status": "error", "message": "Invalid HMAC signature"}), 401

    # 2. Parse Validated Payload
    try:
        data = request.get_json()
        target_ip = data.get("target_ip")
        action = data.get("action")
    except Exception as e:
        return jsonify({"status": "error", "message": "Bad JSON payload"}), 400

    if not target_ip or action != "block":
        return jsonify({"status": "error", "message": "Missing arguments or invalid action"}), 400

    # 3. Pass to Universal Enforcement Engine
    result = enforce_block(target_ip)
    
    # 4. Respond to Sentinel Forge
    if result == "whitelisted":
        return jsonify({"status": "ignored", "reason": "IP is on safety whitelist"}), 200
    elif result == "already_blocked":
        return jsonify({"status": "ignored", "reason": "IP already blocked previously"}), 200
    elif result == "driver_error":
        return jsonify({"status": "error", "message": "Firewall driver execution failed"}), 500
    else:
        return jsonify({"status": "success", "message": f"IP {target_ip} actively blocked"}), 200


if __name__ == '__main__':
    print("==========================================")
    print("  UNIVERSAL AGENT CORE v2.0 STARTING      ")
    print("==========================================")
    init_db()
    load_firewall_driver()
    print(f"[+] Idempotency Cache Initialized.")
    print(f"[+] Zero-Trust HMAC Engine Active.")
    print(f"[+] Loaded {len(IP_WHITELIST)} Whitelisted IPs.")
    print(f"[+] Firewall Type: {CONFIG.get('FIREWALL_TYPE', 'mock')}")
    print("Listening on port 5000 for verified alerts...")
    app.run(host='0.0.0.0', port=5000, debug=False)
