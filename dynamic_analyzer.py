"""
Sentinel Forge - Dynamic Analyzer (The Detective)
==================================================
Core DPI engine that analyzes network traffic, applies Shannon Entropy,
matches rules, and fires HMAC-signed webhooks asynchronously.

Features:
    - IP Fragment Reassembly (Anti-Evasion)
    - Base64/Hex Payload Decoding
    - Shannon Entropy (Encrypted Payload Detection)
    - LRU Rate-Limiting Cache (DDoS Protection)
    - Asynchronous Webhook Dispatch (Non-blocking)
    - Quarantine Buffer (Forensic Evidence)
    - Benign Buffer (Continuous Baseline Updating)
"""

import json
import os
import time
import threading
from collections import OrderedDict
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from packet_normalizer import normalize_packet
from rule_matcher import match_rule
from alert_logger import AlertLogger
from common_utilities import load_config
from defragmenter import FragmentReassembler
from webhook_sender import send_block_request

# --- [NEW] Live Sniffing (Commented out for now) ---
# from scapy.all import sniff
# To enable live sniffing, uncomment the above import and use:
#   sniff(iface=CONFIG.get("SNIFF_INTERFACE", "eth0"), 
#         prn=analyze_live_packet, 
#         filter=CONFIG.get("SNIFF_FILTER", "ip"),
#         store=0)


# ============================================================
# LRU RATE-LIMITING CACHE
# Prevents the Detective from spamming the Agent Core
# with duplicate webhooks during a DDoS attack.
# ============================================================
class LRURateLimiter:
    """
    A Least Recently Used (LRU) cache with a Time-To-Live (TTL).
    If an IP was banned within the last TTL seconds, the webhook
    is silently skipped to protect the Universal Agent from overload.
    """
    def __init__(self, max_size=1024, ttl_seconds=5):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl_seconds
    
    def should_send(self, ip: str) -> bool:
        """
        Returns True if the webhook should fire (IP is new or TTL expired).
        Returns False if the IP was recently banned (skip to prevent spam).
        """
        now = time.time()
        
        if ip in self.cache:
            last_sent = self.cache[ip]
            if now - last_sent < self.ttl:
                return False  # Still within cooldown period
            # TTL expired, allow re-ban
            self.cache.move_to_end(ip)
            self.cache[ip] = now
            return True
        
        # New IP - add to cache
        self.cache[ip] = now
        
        # Evict oldest entries if cache is full
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
        
        return True


# ============================================================
# ASYNCHRONOUS WEBHOOK DISPATCHER
# Fires the HMAC webhook in a background thread so the main
# DPI loop never pauses while waiting for the Agent to respond.
# ============================================================
def async_send_block_request(target_ip: str):
    """
    Dispatches the webhook in a daemon background thread.
    The main packet analysis loop continues immediately.
    """
    thread = threading.Thread(
        target=send_block_request, 
        args=(target_ip,),
        daemon=True
    )
    thread.start()


# ============================================================
# QUARANTINE & BENIGN BUFFER MANAGEMENT
# Saves malicious packets for ML analysis and benign packets
# for continuous baseline updating.
# ============================================================
def save_to_quarantine(pkt, quarantine_path: str):
    """Appends a malicious packet to the quarantine buffer for ML analysis."""
    try:
        wrpcap(quarantine_path, pkt, append=True)
    except Exception as e:
        print(f"[!] Error writing to quarantine buffer: {e}")


def save_to_benign(pkt, benign_path: str):
    """Appends a benign packet to the benign buffer for baseline updating."""
    try:
        wrpcap(benign_path, pkt, append=True)
    except Exception as e:
        print(f"[!] Error writing to benign buffer: {e}")


# ============================================================
# CORE ANALYSIS ENGINE
# ============================================================
def run_analysis(pcap_path, mode='live'):
    """
    Analyzes a PCAP file through the full DPI pipeline.
    
    Modes:
        'live'   - Full output with logging, webhooks, and quarantine.
        'silent' - Silent mode for metrics calculation (no side effects).
    """
    config = load_config()
    rules_path = f"{config['OUTPUT_DIR']}/{config['COMBINED_RULES_FILE']}"
    quarantine_path = config.get("QUARANTINE_BUFFER", "quarantine_buffer.pcap")
    benign_path = config.get("BENIGN_BUFFER", "benign_buffer.pcap")

    if not os.path.exists(rules_path):
        print("[!] Rules file missing.")
        return []
    if not os.path.exists(pcap_path):
        print(f"[!] PCAP {pcap_path} missing.")
        return []

    if mode == 'live':
        print(f"[*] Sentinel Sensor v2: Analyzing {pcap_path}...")
    
    with open(rules_path, "r") as f:
        rules = json.load(f)
    
    logger = AlertLogger(config['OUTPUT_DIR'])
    reassembler = FragmentReassembler()
    
    # Initialize LRU Rate Limiter from config
    rate_limiter = LRURateLimiter(
        max_size=config.get("LRU_CACHE_MAX_SIZE", 1024),
        ttl_seconds=config.get("LRU_CACHE_TTL", 5)
    )
    
    try:
        raw_packets = rdpcap(pcap_path)
    except:
        return []

    detected_alerts = []

    for i, raw_pkt in enumerate(raw_packets):
        # 1. Anti-Evasion: Reassemble Fragments
        pkt = reassembler.process(raw_pkt)
        if not pkt: continue

        # Force Scapy to re-parse TCP layer after reassembly
        if IP in pkt and not (TCP in pkt or UDP in pkt or ICMP in pkt):
            try:
                rebuilt_pkt = IP(bytes(pkt[IP]))
                if TCP in rebuilt_pkt or UDP in rebuilt_pkt or ICMP in rebuilt_pkt:
                    pkt = rebuilt_pkt
            except: pass

        # 2. Normalize (includes Shannon Entropy calculation)
        norm = normalize_packet(pkt)
        if not norm: continue

        # 3. Match against all rules
        packet_matched = False
        for rule in rules:
            matched, score, reasons = match_rule(norm, rule)
            if matched:
                packet_matched = True
                detected_alerts.append({
                    "packet_index": i,
                    "rule": rule.get("rule_id"),
                    "score": score,
                    "entropy": norm.get("entropy", 0.0)
                })
                
                if mode == 'live':
                    # Log the alert
                    logger.log(norm, rule.get("rule_id"), rule.get("meta"), score, reasons)
                    
                    # Save to Quarantine Buffer (Forensic Evidence)
                    save_to_quarantine(raw_pkt, quarantine_path)
                    
                    # LRU Rate Limiting + Async Webhook
                    malicious_ip = norm.get("ip_src")
                    if malicious_ip and rate_limiter.should_send(malicious_ip):
                        async_send_block_request(malicious_ip)
                    elif malicious_ip:
                        print(f"[LRU Cache] Skipping duplicate webhook for {malicious_ip}")
                
                break  # One rule match per packet is sufficient
        
        # 4. Save benign traffic for baseline updating (live mode only)
        if not packet_matched and mode == 'live':
            save_to_benign(raw_pkt, benign_path)

    if mode == 'live':
        print(f"[*] Analysis Complete. {len(detected_alerts)} Alerts Logged.")
        
    return detected_alerts


# ============================================================
# MAIN ENTRY POINT
# ============================================================
def main():
    config = load_config()
    pcap_path = config.get("PCAP_MALWARE_FILE", "synthetic_malware_v2.pcap")

    print("==========================================")
    print("  SENTINEL FORGE DETECTIVE v2.0            ")
    print("==========================================")
    print(f"[*] Anti-Evasion Mode: ENABLED (Reassembly + Decoding)")
    print(f"[*] Shannon Entropy Detection: ENABLED (Threshold: {config.get('ENTROPY_THRESHOLD', 7.5)})")
    print(f"[*] LRU Rate Limiter: ENABLED (TTL: {config.get('LRU_CACHE_TTL', 5)}s)")
    print(f"[*] Quarantine Buffer: {config.get('QUARANTINE_BUFFER', 'quarantine_buffer.pcap')}")
    print(f"[*] Benign Buffer: {config.get('BENIGN_BUFFER', 'benign_buffer.pcap')}")
    print(f"[*] Async Webhooks: ENABLED (Threading)")
    print()

    # --- [CURRENT] Static PCAP Analysis Mode ---
    run_analysis(pcap_path, mode='live')

    # --- [FUTURE] Live Sniffing Mode ---
    # Uncomment the following to enable live network sniffing:
    # print(f"[*] Sniffing on interface: {config.get('SNIFF_INTERFACE', 'eth0')}...")
    # sniff(
    #     iface=config.get("SNIFF_INTERFACE", "eth0"),
    #     prn=lambda pkt: analyze_live_packet(pkt, config),
    #     filter=config.get("SNIFF_FILTER", "ip"),
    #     store=0
    # )


if __name__ == "__main__":
    main()