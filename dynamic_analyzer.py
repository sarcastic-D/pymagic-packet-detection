"""
Sentinel Forge - Dynamic Analyzer (The Detective)
==================================================
Core DPI engine that analyzes live network traffic in real-time.

Detection Pipeline:
    1. Fragment Reassembly (Anti-Evasion)
    2. Packet Normalization + Shannon Entropy
    3. ML Pre-Filter Triage (Decision Tree)
    4. Signature Rule Matching
    5. Zero-Day Anomaly Engine (ML + Entropy fallback)

Optimizations:
    - Rules, local IPs, and AlertLogger loaded ONCE at startup (not per-packet)
    - All imports at module level (no per-packet dictionary lookups)
    - LRU Rate-Limiting Cache prevents webhook spam
    - Asynchronous Webhook Dispatch (non-blocking background threads)
    - --verbose flag for clean vs. detailed terminal output
"""

import json
import os
import time
import socket
import subprocess
import threading
import argparse
from collections import OrderedDict

from scapy.all import rdpcap, wrpcap, sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

from packet_normalizer import normalize_packet
from rule_matcher import match_rule
from alert_logger import AlertLogger
from common_utilities import load_config
from defragmenter import FragmentReassembler
from webhook_sender import send_block_request
from threat_intel import revalidate_blocked_ip

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False


# ============================================================
# ML PRE-FILTER
# Loaded once at startup for microsecond O(depth) inference.
# ============================================================
ML_MODEL = None
if HAS_JOBLIB and os.path.exists("ml_prefilter.joblib"):
    try:
        ML_MODEL = joblib.load("ml_prefilter.joblib")
        print("[+] ML Pre-Filter (Decision Tree) loaded successfully.")
    except Exception as e:
        print(f"[-] Could not load ML model: {e}. All packets will proceed to full DPI.")


def ml_predict(norm_pkt) -> bool:
    """
    Evaluates packet against the trained 7-feature Decision Tree.

    Feature vector (must EXACTLY match train_model.py):
      [entropy, dport, sport, window_size, proto, has_magic_pattern, is_inbound_to_server]

    Returns True if suspicious (route to DPI), False if safe.
    Falls back to True (analyze everything) if no model is loaded.
    """
    if ML_MODEL is None:
        return True  # Zero-Trust fallback: analyze everything
    features = [[
        norm_pkt.get("entropy", 0.0),
        norm_pkt.get("dport", 0),
        norm_pkt.get("sport", 0),
        norm_pkt.get("window_size", 0),
        1 if norm_pkt.get("protocol") == "TCP" else 0,
        norm_pkt.get("has_magic_pattern", 0),       # NEW
        norm_pkt.get("is_inbound_to_server", 0),    # NEW
    ]]
    return ML_MODEL.predict(features)[0] == 1


# ============================================================
# LRU RATE-LIMITING CACHE
# Prevents the Detective from spamming the Agent Core
# with duplicate webhooks during a DDoS attack.
# ============================================================
class LRURateLimiter:
    """
    A Least Recently Used (LRU) cache with a Time-To-Live (TTL).
    If an IP was banned within the last TTL seconds, the webhook
    is silently skipped to protect the Agent Core from overload.
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
            self.cache.move_to_end(ip)
            self.cache[ip] = now
            return True
        self.cache[ip] = now
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
        return True


# ============================================================
# QUARANTINE & BENIGN BUFFER MANAGEMENT
# ============================================================
def save_to_quarantine(pkt, quarantine_path: str):
    """Appends a malicious packet to the quarantine buffer for forensic analysis."""
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
# LIVE PACKET CALLBACK
# Called by Scapy sniff() for every packet on the wire.
# All heavy resources (rules, IPs, logger) are pre-loaded
# at startup and passed in via closure — zero disk I/O per packet.
# ============================================================
def make_packet_handler(rules, ignore_ips, logger, config, rate_limiter,
                        quarantine_path, benign_path, verbose=False):
    """
    Factory function: returns the raw packet callback with all startup
    resources pre-bound. This eliminates all per-packet I/O and subprocess calls.
    """
    entropy_threshold = config.get("ENTROPY_THRESHOLD", 6.5)
    alert_ttl = config.get("LRU_CACHE_TTL", 5)  # seconds

    # Per-(source_ip, rule_id) deduplication cache.
    # Prevents the same rule firing for the same IP from printing/logging
    # multiple times within the TTL window (e.g. 3 identical Jynx packets).
    alert_dedup: dict = {}  # key=(ip, rule_id) → last_alert_timestamp

    def analyze_live_packet(raw_pkt):
        try:
            # --- Fragment handling ---
            pkt = raw_pkt
            if IP in pkt and not (TCP in pkt or UDP in pkt or ICMP in pkt):
                try:
                    rebuilt = IP(bytes(pkt[IP]))
                    if TCP in rebuilt or UDP in rebuilt or ICMP in rebuilt:
                        pkt = rebuilt
                except Exception:
                    pass

            norm = normalize_packet(pkt)
            if not norm:
                return

            # --- Self-sniffing prevention: ignore our own IPs ---
            if norm.get("ip_src") in ignore_ips:
                return

            # --- Directionality check ---
            dst_ip = norm.get("ip_dst", "")
            sport = norm.get("sport", 0)
            is_inbound = dst_ip.startswith("10.") or dst_ip.startswith("192.168.")
            # Legitimate return web traffic has src port 443/80/22 (server → client)
            is_return_web_traffic = is_inbound and sport in [443, 80, 22]

            # --- Triage Gate (Your 3-Way Logic) ---
            # ML=Clean  + Entropy LOW  → definitely benign, skip DPI entirely
            # ML=Clean  + Entropy HIGH → entropy overrides ML, run DPI
            # ML=Suspicious + any      → run DPI regardless of entropy
            #
            # Simplifies to: run_dpi = is_suspicious OR (entropy > threshold)
            is_suspicious = ml_predict(norm)
            entropy_val = norm.get("entropy", 0.0)
            run_dpi = is_suspicious or (entropy_val > entropy_threshold and is_inbound and not is_return_web_traffic)

            if not run_dpi:
                if verbose:
                    print(f"[BENIGN] ML=Clean + Low-Entropy packet from {norm.get('ip_src')} → saved as benign")
                save_to_benign(raw_pkt, benign_path)
                return

            # --- Signature Rule Matching ---
            packet_matched = False
            for rule in rules:
                matched, score, reasons = match_rule(norm, rule)
                if matched:
                    packet_matched = True
                    rule_id = rule.get("rule_id", "UNKNOWN")
                    threat_name = rule.get("meta", {}).get("name",
                                          rule.get("meta", {}).get("source_rootkit", rule_id))
                    malicious_ip = norm.get("ip_src")

                    # --- Alert Deduplication ---
                    # Only print + log if this (ip, rule_id) pair hasn't fired recently.
                    dedup_key = (malicious_ip, rule_id)
                    now = time.time()
                    last_alerted = alert_dedup.get(dedup_key, 0)
                    is_new_alert = (now - last_alerted) > alert_ttl
                    if is_new_alert:
                        alert_dedup[dedup_key] = now
                        print(f"\n{'='*60}")
                        print(f"[!!!] SIGNATURE MATCH: {threat_name}")
                        print(f"  >> Source IP  : {malicious_ip}")
                        print(f"  >> Score      : {score} / 100  |  Rule: {rule_id}")
                        print(f"  >> Reasons    : {reasons}")
                        print(f"{'='*60}")
                        logger.log(norm, rule_id, rule.get("meta", {}), score, reasons)
                    elif verbose:
                        print(f"[Dedup] Suppressing repeat alert for {rule_id} from {malicious_ip}")

                    save_to_quarantine(raw_pkt, quarantine_path)

                    if malicious_ip and rate_limiter.should_send(malicious_ip):
                        send_block_request(malicious_ip)
                        threading.Thread(
                            target=revalidate_blocked_ip,
                            args=(malicious_ip,),
                            daemon=True
                        ).start()
                    elif malicious_ip and verbose:
                        print(f"[LRU Cache] Skipping duplicate webhook for {malicious_ip}")

            # --- Zero-Day Anomaly Engine ---
            if not packet_matched:
                payload_len = len(norm.get("payload", b""))

                # Guard: ML-only flags on tiny payloads (< 32 bytes) are
                # not reliable. Tiny TCP control packets look suspicious to
                # the ML model but have zero entropy and no payload — they
                # are normal TCP handshake/ACK frames, not zero-days.
                # Only escalate to Zero-Day if:
                #   - Entropy is genuinely high (encrypted large payload), OR
                #   - ML flags it AND payload is large enough to be meaningful
                meaningful_ml_flag = is_suspicious and payload_len >= 32
                high_entropy_flag = entropy_val > entropy_threshold and is_inbound and not is_return_web_traffic

                if meaningful_ml_flag or high_entropy_flag:
                    dport = norm.get("dport", "?")
                    ml_verdict = "ML: SUSPICIOUS" if is_suspicious else "ML: Clean (overridden by entropy)"

                    detection_reasons = []
                    if entropy_val > entropy_threshold:
                        detection_reasons.append(f"high_entropy({entropy_val:.2f})")
                    if is_suspicious:
                        detection_reasons.append("ml_flagged")
                    if payload_len > 0:
                        detection_reasons.append(f"encrypted_payload({payload_len}B)")

                    # --- Zero-Day Alert Deduplication ---
                    dedup_key = (norm.get("ip_src"), "ZERO-DAY-ANOMALY")
                    now = time.time()
                    last_alerted = alert_dedup.get(dedup_key, 0)
                    is_new_alert = (now - last_alerted) > alert_ttl

                    if is_new_alert:
                        alert_dedup[dedup_key] = now
                        print(f"\n{'='*60}")
                        print(f"[!!!] ZERO-DAY ANOMALY DETECTED via ML/Entropy Engine [!!!]")
                        print(f"  >> Source IP  : {norm.get('ip_src', '?')}")
                        print(f"  >> Target Port: {dport}")
                        print(f"  >> Payload    : {payload_len} bytes (obfuscated/encrypted)")
                        print(f"  >> Entropy    : {entropy_val:.4f} bits (threshold: {entropy_threshold})")
                        print(f"  >> ML Verdict : {ml_verdict}")
                        print(f"  >> Reason     : No known signature matched. High-entropy payload indicates")
                        print(f"                  unknown malware, encrypted C2 channel, or zero-day exploit.")
                        print(f"{'='*60}")
                        logger.log(norm, "ZERO-DAY-ANOMALY", {
                            "description": "Unknown threat detected via ML/Entropy.",
                            "entropy": entropy_val,
                            "payload_size": payload_len,
                            "target_port": dport
                        }, 100, detection_reasons)
                    elif verbose:
                        print(f"[Dedup] Suppressing repeat Zero-Day alert from {norm.get('ip_src')}")

                    save_to_quarantine(raw_pkt, quarantine_path)
                    malicious_ip = norm.get("ip_src")
                    if malicious_ip and rate_limiter.should_send(malicious_ip):
                        send_block_request(malicious_ip)
                        threading.Thread(
                            target=revalidate_blocked_ip,
                            args=(malicious_ip,),
                            daemon=True
                        ).start()
                    elif malicious_ip and verbose:
                        print(f"[LRU Cache] Skipping duplicate webhook for {malicious_ip}")
                else:
                    save_to_benign(raw_pkt, benign_path)

        except Exception as e:
            print(f"[!] Live Analysis Error: {e}")

    return analyze_live_packet


# ============================================================
# OFFLINE PCAP ANALYSIS ENGINE
# Used by verify_all.py, metric.py, and test pipelines.
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
        raw = json.load(f)
        rules = raw if isinstance(raw, list) else raw.get("rules", [])

    logger = AlertLogger(config['OUTPUT_DIR'])
    reassembler = FragmentReassembler()
    rate_limiter = LRURateLimiter(
        max_size=config.get("LRU_CACHE_MAX_SIZE", 1024),
        ttl_seconds=config.get("LRU_CACHE_TTL", 5)
    )
    entropy_threshold = config.get("ENTROPY_THRESHOLD", 6.5)

    try:
        raw_packets = rdpcap(pcap_path)
    except Exception:
        return []

    detected_alerts = []

    for i, raw_pkt in enumerate(raw_packets):
        pkt = reassembler.process(raw_pkt)
        if not pkt:
            continue

        if IP in pkt and not (TCP in pkt or UDP in pkt or ICMP in pkt):
            try:
                rebuilt = IP(bytes(pkt[IP]))
                if TCP in rebuilt or UDP in rebuilt or ICMP in rebuilt:
                    pkt = rebuilt
            except Exception:
                pass

        norm = normalize_packet(pkt)
        if not norm:
            continue

        entropy_val = norm.get("entropy", 0.0)
        is_suspicious = ml_predict(norm)

        packet_matched = False
        for rule in rules:
            matched, score, reasons = match_rule(norm, rule)
            if matched:
                packet_matched = True
                detected_alerts.append({
                    "packet_index": i,
                    "rule": rule.get("rule_id"),
                    "score": score,
                    "entropy": entropy_val
                })
                if mode == 'live':
                    logger.log(norm, rule.get("rule_id"), rule.get("meta"), score, reasons)
                    save_to_quarantine(raw_pkt, quarantine_path)
                    malicious_ip = norm.get("ip_src")
                    if malicious_ip and rate_limiter.should_send(malicious_ip):
                        threading.Thread(
                            target=send_block_request,
                            args=(malicious_ip,),
                            daemon=True
                        ).start()

        if not packet_matched:
            if is_suspicious or entropy_val > entropy_threshold:
                detected_alerts.append({
                    "packet_index": i,
                    "rule": "ZERO-DAY-ANOMALY",
                    "score": 100,
                    "entropy": entropy_val
                })
                if mode == 'live':
                    logger.log(norm, "ZERO-DAY-ANOMALY",
                               {"description": "No known signature, caught by ML/Entropy"},
                               100, ["high_entropy", "ml_suspicious"])
                    save_to_quarantine(raw_pkt, quarantine_path)
            else:
                if mode == 'live':
                    save_to_benign(raw_pkt, benign_path)

    if mode == 'live':
        print(f"[*] Analysis Complete. {len(detected_alerts)} Alerts Logged.")

    return detected_alerts


# ============================================================
# MAIN ENTRY POINT
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Forge Dynamic Analyzer — Live DPI Engine"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show all events including LRU cache hits and benign packets"
    )
    args = parser.parse_args()

    config = load_config()

    # --- Load Rules ONCE at startup (not per-packet) ---
    rules_path = f"{config['OUTPUT_DIR']}/{config['COMBINED_RULES_FILE']}"
    if not os.path.exists(rules_path):
        print(f"[!] Rules file not found at {rules_path}. Run static_analyzer.py first.")
        return
    with open(rules_path, "r") as f:
        raw = json.load(f)
        rules = raw if isinstance(raw, list) else raw.get("rules", [])

    # --- Build local IP ignore-set ONCE at startup (not per-packet) ---
    ignore_ips = {"127.0.0.1"}
    try:
        all_local_ips = subprocess.check_output(
            ['hostname', '-I'], timeout=2
        ).decode().split()
        ignore_ips.update(all_local_ips)
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ignore_ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    ignore_ips.update(config.get("WHITELIST_IPS", []))

    # --- Create AlertLogger ONCE at startup (not per-packet) ---
    logger = AlertLogger(config.get("OUTPUT_DIR", "output_v2"))

    # --- Initialize Rate Limiter ---
    rate_limiter = LRURateLimiter(
        max_size=config.get("LRU_CACHE_MAX_SIZE", 1024),
        ttl_seconds=config.get("LRU_CACHE_TTL", 5)
    )

    quarantine_path = config.get("QUARANTINE_BUFFER", "quarantine_buffer.pcap")
    benign_path = config.get("BENIGN_BUFFER", "benign_buffer.pcap")
    iface = config.get("SNIFF_INTERFACE", "enp0s3")
    sniff_filter = config.get("SNIFF_FILTER", "ip")
    entropy_threshold = config.get("ENTROPY_THRESHOLD", 6.5)

    # --- Print Startup Banner ---
    print("==========================================")
    print("  SENTINEL FORGE DETECTIVE v2.0          ")
    print("==========================================")
    print(f"[*] Anti-Evasion Mode    : ENABLED (Reassembly + Decoding)")
    print(f"[*] Shannon Entropy      : ENABLED (Threshold: {entropy_threshold})")
    print(f"[*] LRU Rate Limiter     : ENABLED (TTL: {config.get('LRU_CACHE_TTL', 5)}s)")
    print(f"[*] Rules Loaded         : {len(rules)} signatures")
    print(f"[*] Local IPs Ignored    : {sorted(ignore_ips)}")
    print(f"[*] Quarantine Buffer    : {quarantine_path}")
    print(f"[*] Benign Buffer        : {benign_path}")
    print(f"[*] Verbose Mode         : {'ON' if args.verbose else 'OFF (only alerts shown)'}")
    print(f"[*] Async Webhooks       : ENABLED (Threading)")
    print()
    print(f"[*] Sniffing on interface: {iface}  |  Filter: '{sniff_filter}'")
    print(f"[*] Waiting for threats...\n")

    # --- Bind all startup resources via closure and start sniffing ---
    handler = make_packet_handler(
        rules=rules,
        ignore_ips=ignore_ips,
        logger=logger,
        config=config,
        rate_limiter=rate_limiter,
        quarantine_path=quarantine_path,
        benign_path=benign_path,
        verbose=args.verbose
    )

    sniff(
        iface=iface,
        prn=handler,
        filter=sniff_filter,
        store=0
    )


if __name__ == "__main__":
    main()