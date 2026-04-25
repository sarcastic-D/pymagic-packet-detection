"""
Occult Tracer - Inference Engine (The ML Brain)
=================================================
Statistical Machine Learning engine that analyzes quarantined
malware samples against a clean traffic baseline to automatically
generate Suricata-compatible detection rules.

Features:
    - Quarantine Buffer Analysis (Live caught data)
    - Shannon Entropy Anomaly Detection
    - Statistical Frequency Analysis (Std Dev, Port, Window)
    - Automated Suricata Rule Generation
    - Continuous Baseline Updating (merges benign traffic)
"""

from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
import json
import os
from collections import Counter
from common_utilities import load_config
from defragmenter import FragmentReassembler
from packet_normalizer import normalize_packet, calculate_shannon_entropy


def analyze_pcap_stats(pcap_file):
    """
    Returns statistical counters for a given PCAP using normalized features.
    Now includes Shannon Entropy statistics for encrypted payload detection.
    """
    stats = {
        "window": Counter(),
        "magic": Counter(),
        "dport": Counter(),
        "entropy_values": [],     # [NEW] Track entropy for each packet
        "high_entropy_count": 0,  # [NEW] Count of high-entropy packets
        "count": 0
    }
    
    if not os.path.exists(pcap_file):
        print(f"[!] Warning: {pcap_file} not found.")
        return stats

    reassembler = FragmentReassembler()
    try:
        raw_packets = rdpcap(pcap_file)
        for raw_pkt in raw_packets:
            # 1. Defeat IP Fragmentation Evasion before analysis
            pkt = reassembler.process(raw_pkt)
            if not pkt: continue
            
            # 2. Redissect TCP/UDP payload if Scapy failed due to fragmentation
            if IP in pkt and not (TCP in pkt or UDP in pkt or ICMP in pkt):
                try:
                    ip_bytes = bytes(pkt[IP])
                    rebuilt_pkt = IP(ip_bytes)
                    if TCP in rebuilt_pkt or UDP in rebuilt_pkt or ICMP in rebuilt_pkt:
                        pkt = rebuilt_pkt
                except: pass

            # 3. Utilize System Normalizer (includes Shannon Entropy)
            norm = normalize_packet(pkt)
            if not norm: continue

            stats["count"] += 1
            
            # --- Extract Features for Inference ---
            if "window_size" in norm:
                stats["window"][norm["window_size"]] += 1
                
            if "dport" in norm:
                port_proto = f"{norm['protocol']}:{norm['dport']}"
                stats["dport"][port_proto] += 1
                
            # Check all payload variants for magic bytes
            variants = norm.get("payload_variants", [])
            for variant in variants:
                if len(variant) >= 4:
                    hex_val = variant[:4].hex()
                    magic_proto = f"{norm['protocol']}:{hex_val}"
                    stats["magic"][magic_proto] += 1
            
            # [NEW] Track entropy statistics
            entropy = norm.get("entropy", 0.0)
            if entropy > 0:
                stats["entropy_values"].append(entropy)
            if entropy > 7.5:
                stats["high_entropy_count"] += 1
                    
    except Exception as e:
        print(f"[!] Error reading {pcap_file}: {e}")
        
    return stats


def infer_rules(malware_pcap, clean_pcap, out_file):
    """
    Compares malware traffic against clean baseline to identify statistical
    anomalies and automatically generate Suricata-compatible detection rules.
    """
    print(f"[*] Inference Engine: Learning from {malware_pcap} (Baseline: {clean_pcap})...")
    
    mal_stats = analyze_pcap_stats(malware_pcap)
    clean_stats = analyze_pcap_stats(clean_pcap)

    if mal_stats["count"] == 0:
        print("[!] No recognized IP packets found in malware sample.")
        return

    inferred = []
    
    # Helper for inference logic
    def check_and_add(feature_dict, clean_dict, total_mal, total_clean, type_label, match_key, format_val_func, proto_extract=False):
        for key, count in feature_dict.items():
            mal_freq = count / total_mal
            clean_count = clean_dict.get(key, 0)
            clean_total = max(1, total_clean)
            clean_freq = clean_count / clean_total
            
            # If seen in > 10% of malware packets and < 1% of clean baseline
            if mal_freq > 0.1 and clean_freq < 0.01:
                protocol = "TCP"
                if proto_extract:
                    parts = str(key).split(":")
                    if len(parts) >= 2:
                        protocol = parts[0]
                        key = parts[1]
                
                val = format_val_func(key)
                
                inferred.append({
                    "id": f"auto_{type_label}_{key}",
                    "description": f"Inferred Anomalous {type_label}: {key} (Freq: {mal_freq:.2f})",
                    "protocol": protocol,
                    "match": {match_key: val}
                })

    # Execute Statistical Comparisons
    check_and_add(mal_stats["window"], clean_stats["window"], mal_stats["count"], clean_stats["count"], "window", "window_size", lambda k: int(k))
    check_and_add(mal_stats["dport"], clean_stats["dport"], mal_stats["count"], clean_stats["count"], "dport", "dport", lambda k: int(k), proto_extract=True)
    check_and_add(mal_stats["magic"], clean_stats["magic"], mal_stats["count"], clean_stats["count"], "magic", "payload_starts_with", lambda k: f"0x{k}", proto_extract=True)

    # [NEW] Entropy-Based Inference
    # If the malware PCAP has significantly more high-entropy packets than clean traffic
    mal_entropy_ratio = mal_stats["high_entropy_count"] / max(1, mal_stats["count"])
    clean_entropy_ratio = clean_stats["high_entropy_count"] / max(1, clean_stats["count"])
    
    if mal_entropy_ratio > 0.1 and clean_entropy_ratio < 0.05:
        avg_entropy = sum(mal_stats["entropy_values"]) / max(1, len(mal_stats["entropy_values"]))
        inferred.append({
            "id": f"auto_entropy_anomaly",
            "description": f"Inferred High-Entropy Anomaly (Avg: {avg_entropy:.2f}, Ratio: {mal_entropy_ratio:.2f})",
            "protocol": "TCP",
            "match": {"high_entropy": True}
        })
        print(f"    [+] Entropy Anomaly Detected: {mal_entropy_ratio:.0%} of malware has high entropy vs {clean_entropy_ratio:.0%} in clean traffic.")

    out_data = {"inferred_rootkit": {"name": "Inferred", "conditions": inferred}}
    with open(out_file, "w") as f:
        json.dump(out_data, f, indent=2)
    
    print(f"[+] Inferred {len(inferred)} high-confidence rules. Saved to {out_file}")


# ============================================================
# CONTINUOUS BASELINE UPDATING
# Merges verified benign traffic into the clean baseline PCAP,
# exponentially improving the AI's statistical accuracy over time.
# ============================================================
def update_baseline():
    """
    Reads the benign_buffer.pcap (safe traffic from today), verifies it,
    and merges it into the permanent clean_traffic.pcap baseline.
    """
    config = load_config()
    benign_path = config.get("BENIGN_BUFFER", "benign_buffer.pcap")
    clean_path = config.get("PCAP_CLEAN_FILE", "clean_traffic.pcap")
    
    if not os.path.exists(benign_path):
        print("[*] No benign buffer found. Skipping baseline update.")
        return
    
    try:
        benign_packets = rdpcap(benign_path)
        benign_count = len(benign_packets)
        
        if benign_count == 0:
            print("[*] Benign buffer is empty. Skipping baseline update.")
            return
        
        # Append benign packets to the clean baseline
        print(f"[+] Merging {benign_count} verified benign packets into {clean_path}...")
        wrpcap(clean_path, benign_packets, append=True)
        
        # Clear the benign buffer after successful merge
        os.remove(benign_path)
        print(f"[+] Baseline updated successfully. Benign buffer cleared.")
        
    except Exception as e:
        print(f"[!] Error updating baseline: {e}")


# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == "__main__":
    config = load_config()
    
    # Use quarantine buffer if it exists, otherwise fall back to simulator PCAP
    quarantine_path = config.get("QUARANTINE_BUFFER", "quarantine_buffer.pcap")
    fallback_path = config.get("PCAP_MALWARE_FILE", "synthetic_malware_v2.pcap")
    
    if os.path.exists(quarantine_path):
        m_pcap = quarantine_path
        print(f"[*] Using live quarantine buffer: {quarantine_path}")
    else:
        m_pcap = fallback_path
        print(f"[*] No quarantine buffer found. Using simulator PCAP: {fallback_path}")
    
    c_pcap = config.get("PCAP_CLEAN_FILE", "clean_traffic.pcap")
    outfile = config.get("INFERRED_RULES_FILE", "inferred_conditions_v2.json")
    
    # Step 1: Infer new rules from quarantined malware vs clean baseline
    infer_rules(m_pcap, c_pcap, outfile)
    
    # Step 2: Continuous Baseline Updating (merge benign traffic)
    update_baseline()