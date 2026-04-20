import os
import random
import numpy as np
try:
    from sklearn.tree import DecisionTreeClassifier
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from scapy.all import rdpcap, wrpcap, Raw
from scapy.layers.inet import IP, TCP, UDP
from packet_normalizer import normalize_packet
from common_utilities import load_config


def generate_custom_attack_samples(malware_pcap: str):
    """
    Generates synthetic custom-style zero-day attack packets and APPENDS them
    to the malware training PCAP.

    WHY: The standard malware PCAP only has rootkit packets with known weird ports
    (sport=666, sport=41302, etc.). The ML model never sees packets of this form:
        Kali (sport=RANDOM_HIGH) --> Ubuntu (dport=443) with XOR-encrypted payload
    ...so it cannot learn to flag them as SUSPICIOUS.

    This function generates 100 such packets covering:
      - XOR-encrypted random payloads (high entropy, non-TLS, non-HTTP magic)
      - Varied source ports (all high/ephemeral, >1024)
      - Common target ports (443, 80, 22, 8443)
      - Multiple simulated attacker IPs
    """
    print("[*] Generating custom zero-day attack samples for training enrichment...")
    pkts = []
    attacker_ips = ["10.0.2.15", "10.0.2.99", "172.16.0.5", "192.168.2.50"]
    target_ports = [443, 80, 22, 8443]

    for _ in range(100):
        # XOR-encrypted random payload (simulates encrypted C2 beacon)
        payload_size = random.randint(64, 600)
        raw_bytes = os.urandom(payload_size)
        xor_key = random.randint(1, 255)
        xor_payload = bytes([b ^ xor_key for b in raw_bytes])

        src_ip  = random.choice(attacker_ips)
        dst_port = random.choice(target_ports)
        src_port = random.randint(1025, 65000)  # high/ephemeral port = initiator

        pkt = (IP(src=src_ip, dst="192.168.1.100") /
               TCP(sport=src_port, dport=dst_port, window=65535) /
               Raw(load=xor_payload))
        pkts.append(pkt)

    wrpcap(malware_pcap, pkts, append=True)
    print(f"[+] Appended {len(pkts)} custom attack samples to {malware_pcap}")
    print(f"    These teach the ML: high-sport→web-dport + XOR payload = MALICIOUS")

def extract_features(pcap_path):
    """
    Extracts structured, tabular features from packets for ML training.
    """
    if not os.path.exists(pcap_path):
        print(f"[-] PCAP not found: {pcap_path}")
        return []
        
    print(f"[*] Extracting features from {pcap_path}...")
    packets = rdpcap(pcap_path)
    features = []
    
    for pkt in packets:
        norm = normalize_packet(pkt)
        if not norm: continue
        
        # 7-feature vector — must EXACTLY match ml_predict() in dynamic_analyzer.py
        entropy = norm.get("entropy", 0.0)
        dport = norm.get("dport", 0)
        sport = norm.get("sport", 0)
        win_size = norm.get("window_size", 0)
        proto = 1 if norm.get("protocol") == "TCP" else 0
        has_magic = norm.get("has_magic_pattern", 0)       # NEW: non-TLS/non-HTTP payload start
        is_inbound = norm.get("is_inbound_to_server", 0)   # NEW: external→internal on web ports

        features.append([entropy, dport, sport, win_size, proto, has_magic, is_inbound])
        
    return features

def train():
    if not HAS_SKLEARN:
        print("[!] Error: scikit-learn is not installed.")
        print("[!] Run: pip install scikit-learn joblib")
        return

    print("==========================================")
    print("   ML PRE-FILTER TRAINER (Decision Tree)  ")
    print("==========================================")

    config = load_config()
    malware_pcap = config.get("PCAP_MALWARE_FILE", "synthetic_malware_v2.pcap")
    clean_pcap = config.get("PCAP_CLEAN_FILE", "clean_traffic.pcap")

    # 0. Enrich the malware PCAP with custom-style zero-day attack samples.
    #    This teaches the model what encrypted C2 beacons look like (sport=HIGH → dport=443).
    #    Without this, the model only knows rootkit ports (666, 41302) not custom attacks.
    generate_custom_attack_samples(malware_pcap)

    # 1. Extract Training Data
    mal_features = extract_features(malware_pcap)
    clean_features = extract_features(clean_pcap)
    
    if not mal_features or not clean_features:
        print("[-] Missing data. Cannot train model.")
        return
        
    # 2. Label the Data (1 = Suspicious, 0 = Safe)
    X = np.array(mal_features + clean_features)
    y = np.array([1]*len(mal_features) + [0]*len(clean_features))
    
    # 3. Train the Decision Tree Model
    # Max Depth = 5 prevents overfitting and ensures microsecond O(depth) latency
    print(f"[*] Training Explainable Decision Tree on {len(X)} samples...")
    print(f"    Malware samples : {len(mal_features)}")
    print(f"    Clean samples   : {len(clean_features)}")
    print(f"    class_weight    : balanced (prevents bias toward majority class)")
    # class_weight='balanced' makes the model penalize misclassifying the minority
    # class (malware) proportionally more, fixing the "always predict clean" bias.
    model = DecisionTreeClassifier(max_depth=5, random_state=42, class_weight='balanced')
    model.fit(X, y)
    
    # 4. Save the Model
    joblib.dump(model, "ml_prefilter.joblib")
    print("[+] Training Complete. Model saved to ml_prefilter.joblib")
    print("[+] 'dynamic_analyzer.py' will now use this model to triage live packets.")

if __name__ == "__main__":
    train()
