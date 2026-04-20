import os
import numpy as np
try:
    from sklearn.tree import DecisionTreeClassifier
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from scapy.all import rdpcap
from packet_normalizer import normalize_packet
from common_utilities import load_config

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
