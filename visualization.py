import matplotlib.pyplot as plt
import numpy as np
import os
import json
from common_utilities import load_config
from dynamic_analyzer import run_analysis
from scapy.all import rdpcap

# Helper to get ground truth
def get_logical_attack_count(config):
    rules_path = f"{config['OUTPUT_DIR']}/{config['COMBINED_RULES_FILE']}"
    if not os.path.exists(rules_path): return 0
    with open(rules_path, 'r') as f:
        rules = json.load(f)
    return len(rules) * 3

def count_packets(path):
    if not os.path.exists(path): return 0
    try: return len(rdpcap(path))
    except: return 0

def plot_confusion_matrix(tp, fn, fp, tn, outdir):
    matrix = np.array([[tn, fp], [fn, tp]])
    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.matshow(matrix, cmap=plt.cm.Blues)
    plt.title('Sentinel Forge Confusion Matrix', pad=20)
    fig.colorbar(cax)
    
    # [FIX] Set specific tick positions before setting labels
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    
    # Set the labels (Removed the empty '' string as it's no longer needed with explicit ticks)
    ax.set_xticklabels(['Benign', 'Malicious'])
    ax.set_yticklabels(['Benign', 'Malicious'])
    
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    
    for (i, j), z in np.ndenumerate(matrix):
        ax.text(j, i, str(z), ha='center', va='center', fontsize=14, 
                color='white' if z > (tn+tp)/2 else 'black')
    
    path = os.path.join(outdir, 'confusion_matrix.png')
    plt.savefig(path)
    print(f"[+] Saved Confusion Matrix -> {path}")

def plot_detection_rate(tp, fn, total, outdir):
    labels = ['Detected (Success)', 'Missed (Fragmentation)']
    sizes = [tp, fn]
    colors = ['#4CAF50', '#FF5722']
    
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')
    plt.title(f'Attack Detection Rate (Total Alerts: {tp+fn})')
    
    path = os.path.join(outdir, 'detection_rate.png')
    plt.savefig(path)
    print(f"[+] Saved Detection Rate Chart -> {path}")

def main():
    config = load_config()
    outdir = config['OUTPUT_DIR']
    mal_file = config.get("PCAP_MALWARE_FILE", "synthetic_malware_v2.pcap")
    clean_file = config.get("PCAP_CLEAN_FILE", "clean_background.pcap")

    print("[*] Generating Visualizations (Calculating Fresh Metrics)...")

    # 1. Calculate Real Numbers
    clean_alerts = run_analysis(clean_file, mode='silent')
    mal_alerts = run_analysis(mal_file, mode='silent')
    
    total_clean = count_packets(clean_file)
    total_attacks = get_logical_attack_count(config)
    
    TP = len(mal_alerts)
    FP = len(clean_alerts)
    TN = max(0, total_clean - FP)
    FN = max(0, total_attacks - TP)

    print(f"[*] Stats: TP={TP}, FN={FN}, FP={FP}, TN={TN}")

    # 2. Plot
    plot_confusion_matrix(TP, FN, FP, TN, outdir)
    plot_detection_rate(TP, FN, total_attacks, outdir)

if __name__ == "__main__":
    main()