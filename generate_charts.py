"""
Occult Tracer - Thesis Defense Visualizations (Seaborn Edition)
================================================================
Generates simple, clean, and highly relevant academic charts
for Chapter 4 and Chapter 5 using only Seaborn + Pandas.
"""

import os
import csv
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

OUTPUT_DIR = "output_v2"

def setup_sns():
    # Use a highly academic, simple white grid theme
    sns.set_theme(style="whitegrid", context="paper", font_scale=1.3)
    plt.rcParams["figure.figsize"] = (8, 5)

def plot_confusion_matrix():
    """Generates the 60.78% Holistic System Confusion Matrix for Chapter 5"""
    setup_sns()
    
    # Thesis Metrics: TN=1000, FP=0, FN=20, TP=31
    matrix = np.array([[1000, 0], [20, 31]])
    
    plt.figure()
    # Create a simple heatmap
    ax = sns.heatmap(matrix, annot=True, fmt="d", cmap="Blues", cbar=False,
                     xticklabels=["Predicted Clean", "Predicted Threat"],
                     yticklabels=["Actual Clean", "Actual Threat"],
                     annot_kws={"size": 18, "weight": "bold"})
    
    plt.title("Holistic System Confusion Matrix", pad=20, fontweight='bold')
    plt.tight_layout()
    out_path = os.path.join(OUTPUT_DIR, "sns_confusion_matrix.png")
    plt.savefig(out_path, dpi=300)
    print(f"[+] Saved: {out_path}")
    plt.close()

def plot_feature_importance():
    """Generates the Random Forest Weight Bar Chart for Chapter 4"""
    setup_sns()
    
    features = ['window_size', 'sport', 'dport', 'entropy', 'proto', 'is_inbound', 'magic_pattern']
    importance = [0.5086, 0.1490, 0.1177, 0.0950, 0.0828, 0.0320, 0.0149]
    
    # Create DataFrame for clean Seaborn plotting
    df = pd.DataFrame({'Feature': features, 'Importance': importance})
    df = df.sort_values('Importance', ascending=False)
    
    plt.figure()
    sns.barplot(data=df, x='Importance', y='Feature', palette="viridis")
    plt.title("Random Forest: Feature Importance (Weights)", pad=15, fontweight='bold')
    plt.xlabel("Gini Importance Score")
    plt.ylabel("")
    plt.tight_layout()
    out_path = os.path.join(OUTPUT_DIR, "sns_feature_importance.png")
    plt.savefig(out_path, dpi=300)
    print(f"[+] Saved: {out_path}")
    plt.close()

def plot_latency_distribution():
    """Generates the Kernel Density Estimation (KDE) line plot for Detection Latency"""
    setup_sns()
    csv_path = "latency_results.csv"
    
    if not os.path.exists(csv_path):
        print(f"[-] Missing {csv_path}. Run metric.py first.")
        return
    
    latencies = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try: latencies.append(float(row.get("latency_ms", 0)))
            except: pass
            
    if not latencies: return
    
    plt.figure()
    # Simple line plot with filled area (KDE Curve)
    sns.kdeplot(latencies, fill=True, color="crimson", alpha=0.5, linewidth=2)
    plt.title("Time-to-Detect Latency Distribution", pad=15, fontweight='bold')
    plt.xlabel("Latency (Milliseconds)")
    plt.ylabel("Density")
    
    # Add mean line
    plt.axvline(np.mean(latencies), color='black', linestyle='--', label=f'Mean: {np.mean(latencies):.2f}ms')
    plt.legend()
    
    plt.tight_layout()
    out_path = os.path.join(OUTPUT_DIR, "sns_latency_distribution.png")
    plt.savefig(out_path, dpi=300)
    print(f"[+] Saved: {out_path}")
    plt.close()

def plot_detection_pie_chart():
    """Generates a Pie Chart showing Caught vs Missed Threats"""
    setup_sns()
    
    # Holistic Data
    labels = ['Detected (Caught)', 'Missed (Fragmented)']
    sizes = [31, 20]
    colors = ['#22c55e', '#ef4444'] # Enterprise Green and Warning Red
    explode = (0.05, 0) # Slightly separate the slices
    
    plt.figure()
    # Seaborn leverages matplotlib for pie charts, using beautiful styling
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=False, startangle=90, textprops={'fontsize': 12, 'weight': 'bold'})
    
    plt.title("Network Threat Detection Ratio", pad=20, fontweight='bold', fontsize=16)
    plt.axis('equal') 
    
    out_path = os.path.join(OUTPUT_DIR, "sns_accuracy_pie.png")
    plt.savefig(out_path, dpi=300)
    print(f"[+] Saved: {out_path}")
    plt.close()

if __name__ == "__main__":
    try:
        import seaborn
    except ImportError:
        print("[!] Seaborn is not installed. Run: pip install seaborn pandas")
        exit(1)
        
    print("==========================================")
    print("   SEABORN CHART GENERATOR (THESIS)       ")
    print("==========================================")
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    plot_confusion_matrix()
    plot_feature_importance()
    plot_latency_distribution()
    plot_detection_pie_chart()
    
    print("\n[+] All Seaborn charts successfully exported!")
