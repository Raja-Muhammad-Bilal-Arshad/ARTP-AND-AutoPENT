#!/usr/bin/env python3
"""
plot_metrics.py — AutoPENT Experiment Visualizer (IEEE-ready)
Generates multiple comparative plots from aggregate_metrics.csv
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
from datetime import datetime

# === CONFIGURATION ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "../results/artp/web_cluster")

if not os.path.exists(RESULTS_DIR):
    print(f"[❌] Results directory not found: {RESULTS_DIR}")
    exit(1)

CSV_FILE = os.path.join(RESULTS_DIR, "aggregate_metrics.csv")
OUTPUT_PLOT = os.path.join(RESULTS_DIR, "plots_IEEE_style")

def main():
    if not os.path.exists(CSV_FILE):
        print(f"[❌] CSV not found at: {CSV_FILE}")
        return

    print(f"[📊] Loading metrics from {CSV_FILE} ...")
    df = pd.read_csv(CSV_FILE)

    required_cols = ["coverage", "safety_score", "stealth_score", "path_efficiency"]
    for col in required_cols:
        if col not in df.columns:
            print(f"[⚠️] Missing column: {col}")
            return

    # === COMPUTE AGGREGATES ===
    summary = df[required_cols].agg(["mean", "std"])
    print(f"\n[ℹ️] Summary Statistics:\n{summary}\n")

    # === PLOTTING ===
    sns.set(style="whitegrid", font_scale=1.2)
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    pairs = [
        ("coverage", "safety_score", "Coverage vs Safety Score", "Fig. 2a"),
        ("coverage", "stealth_score", "Coverage vs Stealth Score", "Fig. 2b"),
        ("coverage", "path_efficiency", "Coverage vs Path Efficiency", "Fig. 2c"),
    ]

    for ax, (x, y, title, label) in zip(axes, pairs):
        ax.scatter(df[x], df[y], s=50, alpha=0.7, c="royalblue", label="Individual Runs")

        mean_x, mean_y = df[x].mean(), df[y].mean()
        std_x, std_y = df[x].std(), df[y].std()

        ax.errorbar(mean_x, mean_y, xerr=std_x, yerr=std_y,
                    fmt='o', color='red', ecolor='gray', elinewidth=2, capsize=4,
                    label="Mean ± Std")

        ax.set_title(title)
        ax.set_xlabel("Coverage")
        ax.set_ylabel(y.replace("_", " ").title())
        ax.set_xlim(0, 1.05)
        ax.set_ylim(0, 1.05)
        ax.legend()

        # IEEE-style figure annotation
        ax.text(0.02, 0.95, label, transform=ax.transAxes, fontsize=11,
                fontweight='bold', va='top', ha='left', color='dimgray')

    plt.tight_layout()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    pdf_path = f"{OUTPUT_PLOT}_{timestamp}.pdf"
    svg_path = f"{OUTPUT_PLOT}_{timestamp}.svg"

    plt.savefig(pdf_path, bbox_inches="tight")
    plt.savefig(svg_path, bbox_inches="tight")
    plt.show()

    print(f"[✅] Saved plots as:")
    print(f"   → {pdf_path}")
    print(f"   → {svg_path}")

if __name__ == "__main__":
    main()

