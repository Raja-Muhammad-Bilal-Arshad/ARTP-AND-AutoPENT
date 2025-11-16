import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load your results file
df = pd.read_csv("results/artp/web_cluster/aggregate_metrics.csv")

# IEEE-standard style setup
plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams.update({
    "font.size": 12,
    "axes.labelsize": 13,
    "axes.titlesize": 14,
    "grid.alpha": 0.4,
    "lines.markersize": 6,
    "figure.figsize": (10, 6)
})

metrics = ["coverage", "path_efficiency", "recon_precision", "recon_recall", "safety_score", "stealth_score"]

for metric in metrics:
    plt.figure()
    plt.scatter(range(1, len(df)+1), df[metric], color="black", label="Run value", alpha=0.8)
    plt.axhline(y=df[metric].mean(), color="red", linestyle="--", label=f"Mean = {df[metric].mean():.3f}")
    plt.title(f"{metric.replace('_', ' ').title()} Across Runs (IEEE-style)")
    plt.xlabel("Run Number")
    plt.ylabel(metric.replace("_", " ").title())
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(f"results/artp/web_cluster/{metric}_IEEE_plot.png", dpi=300)
    plt.close()

print("[✅] Plots saved in results/artp/web_cluster/")
