#!/usr/bin/env python3
import os
import argparse
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import matplotlib.cm as cm
import re
from pathlib import Path


def detect_adusers_csv(reports_dir):
    """Find ADUsers.csv automatically inside reports directory"""
    for root, _, files in os.walk(reports_dir):
        for f in files:
            if f.lower() == "adusers.csv":
                return os.path.join(root, f)
    return None


def compute_risk_score(row):
    """Simple heuristic for risk scoring"""
    risk = 0
    if "admin" in str(row.get("name", "")).lower():
        risk += 5
    if "svc" in str(row.get("name", "")).lower():
        risk += 3
    if "password" in str(row.get("description", "")).lower():
        risk += 4
    if "disabled" not in str(row.get("status", "")).lower():
        risk += 2
    return min(risk, 10)


def main():
    parser = argparse.ArgumentParser(description="AD User Weighted Risk Graph with Heatmap Overlay")
    parser.add_argument("--reports-dir", required=True, help="Path to reports directory")
    parser.add_argument("--out", required=True, help="Output graph image path")
    parser.add_argument("--summary", required=True, help="Output CSV summary path")
    parser.add_argument("--format", default="png", choices=["png", "pdf", "svg"], help="Output format (default: png)")
    args = parser.parse_args()

    # --- Auto-detect ADUsers.csv ---
    csv_path = detect_adusers_csv(args.reports_dir)
    if not csv_path:
        print(f"[!] ADUsers.csv not found in {args.reports_dir}")
        return
    print(f"[*] Found AD user data: {csv_path}")

    df = pd.read_csv(csv_path)
    if df.empty:
        print("[!] ADUsers.csv is empty or unreadable.")
        return

    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]

    # --- Risk scoring ---
    df["risk"] = df.apply(compute_risk_score, axis=1)

    # --- Find privileged accounts ---
    privileged_users = df[df["risk"] >= 6]["name"].tolist() if "name" in df.columns else []
    print(f"[*] Found {len(privileged_users)} privileged accounts:")
    print(privileged_users)

    # --- Build Graph ---
    G = nx.DiGraph()

    for _, row in df.iterrows():
        user = str(row.get("name", "Unknown"))
        risk = row.get("risk", 0)
        G.add_node(user, risk=risk)

    # Simulated trust relationships (optional edges)
    users = list(G.nodes())
    for i, u in enumerate(users):
        for j, v in enumerate(users):
            if i != j and (hash(u + v) % 23 == 0):  # arbitrary sparse linkage
                G.add_edge(u, v, weight=(G.nodes[v]["risk"] + 1) / 2)

    # --- Visualization ---
    plt.figure(figsize=(12, 10), facecolor="white")
    pos = nx.spring_layout(G, k=0.7, iterations=80, seed=42)

    # Normalize risk values for color mapping
    risks = [G.nodes[n]["risk"] for n in G.nodes()]
    norm = mcolors.Normalize(vmin=min(risks) if risks else 0, vmax=max(risks) if risks else 1)
    cmap = plt.get_cmap("RdYlGn_r")

    node_colors = [cmap(norm(G.nodes[n]["risk"])) for n in G.nodes()]
    node_sizes = [300 + G.nodes[n]["risk"] * 80 for n in G.nodes()]

    edge_weights = [0.5 + G.nodes[e[1]]["risk"] * 0.3 for e in G.edges()]

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9, linewidths=0.7, edgecolors="#333")
    nx.draw_networkx_edges(G, pos, width=edge_weights, alpha=0.5, edge_color="#999")
    nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold", font_color="#000000")

    # --- Colorbar ---
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    cbar = plt.colorbar(sm, ax=plt.gca(), fraction=0.03, pad=0.03)
    cbar.set_label("Risk Level (0-10)", fontsize=10)

    plt.title("Active Directory User Risk Graph (Weighted Heatmap)", fontsize=14, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()

    # --- Save Graph ---
    Path(os.path.dirname(args.out)).mkdir(parents=True, exist_ok=True)
    plt.savefig(args.out, format=args.format, dpi=300)
    print(f"[+] Graph saved to: {args.out}")

    # --- Save Summary CSV ---
    summary_df = df[["name", "risk"]] if "name" in df.columns else df
    summary_df.to_csv(args.summary, index=False)
    print(f"[+] Summary saved to: {args.summary}")


if __name__ == "__main__":
    main()
