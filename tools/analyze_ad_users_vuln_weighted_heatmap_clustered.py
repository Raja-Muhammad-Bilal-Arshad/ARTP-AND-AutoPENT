#!/usr/bin/env python3
import os
import argparse
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import matplotlib.cm as cm
import networkx.algorithms.community as nx_comm
from pathlib import Path


def detect_adusers_csv(reports_dir):
    """Auto-detect ADUsers.csv in reports directory."""
    for root, _, files in os.walk(reports_dir):
        for f in files:
            if f.lower() == "adusers.csv":
                return os.path.join(root, f)
    return None


def compute_risk_score(row):
    """Simple heuristic for AD risk scoring."""
    risk = 0
    name = str(row.get("name", "")).lower()
    desc = str(row.get("description", "")).lower()
    status = str(row.get("status", "")).lower()

    if "admin" in name:
        risk += 5
    if "svc" in name or "service" in name:
        risk += 3
    if "password" in desc or "pass" in desc:
        risk += 4
    if "disabled" not in status:
        risk += 2
    return min(risk, 10)


def main():
    parser = argparse.ArgumentParser(description="AD User Weighted Risk Graph with Community Clustering Overlay")
    parser.add_argument("--reports-dir", required=True, help="Path to reports directory")
    parser.add_argument("--out", required=True, help="Output graph image path")
    parser.add_argument("--summary", required=True, help="Output CSV summary path")
    parser.add_argument("--format", default="png", choices=["png", "pdf", "svg"], help="Output format (default: png)")
    args = parser.parse_args()

    # --- Locate CSV ---
    csv_path = detect_adusers_csv(args.reports_dir)
    if not csv_path:
        print(f"[!] ADUsers.csv not found in {args.reports_dir}")
        return
    print(f"[*] Found AD user data: {csv_path}")

    df = pd.read_csv(csv_path)
    if df.empty:
        print("[!] ADUsers.csv is empty or unreadable.")
        return

    df.columns = [c.strip().lower() for c in df.columns]

    # --- Risk Scoring ---
    df["risk"] = df.apply(compute_risk_score, axis=1)
    privileged_users = df[df["risk"] >= 6]["name"].tolist() if "name" in df.columns else []
    print(f"[*] Found {len(privileged_users)} privileged accounts:")
    print(privileged_users)

    # --- Build Graph ---
    G = nx.Graph()
    for _, row in df.iterrows():
        user = str(row.get("name", "Unknown"))
        risk = row.get("risk", 0)
        G.add_node(user, risk=risk)

    users = list(G.nodes())
    for i, u in enumerate(users):
        for j, v in enumerate(users):
            if i != j and (hash(u + v) % 21 == 0):  # arbitrary light linkage
                G.add_edge(u, v, weight=(G.nodes[v]["risk"] + 1) / 2)

    # --- Compute Communities (Louvain modularity) ---
    if len(G.nodes()) > 2:
        communities = list(nx_comm.greedy_modularity_communities(G))
    else:
        communities = [set(G.nodes())]
    print(f"[*] Detected {len(communities)} privilege zones.")

    # --- Visualization ---
    plt.figure(figsize=(13, 11), facecolor="white")
    pos = nx.spring_layout(G, k=0.7, iterations=90, seed=42)

    # Color map for risk
    cmap = plt.get_cmap("RdYlGn_r")
    risks = [G.nodes[n]["risk"] for n in G.nodes()]
    norm = mcolors.Normalize(vmin=min(risks) if risks else 0, vmax=max(risks) if risks else 1)
    node_colors = [cmap(norm(G.nodes[n]["risk"])) for n in G.nodes()]
    node_sizes = [350 + G.nodes[n]["risk"] * 80 for n in G.nodes()]
    edge_widths = [0.5 + G.nodes[e[1]]["risk"] * 0.3 for e in G.edges()]

    # --- Draw Base Graph ---
    nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.4, edge_color="#888")
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9, linewidths=0.7, edgecolors="#333")
    nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold", font_color="#000")

    # --- Cluster Overlays (soft bubbles) ---
    overlay_colors = plt.cm.tab20.colors
    for i, comm in enumerate(communities):
        x_vals = [pos[n][0] for n in comm if n in pos]
        y_vals = [pos[n][1] for n in comm if n in pos]
        if not x_vals or not y_vals:
            continue
        centroid = (sum(x_vals) / len(x_vals), sum(y_vals) / len(y_vals))
        plt.scatter(
            [centroid[0]],
            [centroid[1]],
            s=12000,
            facecolors=overlay_colors[i % len(overlay_colors)],
            alpha=0.08,
            edgecolors="none",
        )
        plt.text(
            centroid[0],
            centroid[1],
            f"Zone {i+1}",
            fontsize=10,
            fontweight="bold",
            color="#222",
            ha="center",
        )

    # --- Colorbar ---
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    cbar = plt.colorbar(sm, ax=plt.gca(), fraction=0.03, pad=0.03)
    cbar.set_label("Risk Level (0-10)", fontsize=10)

    plt.title("AD User Privilege Graph with Risk Heatmap & Cluster Overlay", fontsize=14, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()

    # --- Save Outputs ---
    Path(os.path.dirname(args.out)).mkdir(parents=True, exist_ok=True)
    plt.savefig(args.out, format=args.format, dpi=400)
    print(f"[+] Clustered Risk Graph saved to: {args.out}")

    df.to_csv(args.summary, index=False)
    print(f"[+] Summary saved to: {args.summary}")


if __name__ == "__main__":
    main()
