#!/usr/bin/env python3
import os
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import argparse

def load_ad_users(csv_path):
    print(f"[*] Loading AD user data from: {csv_path}")
    df = pd.read_csv(csv_path)
    return df

def detect_privileged_accounts(df):
    keywords = ["admin", "director", "vp", "chief", "ceo", "cfo", "coo", "svp", "managing"]
    privileged = df[df["Title"].str.lower().str.contains('|'.join(keywords), na=False)]
    return privileged["Name"].tolist()

def build_weighted_graph(df, privileged_accounts):
    G = nx.DiGraph()
    manager_count = {}

    for _, row in df.iterrows():
        user = row["Name"]
        manager = row["Manager"]
        title = row.get("Title", "")
        enabled = row.get("Enabled", True)
        department = row.get("Department", "")
        G.add_node(user, title=title, enabled=enabled, department=department)

        if pd.notna(manager) and manager.strip() != "":
            # Assign edge risk weights
            if manager in privileged_accounts and user in privileged_accounts:
                weight = 10
                reason = "Privileged→Privileged lateral exposure"
            elif manager not in privileged_accounts and user in privileged_accounts:
                weight = 8
                reason = "Non-Privileged→Privileged escalation"
            elif manager in privileged_accounts and user not in privileged_accounts:
                weight = 6
                reason = "Privileged→Non-Privileged delegation leak"
            else:
                weight = 1
                reason = "Normal relationship"

            if not row["Enabled"]:
                weight += 5
                reason += " (disabled account in chain)"

            G.add_edge(manager, user, weight=weight, reason=reason)
            manager_count.setdefault(user, set()).add(manager)

    # Multiple managers vulnerability
    for u, mgrs in manager_count.items():
        if len(mgrs) > 1:
            for m in mgrs:
                if G.has_edge(m, u):
                    G[m][u]["weight"] += 4
                    G[m][u]["reason"] += " + Multiple managers"

    return G

def analyze_risk_paths(G, privileged_accounts):
    paths = []
    for priv in privileged_accounts:
        for node in G.nodes():
            if node == priv:
                continue
            try:
                path = nx.shortest_path(G, source=node, target=priv)
                total_risk = sum(G[path[i]][path[i + 1]]["weight"] for i in range(len(path) - 1))
                avg_risk = total_risk / (len(path) - 1)
                paths.append({
                    "From": node,
                    "To": priv,
                    "Path": " → ".join(path),
                    "TotalRisk": total_risk,
                    "AvgRisk": round(avg_risk, 2)
                })
            except nx.NetworkXNoPath:
                continue
    return pd.DataFrame(paths)

def plot_weighted_graph(G, privileged_accounts, output_path):
    plt.figure(figsize=(22, 16))
    pos = nx.spring_layout(G, k=0.35, iterations=80, seed=42)

    # Node colors
    node_colors = []
    for node in G.nodes():
        if node in privileged_accounts:
            node_colors.append("#FF6F61")  # red/orange
        else:
            node_colors.append("#C6E5B1")  # light green

    # Edge colors and widths based on weight
    weights = [G[u][v]["weight"] for u, v in G.edges()]
    max_w = max(weights) if weights else 1
    edge_colors = [
        (w / max_w, 0.2, 0.1) if w > 4 else (0.7, 0.7, 0.7) for w in weights
    ]
    widths = [1 + (w / 2) for w in weights]

    nx.draw(
        G, pos,
        with_labels=True,
        node_color=node_colors,
        node_size=800,
        font_size=8,
        font_weight="bold",
        arrowsize=10,
        edge_color=edge_colors,
        width=widths
    )

    plt.title("Weighted AD Privilege Attack Path Graph (Risk-Based)", fontsize=14)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, facecolor="white")
    print(f"[+] Weighted graph saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Weighted AD User Relationship Analysis with Risk Scoring")
    parser.add_argument("--reports-dir", required=True, help="Directory containing ADUsers.csv")
    parser.add_argument("--out", required=True, help="Output image path")
    parser.add_argument("--summary", required=True, help="Output CSV summary path")
    args = parser.parse_args()

    csv_path = os.path.join(args.reports_dir, "ADUsers.csv")
    df = load_ad_users(csv_path)
    privileged_accounts = detect_privileged_accounts(df)
    print(f"[*] Found {len(privileged_accounts)} privileged accounts: {privileged_accounts}")

    G = build_weighted_graph(df, privileged_accounts)
    df_paths = analyze_risk_paths(G, privileged_accounts)
    if not df_paths.empty:
        df_paths.sort_values(by="TotalRisk", ascending=False, inplace=True)
        df_paths.to_csv(args.summary, index=False)
        print(f"[+] Path risk summary saved to: {args.summary}")
    else:
        print("[!] No paths to privileged accounts found.")

    plot_weighted_graph(G, privileged_accounts, args.out)

if __name__ == "__main__":
    main()

