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

def build_graph(df):
    G = nx.DiGraph()

    for _, row in df.iterrows():
        user = row["Name"]
        manager = row["Manager"]
        title = row.get("Title", "")
        department = row.get("Department", "")

        G.add_node(user, title=title, department=department)

        if pd.notna(manager) and manager.strip() != "":
            G.add_edge(manager, user)  # Manager -> Subordinate

    return G

def detect_privileged_accounts(df):
    keywords = ["admin", "director", "vp", "chief", "ceo", "cfo", "coo", "svP", "managing"]
    privileged = df[df["Title"].str.lower().str.contains('|'.join(keywords), na=False)]
    return privileged["Name"].tolist()

def plot_graph(G, privileged_accounts, output_path):
    plt.figure(figsize=(18, 12))
    pos = nx.spring_layout(G, k=0.3, iterations=50)

    # Node colors
    node_colors = []
    for node in G.nodes():
        if node in privileged_accounts:
            node_colors.append("#FF6F61")  # Red-orange for privileged
        else:
            node_colors.append("#AEDFF7")  # Light blue for normal users

    nx.draw(
        G, pos,
        with_labels=True,
        node_color=node_colors,
        node_size=800,
        font_size=8,
        font_weight="bold",
        arrowsize=10,
        edge_color="#B0B0B0",
        width=0.8
    )

    plt.title("Active Directory User Hierarchy & Privilege Paths", fontsize=14)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, facecolor="white")
    print(f"[+] Graph saved to: {output_path}")

def summarize_paths(G, privileged_accounts, out_csv):
    print("[*] Analyzing shortest paths to privileged accounts...")
    paths_data = []
    for node in G.nodes():
        for target in privileged_accounts:
            if node != target and nx.has_path(G, node, target):
                path = nx.shortest_path(G, node, target)
                paths_data.append({
                    "From": node,
                    "To": target,
                    "Path": " -> ".join(path),
                    "Hops": len(path) - 1
                })

    if not paths_data:
        print("[!] No paths to privileged accounts found.")
    else:
        df_paths = pd.DataFrame(paths_data)
        df_paths.to_csv(out_csv, index=False)
        print(f"[+] Path summary saved to: {out_csv}")

def main():
    parser = argparse.ArgumentParser(description="Analyze AD User CSV and plot privilege paths")
    parser.add_argument("--reports-dir", required=True, help="Directory containing ADUsers.csv")
    parser.add_argument("--out", required=True, help="Output image path")
    parser.add_argument("--summary", required=True, help="Output CSV summary path")
    args = parser.parse_args()

    csv_path = os.path.join(args.reports_dir, "ADUsers.csv")
    df = load_ad_users(csv_path)
    G = build_graph(df)
    privileged_accounts = detect_privileged_accounts(df)
    print(f"[*] Found {len(privileged_accounts)} privileged accounts: {privileged_accounts}")

    summarize_paths(G, privileged_accounts, args.summary)
    plot_graph(G, privileged_accounts, args.out)

if __name__ == "__main__":
    main()
