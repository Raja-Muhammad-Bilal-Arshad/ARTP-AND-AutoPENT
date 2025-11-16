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
    manager_count = {}

    for _, row in df.iterrows():
        user = row["Name"]
        manager = row["Manager"]
        title = row.get("Title", "")
        department = row.get("Department", "")
        enabled = row.get("Enabled", True)

        G.add_node(user, title=title, department=department, enabled=enabled)

        if pd.notna(manager) and manager.strip() != "":
            G.add_edge(manager, user)
            manager_count.setdefault(user, set()).add(manager)

    return G, manager_count

def detect_privileged_accounts(df):
    keywords = ["admin", "director", "vp", "chief", "ceo", "cfo", "coo", "svp", "managing"]
    privileged = df[df["Title"].str.lower().str.contains('|'.join(keywords), na=False)]
    return privileged["Name"].tolist()

def detect_vulnerabilities(G, df, manager_count, privileged_accounts):
    vulnerabilities = set()
    reasons = {}

    # 1. Multiple managers
    for user, mgrs in manager_count.items():
        if len(mgrs) > 1:
            vulnerabilities.add(user)
            reasons[user] = "Multiple managers (delegation or misconfig)"

    # 2. Cycles in management
    cycles = list(nx.simple_cycles(G))
    for cycle in cycles:
        for user in cycle:
            vulnerabilities.add(user)
            reasons[user] = "Cycle detected in management chain"

    # 3. Disabled accounts in chain
    for _, row in df.iterrows():
        if not row["Enabled"]:
            user = row["Name"]
            vulnerabilities.add(user)
            reasons[user] = "Disabled account present in chain"

    # 4. Privileged managing privileged
    for u, v in G.edges():
        if u in privileged_accounts and v in privileged_accounts:
            vulnerabilities.add(v)
            reasons[v] = "Privileged manages privileged (lateral exposure)"

    # 5. Non-privileged managing privileged
    for u, v in G.edges():
        if u not in privileged_accounts and v in privileged_accounts:
            vulnerabilities.add(u)
            reasons[u] = "Non-privileged manages privileged (possible escalation)"

    return vulnerabilities, reasons

def summarize_vulnerabilities(vulns, reasons, out_csv):
    if not vulns:
        print("[*] No vulnerable chains detected.")
        return
    data = [{"User": u, "Reason": reasons.get(u, "Unknown")} for u in vulns]
    df = pd.DataFrame(data)
    df.to_csv(out_csv, index=False)
    print(f"[+] Vulnerability summary saved to: {out_csv}")

def plot_graph(G, privileged_accounts, vulnerabilities, output_path):
    plt.figure(figsize=(20, 14))
    pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)

    node_colors = []
    for node in G.nodes():
        if node in privileged_accounts:
            node_colors.append("#FF6F61")  # red/orange
        elif node in vulnerabilities:
            node_colors.append("#FFD580")  # orange/yellow
        else:
            node_colors.append("#C6E5B1")  # soft green

    nx.draw(
        G, pos,
        with_labels=True,
        node_color=node_colors,
        node_size=800,
        font_size=8,
        font_weight="bold",
        arrowsize=10,
        edge_color="#A0A0A0",
        width=0.7
    )

    plt.title("AD Privilege Graph with Vulnerability Chains", fontsize=14)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, facecolor="white")
    print(f"[+] Vulnerability graph saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Analyze AD Users for privilege escalation & vulnerabilities")
    parser.add_argument("--reports-dir", required=True, help="Directory containing ADUsers.csv")
    parser.add_argument("--out", required=True, help="Output image path")
    parser.add_argument("--summary", required=True, help="Output CSV summary path")
    args = parser.parse_args()

    csv_path = os.path.join(args.reports_dir, "ADUsers.csv")
    df = load_ad_users(csv_path)
    G, manager_count = build_graph(df)
    privileged_accounts = detect_privileged_accounts(df)
    print(f"[*] Found {len(privileged_accounts)} privileged accounts: {privileged_accounts}")

    vulnerabilities, reasons = detect_vulnerabilities(G, df, manager_count, privileged_accounts)
    summarize_vulnerabilities(vulnerabilities, reasons, args.summary)
    plot_graph(G, privileged_accounts, vulnerabilities, args.out)

if __name__ == "__main__":
    main()
