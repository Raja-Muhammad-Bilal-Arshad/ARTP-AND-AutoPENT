#!/usr/bin/env python3
"""
tools/plot_ad_attack_path.py

Build and plot focused "Path to Domain Admin" graphs from BloodHound-like CSV reports.

Usage:
  python3 tools/plot_ad_attack_path.py \
    --reports-dir reports \
    --out outputs/ad_attack_path.png \
    --summary outputs/ad_attack_path_summary.csv \
    --format png

Outputs:
  - image (png|pdf|svg) showing shortest paths to Domain Admin nodes (light mode)
  - CSV summary listing actor -> chain -> length -> suggestion

Light-mode styling (white background) suitable for papers / IEEE figures.
"""

from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import math
import sys

# -------------------------
# Robust CSV loader helper
# -------------------------
def read_csv_robust(path: Path) -> pd.DataFrame:
    """Try reading CSV robustly. Return empty DataFrame if unreadable."""
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path, encoding="latin-1")
    except Exception:
        # Attempt python engine with permissive settings
        try:
            return pd.read_csv(path, encoding="latin-1", engine="python", on_bad_lines="warn")
        except Exception:
            # Last resort: return raw lines as single-column frame
            try:
                with path.open("r", encoding="latin-1", errors="ignore") as fh:
                    lines = [l.rstrip("\n") for l in fh if l.strip()]
                if not lines:
                    return pd.DataFrame()
                return pd.DataFrame({"raw_line": lines})
            except Exception:
                return pd.DataFrame()

# -------------------------
# Graph construction
# -------------------------
def build_ad_graph(reports_dir: Path) -> Tuple[nx.DiGraph, List[str]]:
    """Read common BloodHound CSVs in reports_dir, build directed graph, return graph and list of domain admin nodes."""
    G = nx.DiGraph()
    reports_dir = Path(reports_dir)

    # Domain Admin identities (explicit list)
    domain_admins = set()

    # 1) DomainAdmins.csv or DomainAdmins.html (CSV preferred)
    p = reports_dir / "DomainAdmins.csv"
    if p.exists():
        df = read_csv_robust(p)
        # try guess column with name or member
        if not df.empty:
            if 'Name' in df.columns:
                for n in df['Name'].dropna().astype(str).tolist():
                    domain_admins.add(n.strip())
            else:
                # fallback: any first column values
                domain_admins.update(df.iloc[:,0].dropna().astype(str).str.strip().tolist())
    # 2) DomainAdmins could also be members of Domain Admins group; include members of DomainAdmins group by reading DomainGroups/DomainUsers
    # Read DomainGroups.csv (memberships)
    # We'll collect MemberOf edges from Users -> Groups via "Groups-HighValue-members.csv" / "Groups" / "DomainGroups"
    # Common edge CSVs: DomainUsers.csv, DomainGroups.csv, Groups-HighValue-members.csv, Owned-Users.html, Relationships-*.html
    # We'll parse several common files and create edges based on heuristics.

    # Helper to add node types
    def add_node(n, ntype="unknown"):
        if n is None:
            return
        n = str(n).strip()
        if n == "":
            return
        if not G.has_node(n):
            G.add_node(n, type=ntype)

    # 3) MemberOf edges (Users -> Groups) from "DomainUsers.csv" and "DomainGroups.csv" and "Groups-HighValue-members.csv"
    # Many BloodHound CSVs are formatted differently; try several candidates
    member_sources = [
        "Groups-HighValue-members.csv",
        "DomainUsers.csv",
        "DomainGroups.csv",
        "Users_Sessions.csv",
        "Users_userpassword.csv"
    ]
    for fname in member_sources:
        p = reports_dir / fname
        if not p.exists():
            continue
        df = read_csv_robust(p)
        if df.empty:
            continue
        # heuristics: try common column pairs
        # if "Member" and "Group" columns exist:
        if 'Member' in df.columns and 'Group' in df.columns:
            for _, row in df.iterrows():
                m = str(row['Member']).strip()
                g = str(row['Group']).strip()
                if m and g:
                    add_node(m, "user")
                    add_node(g, "group")
                    G.add_edge(m, g, etype="MemberOf")
        # if 'Name' and 'Group' columns:
        elif 'Name' in df.columns and 'Group' in df.columns:
            for _, row in df.iterrows():
                m = str(row['Name']).strip()
                g = str(row['Group']).strip()
                if m and g:
                    add_node(m, "user")
                    add_node(g, "group")
                    G.add_edge(m, g, etype="MemberOf")
        # else try to find any "MemberOf" like columns
        else:
            # try pairs of first two columns
            cols = list(df.columns)
            if len(cols) >= 2:
                for _, row in df.iterrows():
                    a = str(row[cols[0]]).strip()
                    b = str(row[cols[1]]).strip()
                    if a and b:
                        # Heuristic: if second column looks like a group (contains '@' uppercase), consider MemberOf
                        add_node(a, "entity")
                        add_node(b, "entity")
                        G.add_edge(a, b, etype="MemberOf")

    # 4) AdminTo edges (Group/User/Computer -> object) from DCSync lists and Admin reports
    admin_sources = [
        "DCSyncDirect.csv", "DCSyncDirectNonDAUsers.csv", "DCOwners.csv",
        "Computers_UnconstrainedDelegation.csv", "ConstrainedDelegation-All.csv"
    ]
    for fname in admin_sources:
        p = reports_dir / fname
        if not p.exists():
            continue
        df = read_csv_robust(p)
        if df.empty:
            continue
        # Common columns: 'Principal' and 'Object' or 'Computer' etc.
        cols = list(df.columns)
        if 'Principal' in df.columns and 'Object' in df.columns:
            for _, row in df.iterrows():
                a = str(row['Principal']).strip(); b = str(row['Object']).strip()
                if a and b:
                    add_node(a, "principal"); add_node(b, "object")
                    G.add_edge(a, b, etype="AdminTo")
        elif len(cols) >= 2:
            for _, row in df.iterrows():
                a = str(row[cols[0]]).strip(); b = str(row[cols[1]]).strip()
                if a and b:
                    add_node(a, "principal"); add_node(b, "object")
                    G.add_edge(a, b, etype="AdminTo")

    # 5) HasSession edges from "Users_Sessions.csv" or "EA_Sessions.html"
    p = reports_dir / "Users_Sessions.csv"
    if p.exists():
        df = read_csv_robust(p)
        if not df.empty:
            # expect columns such as 'User' and 'Computer'
            if 'User' in df.columns and 'Computer' in df.columns:
                for _, r in df.iterrows():
                    u = str(r['User']).strip(); c = str(r['Computer']).strip()
                    if u and c:
                        add_node(u, "user"); add_node(c, "computer")
                        G.add_edge(u, c, etype="HasSession")
            else:
                # try first two columns as user->computer
                cols = list(df.columns)
                if len(cols) >= 2:
                    for _, r in df.iterrows():
                        u = str(r[cols[0]]).strip(); c = str(r[cols[1]]).strip()
                        if u and c:
                            add_node(u, "user"); add_node(c, "computer")
                            G.add_edge(u, c, etype="HasSession")

    # 6) Relationships-*.html or *.csv may contain lists like "Principal, Property, Target" — try to parse those directly if CSVs exist
    # We'll inspect any file named "Relationships-*.html" and "Relationships-*.csv" but handle malformations gracefully.
    for p in reports_dir.glob("Relationships-*.csv"):
        df = read_csv_robust(p)
        if df.empty:
            continue
        cols = list(df.columns)
        # Heuristic: first col principal, last col target
        if len(cols) >= 2:
            for _, r in df.iterrows():
                a = str(r[cols[0]]).strip()
                b = str(r[cols[-1]]).strip()
                # Some rows describe relation types in middle column
                et = None
                if len(cols) >= 3:
                    et = str(r[cols[1]]).strip()
                if a and b:
                    add_node(a, "entity"); add_node(b, "entity")
                    G.add_edge(a, b, etype=(et or "relation"))

    # 7) Domains/groups/users fallback: DomainGroups.csv & DomainUsers.csv to detect group members
    p = reports_dir / "DomainGroups.csv"
    if p.exists():
        df = read_csv_robust(p)
        if not df.empty:
            cols = list(df.columns)
            if 'Member' in df.columns and 'Group' in df.columns:
                for _, r in df.iterrows():
                    m = str(r['Member']).strip(); g = str(r['Group']).strip()
                    if m and g:
                        add_node(m,'user'); add_node(g,'group'); G.add_edge(m,g, etype="MemberOf")

    # 8) Finally, mark domain_admin nodes more widely by checking groups named 'Domain Admins' or similar
    # scan for group nodes with names like 'DOMAIN ADMINS' in graph
    for n,d in list(G.nodes(data=True)):
        if isinstance(n, str) and ("domain admin" in n.lower() or "domain admins" in n.lower() or n.upper().endswith("DOMAIN ADMINS")):
            domain_admins.add(n)

    # Also if DomainAdmins.csv was empty but DomainAdmins group appears in DomainGroups, include its members
    # If we have a 'Domain Admins' group node, add its inbound members to domain_admins list
    for n in G.nodes():
        if isinstance(n,str) and "domain admins" in n.lower():
            # find predecessors (members)
            for pred in G.predecessors(n):
                domain_admins.add(pred)

    return G, sorted(domain_admins)

# -------------------------
# Path extraction
# -------------------------
def shortest_paths_to_targets(G: nx.DiGraph, targets: List[str], max_depth: int = 6) -> Dict[str, List[List[str]]]:
    """
    For each node in G, compute the shortest simple path(s) to any node in targets.
    Returns mapping: source -> list of shortest path lists (strings).
    """
    results = {}
    target_set = set(targets)
    if not target_set:
        return results

    # Precompute single-source shortest paths to all targets using BFS from each target back
    # We'll reverse graph and BFS from each target to gather distances to sources efficiently.
    Grev = G.reverse(copy=True)
    # distances: node -> (distance, via_target)
    dist = {}
    for t in target_set:
        if t not in Grev:
            continue
        # BFS layer by layer from t
        for node, length in nx.single_source_shortest_path_length(Grev, t, cutoff=max_depth).items():
            # node -> path length in reversed graph = distance from node to t in original graph
            cur = dist.get(node)
            if cur is None or length < cur[0]:
                dist[node] = (length, t)

    # For nodes with a recorded distance, generate the actual shortest path(s)
    for node, (dlen, via_target) in dist.items():
        if node == via_target:
            continue
        try:
            path = nx.shortest_path(G, node, via_target)
            results[node] = [path]
        except Exception:
            # if no path found (weird), skip
            pass
    return results

# -------------------------
# Plot & CSV output
# -------------------------
def suggestion_for_path(path: List[str], G: nx.DiGraph) -> str:
    """Produce a short generic suggestion based on edge types seen in the path."""
    etypes = []
    for u, v in zip(path[:-1], path[1:]):
        et = G.get_edge_data(u, v, default={}).get('etype', '')
        etypes.append(et or '')
    # heuristics
    if any('AdminTo' == e for e in etypes):
        return "Investigate AdminTo edges (privileged access)"
    if any('HasSession' == e for e in etypes):
        return "Lateral movement via active session (HasSession)"
    if any('MemberOf' == e for e in etypes):
        return "Privilege escalation via group membership"
    return "Investigate path relations"

def plot_subgraph_paths(G: nx.DiGraph, paths: Dict[str, List[List[str]]], out_path: Path, image_format: str = "png"):
    # Build subgraph containing only nodes/edges used in selected shortest paths
    sub_nodes = set()
    for src, path_list in paths.items():
        for p in path_list:
            sub_nodes.update(p)
    if not sub_nodes:
        print("[!] No paths to plot (no domain admin targets found).")
        return False

    H = G.subgraph(sub_nodes).copy()

    # Assign visual properties
    node_colors = []
    node_labels = {}
    sizes = []
    types = nx.get_node_attributes(H, 'type')

    for n in H.nodes():
        t = types.get(n, 'entity')
        node_labels[n] = n if len(n) <= 28 else (n[:25] + "...")
        if t == 'group':
            node_colors.append('#9fc5e8')  # light blue
            sizes.append(900)
        elif t == 'user':
            node_colors.append('#f6c1c7')  # light pink
            sizes.append(700)
        elif t == 'computer':
            node_colors.append('#cfe2b3')  # light green
            sizes.append(700)
        else:
            node_colors.append('#f2f2f2')  # neutral
            sizes.append(500)

    # Edge labels from etype
    edge_labels = {}
    for u,v,d in H.edges(data=True):
        et = d.get('etype') or ''
        edge_labels[(u,v)] = et

    # Layout - try shell_layout group by type for a clean hierarchy
    # We'll compute a layered layout: groups near the target (Domain Admins)
    try:
        # Node positions: use spring layout then adjust y by distance to nearest target
        pos = nx.spring_layout(H, k=0.8, seed=42)
    except Exception:
        pos = nx.circular_layout(H)

    plt.figure(figsize=(12, 8))
    ax = plt.gca()
    ax.set_facecolor('white')

    nx.draw_networkx_nodes(H, pos, node_color=node_colors, node_size=sizes, edgecolors='#666666')
    nx.draw_networkx_labels(H, pos, labels=node_labels, font_size=8)

    # draw edges with arrowheads
    nx.draw_networkx_edges(H, pos, arrowstyle='-|>', arrowsize=14, connectionstyle='arc3,rad=0.08', width=1.2)
    # draw edge labels (etype)
    nx.draw_networkx_edge_labels(H, pos, edge_labels=edge_labels, font_size=7)

    plt.title("Focused: Shortest Paths → Domain Admin (light mode)", fontsize=14)
    plt.axis('off')
    ensure_path = Path(out_path)
    ensure_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(str(out_path), format=image_format, dpi=300)
    plt.close()
    return True

def write_summary_csv(paths: Dict[str, List[List[str]]], G: nx.DiGraph, out_csv: Path):
    rows = []
    for src, p_list in sorted(paths.items(), key=lambda x: (len(x[1][0]) if x[1] else 999, x[0])):
        for p in p_list:
            suggestion = suggestion_for_path(p, G)
            rows.append({
                "actor": src,
                "chain": " -> ".join(p),
                "length": len(p)-1,
                "suggestion": suggestion
            })
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["actor","chain","length","suggestion"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    return len(rows)

# -------------------------
# CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", required=True, help="Directory with BloodHound CSV/HTML exports (reports/)")
    parser.add_argument("--out", required=True, help="Output image path (png/pdf/svg)")
    parser.add_argument("--summary", required=True, help="Output concise CSV summary path")
    parser.add_argument("--format", choices=["png","pdf","svg"], default="png")
    parser.add_argument("--max-depth", type=int, default=6, help="Max path length to search for")
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    out_path = Path(args.out)
    summary_path = Path(args.summary)

    if not reports_dir.exists():
        print(f"[!] Reports dir not found: {reports_dir}", file=sys.stderr)
        sys.exit(2)

    print("[*] Building AD graph from reports...")
    G, domain_admins = build_ad_graph(reports_dir)
    if not domain_admins:
        print("[!] No explicit Domain Admin nodes found; will attempt heuristic discovery (searching group names).")
    else:
        print(f"[*] Found Domain Admin nodes: {domain_admins[:10]}")

    # If domain_admins empty, attempt to use common identifiers 'DOMAIN ADMINS'
    if not domain_admins:
        for n in G.nodes():
            if isinstance(n, str) and "domain admin" in n.lower():
                domain_admins.append(n)

    if not domain_admins:
        print("[!] No Domain Admin targets discovered - nothing to compute. Exiting gracefully.")
        sys.exit(0)

    print("[*] Finding shortest paths to Domain Admin nodes (max-depth=%d)..." % args.max_depth)
    paths = shortest_paths_to_targets(G, domain_admins, max_depth=args.max_depth)
    if not paths:
        print("[!] No paths found within max depth. Try increasing --max-depth or review reports.")
        sys.exit(0)

    print(f"[*] Found {len(paths)} source nodes with paths to Domain Admin(s). Producing outputs...")

    wrote = plot_subgraph_paths(G, paths, out_path, image_format=args.format)
    if wrote:
        print(f"[+] Saved image: {out_path}")
    else:
        print("[!] Image not produced (no paths).")

    nrows = write_summary_csv(paths, G, summary_path)
    print(f"[+] Wrote summary CSV ({nrows} rows) to: {summary_path}")

if __name__ == "__main__":
    main()

