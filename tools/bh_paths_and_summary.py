#!/usr/bin/env python3
"""
tools/bh_paths_and_summary.py

Build a directed graph from common BloodHound CSV reports and produce:
  - results/privilege_paths.csv   : shortest path(s) from users -> high-value groups
  - results/hv_groups_summary.csv : list of high-value groups found
  - results/node_summary.csv      : counts by node-type (users, computers, groups)
  - results/edge_summary.csv      : counts by relation type

Usage:
  python3 tools/bh_paths_and_summary.py reports/ results/

Notes:
 - Heuristic: looks for a handful of common CSVs produced by BloodHound.
 - If a CSV is missing it will be skipped (best-effort).
 - Requires networkx (install: pip install networkx).
 - Output CSVs are written into the provided results directory.
"""
from __future__ import annotations
import os, sys, csv, json
from typing import Dict, List, Tuple
from pathlib import Path

try:
    import networkx as nx
except Exception as e:
    print("Missing dependency: networkx. Install with: pip install networkx", file=sys.stderr)
    raise

# ------- Helper CSV readers -------
def read_csv_rows(path: Path) -> List[Dict[str,str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        return [dict((k or "").strip(), (v or "").strip()) for k,v in (row.items())] if False else list(reader)

# ------- Parsers for common reports -------
def parse_admin_groups(path: Path, G: nx.DiGraph):
    # AdminGroups.csv: common columns -> Member, Group
    rows = read_csv_rows(path)
    for r in rows:
        member = r.get("Member") or r.get("User") or r.get("Account") or r.get("MemberName")
        group  = r.get("Group")  or r.get("GroupName") or r.get("AdminGroup")
        if member and group:
            G.add_node(member, type="user")
            G.add_node(group, type="group")
            G.add_edge(member, group, rel="memberOf")

def parse_domain_users(path: Path, G: nx.DiGraph):
    rows = read_csv_rows(path)
    for r in rows:
        uname = r.get("Name") or r.get("User") or r.get("SamAccountName") or r.get("Username")
        if uname:
            G.add_node(uname, type="user")

def parse_domain_computers(path: Path, G: nx.DiGraph):
    rows = read_csv_rows(path)
    for r in rows:
        name = r.get("Name") or r.get("Computer") or r.get("Hostname") or r.get("ComputerName")
        if name:
            G.add_node(name, type="computer")

def parse_local_admins(path: Path, G: nx.DiGraph):
    # Computers_LocalAdminEnumeration.csv: columns -> Member (user), Computer
    rows = read_csv_rows(path)
    for r in rows:
        member = r.get("Member") or r.get("User") or r.get("Account")
        comp   = r.get("Computer") or r.get("Hostname") or r.get("Name")
        if member and comp:
            G.add_node(member, type="user")
            G.add_node(comp, type="computer")
            G.add_edge(member, comp, rel="localAdminOn")

def parse_sessions(path: Path, G: nx.DiGraph):
    # Users_Sessions.csv or Users_Sessions.html.csv: User, Computer
    rows = read_csv_rows(path)
    for r in rows:
        user = r.get("User") or r.get("UserName") or r.get("Account")
        comp = r.get("Computer") or r.get("Host") or r.get("Session")
        if user and comp:
            G.add_node(user, type="user")
            G.add_node(comp, type="computer")
            G.add_edge(user, comp, rel="hasSession")

def parse_dcsync(path: Path, G: nx.DiGraph):
    # DCSyncDirect.csv: User, Computer/DomainController
    rows = read_csv_rows(path)
    for r in rows:
        user = r.get("User") or r.get("Name") or r.get("SamAccountName")
        target = r.get("Computer") or r.get("DomainController") or r.get("Object")
        if user and target:
            G.add_node(user, type="user")
            G.add_node(target, type="computer")
            G.add_edge(user, target, rel="canDCSync")

def parse_unconstrained_delegation(path: Path, G: nx.DiGraph):
    rows = read_csv_rows(path)
    for r in rows:
        comp = r.get("Name") or r.get("Computer") or r.get("Hostname")
        if comp:
            G.add_node(comp, type="computer")
            G.add_edge(comp, comp, rel="unconstrainedDelegation")  # self-edge marker

def parse_constrained_delegation(path: Path, G: nx.DiGraph):
    rows = read_csv_rows(path)
    for r in rows:
        source = r.get("User") or r.get("Name") or r.get("Member")
        target = r.get("AllowedToDelegateTo") or r.get("SPN") or r.get("Computer")
        if source and target:
            G.add_node(source, type="user")
            G.add_node(target, type="computer")
            G.add_edge(source, target, rel="constrainedDelegation")

# Generic mapping heuristics
PARSERS = [
    ("AdminGroups.csv", parse_admin_groups),
    ("DomainUsers.csv", parse_domain_users),
    ("DomainComputers.csv", parse_domain_computers),
    ("Computers_LocalAdminEnumeration.csv", parse_local_admins),
    ("Users_Sessions.csv", parse_sessions),
    ("Users_Sessions.html.csv", parse_sessions),
    ("DCSyncDirect.csv", parse_dcsync),
    ("Computers_UnconstrainedDelegation.csv", parse_unconstrained_delegation),
    ("ConstrainedDelegation-Users.csv", parse_constrained_delegation),
    ("ConstrainedDelegation-All.csv", parse_constrained_delegation),
]

# ------- Utilities -------
def find_high_value_groups(reports_dir: Path) -> List[Tuple[str, Dict]]:
    hv = []
    # Try AdminGroups.csv and DomainAdmins.csv and AdminGroupsPopulatedCount.csv
    candidates = ["DomainAdmins.csv", "AdminGroups.csv", "AdminGroupsPopulatedCount.csv", "AdminsWithoutSensitiveFlag.html.csv"]
    for f in candidates:
        p = reports_dir / f
        if not p.exists():
            continue
        rows = read_csv_rows(p)
        for r in rows:
            name = r.get("Name") or r.get("Group") or r.get("Member")
            high = (r.get("HighValue") or r.get("High Value") or r.get("IsHighValue") or "").lower() == "true"
            admincount = (r.get("AdminCount") or r.get("HasAdminCount") or "").lower() == "true"
            # Heuristic: domain/admin groups often have 'ADMIN' or 'Domain Admin' etc
            is_named_hv = False
            if name and any(k in name.upper() for k in ["DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "ENTERPRISE KEY ADMINS", "KEY ADMINS", "SCHEMA ADMINS"]):
                is_named_hv = True
            if name and (high or admincount or is_named_hv):
                hv.append((name, r))
    return hv

def write_csv_rows(path: Path, rows: List[Dict], fieldnames: List[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

# ------- Main processing -------
def main():
    if len(sys.argv) < 3:
        print("Usage: bh_paths_and_summary.py <reports_dir> <out_dir>")
        sys.exit(1)
    reports_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    G = nx.DiGraph()

    # run parsers
    for fname, parser in PARSERS:
        p = reports_dir / fname
        if p.exists():
            try:
                parser(p, G)
            except Exception as e:
                print(f"Warning: parser failed for {fname}: {e}", file=sys.stderr)

    # Identify high-value target groups
    hv_list = find_high_value_groups(reports_dir)
    hv_names = [name for name, meta in hv_list]

    # If no explicit HV groups found, try heuristics: Domain Admins, Enterprise Admins
    heuristics = ["DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"]
    for h in heuristics:
        if any(h in n.upper() for n in G.nodes):
            hv_names.extend([n for n in G.nodes if h in n.upper()])

    hv_names = list(dict.fromkeys(hv_names))  # dedupe preserving order

    # Node summary
    node_counts = {}
    for n,d in G.nodes(data=True):
        t = d.get("type","unknown")
        node_counts[t] = node_counts.get(t,0) + 1
    node_summary_rows = [{"type":k,"count":v} for k,v in node_counts.items()]
    write_csv_rows(out_dir / "node_summary.csv", node_summary_rows, ["type","count"])

    # Edge summary
    rel_counts = {}
    for u,v,data in G.edges(data=True):
        rel = data.get("rel","edge")
        rel_counts[rel] = rel_counts.get(rel,0) + 1
    edge_summary_rows = [{"relation":k,"count":v} for k,v in rel_counts.items()]
    write_csv_rows(out_dir / "edge_summary.csv", edge_summary_rows, ["relation","count"])

    # HV groups summary
    hv_rows = []
    for name,meta in hv_list:
        hv_rows.append({"group": name, "meta_json": json.dumps(meta)})
    # also add heuristically discovered names
    for name in hv_names:
        if not any(r["group"]==name for r in hv_rows):
            hv_rows.append({"group": name, "meta_json": "{}"})
    write_csv_rows(out_dir / "hv_groups_summary.csv", hv_rows, ["group","meta_json"])

    # Privilege paths: for each user try to find shortest path to any hv group
    paths_rows = []
    users = [n for n,d in G.nodes(data=True) if d.get("type")=="user"]
    if not hv_names:
        print("No high-value groups identified; privilege paths will use heuristic target names if present.", file=sys.stderr)

    for u in users:
        best_path = None
        best_target = None
        for hv in hv_names:
            if hv not in G:
                continue
            try:
                path = nx.shortest_path(G, source=u, target=hv)
                if best_path is None or len(path) < len(best_path):
                    best_path = path
                    best_target = hv
            except nx.NetworkXNoPath:
                continue
        if best_path:
            # collect relation sequence
            rels = []
            for a,b in zip(best_path[:-1], best_path[1:]):
                rels.append(G.edges[a,b].get("rel","edge"))
            paths_rows.append({
                "actor": u,
                "target_group": best_target,
                "path_nodes": json.dumps(best_path),
                "path_relations": json.dumps(rels),
                "path_length": len(best_path)-1
            })

    # sort by path_length asc
    paths_rows.sort(key=lambda r: r["path_length"])
    write_csv_rows(out_dir / "privilege_paths.csv", paths_rows, ["actor","target_group","path_nodes","path_relations","path_length"])

    print("Wrote summaries to:", out_dir)
    print(" - node_summary.csv")
    print(" - edge_summary.csv")
    print(" - hv_groups_summary.csv")
    print(" - privilege_paths.csv")

if __name__ == "__main__":
    main()
