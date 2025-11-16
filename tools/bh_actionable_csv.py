#!/usr/bin/env python3
"""
tools/bh_actionable_csv.py

Produce a one-line actionable CSV for each discovered user -> high-value-group path.

Outputs (into <out_dir>):
  actionable_paths.csv  : actor, target_group, path_nodes (json), path_rels (json), path_length, action_suggestion, priority_score

Notes:
 - Heuristic mapping from relation sequences -> high-level simulated action suggestions.
 - Safe: NO exploit payloads, NO live commands. Suggestions are labels your planner can consume.
 - Requires networkx (pip install networkx).
"""
from __future__ import annotations
import os, sys, csv, json
from pathlib import Path
from typing import List, Dict

try:
    import networkx as nx
except Exception as e:
    print("Missing dependency: networkx. Install with: pip install networkx", file=sys.stderr)
    raise

# --- helpers (reuse parsers from previous tool) ---
def read_csv_rows(path: Path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        return list(reader)

def add_edge(G: nx.DiGraph, a: str, b: str, rel: str, a_type: str="unknown", b_type: str="unknown"):
    G.add_node(a, type=a_type)
    G.add_node(b, type=b_type)
    G.add_edge(a, b, rel=rel)

# Basic parsers (cover common BloodHound CSVs)
def parse_admin_groups(p: Path, G: nx.DiGraph):
    for r in read_csv_rows(p):
        member = r.get("Member") or r.get("User") or r.get("Account") or r.get("MemberName")
        group  = r.get("Group")  or r.get("GroupName") or r.get("AdminGroup")
        if member and group:
            add_edge(G, member, group, "memberOf", a_type="user", b_type="group")

def parse_domain_users(p: Path, G: nx.DiGraph):
    for r in read_csv_rows(p):
        uname = r.get("Name") or r.get("User") or r.get("SamAccountName") or r.get("Username")
        if uname:
            G.add_node(uname, type="user")

def parse_domain_computers(p: Path, G: nx.DiGraph):
    for r in read_csv_rows(p):
        name = r.get("Name") or r.get("Computer") or r.get("Hostname")
        if name:
            G.add_node(name, type="computer")

def parse_local_admins(p: Path, G: nx.DiGraph):
    for r in read_csv_rows(p):
        member = r.get("Member") or r.get("User") or r.get("Account")
        comp   = r.get("Computer") or r.get("Hostname") or r.get("Name")
        if member and comp:
            add_edge(G, member, comp, "localAdminOn", a_type="user", b_type="computer")

def parse_sessions(p: Path, G: nx.DiGraph):
    for r in read_csv_rows(p):
        user = r.get("User") or r.get("UserName") or r.get("Account")
        comp = r.get("Computer") or r.get("Host") or r.get("Session")
        if user and comp:
            add_edge(G, user, comp, "hasSession", a_type="user", b_type="computer")

def parse_dcsync(p: Path, G: nx.DiGraph):
    for r in read_csv_rows(p):
        user = r.get("User") or r.get("Name") or r.get("SamAccountName")
        target = r.get("Computer") or r.get("DomainController") or r.get("Object")
        if user and target:
            add_edge(G, user, target, "canDCSync", a_type="user", b_type="computer")

def parse_unconstrained_delegation(p: Path, G: nx.DiGraph):
    for r in read_csv_rows(p):
        comp = r.get("Name") or r.get("Computer") or r.get("Hostname")
        if comp:
            add_edge(G, comp, comp, "unconstrainedDelegation", a_type="computer", b_type="computer")

def parse_constrained_delegation(p: Path, G: nx.DiGraph):
    for r in read_csv_rows(p):
        src = r.get("User") or r.get("Name") or r.get("Member")
        target = r.get("AllowedToDelegateTo") or r.get("SPN") or r.get("Computer")
        if src and target:
            add_edge(G, src, target, "constrainedDelegation", a_type="user", b_type="computer")

# mapping table: relation sequence -> high-level simulated action
RELATION_TO_ACTION = {
    # direct DC sync right -> highest priority simulated action
    ("canDCSync",): ("attempt_dcsync_simulated", 100),
    # user has session on computer and is local admin on that computer -> abuse local admin to move laterally
    ("hasSession","localAdminOn"): ("abuse_local_admin_simulated", 90),
    # user is memberOf group that is high-value -> try group impersonation / escalate via group membership
    ("memberOf",): ("use_group_membership_simulated", 80),
    # unconstrained delegation on a computer -> abuse delegation to obtain KRB ticket / impersonation
    ("unconstrainedDelegation",): ("abuse_unconstrained_delegation_simulated", 95),
    # constrained delegation -> request service ticket / kerberos relay style (simulated)
    ("constrainedDelegation",): ("abuse_constrained_delegation_simulated", 85),
    # local admin on computer alone -> attempt local post-exploit simulation
    ("localAdminOn",): ("post_exploit_local_admin_simulated", 70),
    # hasSession alone -> attempt lateral movement simulated
    ("hasSession",): ("attempt_lateral_via_session_simulated", 60),
}

# fallback suggestion mapper given full relation list (tries to match subsequences)
def map_relations_to_action(rels: List[str]):
    # exact match first (single-relation or tuple)
    tup = tuple(rels)
    if tup in RELATION_TO_ACTION:
        return RELATION_TO_ACTION[tup]
    # look for priority patterns (longer patterns first)
    for pattern, (action,score) in RELATION_TO_ACTION.items():
        # pattern can be tuple
        pat = tuple(pattern) if isinstance(pattern, (list,tuple)) else (pattern,)
        # check if pat is subsequence of rels in order
        i=0
        for r in rels:
            if r==pat[i]:
                i+=1
                if i==len(pat):
                    return (action, score)
        # continue
    # no pattern matched -> return generic suggestion
    return ("investigate_path_simulated", 10)

# identify high-value group names from reports heuristically
def find_high_value_groups(reports_dir: Path) -> List[str]:
    hv = []
    candidates = ["DomainAdmins.csv", "AdminGroups.csv", "AdminGroupsPopulatedCount.csv", "AdminsWithoutSensitiveFlag.html.csv"]
    for fname in candidates:
        p = reports_dir / fname
        if not p.exists():
            continue
        for r in read_csv_rows(p):
            name = r.get("Name") or r.get("Group") or r.get("Member")
            high = (r.get("HighValue") or r.get("High Value") or r.get("IsHighValue") or "").lower() == "true"
            admincount = (r.get("AdminCount") or r.get("HasAdminCount") or "").lower() == "true"
            is_named_hv = False
            if name and any(k in name.upper() for k in ["DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "KEY ADMINS", "SCHEMA ADMINS"]):
                is_named_hv = True
            if name and (high or admincount or is_named_hv):
                hv.append(name)
    # dedupe preserve order
    seen=set(); out=[]
    for n in hv:
        if n not in seen:
            out.append(n); seen.add(n)
    return out

# main
def main():
    if len(sys.argv) < 3:
        print("Usage: bh_actionable_csv.py <reports_dir> <out_dir>", file=sys.stderr)
        sys.exit(1)
    reports_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    G = nx.DiGraph()

    # run useful parsers
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
    for fname, parser in PARSERS:
        p = reports_dir / fname
        if p.exists():
            try:
                parser(p, G)
            except Exception as e:
                print(f"Warning: parser {fname} failed: {e}", file=sys.stderr)

    hv_groups = find_high_value_groups(reports_dir)
    # fallback keywords
    heuristics = ["DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"]
    for h in heuristics:
        for node in list(G.nodes):
            if h in str(node).upper() and node not in hv_groups:
                hv_groups.append(node)

    # collect users
    users = [n for n,d in G.nodes(data=True) if d.get("type")=="user"]
    results = []

    for u in users:
        best_path = None
        best_target = None
        # if hv_groups empty, skip search (we still may generate generic suggestions)
        if hv_groups:
            for hv in hv_groups:
                if hv not in G:
                    continue
                try:
                    path = nx.shortest_path(G, source=u, target=hv)
                except nx.NetworkXNoPath:
                    continue
                if best_path is None or len(path) < len(best_path):
                    best_path = path
                    best_target = hv
        # If no hv path found, attempt to find interesting nearby nodes (e.g., any computer)
        if best_path is None:
            # try reachability to any computer
            comps = [n for n,d in G.nodes(data=True) if d.get("type")=="computer"]
            for c in comps:
                try:
                    path = nx.shortest_path(G, source=u, target=c)
                    if best_path is None or len(path) < len(best_path):
                        best_path = path
                        best_target = c
                except nx.NetworkXNoPath:
                    continue

        if best_path is None:
            # no path discovered; still record actor with generic investigation suggestion
            action, score = ("investigate_actor_simulated", 5)
            results.append({
                "actor": u, "target_group": "", "path_nodes": json.dumps([]), "path_relations": json.dumps([]),
                "path_length": 0, "action_suggestion": action, "priority_score": score
            })
            continue

        # map relations along path
        rels = []
        for a,b in zip(best_path[:-1], best_path[1:]):
            rels.append(G.edges[a,b].get("rel","edge"))

        # map relations -> action suggestion
        action, score = map_relations_to_action(rels)

        # priority score: base on action score and inverse path length
        # normalize: score * (1 + (1.0 / max(1, path_length)))
        path_len = max(1, len(best_path)-1)
        priority = int(score * (1 + (1.0 / path_len)))

        results.append({
            "actor": u,
            "target_group": best_target or "",
            "path_nodes": json.dumps(best_path),
            "path_relations": json.dumps(rels),
            "path_length": len(best_path)-1,
            "action_suggestion": action,
            "priority_score": priority
        })

    # write CSV
    out_path = out_dir / "actionable_paths.csv"
    fieldnames = ["actor","target_group","path_nodes","path_relations","path_length","action_suggestion","priority_score"]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in sorted(results, key=lambda x: (-x["priority_score"], x["path_length"])):
            writer.writerow(r)

    print("Wrote actionable CSV to:", out_path)

if __name__ == "__main__":
    main()
