#!/usr/bin/env python3
"""
tools/plot_ad_all_graph.py

Build a full AD relationship graph from BloodHound-style reports (CSV/HTML),
and plot everything on a single light-themed graph image.

Usage:
  python3 tools/plot_ad_all_graph.py --reports-dir reports --out outputs/ad_full_graph.png --summary outputs/ad_summary.csv

Notes:
  - Robust CSV reading (tries C-engine, then python-engine, then raw lines).
  - Heuristic parsing of common BloodHound CSV/HTML report structures.
  - Requires: networkx, pandas, matplotlib. Optional: pygraphviz or pydot for graphviz layout.
"""

from __future__ import annotations
import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import json
import math

# try graphviz layout providers
_has_agraph = False
_has_pydot = False
try:
    import pygraphviz  # type: ignore
    _has_agraph = True
except Exception:
    try:
        import pydot  # type: ignore
        _has_pydot = True
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("plot_ad_all_graph")

# ---------- utils ----------
def robust_read_csv(path: Path) -> pd.DataFrame:
    """Try multiple ways to read CSV/HTML table-like files robustly."""
    if not path.exists():
        return pd.DataFrame()
    # direct pandas read_csv attempts
    for kwargs in ({"encoding": "latin-1"},
                   {"encoding": "latin-1", "engine": "python", "on_bad_lines": "skip"},
                   {"encoding": "utf-8", "engine": "python", "on_bad_lines": "skip"}):
        try:
            return pd.read_csv(path, **kwargs)
        except Exception as e:
            log.debug("read_csv attempt failed for %s: %s", path, e)
            continue
    # try HTML table extraction if file is HTML
    try:
        if path.suffix.lower() in (".html", ".htm"):
            dfs = pd.read_html(path, encoding="latin-1")
            if dfs:
                # choose largest table
                dfs_sorted = sorted(dfs, key=lambda d: d.shape[0], reverse=True)
                return dfs_sorted[0]
    except Exception as e:
        log.debug("pd.read_html failed for %s: %s", path, e)
    # as last resort, return a single-column dataframe with raw lines
    try:
        with open(path, "r", encoding="latin-1", errors="ignore") as fh:
            lines = [ln.rstrip("\n") for ln in fh if ln.strip()]
        if not lines:
            return pd.DataFrame()
        return pd.DataFrame({"raw_line": lines})
    except Exception as e:
        log.error("Unable to read %s: %s", path, e)
        return pd.DataFrame()

def safe_get_cols(df: pd.DataFrame) -> List[str]:
    return list(df.columns) if isinstance(df, pd.DataFrame) else []

# ---------- parse & build graph ----------
def load_reports_into_graph(reports_dir: Path) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """Scan reports dir for known BloodHound CSVs/HTMLs and build a directed graph."""
    G = nx.DiGraph()
    stats = {"files_read": [], "rows": {}, "skipped_files": []}

    # Helper node creation
    def add_node(id: str, ntype: str, attrs: Dict[str, Any] = None):
        if not attrs:
            attrs = {}
        if not G.has_node(id):
            G.add_node(id, type=ntype, label=id, **attrs)
        else:
            # merge types if necessary (prefer more specific)
            cur = G.nodes[id].get("type")
            if cur != ntype:
                # prefer Domain Admin / user / computer priority? keep existing unless new is 'domain'/'computer' etc
                G.nodes[id].setdefault("type", ntype)
            G.nodes[id].update(attrs)

    # file heuristics mapping
    reports = sorted(reports_dir.glob("*"))
    log.info("Scanning %d report files in %s", len(reports), reports_dir)
    for p in reports:
        if p.is_dir():
            continue
        df = robust_read_csv(p)
        stats["files_read"].append(str(p))
        nrows = 0
        try:
            nrows = len(df)
        except Exception:
            nrows = 0
        stats["rows"][str(p.name)] = nrows

        fname = p.name.lower()
        cols = safe_get_cols(df)
        # Heuristics for common BloodHound tables
        try:
            if "domainusers" in fname or "domainusers" == p.stem.lower():
                # DomainUsers.csv => each row has Name or ObjectName
                for _, r in df.iterrows():
                    name = r.get("name") or r.get("Name") or r.get("sAMAccountName") or r.get("ObjectName") or r.get("User") or r.get("Username")
                    if not name:
                        # try first column
                        name = str(r.iloc[0]) if len(r)>0 else None
                    if name:
                        add_node(name, "user", {"raw": r.to_dict()})
            elif "domaincomputers" in fname or "domaincomputers" == p.stem.lower():
                for _, r in df.iterrows():
                    name = r.get("name") or r.get("Name") or r.get("Computer") or r.get("ObjectName") or r.get("Hostname")
                    if name:
                        add_node(name, "computer", {"raw": r.to_dict()})
            elif "domaingroups" in fname or "group" in fname and ("domaingroups" in fname or "groups" in fname):
                for _, r in df.iterrows():
                    name = r.get("name") or r.get("Name") or r.get("Group") or r.get("ObjectName")
                    if name:
                        add_node(name, "group", {"raw": r.to_dict()})
            elif "relationships" in fname or "relationship" in fname:
                # Relationships-* files: try to map Source -> Destination columns
                # Common BloodHound: "Source","Destination" OR "From","To" OR "Member","Object"
                if "source" in (c.lower() for c in cols) and "destination" in (c.lower() for c in cols):
                    src_col = next(c for c in cols if c.lower()=="source")
                    dst_col = next(c for c in cols if c.lower()=="destination")
                    for _, r in df.iterrows():
                        s = r.get(src_col)
                        d = r.get(dst_col)
                        if pd.isna(s) or pd.isna(d):
                            continue
                        add_node(s, guess_type_from_name(s))
                        add_node(d, guess_type_from_name(d))
                        rel = detect_relation_from_filename(fname)
                        G.add_edge(s, d, relation=rel, file=str(p.name), raw=r.to_dict())
                elif "from" in (c.lower() for c in cols) and "to" in (c.lower() for c in cols):
                    src_col = next(c for c in cols if c.lower()=="from")
                    dst_col = next(c for c in cols if c.lower()=="to")
                    for _, r in df.iterrows():
                        s = r.get(src_col)
                        d = r.get(dst_col)
                        if pd.isna(s) or pd.isna(d):
                            continue
                        add_node(s, guess_type_from_name(s))
                        add_node(d, guess_type_from_name(d))
                        rel = detect_relation_from_filename(fname)
                        G.add_edge(s, d, relation=rel, file=str(p.name), raw=r.to_dict())
                else:
                    # fallback: try column name hints
                    mapped = False
                    col_lower = [c.lower() for c in cols]
                    # membership like MemberName / ObjectName
                    if "membername" in col_lower and "objectname" in col_lower:
                        mn = next(c for c in cols if c.lower()=="membername")
                        on = next(c for c in cols if c.lower()=="objectname")
                        for _, r in df.iterrows():
                            s = r.get(on); d = r.get(mn)
                            if pd.isna(s) or pd.isna(d): continue
                            add_node(s, guess_type_from_name(s)); add_node(d, guess_type_from_name(d))
                            G.add_edge(d, s, relation="member_of", file=str(p.name), raw=r.to_dict())
                        mapped = True
                    if not mapped:
                        # try every pair of columns: if some rows look like A->B strings
                        # last-resort: skip file
                        stats["skipped_files"].append(str(p.name))
                        log.debug("Skipping relationships-like file with unknown schema: %s cols=%s", p, cols)
            else:
                # other csvs: try to handle intuitively based on filename tokens
                # Examples: LocalAdmin_Computers_.csv, DCSyncDirect.csv, Computers_UnconstrainedDelegation.csv, etc
                if "localadmin" in fname or "local_admin" in fname:
                    # often rows include "ComputerName" and "MemberName" or similar
                    heur = find_columns_for_pair(cols)
                    if heur:
                        a_col, b_col = heur
                        for _, r in df.iterrows():
                            a = r.get(a_col); b = r.get(b_col)
                            if pd.isna(a) or pd.isna(b): continue
                            add_node(a, guess_type_from_name(a)); add_node(b, guess_type_from_name(b))
                            # local admin: user -> computer relation
                            G.add_edge(b, a, relation="local_admin", file=str(p.name), raw=r.to_dict())
                    else:
                        stats["skipped_files"].append(str(p.name))
                elif "dcsync" in fname:
                    heur = find_columns_for_pair(cols)
                    if heur:
                        a_col, b_col = heur
                        for _, r in df.iterrows():
                            a = r.get(a_col); b = r.get(b_col)
                            if pd.isna(a) or pd.isna(b): continue
                            add_node(a, guess_type_from_name(a)); add_node(b, guess_type_from_name(b))
                            G.add_edge(a, b, relation="dcsync_possible", file=str(p.name), raw=r.to_dict())
                elif "unconstraineddelegation" in fname or "unconstrained" in fname:
                    heur = find_columns_for_pair(cols)
                    if heur:
                        a_col, b_col = heur
                        for _, r in df.iterrows():
                            a = r.get(a_col); b = r.get(b_col)
                            if pd.isna(a) or pd.isna(b): continue
                            add_node(a, guess_type_from_name(a)); add_node(b, guess_type_from_name(b))
                            G.add_edge(a, b, relation="unconstrained_delegation", file=str(p.name), raw=r.to_dict())
                elif "kerberoast" in fname or "kerberoastable" in fname:
                    # kerberoastable users
                    for _, r in df.iterrows():
                        name = r.get("Name") or r.get("name") or r.get("User") or (r.iloc[0] if len(r)>0 else None)
                        if name:
                            add_node(name, "user", {"kerberoastable": True})
                else:
                    # ignore files which are likely empty or HTML pages not containing table rows
                    stats["skipped_files"].append(str(p.name))
        except Exception as e:
            log.debug("Exception while parsing %s: %s", p, e)
            stats["skipped_files"].append(str(p.name))
    return G, stats

# ---------- helpers ----------
def guess_type_from_name(name: str) -> str:
    if not isinstance(name, str):
        return "unknown"
    n = name.lower()
    if n.endswith("$") or "dc" in n and n.count(".")>=1 or n.startswith("dc") or n.startswith("host"):
        return "computer"
    if "@" in n or n.count(".")>=1 and n.split("@")[-1].count(".")>=1:
        # email-like or UPN
        return "user"
    if "admin" in n or "group" in n:
        return "group"
    return "user"

def detect_relation_from_filename(fname: str) -> str:
    if "admin" in fname:
        return "admin_to"
    if "member" in fname or "memberof" in fname or "relationships" in fname:
        return "member_of"
    if "localadmin" in fname or "local_admin" in fname:
        return "local_admin"
    if "dcsync" in fname:
        return "dcsync_possible"
    if "unconstrained" in fname:
        return "unconstrained_delegation"
    return "related_to"

def find_columns_for_pair(cols: List[str]) -> Tuple[str, str] or None:
    # return two column names (A,B) heuristically if found
    low = [c.lower() for c in cols]
    # prefer common pairs
    pairs = [
        ("ObjectName","MemberName"), ("ObjectName","Member"),
        ("ComputerName","MemberName"), ("ComputerName","User"),
        ("MemberName","ObjectName"), ("Source","Destination"),
        ("From","To"), ("Member","ObjectName"), ("Name","MemberName"),
        ("MemberName","Host")
    ]
    for a,b in pairs:
        for ca in cols:
            if ca.lower()==a.lower():
                for cb in cols:
                    if cb.lower()==b.lower():
                        return ca, cb
    # fallback: if at least 2 columns exist, choose first and second
    if len(cols) >= 2:
        return cols[0], cols[1]
    return None

# ---------- plotting ----------
def draw_graph(G: nx.DiGraph, out_path: Path, summary_csv: Path = None, figsize=(16,12), max_nodes_to_draw=2000):
    """Plot the graph. If graph is extremely large, we sample or limit."""
    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()
    log.info("Graph: nodes=%d edges=%d", n_nodes, n_edges)

    # Build node groups and colors
    node_types = {}
    for n,d in G.nodes(data=True):
        t = d.get("type","unknown")
        node_types.setdefault(t, []).append(n)

    color_map = {
        "user": "#1f77b4",
        "group": "#2ca02c",
        "computer": "#ff7f0e",
        "domain": "#9467bd",
        "unknown": "#7f7f7f"
    }
    node_colors = []
    node_sizes = []
    for n,d in G.nodes(data=True):
        t = d.get("type","unknown")
        node_colors.append(color_map.get(t,"#bbbbbb"))
        if t=="user":
            node_sizes.append(120)
        elif t=="group":
            node_sizes.append(300)
        elif t=="computer":
            node_sizes.append(170)
        else:
            node_sizes.append(100)

    # Edge colors by relation
    rel_color = {
        "member_of": "#6baed6",
        "admin_to": "#de2d26",
        "local_admin": "#e6550d",
        "dcsync_possible": "#31a354",
        "unconstrained_delegation": "#756bb1",
        "related_to": "#9e9ac8"
    }
    edge_colors = [rel_color.get(d.get("relation","related_to"), "#999999") for u,v,d in G.edges(data=True)]

    # choose layout: try graphviz dot/neato if available for larger graphs
    pos = None
    try:
        if _has_agraph:
            pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
        elif _has_pydot:
            pos = nx.nx_pydot.graphviz_layout(G, prog="dot")
    except Exception as e:
        log.debug("Graphviz layout failed, falling back to spring: %s", e)
        pos = None

    if pos is None:
        # if graph large, use spring_layout with limited iterations
        if n_nodes > 1000:
            pos = nx.spring_layout(G, k=0.5/math.sqrt(n_nodes), iterations=50)
        else:
            pos = nx.spring_layout(G, k=0.35, iterations=120)

    # maybe draw only a subgraph if extremely large
    draw_graph = G
    if n_nodes > max_nodes_to_draw:
        # pick top nodes by degree
        deg = sorted(G.degree(), key=lambda x: x[1], reverse=True)[:max_nodes_to_draw]
        top_nodes = set([n for n,_ in deg])
        draw_graph = G.subgraph(top_nodes).copy()
        log.info("Graph too large, drawing subgraph with %d nodes", draw_graph.number_of_nodes())
        # recompute pos for subgraph
        pos = {n: pos[n] for n in draw_graph.nodes() if n in pos}

    # plotting
    plt.figure(figsize=figsize)
    ax = plt.gca()
    ax.set_facecolor("white")
    plt.axis("off")

    # draw nodes
    nx.draw_networkx_nodes(draw_graph, pos,
                           node_color=[color_map.get(draw_graph.nodes[n].get("type","unknown"), "#999999") for n in draw_graph.nodes()],
                           node_size=[120 if draw_graph.nodes[n].get("type","user") else 300 if draw_graph.nodes[n].get("type","group") else 170 for n in draw_graph.nodes()],
                           alpha=0.9)

    # draw edges
    nx.draw_networkx_edges(draw_graph, pos, edge_color=[rel_color.get(d.get("relation","related_to"), "#999999") for _,_,d in draw_graph.edges(data=True)], arrowsize=10, alpha=0.7, width=1.0)

    # draw labels for high-degree or important nodes (Domain Admins / groups)
    label_nodes = {}
    for n,d in draw_graph.nodes(data=True):
        if d.get("type") in ("group","domain") or draw_graph.degree(n) > 6:
            label_nodes[n] = d.get("label", n)
    nx.draw_networkx_labels(draw_graph, pos, labels=label_nodes, font_size=8)

    # legend (manual)
    import matplotlib.patches as mpatches
    patches = []
    for typ,color in color_map.items():
        patches.append(mpatches.Patch(color=color, label=typ))
    plt.legend(handles=patches, loc="lower left", fontsize=8, frameon=True)

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=300)
    plt.close()
    log.info("Wrote graph image to %s", out_path)

def compute_shortest_paths_to_domain_admins(G: nx.DiGraph, max_depth:int=6) -> List[Dict[str,Any]]:
    """Return list of shortest paths from non-DA nodes to any Domain Admin node (up to max_depth)"""
    # find Domain Admins by name heuristics
    da_nodes = [n for n,d in G.nodes(data=True) if (("domain admins" in n.lower()) or d.get("type")=="domain" or ("domain admin" in n.lower()) or d.get("type")=="group" and ("domain admins" in n.lower()))]
    if not da_nodes:
        # also look for explicit users flagged in nodes
        da_nodes = [n for n,d in G.nodes(data=True) if d.get("is_domain_admin") or d.get("label","").lower().endswith("@doazlab.com")]
    paths = []
    if not da_nodes:
        log.info("No Domain Admin nodes detected by heuristics")
        return paths
    log.info("Domain Admin nodes found: %s", da_nodes[:10])
    # for each node that's a user/group not in da_nodes, attempt shortest path
    for source in G.nodes():
        if source in da_nodes:
            continue
        try:
            for target in da_nodes:
                if nx.has_path(G, source, target):
                    sp = nx.shortest_path(G, source, target)
                    if len(sp)-1 <= max_depth:
                        paths.append({"source": source, "target": target, "hops": len(sp)-1, "path": sp})
                        break
        except Exception:
            continue
    # sort by hops
    return sorted(paths, key=lambda x: x["hops"])

# ---------- main ----------
def main():
    p = argparse.ArgumentParser(description="Plot full AD relationship graph from BloodHound reports")
    p.add_argument("--reports-dir", required=True, help="Directory with BloodHound CSV/HTML reports")
    p.add_argument("--out", required=True, help="Output image path (png/pdf/svg)")
    p.add_argument("--summary", required=False, help="Output CSV summary of shortest paths to Domain Admins")
    p.add_argument("--max-depth", type=int, default=6, help="Max hops for shortest paths to DA")
    p.add_argument("--max-draw-nodes", type=int, default=2000, help="If graph bigger, draw top-degree subgraph")
    args = p.parse_args()

    reports_dir = Path(args.reports_dir)
    if not reports_dir.exists():
        log.error("Reports dir not found: %s", reports_dir)
        sys.exit(2)

    G, stats = load_reports_into_graph(reports_dir)
    log.info("Parsed reports. Files read: %d; skipped: %d", len(stats.get("files_read",[])), len(stats.get("skipped_files",[])))
    # compute shortest paths to DA
    paths = compute_shortest_paths_to_domain_admins(G, max_depth=args.max_depth)
    if args.summary:
        out_summary = Path(args.summary)
        rows = []
        for pth in paths:
            rows.append({"source": pth["source"], "target": pth["target"], "hops": pth["hops"], "path": " -> ".join(pth["path"])})
        pd.DataFrame(rows).to_csv(out_summary, index=False)
        log.info("Wrote summary CSV: %s (rows=%d)", out_summary, len(rows))

    draw_graph(G, Path(args.out), summary_csv=Path(args.summary) if args.summary else None, max_nodes_to_draw=args.max_draw_nodes)
    log.info("Done.")

if __name__ == "__main__":
    main()
