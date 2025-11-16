#!/usr/bin/env python3
"""
tools/bloodhound_reports_to_state.py
Converts a BloodHound "reports" directory (CSV reports) into a harness-friendly state JSON.

Usage:
  python3 tools/bloodhound_reports_to_state.py reports/ state_bh.json

Notes:
 - Heuristic parsing: tries many common BloodHound CSV column names.
 - Safe: does not call network, only reads CSV/HTML files.
 - Output contains: meta, hosts (host/ip/tags), accounts (user -> meta), relations list.
"""
from __future__ import annotations
import sys, os, json, glob, csv
from typing import Dict, Any, List

def read_csv(path):
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            rows = [r for r in reader]
            return rows
    except Exception:
        return []

def add_host(hosts: List[Dict[str,Any]], name: str, ip: str=None):
    if not name:
        return
    # avoid duplicates
    for h in hosts:
        if h.get("host")==name or h.get("ip")==ip:
            return
    entry = {"host": name}
    if ip:
        entry["ip"] = ip
    entry["tags"] = ["ad"]
    hosts.append(entry)

def add_account(accounts: Dict[str,Any], name: str, props: Dict[str,Any]=None):
    if not name:
        return
    if name not in accounts:
        accounts[name] = []
    accounts[name].append(props or {})

def add_relation(relations: List[Dict[str,Any]], frm: str, rel: str, to: str):
    if not frm or not to:
        return
    relations.append({"from": frm, "rel": rel, "to": to})

def parse_domain_computers(reports_dir, hosts, relations, accounts):
    path = os.path.join(reports_dir, "DomainComputers.csv")
    rows = read_csv(path)
    for r in rows:
        # common columns: 'Name', 'Computer', 'Hostname'
        name = r.get("Name") or r.get("Computer") or r.get("Hostname") or r.get("ComputerName")
        ip = r.get("IPv4") or r.get("IPv4Address") or r.get("IP")
        add_host(hosts, name, ip)

def parse_domain_users(reports_dir, hosts, relations, accounts):
    path = os.path.join(reports_dir, "DomainUsers.csv")
    rows = read_csv(path)
    for r in rows:
        # common columns: 'User', 'Name', 'SamAccountName'
        uname = r.get("Name") or r.get("User") or r.get("SamAccountName") or r.get("Username")
        add_account(accounts, uname, {"raw": r})

def parse_admins(reports_dir, hosts, relations, accounts):
    # DomainAdmins.csv or AdminGroups.csv
    for fname in ("DomainAdmins.csv","AdminGroups.csv","AdminsWithoutSensitiveFlag.html.csv"):
        path = os.path.join(reports_dir, fname)
        if not os.path.exists(path):
            continue
        rows = read_csv(path)
        for r in rows:
            # possible columns: 'Member','User','Account','Principal'
            member = r.get("Member") or r.get("User") or r.get("Account") or r.get("Principal") or r.get("MemberName")
            group = r.get("Group") or r.get("AdminGroup") or r.get("GroupName") or "Domain Admins"
            if member:
                add_account(accounts, member, {"raw": r})
                add_relation(relations, member, "memberOf", group)

def parse_dc_sync(reports_dir, hosts, relations, accounts):
    path = os.path.join(reports_dir, "DCSyncDirect.csv")
    if not os.path.exists(path):
        return
    rows = read_csv(path)
    for r in rows:
        # common: 'User','Object','Computer','From','To'
        user = r.get("User") or r.get("SamAccountName") or r.get("Name")
        target = r.get("Computer") or r.get("DomainController") or r.get("Object")
        add_account(accounts, user, {"raw": r})
        add_host(hosts, target)
        add_relation(relations, user, "canDCSync", target)

def parse_unconstrained_delegation(reports_dir, hosts, relations, accounts):
    path = os.path.join(reports_dir, "Computers_UnconstrainedDelegation.csv")
    if not os.path.exists(path):
        return
    rows = read_csv(path)
    for r in rows:
        comp = r.get("Name") or r.get("Computer") or r.get("Hostname")
        add_host(hosts, comp)
        add_relation(relations, comp, "unconstrainedDelegation", comp)

def parse_sessions(reports_dir, hosts, relations, accounts):
    path = os.path.join(reports_dir, "Users_Sessions.csv")
    if not os.path.exists(path):
        path = os.path.join(reports_dir, "Users_Sessions.html.csv")
    if not os.path.exists(path):
        return
    rows = read_csv(path)
    for r in rows:
        user = r.get("User") or r.get("UserName") or r.get("Account")
        comp = r.get("Computer") or r.get("Host") or r.get("Session")
        add_account(accounts, user, {"raw": r})
        add_host(hosts, comp)
        add_relation(relations, user, "hasSession", comp)

def parse_mappings_generic(reports_dir, hosts, relations, accounts):
    # Try several useful CSVs for relations: GPO owners, AdminTo, LocalAdmin enumerations, Kerberoastable
    mappings = [
        ("Computers_LocalAdminEnumeration.csv","localAdminOn","Computer"),
        ("DCOwners.csv","ownerOf","DomainController"),
        ("Computers_MSSQL.csv","hasMSSQL","Computer"),
        ("Kerberoastable_Users.html.csv","kerberoastable","User")
    ]
    for fname, relname, label in mappings:
        path = os.path.join(reports_dir, fname)
        if not os.path.exists(path):
            continue
        rows = read_csv(path)
        for r in rows:
            # heuristics to get actor and target
            actor = r.get("Member") or r.get("User") or r.get("Account") or r.get("Name")
            target = r.get("Computer") or r.get("Hostname") or r.get("Object") or r.get(label)
            add_account(accounts, actor, {"raw": r})
            add_host(hosts, target)
            add_relation(relations, actor, relname, target)

def main():
    if len(sys.argv) < 3:
        print("Usage: bloodhound_reports_to_state.py <reports_dir> <out_state.json>")
        sys.exit(1)
    reports_dir = sys.argv[1]
    out_path = sys.argv[2]
    hosts: List[Dict[str,Any]] = []
    accounts: Dict[str,Any] = {}
    relations: List[Dict[str,Any]] = []

    # run parsers (safe to call even if files missing)
    parse_domain_computers(reports_dir, hosts, relations, accounts)
    parse_domain_users(reports_dir, hosts, relations, accounts)
    parse_admins(reports_dir, hosts, relations, accounts)
    parse_dc_sync(reports_dir, hosts, relations, accounts)
    parse_unconstrained_delegation(reports_dir, hosts, relations, accounts)
    parse_sessions(reports_dir, hosts, relations, accounts)
    parse_mappings_generic(reports_dir, hosts, relations, accounts)

    state = {
        "meta": {"sandbox": True, "source": "bloodhound_reports", "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime())},
        "hosts": hosts,
        "accounts": accounts,
        "relations": relations,
        "notes": "Generated heuristically from BloodHound CSV reports. Sanitize before publishing."
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    print("Wrote state to", out_path)

if __name__ == "__main__":
    main()
