#!/usr/bin/env python3
# tools/bloodhound_to_state.py
import json, zipfile, sys, os, time

def parse_sharp_zip(zip_path):
    nodes = []
    edges = []
    with zipfile.ZipFile(zip_path) as z:
        for fname in z.namelist():
            if fname.endswith(".json"):
                data = json.loads(z.read(fname).decode())
                # many SharpHound files are lists of dicts with properties
                for item in data:
                    nodes.append(item)
    return nodes

def build_state_from_nodes(nodes):
    hosts = []
    accounts = {}
    relations = []
    for n in nodes:
        objtype = n.get('_type') or n.get('ObjectType') or n.get('type')
        if not objtype:
            continue
        if objtype.lower() in ('computer', 'machine', 'host'):
            ip = n.get('ipv4') or n.get('ip') or None
            hosts.append({"host": n.get('Name') or n.get('ComputerName') or n.get('ObjectIdentifier'), "ip": ip, "tags": ["ad"]})
        if objtype.lower() in ('user','account'):
            dn = n.get('Name') or n.get('DisplayName') or n.get('objectid')
            accounts.setdefault(dn, []).append({"name": dn, "properties": n})
        # relationships: simplified - look for MemberOf / AdminTo / HasSession keys in item
        for k in ('MemberOf','AdminTo','HasSession','CanRDP','AllowedToDelegate'):
            if k in n:
                targets = n.get(k) or []
                for t in targets:
                    relations.append({"from": n.get('Name'), "rel": k, "to": t})
    state = {
        "meta": {"sandbox": True, "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        "hosts": hosts,
        "accounts": accounts,
        "relations": relations,
        "raw_nodes_count": len(nodes)
    }
    return state

def main():
    if len(sys.argv) < 3:
        print("Usage: bloodhound_to_state.py sharp.zip out_state.json")
        sys.exit(1)
    zip_path = sys.argv[1]
    out = sys.argv[2]
    nodes = parse_sharp_zip(zip_path)
    state = build_state_from_nodes(nodes)
    with open(out, "w") as f:
        json.dump(state, f, indent=2)
    print("Wrote", out)

if __name__ == "__main__":
    main()
