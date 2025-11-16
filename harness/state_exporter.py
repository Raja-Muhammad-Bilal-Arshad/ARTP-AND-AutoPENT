#!/usr/bin/env python3
"""
state_exporter.py -- produce sanitized state.json for a target.

Behavior:
 - If harness_targets/<target>/state_source.json exists, use it (sanitizes)
 - Otherwise create a minimal synthetic sanitized state (safe default)
 - Writes state.json to the specified --out path
"""

import json, os, datetime
from typing import Dict

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def load_json(path):
    with open(path) as f: return json.load(f)

def write_json(obj, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f: json.dump(obj, f, indent=2)

def sanitize_state(raw: Dict) -> Dict:
    # Remove any fields that look sensitive (passwords, tokens)
    sanitized = {}
    for k,v in raw.items():
        if k.lower() in ("password","token","private_key","creds"):
            continue
        sanitized[k] = v
    # canonical fields
    sanitized.setdefault("generated_at", now_iso())
    return sanitized

def export_state_for_target(target_name: str, out_path: str, seed: int = 42):
    candidate = os.path.join("..", "harness_targets", target_name, "state_source.json")
    if os.path.exists(candidate):
        raw = load_json(candidate)
        state = sanitize_state(raw)
    else:
        # make a small safe synthetic state
        state = {
            "target_name": target_name,
            "hosts": [
                {"ip": "10.0.0.2", "hostname": "web1", "services": [{"name":"http","port":80,"confidence":0.95}], "confidence":0.95},
                {"ip": "10.0.0.3", "hostname": "web2", "services": [{"name":"http","port":8080,"confidence":0.9}], "confidence":0.9}
            ],
            "endpoints": [
                {"host":"10.0.0.2","path":"/","method":"GET","confidence":0.95},
                {"host":"10.0.0.2","path":"/login","method":"POST","confidence":0.9},
                {"host":"10.0.0.3","path":"/admin","method":"GET","confidence":0.85}
            ],
            # ground_truth is used by executor to compute coverage; it's safe & synthetic
            "ground_truth": [
                {"host":"10.0.0.2","path":"/login"},
                {"host":"10.0.0.3","path":"/admin"}
            ],
            "generated_at": now_iso(),
            "seed": seed
        }
    write_json(state, out_path)
    return state

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    st = export_state_for_target(args.target, args.out, args.seed)
    print("[state_exporter] wrote state to", args.out)
