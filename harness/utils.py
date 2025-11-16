#!/usr/bin/env python3
"""
utils.py -- small helpers used by harness modules.
"""

import json, datetime, os

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def read_json(path):
    with open(path) as f: return json.load(f)

def write_json(obj, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f: json.dump(obj, f, indent=2)

def safe_mkdir(path):
    os.makedirs(path, exist_ok=True)
