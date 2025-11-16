#!/usr/bin/env python3
"""
aggregate_metrics.py — combines metrics.json + run_info.json for each run into a single CSV,
with fallbacks for older runs missing run_info.json.

Usage:
    python3 tools/aggregate_metrics.py results/<agent>/<target>

Output:
    results/<agent>/<target>/aggregate_metrics.csv
"""
import os, sys, json, csv, glob, statistics, time, re
from datetime import datetime, timezone

# ---- Simple color helpers ----
def color(txt, c):
    codes = {
        "cyan": "\033[96m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    return f"{codes.get(c,'')}{txt}{codes['reset']}"

def utc_iso_from_epoch(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_seed_from_name(name):
    # attempts to find seedNN or seed_NN patterns
    m = re.search(r"seed[_-]?(\d+)", name)
    if m:
        try:
            return int(m.group(1))
        except:
            return None
    return None

# ---- Input directory ----
if len(sys.argv) != 2:
    print(color(f"[❌] Usage: {sys.argv[0]} results/<agent>/<target>", "red"))
    sys.exit(1)

base_dir = sys.argv[1]
if not os.path.isdir(base_dir):
    print(color(f"[❌] Directory not found: {base_dir}", "red"))
    sys.exit(2)

print(color(f"[🧩] Scanning metrics in: {base_dir}", "cyan"))

# ---- Collect all run directories ----
run_dirs = sorted(glob.glob(os.path.join(base_dir, "run_*")))
if not run_dirs:
    print(color("[⚠️] No run directories found.", "yellow"))
    sys.exit(0)

rows = []
metrics_fields = set()
info_fields = set()

for d in run_dirs:
    metrics_path = os.path.join(d, "metrics.json")
    info_path = os.path.join(d, "run_info.json")
    row = {"run": os.path.basename(d)}

    # Try run_info.json first (preferred)
    if os.path.exists(info_path):
        try:
            info = json.load(open(info_path))
            # normalize keys (ensure basic fields present)
            row.update(info)
            info_fields.update(info.keys())
        except Exception as e:
            print(color(f"[⚠️] Failed to load run_info.json in {d}: {e}", "yellow"))
    else:
        # Fallback: construct minimal run_info from folder/mtimes
        print(color(f"[⚠️] Missing run_info.json in {d} — using fallbacks", "yellow"))
        # infer seed from folder name if possible
        inferred_seed = parse_seed_from_name(os.path.basename(d))
        row["seed"] = inferred_seed if inferred_seed is not None else ""
        # use metrics.json mtime as end_time (if available), or dir mtime
        use_mtime = None
        if os.path.exists(metrics_path):
            use_mtime = os.path.getmtime(metrics_path)
        else:
            use_mtime = os.path.getmtime(d)
        end_iso = utc_iso_from_epoch(int(use_mtime))
        row["end_time_utc"] = end_iso
        # we can't know precise start_time or duration, leave empty
        row.setdefault("start_time_utc", "")
        row.setdefault("duration_seconds", "")
        row.setdefault("duration_hms", "")
        # leave agent/target if parseable from parent path
        try:
            parts = os.path.normpath(base_dir).split(os.sep)
            row.setdefault("agent", parts[-2] if len(parts) >= 2 else "")
            row.setdefault("target", parts[-1] if len(parts) >= 1 else "")
            info_fields.update(["agent","target","start_time_utc","end_time_utc","duration_seconds","duration_hms","seed"])
        except:
            pass

    # merge metrics (if exists) - may override fallback end_time if metrics includes fields
    if os.path.exists(metrics_path):
        try:
            m = json.load(open(metrics_path))
            row.update(m)
            metrics_fields.update(m.keys())
        except Exception as e:
            print(color(f"[⚠️] Failed to load metrics.json in {d}: {e}", "yellow"))
    else:
        print(color(f"[⚠️] Missing metrics.json in {d}", "yellow"))

    rows.append(row)

# ---- Write aggregate CSV ----
if not rows:
    print(color("[⚠️] No data to aggregate.", "yellow"))
    sys.exit(0)

# determine stable CSV field order:
# run, then sorted info fields, then sorted metrics fields (but ensure common run_info keys placed early)
preferred_info_order = ["agent","target","seed","start_time_utc","end_time_utc","duration_seconds","duration_hms"]
other_info = sorted([f for f in info_fields if f not in preferred_info_order])
metrics_only = sorted(metrics_fields)

csv_fields = ["run"] + [f for f in preferred_info_order if f in info_fields] + other_info + metrics_only

csv_path = os.path.join(base_dir, "aggregate_metrics.csv")
with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=csv_fields)
    writer.writeheader()
    # ensure each row has all fields (missing -> empty string)
    for r in rows:
        flat = {k: (r.get(k, "") if r.get(k, "") is not None else "") for k in csv_fields}
        writer.writerow(flat)

print(color(f"[✅] Wrote CSV: {csv_path}", "green"))

# ---- Summary stats ----
numeric_keys = [
    "coverage",
    "path_efficiency",
    "recon_precision",
    "recon_recall",
    "safety_score",
    "stealth_score",
]
found = False
for key in numeric_keys:
    vals = []
    for rr in rows:
        try:
            v = rr.get(key, None)
            if v is None or v == "":
                continue
            fv = float(v)
            vals.append(fv)
        except Exception:
            pass
    if vals:
        mean = statistics.mean(vals)
        std = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        print(color(f"   {key:<20} mean={mean:.4f}  std={std:.4f}", "cyan"))
        found = True

if not found:
    print(color("[⚠️] No numeric metrics found to summarize.", "yellow"))
else:
    print(color(f"\n[📊] Aggregation complete at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}", "bold"))

