#!/usr/bin/env python3
"""
tools/csv_to_plan.py
Convert actionable_paths.csv into planner-compatible plan.json
Creates output directory if missing.
"""
import csv, json, sys
from pathlib import Path

def main():
    if len(sys.argv) < 3:
        print("Usage: csv_to_plan.py <actionable_csv> <plan_output.json>", file=sys.stderr)
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    json_path = Path(sys.argv[2])

    if not csv_path.exists():
        print(f"Error: CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(2)

    # ensure parent dir exists
    if json_path.parent and not json_path.parent.exists():
        json_path.parent.mkdir(parents=True, exist_ok=True)

    steps = []
    with csv_path.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            actor = row.get("actor", "")
            target = row.get("target_group", "")
            action = row.get("action_suggestion", "")
            try:
                score  = int(row.get("priority_score", 0))
            except Exception:
                score = 0
            path_nodes = []
            try:
                path_nodes = json.loads(row.get("path_nodes", "[]"))
            except Exception:
                path_nodes = []

            path_summary = " -> ".join(path_nodes) if path_nodes else actor

            steps.append({
                "actor": actor,
                "target": target,
                "action": action,
                "priority": score,
                "notes": f"path: {path_summary}"
            })

    plan = {
        "plan_name": "AutoPENT_AD_Plan",
        "generated_from": csv_path.name,
        "steps": sorted(steps, key=lambda x: -x["priority"])
    }

    with json_path.open("w", encoding="utf-8") as out:
        json.dump(plan, out, indent=2)

    print(f"[+] Wrote planner plan: {json_path}")

if __name__ == "__main__":
    main()

