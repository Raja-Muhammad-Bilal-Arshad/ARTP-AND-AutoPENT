#!/usr/bin/env python3
"""
verifier.py -- simple symbolic verifier used by AutoPENT harness.

Functionality:
 - Validate plan schema (basic checks)
 - Run blocklist checks (disallowed substrings)
 - Compute per-step impact flags and violations count
 - Emit verifier.json with final_decision: approved | hold_for_human | blocked
"""

import json
import os
import datetime
from typing import List, Dict

# Configurable verifier parameters
BLOCKLIST = ["rm -rf", "nc -e", "bash -i", "curl http://", "wget http://"]
IMPACT_THRESHOLD = 0.8     # any step with meta.confidence > this and labelled 'high' is flagged
MAX_BLOCK_VIOLATIONS = 3   # if violations exceed this -> blocked

def _now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def load_json(path: str):
    with open(path, "r") as f:
        return json.load(f)

def write_json(obj, path: str):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

def check_schema(plan: List[Dict]) -> List[Dict]:
    checks = []
    for step in plan:
        issues = []
        sid = step.get("step_id", None)
        if "action" not in step:
            issues.append("missing_action")
        if "target" not in step:
            issues.append("missing_target")
        if "meta" not in step:
            issues.append("missing_meta")
        checks.append({"step_id": sid, "status": "ok" if not issues else "flagged", "issues": issues})
    return checks

def run_blocklist(plan: List[Dict]) -> List[Dict]:
    results = []
    for step in plan:
        sid = step.get("step_id")
        issues = []
        # Check textual fields for blocklisted substrings
        serialized = json.dumps(step).lower()
        for blk in BLOCKLIST:
            if blk in serialized:
                issues.append(f"blocklist:{blk}")
        results.append({"step_id": sid, "issues": issues})
    return results

def compute_impact_flags(plan: List[Dict]) -> List[Dict]:
    flags = []
    for step in plan:
        sid = step.get("step_id")
        meta = step.get("meta", {})
        confidence = float(meta.get("confidence", 0.0))
        impact_label = meta.get("impact", "unknown")
        flagged = False
        reasons = []
        # Simple rule: if explicit impact=high or confidence > threshold & impact not 'unknown'
        if impact_label == "high":
            flagged = True
            reasons.append("impact_label_high")
        if confidence >= IMPACT_THRESHOLD and impact_label in ("medium", "high"):
            flagged = True
            reasons.append("confidence_above_threshold")
        flags.append({"step_id": sid, "flagged": flagged, "reasons": reasons, "confidence": confidence})
    return flags

def verify_plan(plan_path: str, out_dir: str, auto_approve: bool=False):
    plan = load_json(plan_path)
    step_schema_checks = check_schema(plan)
    blocklist_checks = run_blocklist(plan)
    impact_flags = compute_impact_flags(plan)

    # merge checks by step_id
    verifier_checks = []
    total_violations = 0
    any_flagged_for_human = False
    for sc in step_schema_checks:
        sid = sc["step_id"]
        issues = list(sc.get("issues", []))
        # add blocklist issues
        bl = next((b for b in blocklist_checks if b["step_id"] == sid), None)
        if bl:
            issues.extend(bl.get("issues", []))
        # add impact reasons
        inf = next((i for i in impact_flags if i["step_id"] == sid), None)
        if inf and inf.get("flagged"):
            issues.extend(inf.get("reasons", []))
            any_flagged_for_human = True
        total_violations += len(issues)
        status = "ok" if len(issues) == 0 else "flagged"
        verifier_checks.append({"step_id": sid, "status": status, "issues": issues})

    if total_violations >= MAX_BLOCK_VIOLATIONS:
        final_decision = "blocked"
    elif any_flagged_for_human and not auto_approve:
        final_decision = "hold_for_human"
    else:
        final_decision = "approved"

    out = {
        "plan_id": os.path.basename(plan_path),
        "verifier_checks": verifier_checks,
        "final_decision": final_decision,
        "total_violations": total_violations,
        "timestamp": _now_iso()
    }

    write_json(out, os.path.join(out_dir, "verifier.json"))
    return out

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--plan", required=True)
    p.add_argument("--outdir", required=True)
    p.add_argument("--auto-approve", action="store_true")
    args = p.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    result = verify_plan(args.plan, args.outdir, auto_approve=args.auto_approve)
    print("[verifier] result:", result["final_decision"])
