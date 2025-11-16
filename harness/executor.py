#!/usr/bin/env python3
"""
executor.py -- deterministic simulated executor and metrics calculator.

- Reads plan.json and state.json to map discoveries to ground-truth
- Simulates each step outcome (success/failure), p_det (detection probability)
- Produces exec_trace.json and metrics.json
"""

import json, os, datetime, math, random
from typing import List, Dict

# Basic default detection probabilities by action type (tunable)
BASE_P_DET = {
    "crawl": 0.01,
    "enumerate": 0.02,
    "check_creds": 0.05,
    "attempt_exploit_simulated": 0.1,
    "escalate_simulated": 0.08
}

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def load_json(p): 
    with open(p) as f: return json.load(f)
def write_json(obj, p): 
    with open(p,"w") as f: json.dump(obj, f, indent=2)

def deterministic_rng(seed):
    r = random.Random(seed)
    return r

def simulate_step(step: Dict, rng: random.Random):
    action = step.get("action","unknown")
    meta = step.get("meta",{})
    confidence = float(meta.get("confidence", 0.5))
    # base detect probability, adjusted by inverse confidence (higher confidence -> maybe more aggressive)
    p_det = BASE_P_DET.get(action, 0.05) * (1.0 + (1.0 - confidence))
    # success prob scales with reported confidence
    success_prob = min(0.95, 0.3 + 0.7 * confidence)
    success = rng.random() < success_prob
    detected = rng.random() < p_det
    result = {
        "step_id": step.get("step_id"),
        "action": action,
        "target": step.get("target"),
        "params": step.get("params", {}),
        "meta": meta,
        "result": "success" if success else "fail",
        "p_det": round(p_det, 4),
        "detected": bool(detected),
        "timestamp": now_iso()
    }
    return result

def compute_metrics(exec_trace: List[Dict], state: Dict):
    # Compute coverage: compare discovered elements in exec_trace to ground-truth in state
    # We expect state may contain 'ground_truth' list of endpoints/services
    G = state.get("ground_truth", [])
    # convert G to set of canonical strings
    gt_set = set()
    for g in G:
        if isinstance(g, dict):
            gt_set.add(json.dumps(g, sort_keys=True))
        else:
            gt_set.add(str(g))
    discovered = []
    for s in exec_trace:
        # infer discovered element from result notes: prefer target.endpoint or target.url
        t = s.get("target", {})
        discovered.append(json.dumps(t, sort_keys=True))
    Dset = set(discovered)
    if len(gt_set) == 0:
        coverage = 0.0
    else:
        coverage = len(gt_set & Dset) / max(1, len(gt_set))
    # Recon precision/recall: treat discovered endpoints as D, ground truth as R
    R = gt_set
    D = Dset
    recon_tp = len(R & D)
    recon_precision = recon_tp / len(D) if len(D) > 0 else 0.0
    recon_recall = recon_tp / len(R) if len(R) > 0 else 0.0

    # Path efficiency: a placeholder: ratio of successful steps to length (clipped)
    successes = sum(1 for s in exec_trace if s["result"] == "success")
    total = len(exec_trace) if len(exec_trace)>0 else 1
    path_efficiency = min(1.0, successes/total)

    # SafetyScore (simple): penalize detected steps and steps flagged with 'impact' high
    alpha = 1.0; beta = 0.5; gamma = 1.0
    penalty = 0.0
    for s in exec_trace:
        if s.get("detected", False):
            penalty += alpha * 1.0
        impact = s.get("meta", {}).get("impact")
        if impact == "high":
            penalty += alpha * 1.0
    safety_score = max(0.0, 1.0 - (penalty / (gamma + len(exec_trace))))

    # StealthScore: 1 - RunDetectProb
    run_detect_prob = 1.0 - math.prod([1.0 - s.get("p_det", 0.0) for s in exec_trace]) if exec_trace else 0.0
    stealth_score = max(0.0, 1.0 - run_detect_prob)

    return {
        "coverage": round(coverage, 4),
        "path_efficiency": round(path_efficiency, 4),
        "recon_precision": round(recon_precision, 4),
        "recon_recall": round(recon_recall, 4),
        "safety_score": round(safety_score, 4),
        "stealth_score": round(stealth_score, 4)
    }

def run_executor(plan_path: str, state_path: str, outdir: str, seed: int = 42):
    plan = load_json(plan_path)
    state = load_json(state_path) if os.path.exists(state_path) else {}
    rng = deterministic_rng(seed)
    exec_steps = []
    for step in plan:
        exec_steps.append(simulate_step(step, rng))
    os.makedirs(outdir, exist_ok=True)
    write_json({"run_id": os.path.basename(outdir), "steps": exec_steps}, os.path.join(outdir, "exec_trace.json"))
    metrics = compute_metrics(exec_steps, state)
    write_json(metrics, os.path.join(outdir, "metrics.json"))
    # also write a short summary
    summary = {
        "run_id": os.path.basename(outdir),
        "timestamp": now_iso(),
        "seed": seed,
        "num_steps": len(exec_steps),
        "metrics": metrics
    }
    write_json(summary, os.path.join(outdir, "run_info.json"))
    return summary

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--plan", required=True)
    p.add_argument("--state", required=False, default=None)
    p.add_argument("--outdir", required=True)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    s = run_executor(args.plan, args.state, args.outdir, seed=args.seed)
    print("[executor] wrote metrics:", s["metrics"])
