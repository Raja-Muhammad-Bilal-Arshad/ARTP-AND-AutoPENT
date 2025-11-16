# web_cluster template (AutoPENT)


This folder contains a sanitized example target used by the AutoPENT harness for web-target experiments.


## Files
- `docker-compose.yml` — launches Juice Shop (port 3000) and DVWA (port 80) in a local bridge network.
- `example_state.json` — sanitized ground-truth state for recon/evaluation metrics.


## How to use
1. Ensure you are running on an isolated lab machine or VM (do not expose to the public internet).
2. From the repo root:


```bash
# Deploy the template into the harness workspace (copies files to harness_targets/web_cluster)
python3 ./harness/harness.py deploy web_cluster


# Start containers (optional) if you want to run the actual target locally
cd harness_targets/web_cluster
docker-compose up -d


# Dump the sanitized state (harness will write state.json if not present)
python3 ./harness/harness.py dump_state --target web_cluster --out state.json --seed 42


# Run the rule-based adapter through harness (will generate a plan and run simulated executor)
python3 ./harness/harness.py run_plan --plan results/run1/plan.json --outdir results/run1 --agent rule_based --auto-adapter --mode rule --seed 42 --auto-approve
