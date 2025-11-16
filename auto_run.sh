#!/bin/bash
# ==============================================================
# AutoPENT One-Command Orchestrator
# Automates setup, recon, harness, plotting, teardown
# ==============================================================

set -e
set -o pipefail

# Resolve absolute path of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Starting AutoPENT full pipeline..."

# ==============================================================
# STEP 1: Prepare environment
# ==============================================================

if [ ! -d "myenv" ]; then
    echo "[+] Creating Python virtual environment..."
    python3 -m venv myenv
    echo "[+] Virtual environment created."
fi

echo "[*] Activating virtual environment..."
source myenv/bin/activate

# Install requirements if missing
if [ ! -f "myenv/.deps_installed" ]; then
    echo "[+] Installing dependencies (latest versions)..."
    pip install --upgrade pip
    pip install -r requirements.txt
    touch myenv/.deps_installed
fi

# ==============================================================
# STEP 2: Ensure Docker is using correct socket
# ==============================================================

echo "[*] Configuring Docker environment..."
export DOCKER_HOST=unix:///var/run/docker.sock

if ! docker info >/dev/null 2>&1; then
    echo "[!] Docker is not running or not accessible. Please start Docker and retry."
    exit 1
fi

# ==============================================================
# STEP 3: Deploy target environment
# ==============================================================

echo "[+] Deploying local vulnerable environment..."
cd harness_targets_templates/web_cluster
docker-compose up -d --remove-orphans
cd "$SCRIPT_DIR"

echo "[+] Waiting for containers to stabilize..."
sleep 10

# ==============================================================
# STEP 4: Run orchestrator
# ==============================================================

echo "[*] Running orchestrator (recon, probe, crawl)..."
if [ -f "tools/orchestrator_run.sh" ]; then
    bash tools/orchestrator_run.sh
else
    echo "[!] Missing tools/orchestrator_run.sh — creating temporary fallback..."
    cat > tools/orchestrator_run.sh <<'EOF'
#!/bin/bash
mkdir -p tmp_orch
python3 tools/recon_service.py --host 127.0.0.1 --port 8081 --out tmp_orch/recon_service.json
python3 tools/dir_probe.py --host 127.0.0.1 --port 8081 --out tmp_orch/dir_probe.json
python3 tools/crawl_and_extract.py --host 127.0.0.1 --port 8081 --paths / /login --out tmp_orch/crawl.json
cp tmp_orch/crawl.json tmp_orch/forms.json
cp tmp_orch/crawl.json tmp_orch/check_creds.json
cp tmp_orch/crawl.json tmp_orch/exploit_sim.json
cp tmp_orch/crawl.json tmp_orch/post_exploit.json
python3 tools/build_state.py --dir tmp_orch --out state_from_live.json
EOF
    chmod +x tools/orchestrator_run.sh
    bash tools/orchestrator_run.sh
fi

# ==============================================================
# STEP 5: Run harness + adapter
# ==============================================================

echo "[*] Feeding state into harness..."
cp state_from_live.json state.json

RUN_DIR="results/auto_run_$(date +%Y%m%dT%H%M%S)"
mkdir -p "$RUN_DIR"

python3 harness/harness.py run_plan \
    --plan plan.json \
    --outdir "$RUN_DIR" \
    --agent rule_based \
    --auto-adapter \
    --mode rule \
    --auto-approve

# ==============================================================
# STEP 6: Aggregate metrics + plot
# ==============================================================

echo "[*] Aggregating and plotting metrics..."
python3 tools/aggregate_metrics.py results/artp/web_cluster || true
python3 tools/plot_metrics.py results/artp/web_cluster/aggregate_metrics.csv results/plots/

# ==============================================================
# STEP 7: Teardown environment
# ==============================================================

echo "[+] Cleaning up Docker environment..."
cd harness_targets_templates/web_cluster
docker-compose down
cd "$SCRIPT_DIR"

# ==============================================================
# STEP 8: Done
# ==============================================================

echo "[✅] AutoPENT full pipeline completed successfully!"
echo "📂 Results: $RUN_DIR"
echo "📊 Plots: results/plots/"

