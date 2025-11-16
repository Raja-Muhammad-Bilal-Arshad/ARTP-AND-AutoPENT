#!/usr/bin/env bash
# tools/orchestrator_run.sh
# Usage: bash tools/orchestrator_run.sh
set -euo pipefail
HOST=127.0.0.1
PORT=8081
OUTDIR=tmp_orch
mkdir -p "$OUTDIR"
python3 tools/recon_service.py --host $HOST --port $PORT --out "$OUTDIR/recon_service.json"
python3 tools/dir_probe.py --host $HOST --port $PORT --out "$OUTDIR/dir_probe.json"
# extract candidate paths
CANDIDATES=$(python3 - <<PY
import json
j=json.load(open("$OUTDIR/dir_probe.json"))
paths=[c["path"].replace("http://$HOST:$PORT","") for c in j.get("candidates",[])]
print(" ".join(paths) if paths else "/ /login")
PY
)
python3 tools/crawl_and_extract.py --host $HOST --port $PORT --paths $CANDIDATES --out "$OUTDIR/crawl.json"

python3 tools/crawl_and_extract.py --host $HOST --port $PORT --paths / /login --out "$OUTDIR/crawl.json"
python3 tools/enumerate_forms.py --crawl "$OUTDIR/crawl.json" --out "$OUTDIR/forms.json"
python3 tools/check_creds_sim.py --forms "$OUTDIR/forms.json" --host $HOST --port $PORT --out "$OUTDIR/check_creds.json"
python3 tools/exploit_simulator.py --crawl "$OUTDIR/crawl.json" --check "$OUTDIR/check_creds.json" --out "$OUTDIR/exploit_sim.json"
python3 tools/post_exploit_sim.py --exploit "$OUTDIR/exploit_sim.json" --out "$OUTDIR/post_exploit.json"

# Combine into a normalized state (example)
python3 - <<PY
import json, time, sys
o={}
o['meta']={'sandbox':True,'collected_at':time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
for fname in ['recon_service.json','crawl.json','forms.json','check_creds.json','exploit_sim.json','post_exploit.json']:
    try:
        with open('tmp_orch/'+fname) as f:
            o[fname.replace('.json','')]=json.load(f)
    except Exception as e:
        o[fname.replace('.json','')]={"error":str(e)}
with open('state_from_live.json','w') as f:
    json.dump(o,f,indent=2)
print('Wrote state_from_live.json')
PY

echo "Complete. State saved to state_from_live.json"
