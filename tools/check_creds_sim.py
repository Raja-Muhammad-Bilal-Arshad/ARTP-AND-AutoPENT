#!/usr/bin/env python3
# tools/check_creds_sim.py
# Usage: python3 check_creds_sim.py --forms forms_summary.json --host 127.0.0.1 --port 8081 --out check_creds.json

import argparse, json, requests, time

DEFAULTS = [("admin","admin"), ("admin","password"), ("root","root")]

def try_login(action_url, method, creds):
    # conservative: only test POST endpoints that look like login
    if method != "POST":
        return {"tried": False, "reason":"non-post"}
    try:
        user, pwd = creds
        r = requests.post(action_url, data={"username": user, "password": pwd}, timeout=4, allow_redirects=False)
        # heuristic: a 302 or 200 with body changed vs initial indicates potential login success in lab
        ok = (r.status_code in (200,302))
        return {"tried": True, "username": user, "password": pwd, "status": r.status_code, "success": ok}
    except Exception as e:
        return {"tried": True, "error": str(e)}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--forms", default="forms_summary.json")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--out", default="check_creds.json")
    args = p.parse_args()

    with open(args.forms) as f:
        forms = json.load(f).get("forms", [])
    results = []
    base = f"http://{args.host}:{args.port}"
    for form in forms:
        action = form.get("action")
        if not action:
            action = base
        # Only attempt once per form with the small DEFAULTS list
        for cred in DEFAULTS:
            r = try_login(action, form.get("method","GET"), cred)
            # stop on first success
            results.append({"form":form,"attempt":cred,"result":r})
            if r.get("success"):
                break

    out = {"meta": {"collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "sandbox": True}, "results": results}
    with open(args.out,"w") as f:
        json.dump(out, f, indent=2)
    print("Wrote", args.out)

if __name__ == "__main__":
    main()
