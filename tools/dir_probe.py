#!/usr/bin/env python3
# tools/dir_probe.py - light, safe directory discovery (small list)
import argparse, requests, json, time
from urllib.parse import urljoin

WORDLIST = ["login","admin","user","dashboard","wp-login.php","signin","auth","accounts","account","admin/login"]

def probe(host, port, paths=None, timeout=3):
    base = f"http://{host}:{port}"
    found=[]
    cand = paths if paths else WORDLIST
    for p in cand:
        url = urljoin(base, p if p.startswith("/") else f"/{p}")
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True)
            if r.status_code < 400:
                found.append({"path": url, "status": r.status_code})
        except Exception as e:
            # ignore timeouts; safe lab use
            pass
    return {"meta": {"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, "candidates": found}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--out", default="dir_probe.json")
    args = p.parse_args()
    res = probe(args.host, args.port)
    with open(args.out,"w") as f:
        json.dump(res, f, indent=2)
    print("Wrote", args.out)

if __name__ == "__main__":
    main()
