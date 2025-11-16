#!/usr/bin/env python3
# tools/recon_service.py
# Usage: python3 recon_service.py --host 127.0.0.1 --port 8081 --out recon_service.json

import argparse, socket, json, time, sys
from urllib.parse import urljoin
import requests

def tcp_banner(host: str, port: int, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # send a small probe if HTTP (GET)
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = s.recv(4096)
                return data.decode(errors="ignore")
            except Exception:
                return ""
    except Exception as e:
        return f"error: {e}"

def http_headers(host: str, port: int, timeout=3.0):
    url = f"http://{host}:{port}/"
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        return {"status_code": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--out", default="state_from_live_recon_service.json")
    args = p.parse_args()

    state = {
        "meta": {"collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "sandbox": True},
        "host": args.host,
        "port": args.port,
        "tcp_banner": tcp_banner(args.host, args.port),
        "http": http_headers(args.host, args.port)
    }
    with open(args.out, "w") as f:
        json.dump(state, f, indent=2)
    print("Wrote", args.out)

if __name__ == "__main__":
    main()
