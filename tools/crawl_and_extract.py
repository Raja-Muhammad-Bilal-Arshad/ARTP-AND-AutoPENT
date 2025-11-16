#!/usr/bin/env python3
# tools/crawl_and_extract.py
# Usage: python3 crawl_and_extract.py --host 127.0.0.1 --port 8081 --paths / /login --out crawl_state.json

import argparse, requests, json, time
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def fetch_page(url, timeout=5):
    try:
        r = requests.get(url, timeout=timeout)
        return {"status": r.status_code, "text": r.text, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        form = {}
        form["action"] = urljoin(base_url, f.get("action") or "")
        form["method"] = (f.get("method") or "GET").upper()
        inputs = []
        for i in f.find_all(["input","textarea","select"]):
            inputs.append({"name": i.get("name"), "type": i.get("type"), "value": i.get("value")})
        form["inputs"] = inputs
        forms.append(form)
    return forms

def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        links.append(urljoin(base_url, a["href"]))
    return list(set(links))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--paths", nargs="+", default=["/","/login"])
    p.add_argument("--out", default="state_from_live_crawl.json")
    args = p.parse_args()

    base = f"http://{args.host}:{args.port}"
    pages = {}
    all_forms = []
    for path in args.paths:
        url = base + (path if path.startswith("/") else "/" + path)
        page = fetch_page(url)
        pages[path] = page
        if "text" in page:
            forms = extract_forms(page["text"], url)
            links = extract_links(page["text"], url)
            pages[path]["forms"] = forms
            pages[path]["links"] = links
            all_forms.extend(forms)
    out = {
        "meta": {"collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "sandbox": True},
        "host": args.host,
        "port": args.port,
        "pages": pages,
        "forms": all_forms
    }
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print("Wrote", args.out)

if __name__ == "__main__":
    main()
