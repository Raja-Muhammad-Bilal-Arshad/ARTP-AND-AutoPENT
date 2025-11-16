#!/usr/bin/env python3
# tools/enumerate_forms.py
# Usage: python3 enumerate_forms.py --crawl state_from_live_crawl.json --out forms_summary.json

import argparse, json, time

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--crawl", default="state_from_live_crawl.json")
    p.add_argument("--out", default="forms_summary.json")
    args = p.parse_args()

    with open(args.crawl) as f:
        crawl = json.load(f)
    forms = crawl.get("forms", [])
    summary = []
    for i, form in enumerate(forms, start=1):
        summary.append({
            "id": f"form_{i}",
            "action": form.get("action"),
            "method": form.get("method"),
            "inputs": [{"name": ip.get("name"), "type": ip.get("type")} for ip in form.get("inputs",[])]
        })
    out = {"meta": {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "sandbox": True}, "forms": summary}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print("Wrote", args.out)

if __name__ == "__main__":
    main()
