#!/usr/bin/env python3
"""Tool 9/9 - IDOR / object-reference enumeration detector.

Given a URL whose object identifier is a number (e.g. ?id=100), requests
adjacent IDs and reports IDs that return a distinct 200 response. This is a
CANDIDATE for missing per-object authorization (IDOR); confirm manually with
two accounts, because a public endpoint returning distinct objects is not
always a vulnerability.
"""
import argparse
import sys
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from common import banner, http_request


def build_url(url, param, value):
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    return urlunparse(parsed._replace(query=urlencode(new_qs)))


def run(url, timeout=8.0, param=None, span=3):
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    qmap = {k: v for k, v in qs}
    numeric = [(k, v) for k, v in qs if v.isdigit()]

    if not numeric:
        return {"tool": "idor_scanner", "target": url,
                "error": "no numeric query parameter found (pass e.g. ?id=1)",
                "param": None, "base_id": None, "tested_ids": [], "findings": []}

    if param and param in qmap and qmap[param].isdigit():
        pname, pval = param, qmap[param]
    else:
        pname, pval = numeric[0]
    base_id = int(pval)

    def fetch(pid):
        try:
            st, _, body = http_request(build_url(url, pname, str(pid)), timeout=timeout)
            return st, len(body), body
        except RuntimeError:
            return None, 0, ""

    base_st, base_len, base_body = fetch(base_id)
    findings = []
    tested = []
    for off in range(1, span + 1):
        for sign in (1, -1):
            pid = base_id + sign * off
            if pid < 0:
                continue
            st, ln, body = fetch(pid)
            tested.append(pid)
            if st == 200 and ln > 0 and body != base_body:
                findings.append({"id": pid, "status": st, "different_from_base": True})

    findings.sort(key=lambda x: x["id"])
    return {"tool": "idor_scanner", "target": url, "param": pname,
            "base_id": base_id, "base_status": base_st,
            "tested_ids": sorted(set(tested)), "findings": findings}


def main():
    banner("IDORScanner")
    ap = argparse.ArgumentParser(description="detect object-reference enumeration (IDOR candidates)")
    ap.add_argument("url", help="URL with a numeric object id, e.g. http://host/user?id=100")
    ap.add_argument("--param", default=None, help="explicit id parameter name")
    ap.add_argument("--span", type=int, default=3, help="how many adjacent ids to test")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    result = run(args.url, args.timeout, args.param, args.span)

    print(f"[*] target : {result['target']}")
    if result.get("error"):
        print(f"[!] {result['error']}")
        return 1
    print(f"[*] id param : {result['param']} (base={result['base_id']}, HTTP {result['base_status']})")
    print(f"[*] tested   : {', '.join(str(i) for i in result['tested_ids'])}")

    if not result["findings"]:
        print("\n[-] no adjacent IDs returned distinct 200 responses")
    else:
        print(f"\n[+] {len(result['findings'])} adjacent ID(s) returned distinct 200 responses (potential IDOR):")
        for f in result["findings"]:
            print(f"  [CANDIDATE] id={f['id']} (HTTP {f['status']}) - verify with two accounts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
