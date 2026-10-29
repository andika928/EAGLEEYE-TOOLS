#!/usr/bin/env python3
"""Tool 5/6 - Reflected-XSS detector.

Injects a unique marker and payloads into each query parameter and reports
reflection points with a confidence tier.

CLI:
    python xss_scanner.py "http://host/search?q=test"

Programmatic:
    import xss_scanner
    result = xss_scanner.run("http://host/search?q=test")
"""
import argparse
import random
import string
import sys
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from common import banner, http_request


def build_url(url, param, value):
    """Replace the value of one query parameter and return the new URL."""
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    return urlunparse(parsed._replace(query=urlencode(new_qs)))


def run(url, timeout=8.0):
    """Detect reflected-XSS candidates and return a JSON-serializable dict."""
    parsed = urlparse(url)
    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]

    marker = "Xz" + "".join(random.choices(string.ascii_letters + string.digits,
                                           k=8)) + "zX"
    payloads = [
        ("script", f"<script>alert('{marker}')</script>"),
        ("img", f"<img src=x onerror=alert('{marker}')>"),
        ("svg", f"<svg/onload=alert('{marker}')>"),
    ]

    findings = []
    for param in params:
        try:
            st, _, body = http_request(build_url(url, param, marker),
                                       timeout=timeout)
        except RuntimeError:
            continue
        if marker not in body:
            continue

        for name, payload in payloads:
            try:
                _, _, body2 = http_request(build_url(url, param, payload),
                                           timeout=timeout)
            except RuntimeError:
                continue
            if marker not in body2:
                continue
            if payload in body2:
                findings.append({"param": param, "payload": name,
                                 "confidence": "raw"})
            else:
                findings.append({"param": param, "payload": name,
                                 "confidence": "encoded/context"})
            break

    return {"tool": "xss_scanner", "target": url, "marker": marker,
            "params": params, "findings": findings}


def main():
    banner("XSSScanner")
    ap = argparse.ArgumentParser(description="detect reflected XSS candidates")
    ap.add_argument("url", help="URL with query params, e.g. http://host/search?q=x")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="request timeout in seconds (default: 8)")
    args = ap.parse_args()

    result = run(args.url, args.timeout)

    print(f"[*] url    : {args.url}")
    print(f"[*] params : {', '.join(result['params']) if result['params'] else '(none)'}")
    print(f"[*] marker : {result['marker']}")

    if not result["params"]:
        print("[!] no query parameters found in URL")
        return 1

    for param in result["params"]:
        print(f"\n[*] testing param '{param}'")
        found = [f for f in result["findings"] if f["param"] == param]
        if not found:
            print("  [-] value not reflected")
        for f in found:
            conf = "RAW (high confidence)" if f["confidence"] == "raw" \
                else "marker reflected (verify HTML context)"
            print(f"  [CANDIDATE] {f['payload']} payload {conf}")

    if not result["findings"]:
        print("\n[-] no reflected-XSS candidates detected")
    else:
        print(f"\n[+] {len(result['findings'])} candidate(s) - verify context manually")
    return 0


if __name__ == "__main__":
    sys.exit(main())
