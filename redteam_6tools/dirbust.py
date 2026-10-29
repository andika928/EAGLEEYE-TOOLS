#!/usr/bin/env python3
"""Tool 3/6 - Web directory/file brute-forcer with advanced soft-404 & site-gate detection.

CLI:
    python dirbust.py http://host/ -w wordlists/dirs.txt -e php,html

Programmatic:
    import dirbust
    result = dirbust.run("http://host/", "wordlists/dirs.txt")
"""
import argparse
import random
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from common import banner, eprint, http_request_ex, read_wordlist

DEFAULT_STATUSES = "200,201,204,301,302,307,308,401,403,405,500"
NON_HTML_EXTENSIONS = {
    "env", "bak", "sql", "zip", "gz", "tar", "json", "yml", "yaml", "xml",
    "conf", "ini", "txt", "log", "cfg", "py", "sh", "dump"
}


def detect_site_gate(target_url, final_url, body):
    """Detect if the target is being intercepted by an ISP blockpage or captive portal."""
    target_host = urlparse(target_url).netloc.lower().split(":")[0]
    final_host = urlparse(final_url).netloc.lower().split(":")[0] if final_url else ""

    if final_host and final_host != target_host:
        if not (final_host.endswith("." + target_host) or target_host.endswith("." + final_host)):
            return {
                "detected": True,
                "type": "Cross-Domain Interception / ISP Blockpage",
                "gate_host": final_host,
                "gate_url": final_url,
                "reason": f"Traffic redirected to third-party domain '{final_host}'"
            }

    body_low = (body or "").lower()
    url_low = (final_url or "").lower()
    gate_indicators = [
        ("internetbaik", "Telkomsel InternetBaik ISP Block"),
        ("internet positif", "Internet Positif Indonesia Block"),
        ("trustpositif", "Kominfo TrustPositif Block"),
        ("mercusuar", "Telkom Mercusuar Captive Portal"),
        ("block?orig_url=", "ISP / Gateway URL Redirection Block"),
        ("blocked by your network administrator", "Network Administrator Policy Gate"),
    ]

    for pattern, name in gate_indicators:
        if pattern in body_low or pattern in url_low:
            return {
                "detected": True,
                "type": name,
                "gate_host": final_host or target_host,
                "gate_url": final_url,
                "reason": f"Matched gateway/blockpage signature '{pattern}'"
            }

    return None


def run(base_url, wordlist_path, extensions="", threads=30, timeout=8.0,
        statuses=DEFAULT_STATUSES, soft404=True):
    """Discover web paths and return a JSON-serializable result dict."""
    base = base_url.rstrip("/") + "/"
    target_host = urlparse(base).netloc.lower().split(":")[0]
    status_set = {int(x) for x in statuses.split(",") if x.strip()}
    exts = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]

    soft_len = None
    soft_status = None
    site_gate = None

    if soft404:
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        probe = urljoin(base, f"__redteam_missing_{token}.html")
        try:
            st, _, body, final_url = http_request_ex(probe, timeout=timeout)
            soft_status, soft_len = st, len(body)
            site_gate = detect_site_gate(probe, final_url, body)
        except RuntimeError:
            soft_status = soft_len = None

    # If target is behind a third-party Site Gate (ISP block), return immediately with 0 false positives
    if site_gate and site_gate["gate_host"] != target_host:
        return {
            "tool": "dirbust",
            "target": base,
            "site_gate": site_gate,
            "soft404_baseline": {"status": soft_status, "length": soft_len},
            "tested": 0,
            "paths": [],
            "note": f"Directory bruteforce suppressed: target traffic intercepted by {site_gate['gate_host']} ({site_gate['type']})."
        }

    raw = read_wordlist(wordlist_path)
    words = [w.strip("/") for w in raw]

    targets = []
    for w in sorted(set(words)):
        targets.append(w)
        for ext in exts:
            targets.append(f"{w}.{ext}")

    results = []

    def check(path):
        try:
            st, hdrs, body, final_url = http_request_ex(urljoin(base, path), timeout=timeout)
            return path, st, len(body), hdrs, body, final_url
        except RuntimeError:
            return path, None, 0, {}, "", ""

    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futures = {ex.submit(check, p): p for p in targets}
        for fut in as_completed(futures):
            path, st, length, hdrs, body, final_url = fut.result()
            if st is None or st not in status_set:
                continue

            # 1. Site Gate / Captive Portal detection
            if detect_site_gate(urljoin(base, path), final_url, body):
                continue

            # 2. Fuzzy Soft-404 Detection (±60 bytes or ±5% of baseline)
            if st == 200 and soft_len is not None:
                if abs(length - soft_len) <= 60 or (soft_len > 0 and abs(length - soft_len) / soft_len < 0.05):
                    continue

            # 3. Content-Type and Non-HTML File check
            ext_part = path.split(".")[-1].lower() if "." in path else ""
            if ext_part in NON_HTML_EXTENSIONS:
                ctype = (hdrs.get("content-type") or "").lower()
                body_low = body[:400].lower() if body else ""
                if "text/html" in ctype or "<!doctype html" in body_low or "<html" in body_low:
                    continue  # Soft-404 HTML returned for non-html file extension

            results.append({"path": "/" + path, "status": st, "length": length})

    results.sort(key=lambda x: (x["status"], x["path"]))
    return {
        "tool": "dirbust",
        "target": base,
        "site_gate": site_gate,
        "soft404_baseline": {"status": soft_status, "length": soft_len},
        "tested": len(targets),
        "paths": results,
    }


def main():
    banner("DirBuster")
    ap = argparse.ArgumentParser(description="web content discovery")
    ap.add_argument("url", help="base URL, e.g. http://host/ or https://host/")
    ap.add_argument("-w", "--wordlist", required=True,
                    help="file with one path entry per line")
    ap.add_argument("-e", "--extensions", default="",
                    help="comma-separated extensions, e.g. php,html,js")
    ap.add_argument("-t", "--threads", type=int, default=30,
                    help="worker threads (default: 30)")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="request timeout in seconds (default: 8)")
    ap.add_argument("-s", "--status", default=DEFAULT_STATUSES,
                    help="status codes to report")
    ap.add_argument("--no-soft404", action="store_true",
                    help="disable soft-404 filtering")
    args = ap.parse_args()

    try:
        result = run(args.url, args.wordlist, args.extensions, args.threads,
                     args.timeout, args.status, not args.no_soft404)
    except OSError as exc:
        eprint(f"[!] cannot read wordlist: {exc}")
        return 1

    if result.get("site_gate"):
        sg = result["site_gate"]
        print(f"[*] site gate : {sg['type']} ({sg['gate_host']})")
    if result.get("soft404_baseline", {}).get("status") is not None:
        b = result["soft404_baseline"]
        print(f"[*] soft-404 baseline: status={b['status']}, len={b['length']}")

    print(f"[*] base  : {result['target']}")
    print(f"[*] paths : {result['tested']} tested, {args.threads} threads")

    for p in result["paths"]:
        print(f"  [{p['status']}] {p['path']}  (len={p['length']})")

    print(f"\n[*] done: {len(result['paths'])} interesting path(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
