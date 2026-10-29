#!/usr/bin/env python3
"""Tool 8/9 - SSRF detector (out-of-band / OAST callback).

Starts a local HTTP listener, injects the callback URL into URL-looking query
parameters, and reports parameters that make the target fetch the callback.
A received callback is HIGH-confidence SSRF (no false positive).

For external targets the target must be able to reach your callback host; pass
--callback http://<your-public-host>:<port>.
"""
import argparse
import random
import string
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from common import banner, http_request

SSRF_PARAM_HINTS = (
    "url", "uri", "link", "path", "src", "source", "target", "dest",
    "destination", "callback", "webhook", "redirect", "next", "return",
    "returnurl", "proxy", "image", "img", "file", "fetch", "load", "host",
    "domain", "endpoint", "feed", "rss",
)


def build_url(url, param, value):
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    return urlunparse(parsed._replace(query=urlencode(new_qs)))


def _start_listener():
    hits = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _ok(self):
            hits.append(self.path)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _ok
        do_POST = _ok

    srv = ThreadingHTTPServer(("0.0.0.0", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], hits


def run(url, timeout=8.0, callback=None, params=None, wait=1.0):
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    qnames = [k for k, _ in qs]

    if params:
        candidates = [p for p in params if p in qnames]
    else:
        candidates = [p for p in qnames if any(h in p.lower() for h in SSRF_PARAM_HINTS)]
        if not candidates:
            candidates = qnames

    if not candidates:
        return {"tool": "ssrf_scanner", "target": url,
                "error": "no query parameters to test", "callback": None,
                "candidates": [], "findings": []}

    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    srv, port, hits = _start_listener()
    try:
        cb = callback or f"http://127.0.0.1:{port}/{token}"
        findings = []
        for param in candidates:
            before = len(hits)
            try:
                http_request(build_url(url, param, cb), timeout=timeout)
            except RuntimeError:
                pass
            deadline = time.time() + wait
            while time.time() < deadline and len(hits) == before:
                time.sleep(0.05)
            new_hits = hits[before:]
            if any(token in h for h in new_hits):
                findings.append({"param": param, "callback": cb, "confirmed": True})

        return {"tool": "ssrf_scanner", "target": url, "callback": cb,
                "candidates": candidates, "findings": findings}
    finally:
        srv.shutdown()


def main():
    banner("SSRFScanner (OAST)")
    ap = argparse.ArgumentParser(description="detect SSRF via out-of-band callback")
    ap.add_argument("url", help="URL with params, e.g. http://host/fetch?url=x")
    ap.add_argument("--callback", default=None, help="explicit callback base URL")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--wait", type=float, default=1.0)
    ap.add_argument("--param", action="append", default=None,
                    help="restrict to a param (repeatable)")
    args = ap.parse_args()

    result = run(args.url, args.timeout, args.callback, args.param, args.wait)

    print(f"[*] target     : {result['target']}")
    print(f"[*] callback   : {result.get('callback')}")
    print(f"[*] candidates : {', '.join(result['candidates'])}")

    if result.get("error"):
        print(f"[!] {result['error']}")
        return 1
    if not result["findings"]:
        print("\n[-] no SSRF callback received (no confirmed SSRF)")
    else:
        print(f"\n[+] {len(result['findings'])} parameter(s) triggered a callback:")
        for f in result["findings"]:
            print(f"  [CONFIRMED] param={f['param']} -> callback received")
    return 0


if __name__ == "__main__":
    sys.exit(main())
