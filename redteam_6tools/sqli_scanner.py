#!/usr/bin/env python3
"""Tool 4/6 - Heuristic SQL-injection detector.

Covers error-based, boolean-based, and time-based blind detection on GET query
parameters. Results are CANDIDATES for manual confirmation.

CLI:
    python sqli_scanner.py "http://host/item?id=1"

Programmatic:
    import sqli_scanner
    result = sqli_scanner.run("http://host/item?id=1")
"""
import argparse
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from common import banner, http_request

ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "uncaught mysqli",
    "mysqli_sql_exception",
    "mysql_fetch_",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "ora-01756", "ora-00933", "ora-00907", "ora-00942", "ora-01400",
    "pg_query(): query failed",
    "pg_exec(): query failed",
    "sqlstate[",
    "sqlite3::sqlexception",
    "sqlite error:",
    "pdoexception",
    "db2 sql error",
    "syntax error at or near",
]


def build_url(url, param, value):
    """Replace the value of one query parameter and return the new URL."""
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    return urlunparse(parsed._replace(query=urlencode(new_qs)))


def request(url, timeout, extra=0.0):
    """Return (status, body, elapsed). Never raises."""
    start = time.time()
    try:
        st, _, body = http_request(url, timeout=timeout + extra)
        return st, body, time.time() - start
    except RuntimeError:
        return None, "", time.time() - start


def run(url, timeout=8.0, sleep=5):
    """Detect SQLi candidates and return a JSON-serializable result dict."""
    parsed = urlparse(url)
    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]

    findings = []
    for param in params:
        base_st, base_body, _ = request(url, timeout)
        base_len = len(base_body or "")

        # 1) error-based (differential: a signature counts only if it appears
        #    AFTER injection and is NOT already present on the normal page)
        base_low = (base_body or "").lower()
        hit = None
        for payload in ["'", '"', "')", "' OR '1'='1", "' AND '1'='1"]:
            st, body, _ = request(build_url(url, param, payload), timeout)
            low = (body or "").lower()
            for pat in ERROR_PATTERNS:
                if pat in low and pat not in base_low:
                    hit = (payload, pat)
                    break
            if hit:
                break
        if hit:
            findings.append({"param": param, "type": "error-based",
                             "detail": f"{hit[0]} -> {hit[1]!r}"})

        # 2) boolean-based
        url_true = build_url(url, param, "' AND '1'='1")
        url_false = build_url(url, param, "' AND '1'='2")
        st_t, body_t, _ = request(url_true, timeout)
        st_f, body_f, _ = request(url_false, timeout)
        threshold = max(50, int(base_len * 0.15)) if base_len else 50
        if st_t != st_f or abs(len(body_t or "") - len(body_f or "")) > threshold:
            findings.append({"param": param, "type": "boolean-based",
                             "detail": "'1'='1 vs '1'='2"})

        # 3) time-based (hardened: baseline + SLEEP(0) control + repeated runs,
        #    compared on *minimum* latency to reject slow/noisy sites and WAFs)
        base_times = []
        for _ in range(3):
            st, _, t = request(url, timeout)
            if st is not None:
                base_times.append(t)
        ctrl_url = build_url(url, param, "' AND SLEEP(0)-- -")
        ctrl_times = []
        for _ in range(2):
            st, _, t = request(ctrl_url, timeout)
            if st is not None:
                ctrl_times.append(t)

        refs = []
        if base_times:
            refs.append(min(base_times))
        if ctrl_times:
            refs.append(min(ctrl_times))
        reference = max(refs) if refs else 0.0

        for label, payload in [
            ("MySQL", f"' AND SLEEP({sleep})-- -"),
            ("PostgreSQL", f"' AND pg_sleep({sleep})-- -"),
            ("MSSQL", f"'; WAITFOR DELAY '0:0:{sleep}'-- -"),
        ]:
            times = []
            for _ in range(3):
                st, _, elapsed = request(build_url(url, param, payload),
                                         timeout, extra=sleep + 3)
                if st is None:
                    break
                times.append(elapsed)
            if len(times) < 3:
                continue
            best = min(times)
            delta = best - reference
            if delta >= sleep * 0.8:
                findings.append({
                    "param": param, "type": "time-based",
                    "detail": f"{label} (+{delta:.1f}s over {reference:.1f}s baseline)",
                })
                break

    return {"tool": "sqli_scanner", "target": url, "params": params,
            "findings": findings}


def main():
    banner("SQLiScanner (heuristic)")
    ap = argparse.ArgumentParser(description="detect SQL injection candidates")
    ap.add_argument("url", help="URL with query params, e.g. http://host/item?id=1")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="request timeout in seconds (default: 8)")
    ap.add_argument("--sleep", type=int, default=5,
                    help="delay for time-based payloads (default: 5)")
    args = ap.parse_args()

    result = run(args.url, args.timeout, args.sleep)

    print(f"[*] url    : {args.url}")
    print(f"[*] params : {', '.join(result['params']) if result['params'] else '(none)'}")

    if not result["params"]:
        print("[!] no query parameters found in URL")
        return 1

    for param in result["params"]:
        print(f"\n[*] testing param '{param}'")
        for f in result["findings"]:
            if f["param"] == param:
                print(f"  [CANDIDATE] {f['type']} SQLi  (detail={f['detail']!r})")

    if not result["findings"]:
        print("\n[-] no SQLi candidates detected")
    else:
        print(f"\n[+] {len(result['findings'])} candidate(s) - CONFIRM MANUALLY "
              f"before reporting")
    return 0


if __name__ == "__main__":
    sys.exit(main())
