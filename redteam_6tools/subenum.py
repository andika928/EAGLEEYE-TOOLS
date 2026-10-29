#!/usr/bin/env python3
"""Tool 2/6 - DNS subdomain enumerator with wildcard-DNS filtering.

CLI:
    python subenum.py example.com -w wordlists/subdomains.txt -t 100

Programmatic:
    import subenum
    result = subenum.run("example.com", "wordlists/subdomains.txt")
"""
import argparse
import random
import socket
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from common import banner, eprint, read_wordlist


def resolve(host):
    """Return a sorted list of IPv4 addresses for host, or [] if none."""
    try:
        _, _, addrs = socket.gethostbyname_ex(host)
        return sorted(set(addrs))
    except socket.gaierror:
        return []


def wildcard_ips(domain):
    """Probe a random subdomain to detect wildcard DNS records."""
    token = "wc" + "".join(random.choices(string.ascii_lowercase + string.digits,
                                          k=12))
    return resolve(f"{token}.{domain}")


def run(domain, wordlist_path, threads=60, timeout=5.0):
    """Enumerate subdomains and return a JSON-serializable result dict."""
    domain = domain.strip().strip(".")
    socket.setdefaulttimeout(timeout)

    wc = wildcard_ips(domain)
    raw = read_wordlist(wordlist_path)
    words = [w.rstrip(".") for w in raw]

    subs = sorted({f"{w}.{domain}" for w in words if w and w != "*"})

    found = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futures = {ex.submit(resolve, s): s for s in subs}
        for fut in as_completed(futures):
            sub = futures[fut]
            try:
                ips = fut.result()
            except Exception:
                ips = []
            if not ips:
                continue
            if wc and set(ips) == set(wc):
                continue  # skip wildcard responses (false-positive control)
            found.append({"host": sub, "ips": ips})

    found.sort(key=lambda x: x["host"])
    return {
        "tool": "subenum",
        "target": domain,
        "wildcard_ips": wc,
        "tested": len(subs),
        "subdomains": found,
    }


def main():
    banner("SubEnumerator")
    ap = argparse.ArgumentParser(description="DNS subdomain enumerator")
    ap.add_argument("domain", help="target domain (e.g. example.com)")
    ap.add_argument("-w", "--wordlist", required=True,
                    help="file with one subdomain prefix per line")
    ap.add_argument("-t", "--threads", type=int, default=60,
                    help="worker threads (default: 60)")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="DNS timeout in seconds (default: 5)")
    args = ap.parse_args()

    try:
        result = run(args.domain, args.wordlist, args.threads, args.timeout)
    except OSError as exc:
        eprint(f"[!] cannot read wordlist: {exc}")
        return 1

    if result["wildcard_ips"]:
        print(f"[!] wildcard DNS detected -> {', '.join(result['wildcard_ips'])}; "
              f"those addresses will be filtered out")

    print(f"[*] domain  : {result['target']}")
    print(f"[*] testing : {result['tested']} subdomain(s), {args.threads} threads")

    for s in result["subdomains"]:
        print(f"  [FOUND] {s['host']} -> {', '.join(s['ips'])}")

    print(f"\n[*] done: {len(result['subdomains'])} live subdomain(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
