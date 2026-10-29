"""
Stage 2: Asset Discovery (Subfinder Core).
Passive OSINT & wordlist enumeration with multi-layer Wildcard-DNS elimination
to achieve Zero False Positives.
"""

from __future__ import annotations
import json
import random
import socket
import string
import sys
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Callable


DEFAULT_WORDLIST_DIR = Path(__file__).resolve().parent.parent / "redteam_6tools" / "wordlists"
SUBDOMAINS_WORDLIST = DEFAULT_WORDLIST_DIR / "subdomains.txt"


def resolve_ips(host: str, timeout: float = 2.5) -> List[str]:
    """Resolve IPv4 addresses for host; returns sorted list or []."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        _, _, addrs = socket.gethostbyname_ex(host)
        return sorted(set(addrs))
    except (socket.gaierror, socket.timeout, OSError):
        return []
    finally:
        socket.setdefaulttimeout(old_timeout)


def detect_wildcard_ips(domain: str) -> Set[str]:
    """
    Probe random non-existent subdomains to fingerprint wildcard DNS responses.
    Zero False Positive Control: identifies catch-all DNS routing.
    """
    wildcard_ips = set()
    for _ in range(2):
        rand_token = "rg-wc-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        probe_host = f"{rand_token}.{domain}"
        ips = resolve_ips(probe_host, timeout=2.5)
        wildcard_ips.update(ips)
    return wildcard_ips


def fetch_crt_sh_subdomains(domain: str, timeout: float = 4.0) -> Set[str]:
    """Query crt.sh Certificate Transparency logs for passive subdomain discovery."""
    found = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ReconGuard-Subfinder/1.0", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                if isinstance(data, list):
                    for item in data:
                        name_val = item.get("name_value", "")
                        for line in name_val.split("\n"):
                            line = line.strip().lower()
                            if line and not line.startswith("*.") and domain in line:
                                found.add(line)
    except Exception:
        # crt.sh can be rate limited or offline; fallback cleanly to wordlist
        pass
    return found


class SubfinderCore:
    """Core Subdomain Discovery Engine with Wildcard Suppression."""

    def __init__(self, threads: int = 40, timeout: float = 3.0, wordlist_path: Optional[Path] = None):
        self.threads = max(5, min(threads, 100))
        self.timeout = timeout
        self.wordlist_path = wordlist_path or SUBDOMAINS_WORDLIST

    def load_wordlist(self) -> List[str]:
        """Load curated wordlist from file."""
        if not self.wordlist_path.exists():
            return ["www", "api", "mail", "app", "dev", "stage", "test", "admin", "portal", "cdn", "auth", "vpn"]
        with open(self.wordlist_path, encoding="utf-8-sig", errors="replace") as fh:
            return [line.strip().lower() for line in fh if line.strip() and not line.startswith("#")]

    def run(
        self,
        domain: str,
        log_cb: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """
        Execute calibrated subdomain enumeration.
        Returns: {
            "domain": str,
            "wildcard_ips": list[str],
            "discovered_assets": list[dict],
            "total_candidates": int,
            "live_count": int,
            "wildcards_filtered": int
        }
        """
        def log(msg: str):
            if log_cb:
                log_cb(msg)

        domain = domain.strip().lower().rstrip(".")
        log(f"[*] [Subfinder] Fingerprinting Wildcard DNS for *.{domain}...")
        wildcard_ips = detect_wildcard_ips(domain)
        if wildcard_ips:
            log(f"[!] [Subfinder] Wildcard DNS ACTIVE: {', '.join(wildcard_ips)} (Filtering enabled)")
        else:
            log(f"[+] [Subfinder] No Wildcard DNS detected (Standard zone)")

        # Collect candidate subdomains (Passive + Wordlist)
        log(f"[*] [Subfinder] Querying Certificate Transparency (crt.sh)...")
        candidates = fetch_crt_sh_subdomains(domain, timeout=3.5)
        log(f"[+] [Subfinder] crt.sh discovered {len(candidates)} passive candidates")

        words = self.load_wordlist()
        for w in words:
            candidates.add(f"{w}.{domain}")

        # Ensure apex is always probed
        candidates.add(domain)

        log(f"[*] [Subfinder] Resolving {len(candidates)} candidate subdomains with {self.threads} threads...")
        live_assets = []
        wildcards_filtered = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_host = {
                executor.submit(resolve_ips, host, self.timeout): host
                for host in candidates
            }
            for fut in as_completed(future_to_host):
                host = future_to_host[fut]
                ips = fut.result()
                if not ips:
                    continue

                # ZERO FALSE POSITIVE WILDCARD FILTER
                if wildcard_ips and set(ips).issubset(wildcard_ips):
                    wildcards_filtered += 1
                    continue

                primary_ip = ips[0]
                live_assets.append({
                    "host": host,
                    "ip": primary_ip,
                    "all_ips": ips,
                    "is_wildcard": False
                })

        # Sort with apex host first, then subdomains
        live_assets.sort(key=lambda a: (0 if a["host"] == domain else 1, a["host"]))
        log(f"[+] [Subfinder] Completed: {len(live_assets)} verified live assets ({wildcards_filtered} wildcards eliminated)")

        return {
            "domain": domain,
            "wildcard_ips": sorted(list(wildcard_ips)),
            "discovered_assets": live_assets,
            "total_candidates": len(candidates),
            "live_count": len(live_assets),
            "wildcards_filtered": wildcards_filtered
        }
