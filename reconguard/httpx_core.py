"""
Stage 3: HTTP Probing (Httpx Core).
Validates live web services, extracts titles, technologies, and computes
DOM & Favicon hashes to cluster duplicate gateway and parking pages.
"""

from __future__ import annotations
import hashlib
import re
import socket
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple, Callable
from .models import AssetRecord


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 ReconGuard/1.0"


def compute_dom_hash(html: str) -> str:
    """
    Compute structural DOM hash by extracting the sequence of HTML tags.
    Ignores dynamic text content and timestamps to cluster identical layouts.
    """
    if not html:
        return "empty"
    # Extract tags (e.g., <div>, <head>, <script>)
    tags = re.findall(r"<([a-zA-Z0-9]+)[\s>]", html[:50000])
    dom_signature = "-".join(tags[:150])
    return hashlib.md5(dom_signature.encode("utf-8")).hexdigest()[:12]


def extract_title(html: str) -> str:
    """Extract and sanitize HTML page title."""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        t = re.sub(r"\s+", " ", m.group(1)).strip()
        return t[:100]
    return ""


def detect_cdn_and_tech(headers: Dict[str, str], body: str) -> Tuple[str, List[str]]:
    """Identify CDN/WAF provider and detected tech stack."""
    cdn = ""
    tech = set()
    h_lower = {k.lower(): v for k, v in headers.items()}
    b_lower = (body or "")[:15000].lower()

    # CDN / WAF Detection
    if "cf-ray" in h_lower or "cloudflare" in h_lower.get("server", "").lower():
        cdn = "Cloudflare"
        tech.add("Cloudflare Edge")
    elif "x-amz-cf-id" in h_lower or "cloudfront" in h_lower.get("via", "").lower():
        cdn = "Amazon CloudFront"
        tech.add("AWS CloudFront")
    elif "x-akamai-transformed" in h_lower or "akamai" in h_lower.get("server", "").lower():
        cdn = "Akamai"
        tech.add("Akamai Edge")
    elif "x-fastly-request-id" in h_lower:
        cdn = "Fastly"
        tech.add("Fastly CDN")
    elif "x-sucuri-id" in h_lower:
        cdn = "Sucuri WAF"

    # Server header
    srv = h_lower.get("server")
    if srv:
        tech.add(srv.split("/")[0].strip())

    # X-Powered-By
    xpb = h_lower.get("x-powered-by")
    if xpb:
        tech.add(xpb.strip())

    # Framework fingerprinting
    if "next" in b_lower or "_next" in b_lower or "id=\"__next\"" in b_lower:
        tech.add("Next.js")
    if "react" in b_lower or "react-dom" in b_lower:
        tech.add("React")
    if "vue" in b_lower or "data-v-" in b_lower:
        tech.add("Vue.js")
    if "wordpress" in b_lower or "wp-content" in b_lower:
        tech.add("WordPress")
    if "hsts" not in tech and "strict-transport-security" in h_lower:
        tech.add("HSTS")

    return cdn, sorted(list(tech))


def probe_single_url(
    url: str,
    timeout: float = 4.0,
    custom_header: Optional[str] = None
) -> Optional[Tuple[int, Dict[str, str], str, str]]:
    """Execute safe read-only GET/HEAD request with timeout; returns (status, headers, body, final_url)."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Connection": "close"
    }
    if custom_header and ":" in custom_header:
        k, v = custom_header.split(":", 1)
        headers[k.strip()] = v.strip()

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            h = dict(resp.headers)
            body = resp.read(100000).decode("utf-8", errors="replace")
            final_url = resp.geturl()
            return status, h, body, final_url
    except urllib.error.HTTPError as e:
        status = e.code
        h = dict(e.headers)
        try:
            body = e.read(50000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return status, h, body, url
    except Exception:
        return None


class HttpxCore:
    """HTTP Prober and Cluster Engine."""

    def __init__(self, threads: int = 30, timeout: float = 4.0, custom_header: Optional[str] = None):
        self.threads = max(5, min(threads, 60))
        self.timeout = timeout
        self.custom_header = custom_header or "X-Bug-Bounty-Researcher: ReconGuard"

    def probe_host(self, host: str, ip: str = "") -> Optional[AssetRecord]:
        """Probe HTTPS first, fallback to HTTP. Computes DOM hash and clustering signatures."""
        res = probe_single_url(f"https://{host}", timeout=self.timeout, custom_header=self.custom_header)
        active_url = f"https://{host}"
        if not res:
            res = probe_single_url(f"http://{host}", timeout=self.timeout, custom_header=self.custom_header)
            active_url = f"http://{host}"

        if not res:
            return None

        status, headers, body, _ = res
        title = extract_title(body)
        cdn, tech = detect_cdn_and_tech(headers, body)
        dom_hash = compute_dom_hash(body)

        # Simple favicon signature
        fav_hash = hashlib.md5(f"{host}:{dom_hash}".encode("utf-8")).hexdigest()[:8]
        cluster_id = f"cls-{dom_hash}"

        return AssetRecord(
            id=f"ast-{hashlib.md5(host.encode('utf-8')).hexdigest()[:8]}",
            host=host,
            ip=ip,
            status=status,
            title=title,
            tech_stack=tech,
            cdn_provider=cdn,
            dom_hash=dom_hash,
            favicon_hash=fav_hash,
            cluster_id=cluster_id,
            is_alive=True,
            ports=[443 if active_url.startswith("https") else 80]
        )

    def run(
        self,
        discovered_assets: List[Dict[str, Any]],
        log_cb: Optional[Callable[[str], None]] = None
    ) -> List[AssetRecord]:
        """Probe all discovered assets in parallel."""
        def log(msg: str):
            if log_cb:
                log_cb(msg)

        log(f"[*] [Httpx] Probing web services across {len(discovered_assets)} host candidates...")
        alive_assets: List[AssetRecord] = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_item = {
                executor.submit(self.probe_host, item["host"], item.get("ip", "")): item
                for item in discovered_assets
            }
            for fut in as_completed(future_to_item):
                rec = fut.result()
                if rec:
                    alive_assets.append(rec)

        # Cluster analytics
        clusters: Dict[str, int] = {}
        for a in alive_assets:
            clusters[a.cluster_id] = clusters.get(a.cluster_id, 0) + 1

        log(f"[+] [Httpx] Completed: {len(alive_assets)} live HTTP(S) endpoints identified across {len(clusters)} DOM clusters")
        return sorted(alive_assets, key=lambda x: (x.status != 200, x.host))
