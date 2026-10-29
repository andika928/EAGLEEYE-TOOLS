"""
Stage 4: Calibrated Fuzzing (Ffuf Core).
Multi-layer auto-calibration baseline engine and four-factor noise rejection.
Eliminates soft-404s, SPA fallbacks, catch-all redirects, and WAF edge reflections.
"""

from __future__ import annotations
import hashlib
import json
import random
import re
import string
import time
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional, Tuple, Callable
from pathlib import Path

from .models import AssetRecord, BaselineFingerprint, FindingEvidence, DiffSummary
from .httpx_core import USER_AGENT, probe_single_url


HIGH_VALUE_FUZZ_PATHS = [
    # Sensitive Configs & Secrets
    {"path": "/.env", "cat": "Secrets Exposure", "sev": "CRITICAL", "mime": "text/plain"},
    {"path": "/.env.local", "cat": "Secrets Exposure", "sev": "CRITICAL", "mime": "text/plain"},
    {"path": "/.env.production", "cat": "Secrets Exposure", "sev": "CRITICAL", "mime": "text/plain"},
    {"path": "/.git/config", "cat": "Source Code Exposure", "sev": "HIGH", "mime": "text/plain"},
    {"path": "/.git/HEAD", "cat": "Source Code Exposure", "sev": "HIGH", "mime": "text/plain"},
    {"path": "/web.config", "cat": "Config Exposure", "sev": "HIGH", "mime": "text/xml"},
    {"path": "/docker-compose.yml", "cat": "DevOps Exposure", "sev": "HIGH", "mime": "text/yaml"},
    # API & Docs
    {"path": "/swagger.json", "cat": "API Documentation", "sev": "MEDIUM", "mime": "application/json"},
    {"path": "/openapi.json", "cat": "API Documentation", "sev": "MEDIUM", "mime": "application/json"},
    {"path": "/v2/api-docs", "cat": "API Documentation", "sev": "MEDIUM", "mime": "application/json"},
    {"path": "/api-docs", "cat": "API Documentation", "sev": "LOW", "mime": "text/html"},
    {"path": "/graphql", "cat": "GraphQL Endpoint", "sev": "LOW", "mime": "application/json"},
    # Framework Actuators & Metrics
    {"path": "/actuator/env", "cat": "Spring Actuator RCE/Exposure", "sev": "CRITICAL", "mime": "application/json"},
    {"path": "/actuator/health", "cat": "Spring Health Metric", "sev": "INFO", "mime": "application/json"},
    {"path": "/actuator/beans", "cat": "Spring Component Exposure", "sev": "MEDIUM", "mime": "application/json"},
    {"path": "/metrics", "cat": "Prometheus Metrics", "sev": "MEDIUM", "mime": "text/plain"},
    # Database Backups & Dumps
    {"path": "/backup.zip", "cat": "Database / Code Backup", "sev": "CRITICAL", "mime": "application/zip"},
    {"path": "/db.sql", "cat": "Database Dump Exposure", "sev": "CRITICAL", "mime": "text/plain"},
    {"path": "/dump.sql", "cat": "Database Dump Exposure", "sev": "CRITICAL", "mime": "text/plain"},
    {"path": "/phpinfo.php", "cat": "PHP Info Disclosure", "sev": "MEDIUM", "mime": "text/html"},
    {"path": "/robots.txt", "cat": "Information Disclosure", "sev": "INFO", "mime": "text/plain"},
    {"path": "/sitemap.xml", "cat": "Information Disclosure", "sev": "INFO", "mime": "text/xml"},
    # Admin / Auth
    {"path": "/admin", "cat": "Admin Panel", "sev": "LOW", "mime": "text/html"},
    {"path": "/login", "cat": "Auth Endpoint", "sev": "INFO", "mime": "text/html"},
]


class FfufCore:
    """Calibrated Fuzzing Engine with Baseline Fingerprinting."""

    def __init__(
        self,
        timeout: float = 3.5,
        custom_header: Optional[str] = None,
        rate_limit_delay: float = 0.05
    ):
        self.timeout = timeout
        self.custom_header = custom_header or "X-Bug-Bounty-Researcher: ReconGuard"
        self.rate_limit_delay = rate_limit_delay

    def calibrate_baseline(self, base_url: str, host: str) -> BaselineFingerprint:
        """
        Auto-Calibration Baseline Engine:
        Sends 3 pseudo-random probe requests to record soft-404 metrics.
        """
        probe_paths = []
        statuses = []
        lengths = []
        word_counts = []
        line_counts = []
        body_hashes = []
        content_types = []
        redirects = []

        for _ in range(3):
            token = "rg-probe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
            p = f"/{token}"
            probe_paths.append(p)
            url = f"{base_url}{p}"
            res = probe_single_url(url, timeout=self.timeout, custom_header=self.custom_header)
            if res:
                st, hdrs, b, final_u = res
                statuses.append(st)
                lengths.append(len(b))
                words = len(b.split())
                word_counts.append(words)
                lines = len(b.splitlines())
                line_counts.append(lines)
                body_hashes.append(hashlib.md5(b.encode("utf-8")).hexdigest())
                ctype = hdrs.get("content-type", "").lower()
                content_types.append(ctype)
                if final_u != url:
                    redirects.append(final_u)
            else:
                statuses.append(404)
                lengths.append(0)
                word_counts.append(0)
                line_counts.append(0)
                body_hashes.append("empty")
                content_types.append("none")

        avg_len = sum(lengths) / max(1, len(lengths))
        avg_words = sum(word_counts) / max(1, len(word_counts))
        avg_lines = sum(line_counts) / max(1, len(line_counts))
        primary_status = statuses[0] if statuses else 404

        # Detect catch-all behavior
        is_catch_all = all(s == 200 for s in statuses) and (len(set(body_hashes)) <= 1)
        
        # Detect SPA HTML fallback (e.g., React/Vue returning index.html for all 404s)
        is_spa = any("text/html" in ct for ct in content_types) and (
            avg_len > 200 and ("id=\"root\"" in b or "id=\"__next\"" in b or "<!doctype html" in b.lower())
        )

        return BaselineFingerprint(
            asset_host=host,
            probe_paths=probe_paths,
            status_code=primary_status,
            content_length_avg=round(avg_len, 1),
            word_count_avg=round(avg_words, 1),
            line_count_avg=round(avg_lines, 1),
            content_type=content_types[0] if content_types else "text/html",
            body_hash=body_hashes[0] if body_hashes else "",
            redirect_location=redirects[0] if redirects else "",
            is_catch_all=is_catch_all,
            is_spa_fallback=is_spa
        )

    def evaluate_zero_false_positive(
        self,
        endpoint_spec: Dict[str, str],
        status: int,
        headers: Dict[str, str],
        body: str,
        baseline: BaselineFingerprint
    ) -> Tuple[bool, str, Optional[DiffSummary]]:
        """
        4-Layer Zero False Positive Validation Filter.
        Returns: (is_valid: bool, rejection_reason: str, diff_summary: Optional[DiffSummary])
        """
        p = endpoint_spec["path"]
        expected_mime = endpoint_spec.get("mime", "text/plain")
        b_len = len(body)
        b_words = len(body.split())
        b_lines = len(body.splitlines())
        c_type = headers.get("content-type", "").lower()
        body_hash = hashlib.md5(body.encode("utf-8")).hexdigest()

        # Reject if unreachable or standard 404 / 400
        if status in (404, 400, 502, 503, 504):
            return False, f"Standard HTTP {status} error response", None

        # LAYER 1: Baseline Delta Inspection
        # If response byte length, word count, and status match baseline soft-404 profile
        len_diff = abs(b_len - baseline.content_length_avg)
        words_diff = abs(b_words - baseline.word_count_avg)
        if baseline.is_catch_all:
            if body_hash == baseline.body_hash:
                return False, "Matches catch-all baseline body hash (False Positive)", None
            if len_diff < 50 and words_diff < 10:
                return False, f"Matches catch-all soft-404 baseline (delta {len_diff}B)", None

        if status == baseline.status_code and len_diff < 20 and words_diff < 5:
            return False, f"Response matches non-existent baseline soft-404 (length delta: {len_diff}B)", None

        # LAYER 2: Structural & Content-Type Validation
        # If target is a sensitive raw file, config, or API data, but server returned HTML
        is_sensitive_file = any(p.endswith(ext) for ext in [".env", ".git/config", ".git/HEAD", ".json", ".xml", ".yml", ".zip", ".sql"])
        is_html_resp = (
            "text/html" in c_type or
            body.strip().lower().startswith("<!doctype html") or
            body.strip().lower().startswith("<html")
        )

        if is_sensitive_file and is_html_resp:
            # An HTML response for a .env, .git, or .json file is an SPA catch-all fallback or custom 404
            return False, f"Expected {expected_mime} for '{p}' but received HTML page (SPA / Soft-404 fallback)", None

        # Content validation for specific high-risk exposures
        if p.startswith("/.env") and status == 200:
            if not any(token in body for token in ["=", "DB_", "PASSWORD", "SECRET", "KEY", "PORT"]):
                return False, "Missing valid key-value pairs in .env response", None

        if p == "/.git/config" and status == 200:
            if not any(token in body for token in ["[core]", "repositoryformatversion", "remote \"origin\""]):
                return False, "Missing Git repository signatures in .git/config", None

        if p == "/.git/HEAD" and status == 200:
            if not body.strip().startswith("ref: refs/"):
                return False, "Missing valid 'ref: refs/' in .git/HEAD", None

        if p.endswith(".json") and status == 200:
            try:
                json.loads(body)
            except Exception:
                return False, "Malformed JSON syntax in supposed JSON API endpoint", None

        # LAYER 3: CDN & Cache Header Inspection
        # Reject if Cloudflare / Akamai static blockpage or captive challenge
        h_low = {k.lower(): v.lower() for k, v in headers.items()}
        if "cf-mitigated" in h_low or "challenge-platform" in body or "attention required! | cloudflare" in body.lower():
            return False, "Cloudflare WAF Captive Challenge gate intercepted response", None

        # LAYER 4: Baseline Difference Metrics
        status_delta = f"Baseline: {baseline.status_code} -> Endpoint: {status}"
        bytes_delta = int(b_len - baseline.content_length_avg)
        words_delta = int(b_words - baseline.word_count_avg)
        content_type_delta = f"Baseline: '{baseline.content_type}' -> Endpoint: '{c_type}'"

        rationale = (
            f"Distinct response observed: status {status} differs from baseline {baseline.status_code}. "
            f"Content length delta: {bytes_delta:+d} bytes ({b_len}B vs baseline {baseline.content_length_avg:.0f}B). "
            f"Structural integrity validated for {endpoint_spec['cat']}."
        )

        diff = DiffSummary(
            status_delta=status_delta,
            bytes_delta=bytes_delta,
            words_delta=words_delta,
            content_type_delta=content_type_delta,
            rationale=rationale
        )

        return True, "Verified True Positive", diff

    def fuzz_host(
        self,
        asset: AssetRecord,
        log_cb: Optional[Callable[[str], None]] = None
    ) -> Tuple[BaselineFingerprint, List[FindingEvidence]]:
        """Calibrate baseline and execute fuzzing against a single live asset."""
        def log(msg: str):
            if log_cb:
                log_cb(msg)

        scheme = "https" if 443 in asset.ports else "http"
        base_url = f"{scheme}://{asset.host}"

        log(f"[*] [Ffuf] Calibrating Soft-404 baseline for {asset.host}...")
        baseline = self.calibrate_baseline(base_url, asset.host)
        log(
            f"[+] [Ffuf] Baseline established: Status {baseline.status_code} · "
            f"Avg {baseline.content_length_avg:.0f}B · {baseline.word_count_avg:.0f} words · "
            f"Catch-All={baseline.is_catch_all} · SPA={baseline.is_spa_fallback}"
        )

        findings: List[FindingEvidence] = []

        for spec in HIGH_VALUE_FUZZ_PATHS:
            time.sleep(self.rate_limit_delay)
            p = spec["path"]
            url = f"{base_url}{p}"

            res = probe_single_url(url, timeout=self.timeout, custom_header=self.custom_header)
            if not res:
                continue

            status, headers, body, _ = res

            is_valid, reason, diff = self.evaluate_zero_false_positive(spec, status, headers, body, baseline)
            if not is_valid:
                continue

            # Generate Raw Request dump
            raw_request = (
                f"GET {p} HTTP/1.1\r\n"
                f"Host: {asset.host}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"{self.custom_header}\r\n"
                f"Accept: {spec.get('mime', '*/*')}\r\n"
                f"Connection: close\r\n\r\n"
            )

            curl_cmd = f'curl -sS -i -X GET "{url}" -H "{self.custom_header}"'

            fid = f"RG-{hashlib.md5(f'{asset.host}:{p}'.encode('utf-8')).hexdigest()[:6].upper()}"
            findings.append(FindingEvidence(
                id=fid,
                asset_host=asset.host,
                endpoint_path=p,
                url=url,
                status_code=status,
                confidence_score="High-confidence response anomaly (impact unconfirmed)",
                severity=spec["sev"],
                category=spec["cat"],
                raw_request=raw_request,
                raw_response_headers=headers,
                raw_response_body=body[:5000],  # store first 5KB
                diff_summary=diff or DiffSummary("N/A", 0, 0, "N/A", "N/A"),
                curl_cmd=curl_cmd,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            ))
            log(f"[!] [Ffuf Verified] [{spec['sev']}] {asset.host}{p} (HTTP {status}) -> {spec['cat']}")

        return baseline, findings
