"""
Comprehensive Unit Test Suite for ReconGuard ASM & Zero-False-Positive Validation Platform.
Validates all 5 stages defined in prd.md2:
1. Scope & Policy Guard
2. Asset Discovery (Subfinder Core) with Wildcard DNS filtering
3. HTTP Probing (Httpx Core) with DOM/Favicon hash clustering
4. Calibrated Fuzzing (Ffuf Core) with soft-404 baseline & SPA fallback elimination
5. Evidence & Diff Engine with credential redaction & Markdown export
"""

import unittest
import json
from unittest.mock import patch, MagicMock

from reconguard.models import ScopeConfig, AssetRecord, BaselineFingerprint, FindingEvidence, DiffSummary, ReconGuardReport
from reconguard.scope_guard import ScopeGuard
from reconguard.subfinder_core import SubfinderCore, detect_wildcard_ips
from reconguard.httpx_core import HttpxCore, compute_dom_hash, extract_title, detect_cdn_and_tech
from reconguard.ffuf_core import FfufCore, HIGH_VALUE_FUZZ_PATHS
from reconguard.evidence_engine import EvidenceEngine
from reconguard.pipeline import ReconGuardPipeline


class TestReconGuardPipeline(unittest.TestCase):

    # =========================================================================
    # STAGE 1 TESTS: Scope & Policy Guard
    # =========================================================================
    def test_scope_guard_in_scope_exact_and_wildcard(self):
        scope = ScopeConfig(
            in_scope_domains=["example.com", "*.example.com", "sub.target.org"],
            out_of_scope_regex=[r".*logout.*", r".*\.corp\..*"]
        )
        guard = ScopeGuard(scope)

        # In-scope
        self.assertTrue(guard.is_in_scope("example.com")[0])
        self.assertTrue(guard.is_in_scope("api.example.com")[0])
        self.assertTrue(guard.is_in_scope("dev.test.example.com")[0])
        self.assertTrue(guard.is_in_scope("sub.target.org")[0])

        # Out-of-scope domain
        self.assertFalse(guard.is_in_scope("evil.com")[0])
        self.assertFalse(guard.is_in_scope("other.target.org")[0])

        # Out-of-scope regex block
        self.assertFalse(guard.is_in_scope("logout.example.com")[0])
        self.assertFalse(guard.is_in_scope("internal.corp.example.com")[0])

    def test_scope_guard_normalize_host(self):
        guard = ScopeGuard()
        self.assertEqual(guard.normalize_host("https://api.example.com:8443/v1/users"), "api.example.com")
        self.assertEqual(guard.normalize_host("user@dev.example.com"), "dev.example.com")
        self.assertEqual(guard.normalize_host("  EXAMPLE.COM.  "), "example.com")

    # =========================================================================
    # STAGE 2 TESTS: Subfinder Core & Wildcard Filtering
    # =========================================================================
    def test_subfinder_wildcard_filtering(self):
        subfinder = SubfinderCore()
        
        # Mock wildcard resolver: any random token resolves to 192.0.2.1
        with patch("reconguard.subfinder_core.resolve_ips") as mock_resolve:
            mock_resolve.side_effect = lambda h, timeout=2.5: (
                ["192.0.2.1"] if "rg-wc-" in h or "fake-ghost" in h else
                ["93.184.216.34"] if "api.example.com" in h else
                ["93.184.216.35"] if "example.com" in h else []
            )
            with patch.object(subfinder, "load_wordlist", return_value=["api", "fake-ghost"]):
                with patch("reconguard.subfinder_core.fetch_crt_sh_subdomains", return_value=set()):
                    res = subfinder.run("example.com")

                    # Wildcard IP 192.0.2.1 detected
                    self.assertIn("192.0.2.1", res["wildcard_ips"])
                    # fake-ghost resolves to wildcard IP, so it must be eliminated
                    discovered_hosts = [a["host"] for a in res["discovered_assets"]]
                    self.assertIn("api.example.com", discovered_hosts)
                    self.assertNotIn("fake-ghost.example.com", discovered_hosts)
                    self.assertGreaterEqual(res["wildcards_filtered"], 1)

    # =========================================================================
    # STAGE 3 TESTS: Httpx Core & DOM Clustering
    # =========================================================================
    def test_httpx_dom_hash_and_clustering(self):
        html1 = "<html><head><title>Default Gateway</title></head><body><div class='wrap'><p>Status 200</p></div></body></html>"
        html2 = "<html><head><title>Default Gateway</title></head><body><div class='wrap'><p>Status 200 - Server timestamp 17:00</p></div></body></html>"
        html_different = "<html><head><title>Admin Dashboard</title></head><body><main><table><tr><td>Data</td></tr></table></main></body></html>"

        # html1 and html2 have identical HTML tag sequences -> identical DOM hash
        hash1 = compute_dom_hash(html1)
        hash2 = compute_dom_hash(html2)
        hash_diff = compute_dom_hash(html_different)

        self.assertEqual(hash1, hash2, "Identical tag layouts must share the same DOM hash")
        self.assertNotEqual(hash1, hash_diff, "Different structural layouts must have different DOM hashes")

    def test_httpx_cdn_and_tech_detection(self):
        headers = {
            "server": "cloudflare",
            "cf-ray": "8c45991823-SIN",
            "x-powered-by": "Next.js",
            "strict-transport-security": "max-age=31536000"
        }
        body = "<div id='__next'>Hello World</div>"
        cdn, tech = detect_cdn_and_tech(headers, body)
        self.assertEqual(cdn, "Cloudflare")
        self.assertIn("Next.js", tech)
        self.assertIn("HSTS", tech)

    # =========================================================================
    # STAGE 4 TESTS: Calibrated Ffuf Core & Zero-False-Positive Filtering
    # =========================================================================
    def test_ffuf_zero_fp_rejects_spa_html_fallback(self):
        ffuf = FfufCore()
        baseline = BaselineFingerprint(
            asset_host="app.example.com",
            status_code=404,
            content_length_avg=350.0,
            word_count_avg=30.0,
            line_count_avg=10.0,
            content_type="text/html",
            body_hash="abc",
            is_catch_all=False,
            is_spa_fallback=True
        )

        spec = {"path": "/.env", "cat": "Secrets Exposure", "sev": "CRITICAL", "mime": "text/plain"}
        # SPA server returns 200 with React HTML page for any route
        spa_body = "<!doctype html><html><head><title>Single Page App</title></head><body><div id='root'></div></body></html>"
        headers = {"content-type": "text/html; charset=utf-8"}

        is_valid, reason, _ = ffuf.evaluate_zero_false_positive(spec, 200, headers, spa_body, baseline)
        self.assertFalse(is_valid, "SPA HTML fallback for .env must be rejected as False Positive")
        self.assertIn("Expected text/plain", reason)

    def test_ffuf_zero_fp_rejects_catch_all_identical_body(self):
        ffuf = FfufCore()
        catch_all_body = "<html><body>Parked Domain Page</body></html>"
        bh = "b328a8d"
        baseline = BaselineFingerprint(
            asset_host="parked.example.com",
            status_code=200,
            content_length_avg=len(catch_all_body),
            word_count_avg=len(catch_all_body.split()),
            line_count_avg=1.0,
            content_type="text/html",
            body_hash=bh,
            is_catch_all=True
        )

        spec = {"path": "/admin", "cat": "Admin Panel", "sev": "LOW", "mime": "text/html"}
        with patch("hashlib.md5") as mock_md5:
            mock_md5.return_value.hexdigest.return_value = bh
            is_valid, reason, _ = ffuf.evaluate_zero_false_positive(spec, 200, {"content-type": "text/html"}, catch_all_body, baseline)
            self.assertFalse(is_valid, "Identical catch-all response must be discarded")
            self.assertIn("catch-all baseline", reason)

    def test_ffuf_zero_fp_accepts_genuine_env_exposure(self):
        ffuf = FfufCore()
        baseline = BaselineFingerprint(
            asset_host="api.example.com",
            status_code=404,
            content_length_avg=140.0,
            word_count_avg=15.0,
            line_count_avg=5.0,
            content_type="text/html",
            body_hash="404hash"
        )

        spec = {"path": "/.env", "cat": "Secrets Exposure", "sev": "CRITICAL", "mime": "text/plain"}
        genuine_env = "DB_HOST=10.0.0.5\nDB_PASSWORD=SuperSecretPass99!\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        headers = {"content-type": "text/plain"}

        is_valid, reason, diff = ffuf.evaluate_zero_false_positive(spec, 200, headers, genuine_env, baseline)
        self.assertTrue(is_valid, "Genuine .env file with credentials must be accepted as True Positive")
        self.assertEqual(reason, "Verified True Positive")
        self.assertIsNotNone(diff)
        self.assertIn("differ", diff.rationale.lower())

    # =========================================================================
    # STAGE 5 TESTS: Evidence Engine & Sanitized Markdown Report
    # =========================================================================
    def test_evidence_engine_sanitizes_secrets(self):
        raw_http = (
            "GET /.env HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret\r\n"
            "Cookie: session_id=abc123secretcookie\r\n"
            "DB_PASSWORD=supersecret_pass_123!\r\n"
        )
        sanitized = EvidenceEngine.sanitize_secrets(raw_http)
        self.assertNotIn("supersecret", sanitized)
        self.assertNotIn("abc123secretcookie", sanitized)
        self.assertIn("[REDACTED_BEARER_TOKEN]", sanitized)
        self.assertIn("[REDACTED_SESSION_COOKIES]", sanitized)
        self.assertIn("[REDACTED_PASSWORD]", sanitized)

    def test_evidence_engine_markdown_report_structure(self):
        scope = ScopeConfig(in_scope_domains=["target.com"])
        finding = FindingEvidence(
            id="RG-A1B2C3",
            asset_host="api.target.com",
            endpoint_path="/.env",
            url="https://api.target.com/.env",
            status_code=200,
            confidence_score="100% Verified Anomaly",
            severity="CRITICAL",
            category="Secrets Exposure",
            raw_request="GET /.env HTTP/1.1\r\nHost: api.target.com\r\n",
            raw_response_headers={"content-type": "text/plain"},
            raw_response_body="DB_HOST=127.0.0.1\n",
            diff_summary=DiffSummary("404 -> 200", 50, 10, "text/html -> text/plain", "Confirmed anomaly"),
            curl_cmd='curl -sS -i -X GET "https://api.target.com/.env"',
            timestamp="2026-10-15 12:00:00 UTC"
        )
        report = ReconGuardReport(
            program_name="ReconGuard-target.com",
            target_domain="target.com",
            scan_date="2026-10-15",
            scope=scope,
            assets=[AssetRecord("ast-1", "api.target.com", "1.2.3.4", 200, "API", ["Nginx"], "Direct", "dom1", "fav1", "cls1", True, [443])],
            baselines={"api.target.com": BaselineFingerprint("api.target.com", ["/r1"], 404, 200.0, 20.0, 5.0, "text/html", "h1")},
            findings=[finding],
            summary={"status": "COMPLETED"}
        )

        md = EvidenceEngine.generate_markdown_report(report)
        self.assertIn("# 🛡️ ReconGuard Evidence-Led Active Reconnaissance Report", md)
        self.assertIn("Independently confirmed vulnerability:** No", md)
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Discovered Asset Inventory", md)
        self.assertIn("## 3. Calibrated Baseline Soft-404 Profiles", md)
        self.assertIn("## 4. Observations & Evidence", md)
        self.assertIn("RG-A1B2C3", md)
        self.assertIn("Reproduction cURL Command", md)


if __name__ == "__main__":
    unittest.main()
