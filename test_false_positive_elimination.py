#!/usr/bin/env python3
"""
Unit Test Suite for False Positive Elimination & cURL Command Parsing.
Verifies that:
1. cURL commands and full URLs are cleanly parsed to real target domains.
2. Mangled/corrupted strings (like 'curl-I-sS-khttps') are rejected.
3. Unresolvable DNS domains (NXDOMAIN) do NOT produce false positive vulnerability alerts.
4. Real domains (like 'infomaniak.com') resolve and provide accurate telemetry.
5. Frontend defaultAssets contain valid liveUrl endpoints.
"""

import unittest
import json
import urllib.request
import urllib.error
from pathlib import Path

from server import extract_clean_domain, check_domain_resolves


BASE_URL = "http://localhost:8080"
ALT_URL = "http://localhost:8081"


def get_active_url():
    for url in [BASE_URL, ALT_URL]:
        try:
            req = urllib.request.Request(f"{url}/api/report", method="GET")
            with urllib.request.urlopen(req, timeout=3) as res:
                if res.status == 200:
                    return url
        except Exception:
            pass
    return BASE_URL


class TestFalsePositiveElimination(unittest.TestCase):
    def test_extract_clean_domain_from_curl(self):
        cases = [
            ("curl -I -sS -k https://infomaniak.com", "infomaniak.com"),
            ("curl -I -sS -k https://login.infomaniak.com", "login.infomaniak.com"),
            ("curl -I -sS -k \"https://login.infomaniak.com/oauth\"", "login.infomaniak.com"),
            ("curl https://api.infomaniak.com", "api.infomaniak.com"),
            ("https://manager.infomaniak.com/dashboard", "manager.infomaniak.com"),
            ("infomaniak.com", "infomaniak.com"),
            ("curl -X POST https://example.com/api", "example.com"),
            ("curl-I-sS-khttps", ""),
            ("invalid_no_dot", ""),
        ]
        for inp, expected in cases:
            self.assertEqual(extract_clean_domain(inp), expected, f"Failed on input: {inp}")

    def test_dns_resolution_accuracy(self):
        # infomaniak.com should resolve
        self.assertTrue(check_domain_resolves("infomaniak.com"))
        self.assertTrue(check_domain_resolves("login.infomaniak.com"))
        self.assertTrue(check_domain_resolves("localhost"))
        # Non-existent domain should NOT resolve (NXDOMAIN)
        self.assertFalse(check_domain_resolves("curl-I-sS-khttps"))
        self.assertFalse(check_domain_resolves("this-domain-surely-does-not-exist-nxdomain-999.test"))

    def test_api_rejects_corrupted_domain(self):
        # Attempting to audit 'curl-I-sS-khttps' must be rejected with 400
        req = urllib.request.Request(
            f"{get_active_url()}/api/audit",
            data=json.dumps({"target": "curl-I-sS-khttps"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as res:
                self.fail("Server accepted corrupted domain string!")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            e.close()

    def test_api_suppresses_false_positives_on_nxdomain(self):
        # Unresolvable domain should return dns_resolved: false with 0 findings
        req = urllib.request.Request(
            f"{get_active_url()}/api/audit",
            data=json.dumps({"target": "nxdomain-test-unresolvable-domain-12345.com"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            self.assertEqual(res.status, 200)
            body = json.loads(res.read().decode("utf-8"))
            self.assertFalse(body.get("dns_resolved", True))
            self.assertEqual(len(body.get("findings", [])), 0)
            self.assertEqual(body.get("severity_counts", {}).get("CRITICAL", 0), 0)

    def test_frontend_app_js_integrity(self):
        app_js = Path("web/app.js").read_text(encoding="utf-8")
        # Ensure sanitizeDomain and isValidDomain exist
        self.assertIn("function isValidDomain(", app_js)
        self.assertIn("function sanitizeDomain(", app_js)
        # Ensure liveUrl is used for proofOpenTargetBtn and copyCurl
        self.assertIn("ast.liveUrl", app_js)
        self.assertIn("currentInspectedAsset.liveUrl", app_js)
        # Ensure login.infomaniak.com is configured
        self.assertIn("login.infomaniak.com", app_js)
        self.assertIn("manager.infomaniak.com", app_js)

    def test_site_gate_detection_and_signature_verification(self):
        from redteam_6tools.misconfig_scanner import detect_site_gate, is_valid_file_exposure

        # 1. Test Telkomsel Internet Baik / Captive Portal redirection detection
        gate = detect_site_gate("http://bitso.com", "https://internetbaik.telkomsel.com/block?orig_url=http://bitso.com", "<html>...</html>")
        self.assertTrue(gate["detected"])
        self.assertEqual(gate["gate_host"], "internetbaik.telkomsel.com")

        # 2. Test HTML blockpage rejection on sensitive files (Bitso scenario)
        blockpage_html = "<html><head><title>Internet Baik - Telkomsel</title></head><body>Situs Diblokir</body></html>" * 200
        headers_html = {"content-type": "text/html; charset=UTF-8"}
        v_env, _ = is_valid_file_exposure(".env", 200, headers_html, blockpage_html)
        self.assertFalse(v_env)

        v_git, _ = is_valid_file_exposure(".git/HEAD", 200, headers_html, blockpage_html)
        self.assertFalse(v_git)

        v_aws, _ = is_valid_file_exposure(".aws/credentials", 200, headers_html, blockpage_html)
        self.assertFalse(v_aws)

        v_zip, _ = is_valid_file_exposure("backup.zip", 200, headers_html, blockpage_html)
        self.assertFalse(v_zip)

        v_sql, _ = is_valid_file_exposure("db.sql", 200, headers_html, blockpage_html)
        self.assertFalse(v_sql)

        # 3. Test genuine file exposure validation
        genuine_env = "DB_HOST=127.0.0.1\nDB_PASSWORD=supersecret_pass_123!\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        v_gen_env, _ = is_valid_file_exposure(".env", 200, {"content-type": "text/plain"}, genuine_env)
        self.assertTrue(v_gen_env)

        genuine_git = "ref: refs/heads/main\n"
        v_gen_git, _ = is_valid_file_exposure(".git/HEAD", 200, {"content-type": "application/octet-stream"}, genuine_git)
        self.assertTrue(v_gen_git)

        genuine_aws = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        v_gen_aws, _ = is_valid_file_exposure(".aws/credentials", 200, {"content-type": "text/plain"}, genuine_aws)
        self.assertTrue(v_gen_aws)

    def test_nuclei_engine_site_gate_null_safety(self):
        """Verify that when no site gate is detected (detect_site_gate returns None), run_template does not crash."""
        from redteam_6tools.nuclei_engine import run_template, BUILTIN_TEMPLATES
        # Builtin template executed against clean local target
        tmpl = BUILTIN_TEMPLATES[0]
        # Should execute safely without raising "'NoneType' object is not subscriptable"
        res = run_template(tmpl, "http://127.0.0.1:65534", timeout=0.5)
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()


