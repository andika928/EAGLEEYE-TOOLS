#!/usr/bin/env python3
"""Unit tests for evidence-led security validation packs."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_DIR = Path(__file__).parent / "redteam_6tools"
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import injection_audit  # noqa: E402
import privilege_audit  # noqa: E402
import sensitive_data_audit  # noqa: E402
import runner  # noqa: E402
import poc  # noqa: E402


class TestValidationPacks(unittest.TestCase):
    def test_injection_pack_preserves_candidate_status_and_gaps(self):
        sql = {
            "params": ["q"],
            "findings": [{"type": "boolean", "param": "q", "detail": "bounded delta"}],
        }
        xss = {
            "params": ["q"],
            "findings": [{"param": "q", "payload": "marker", "confidence": "encoded"}],
        }
        with patch.object(injection_audit.sqli_scanner, "run", return_value=sql), \
                patch.object(injection_audit.xss_scanner, "run", return_value=xss):
            result = injection_audit.run("https://example.test/?q=1")

        self.assertEqual(result["assessment_class"], "Injection Attacks")
        self.assertEqual(len(result["observations"]), 2)
        self.assertEqual(result["observations"][0]["confidence"], "candidate")
        self.assertIn("not_tested", {item["status"] for item in result["coverage"]})

    def test_privilege_pack_never_confirms_without_two_roles(self):
        auth = {"findings": [{"type": "Cookie posture", "severity": "LOW", "detail": "flag absent"}]}
        idor = {"findings": [{"id": "102", "status": 200}]}
        with patch.object(privilege_audit.auth_scanner, "run", return_value=auth), \
                patch.object(privilege_audit.idor_scanner, "run", return_value=idor):
            result = privilege_audit.run("https://example.test/object/101")

        self.assertEqual(result["validation_state"], "two_role_validation_required")
        self.assertEqual(result["observations"][0]["confidence"], "candidate")
        self.assertTrue(any("two users" in item["control"] for item in result["coverage"]))
        self.assertTrue(any("low-privilege" in item for item in result["limitations"]))

    def test_sensitive_data_pack_suppresses_site_gate_results(self):
        gate = {"detected": True, "reason": "captive portal"}
        misconfig = {"findings": [], "checks": {"site_gate": gate}}
        config = {"disclosed_headers": [{"header": "Server", "value": "example"}]}
        with patch.object(sensitive_data_audit.misconfig_scanner, "run", return_value=misconfig), \
                patch.object(sensitive_data_audit.secscan, "run", return_value=config):
            result = sensitive_data_audit.run("https://example.test")

        self.assertEqual(result["site_gate"], gate)
        self.assertEqual(result["coverage"][0]["status"], "suppressed")
        self.assertEqual(result["observations"][0]["confidence"], "observed")
        self.assertNotIn("body", result["observations"][0])

    def test_runner_exposes_all_validation_packs(self):
        expected = {"injection_audit", "privilege_audit", "sensitive_data_audit"}
        self.assertTrue(expected.issubset(runner.TOOLS))

    def test_pack_pocs_are_evidence_only_and_do_not_promote_candidates(self):
        result = {
            "observations": [{
                "title": "Adjacent object response",
                "severity": "HIGH",
                "confidence": "candidate",
                "evidence": "HTTP 200 differed from baseline",
                "validation": "Compare with two authorized accounts.",
            }]
        }
        pocs = poc.build_pocs("privilege_audit", "https://example.test/?id=1", result)

        self.assertEqual(len(pocs), 1)
        self.assertTrue(pocs[0]["evidence_only"])
        self.assertEqual(pocs[0]["confidence"], "candidate")
        self.assertIn("two authorized accounts", pocs[0]["validation"])

    def test_direct_header_observation_is_not_called_exploitable(self):
        result = {
            "observations": [{
                "title": "Server header is disclosed",
                "severity": "INFO",
                "confidence": "observed",
                "evidence": "Server: example",
                "validation": "Assess material impact.",
            }]
        }
        pocs = poc.build_pocs("sensitive_data_audit", "https://example.test", result)

        self.assertEqual(pocs[0]["confidence"], "observed")
        self.assertNotEqual(pocs[0]["confidence"], "confirmed")

    def test_frontend_always_exposes_evidence_or_validation_plan(self):
        app_js = (Path(__file__).parent / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("validation-observation-poc", app_js)
        self.assertIn("validation-plan-btn", app_js)
        self.assertIn("This is a test procedure, not proof of a vulnerability.", app_js)


if __name__ == "__main__":
    unittest.main()
