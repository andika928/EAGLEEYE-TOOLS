#!/usr/bin/env python3
"""Sensitive-data exposure reconnaissance with evidence suppression."""
from __future__ import annotations

import misconfig_scanner
import secscan


def run(url, timeout=8.0):
    misconfig = misconfig_scanner.run(url, timeout=timeout)
    config = secscan.run(url, timeout=max(timeout, 10.0))
    observations = []

    for item in misconfig.get("findings", []):
        observations.append({
            "category": "Sensitive data exposure",
            "title": item.get("type", "Exposure observation"),
            "severity": item.get("severity", "MEDIUM"),
            "confidence": "evidence_filtered",
            "evidence": item.get("detail", ""),
            "validation": "Review the sanitized evidence and confirm that exposed content is sensitive and in scope.",
        })
    for item in config.get("disclosed_headers", []):
        observations.append({
            "category": "Technology disclosure",
            "title": f"{item.get('header', 'Response header')} is disclosed",
            "severity": "INFO",
            "confidence": "observed",
            "evidence": str(item.get("value", ""))[:160],
            "validation": "Determine whether the disclosed version materially increases exploitability.",
        })

    gate = misconfig.get("checks", {}).get("site_gate") or config.get("site_gate")
    return {
        "tool": "sensitive_data_audit",
        "target": url,
        "assessment_class": "Sensitive Data Exposure",
        "safety_profile": "bounded public GET/OPTIONS requests with soft-404 and interception filtering",
        "validation_state": "review_required",
        "observations": observations,
        "coverage": [
            {"control": "Known sensitive-file exposure", "status": "suppressed" if gate else "tested"},
            {"control": "Directory listing", "status": "suppressed" if gate else "tested"},
            {"control": "Verbose error disclosure", "status": "suppressed" if gate else "tested"},
            {"control": "Response-header disclosure", "status": "tested"},
            {"control": "Authenticated records and tenant isolation", "status": "not_tested"},
            {"control": "Logs, backups outside web root, and database contents", "status": "not_tested"},
        ],
        "limitations": [
            "Response bodies and secret values are not returned in the normalized observation list.",
            "Site-gate, captive-portal, and soft-404 responses are suppressed.",
            "No absence-of-exposure conclusion is made for untested authenticated or internal systems.",
        ],
        "site_gate": gate,
        "raw_modules": {"misconfig": misconfig, "security_config": config},
    }
