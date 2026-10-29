#!/usr/bin/env python3
"""Evidence-led injection surface assessment for authorized targets.

Combines the existing differential SQL injection and reflected-XSS probes.
Every result remains a candidate until a human validates context and impact.
"""
from __future__ import annotations

import sqli_scanner
import xss_scanner


def run(url, timeout=8.0, sleep=3):
    sql = sqli_scanner.run(url, timeout=timeout, sleep=sleep)
    xss = xss_scanner.run(url, timeout=timeout)
    observations = []

    for item in sql.get("findings", []):
        observations.append({
            "category": "SQL injection",
            "title": f"{item.get('type', 'differential')} candidate in {item.get('param', 'parameter')}",
            "severity": "HIGH",
            "confidence": "candidate",
            "evidence": item.get("detail", "Response differential observed"),
            "validation": "Reproduce in an isolated authorized environment and confirm database influence.",
        })
    for item in xss.get("findings", []):
        raw = item.get("confidence") == "raw"
        observations.append({
            "category": "Reflected input",
            "title": f"Reflected marker in {item.get('param', 'parameter')}",
            "severity": "HIGH" if raw else "MEDIUM",
            "confidence": "high" if raw else "candidate",
            "evidence": f"Payload class {item.get('payload', 'marker')}; reflection={item.get('confidence', 'unknown')}",
            "validation": "Inspect the exact HTML/JavaScript context; reflection alone does not prove script execution.",
        })

    params = sorted(set((sql.get("params") or []) + (xss.get("params") or [])))
    return {
        "tool": "injection_audit",
        "target": url,
        "assessment_class": "Injection Attacks",
        "safety_profile": "bounded differential GET probes; no data modification",
        "validation_state": "review_required",
        "observations": observations,
        "coverage": [
            {"control": "SQL error differential", "status": "tested" if params else "not_tested"},
            {"control": "SQL boolean differential", "status": "tested" if params else "not_tested"},
            {"control": "SQL timing differential", "status": "tested" if params else "not_tested"},
            {"control": "Reflected input context", "status": "tested" if params else "not_tested"},
            {"control": "Stored injection and second-order flows", "status": "not_tested"},
            {"control": "OS/LDAP/template injection", "status": "not_tested"},
        ],
        "limitations": [
            "No state-changing requests are sent.",
            "No finding is considered exploitable without manual confirmation.",
            "Authenticated and stored-input workflows require a dedicated test account and test plan.",
        ],
        "raw_modules": {"sql": sql, "xss": xss},
    }
