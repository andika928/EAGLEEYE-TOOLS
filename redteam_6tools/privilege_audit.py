#!/usr/bin/env python3
"""Privilege-boundary reconnaissance with explicit coverage gaps.

The module combines adjacent-object response comparison with passive session
inspection. It never labels privilege escalation confirmed without two-role
authorization evidence.
"""
from __future__ import annotations

import auth_scanner
import idor_scanner


def run(url, timeout=8.0, span=2):
    auth = auth_scanner.run(url, timeout=timeout)
    idor = idor_scanner.run(url, timeout=timeout, span=span)
    observations = []

    for item in idor.get("findings", []):
        observations.append({
            "category": "Object-level authorization",
            "title": f"Adjacent object {item.get('id')} returned a distinct response",
            "severity": "HIGH",
            "confidence": "candidate",
            "evidence": f"HTTP {item.get('status')} differed from the baseline object response",
            "validation": "Compare the same object with two authorized accounts; public objects are not IDOR.",
        })
    for item in auth.get("findings", []):
        observations.append({
            "category": "Session boundary",
            "title": item.get("type", "Session-control observation"),
            "severity": item.get("severity", "MEDIUM"),
            "confidence": "configuration_observation",
            "evidence": item.get("detail", ""),
            "validation": "Validate whether the observed control affects an authenticated privilege boundary.",
        })

    idor_tested = not bool(idor.get("error"))
    return {
        "tool": "privilege_audit",
        "target": url,
        "assessment_class": "Privilege Escalation",
        "safety_profile": "read-only adjacent-object comparison and passive session inspection",
        "validation_state": "two_role_validation_required",
        "observations": observations,
        "coverage": [
            {"control": "Adjacent object-reference behavior", "status": "tested" if idor_tested else "not_tested"},
            {"control": "Cookie and token posture", "status": "tested"},
            {"control": "Horizontal authorization with two users", "status": "not_tested"},
            {"control": "Vertical authorization with user/admin roles", "status": "not_tested"},
            {"control": "Function-level authorization and workflow bypass", "status": "not_tested"},
        ],
        "limitations": [
            "Distinct adjacent responses are not proof of unauthorized access.",
            "Confirmed privilege escalation requires controlled low-privilege and high-privilege accounts.",
            "No credentials, role changes, or write operations are attempted.",
        ],
        "raw_modules": {"auth": auth, "idor": idor},
    }
