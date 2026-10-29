#!/usr/bin/env python3
"""Programmatic runner for the 9-tool toolkit.

Imports the tool modules directly (no subprocess, no pipes) and dispatches to
their structured `run()` functions, returning JSON-serializable dicts. This is
what the dashboard backend uses to execute scans.

Usage:
    import runner
    result = runner.run_tool("portscanner", "example.com")
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure sibling modules (common.py and the tool scripts) are importable.
_TOOL_DIR = Path(__file__).resolve().parent
if str(_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOL_DIR))

import portscanner  # noqa: E402
import subenum  # noqa: E402
import dirbust  # noqa: E402
import sqli_scanner  # noqa: E402
import xss_scanner  # noqa: E402
import secscan  # noqa: E402
import csrf_scanner  # noqa: E402
import ssrf_scanner  # noqa: E402
import idor_scanner  # noqa: E402
import apk_recon  # noqa: E402
import ipa_recon  # noqa: E402
import app_store_recon  # noqa: E402
import misconfig_scanner  # noqa: E402
import auth_scanner  # noqa: E402
import dapp_scanner  # noqa: E402
import nuclei_engine  # noqa: E402
import injection_audit  # noqa: E402
import privilege_audit  # noqa: E402
import sensitive_data_audit  # noqa: E402

TOOLS = {
    "portscanner": portscanner.run,
    "subenum": subenum.run,
    "dirbust": dirbust.run,
    "sqli_scanner": sqli_scanner.run,
    "xss_scanner": xss_scanner.run,
    "secscan": secscan.run,
    "csrf_scanner": csrf_scanner.run,
    "ssrf_scanner": ssrf_scanner.run,
    "idor_scanner": idor_scanner.run,
    "apk_recon": apk_recon.run,
    "ipa_recon": ipa_recon.run,
    "app_store_recon": app_store_recon.run,
    "misconfig_scanner": misconfig_scanner.run,
    "auth_scanner": auth_scanner.run,
    "dapp_scanner": dapp_scanner.run,
    "nuclei_engine": nuclei_engine.run,
    "surface_recon": nuclei_engine.run_automated_surface_recon,
    "injection_audit": injection_audit.run,
    "privilege_audit": privilege_audit.run,
    "sensitive_data_audit": sensitive_data_audit.run,
}

WORDLIST_DIR = _TOOL_DIR / "wordlists"

# Human-friendly metadata for the dashboard UI.
TOOL_LABELS = {
    "portscanner": "Port Scanner",
    "subenum": "Subdomain Enumerator",
    "dirbust": "Directory Brute-Forcer",
    "sqli_scanner": "SQL Injection Detector",
    "xss_scanner": "Reflected XSS Detector",
    "secscan": "Security Config Analyzer",
    "csrf_scanner": "CSRF Protection Check",
    "ssrf_scanner": "SSRF Detector (OAST)",
    "idor_scanner": "IDOR / Object Enumeration",
    "apk_recon": "Android APK Recon",
    "ipa_recon": "iOS IPA Recon",
    "app_store_recon": "Apple App Store Passive Recon",
    "misconfig_scanner": "Misconfiguration / Data Exposure",
    "auth_scanner": "Auth & Session",
    "dapp_scanner": "dApp Misconfiguration",
    "nuclei_engine": "Custom Nuclei / Nessus Engine",
    "surface_recon": "Automated Surface Recon",
    "injection_audit": "Injection Attack Surface",
    "privilege_audit": "Privilege Boundary Review",
    "sensitive_data_audit": "Sensitive Data Exposure",
}


def run_tool(name: str, target: str, options: dict | None = None):
    """Dispatch one tool and return its structured result dict."""
    options = options or {}
    fn = TOOLS[name]

    if name == "nuclei_engine":
        return fn(target, mode="nuclei", template_ids=options.get("template_ids"))
    if name == "surface_recon":
        return fn(target, options=options)
    if name == "portscanner":
        return fn(target, ports_spec=options.get("ports", "1-1024,3389,8080,8443"),
                  timeout=float(options.get("timeout", 2.0)),
                  threads=int(options.get("threads", 300)),
                  grab=bool(options.get("grab", False)))
    if name == "subenum":
        wl = options.get("wordlist") or str(WORDLIST_DIR / "subdomains.txt")
        return fn(target, wl, threads=int(options.get("threads", 60)),
                  timeout=float(options.get("timeout", 5.0)))
    if name == "dirbust":
        wl = options.get("wordlist") or str(WORDLIST_DIR / "dirs.txt")
        return fn(target, wl, extensions=options.get("extensions", ""),
                  threads=int(options.get("threads", 30)),
                  timeout=float(options.get("timeout", 8.0)))
    if name == "sqli_scanner":
        return fn(target, timeout=float(options.get("timeout", 8.0)),
                  sleep=int(options.get("sleep", 3)))
    if name == "xss_scanner":
        return fn(target, timeout=float(options.get("timeout", 8.0)))
    if name == "secscan":
        return fn(target, timeout=float(options.get("timeout", 10.0)))
    if name == "csrf_scanner":
        return fn(target, timeout=float(options.get("timeout", 10.0)))
    if name == "ssrf_scanner":
        return fn(target, timeout=float(options.get("timeout", 8.0)),
                  callback=options.get("callback"),
                  params=options.get("params"),
                  wait=float(options.get("wait", 1.0)))
    if name == "idor_scanner":
        return fn(target, timeout=float(options.get("timeout", 8.0)),
                  param=options.get("param"), span=int(options.get("span", 3)))
    if name == "apk_recon":
        return fn(target, max_urls=int(options.get("max_urls", 200)),
                  max_secrets=int(options.get("max_secrets", 100)))
    if name == "ipa_recon":
        return fn(target, max_urls=int(options.get("max_urls", 200)),
                  max_secrets=int(options.get("max_secrets", 100)))
    if name == "app_store_recon":
        return fn(target)
    if name in ("misconfig_scanner", "auth_scanner", "dapp_scanner"):
        return fn(target, timeout=float(options.get("timeout", 8.0)))
    if name == "injection_audit":
        return fn(target, timeout=float(options.get("timeout", 8.0)),
                  sleep=min(3, max(1, int(options.get("sleep", 3)))))
    if name == "privilege_audit":
        return fn(target, timeout=float(options.get("timeout", 8.0)), span=2)
    if name == "sensitive_data_audit":
        return fn(target, timeout=float(options.get("timeout", 8.0)))

    raise ValueError(f"unknown tool: {name}")
