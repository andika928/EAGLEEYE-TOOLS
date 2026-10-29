#!/usr/bin/env python3
"""Tool 6/6 - Web security configuration analyzer.

Checks HTTP security headers, cookie flags, server info disclosure, transport
encryption, and the TLS certificate for HTTPS targets. Reports objective facts.

CLI:
    python secscan.py https://example.com

Programmatic:
    import secscan
    result = secscan.run("https://example.com")
"""
import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

from common import banner, http_request_ex

SECURITY_HEADERS = {
    "Content-Security-Policy": "mitigates XSS and data injection",
    "Strict-Transport-Security": "forces HTTPS (HSTS)",
    "X-Content-Type-Options": "prevents MIME type sniffing",
    "X-Frame-Options": "mitigates clickjacking",
    "Referrer-Policy": "controls referrer information leakage",
    "Permissions-Policy": "restricts browser features",
}

INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                "X-AspNetMvc-Version", "X-Generator", "X-Runtime"]


def check_tls(host, port, timeout=6.0):
    """Return the peer certificate dict, or None on failure."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


def run(url, timeout=10.0):
    """Analyze a URL's security config and return a JSON-serializable dict.

    Raises RuntimeError if the target cannot be reached over HTTP(S).
    """
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)

    # Use the FINAL url after redirects so transport/TLS reflect what actually
    # served the response (avoids a false "plaintext" finding on http->https
    # redirects).
    status, headers, body, final_url = http_request_ex(url, timeout=timeout)
    final_parsed = urlparse(final_url) if final_url else parsed
    transport = (final_parsed.scheme or parsed.scheme or "http").lower()
    redirected = bool(final_url) and final_url.rstrip("/") != url.rstrip("/")
    upgraded_to_https = parsed.scheme == "http" and transport == "https"
    lower = {k.lower(): v for k, v in headers.items()}

    # Site gate / ISP block detection
    target_host = (parsed.hostname or "").lower()
    final_host = (final_parsed.hostname or "").lower()
    site_gate = None
    if final_host and final_host != target_host:
        if not (final_host.endswith("." + target_host) or target_host.endswith("." + final_host)):
            site_gate = {
                "detected": True,
                "type": "Cross-Domain Interception / ISP Blockpage",
                "gate_host": final_host,
                "gate_url": final_url,
                "reason": f"Traffic redirected to third-party domain '{final_host}'"
            }

    missing = []
    for hdr, why in SECURITY_HEADERS.items():
        if hdr.lower() not in lower:
            missing.append({"header": hdr, "why": why})

    disclosed = []
    for h in INFO_HEADERS:
        if h.lower() in lower:
            disclosed.append({"header": h, "value": lower[h.lower()]})

    cookies = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            name = v.split("=", 1)[0] if "=" in v else "?"
            missing_flags = []
            if "httponly" not in v.lower():
                missing_flags.append("HttpOnly")
            if "secure" not in v.lower():
                missing_flags.append("Secure")
            if "samesite" not in v.lower():
                missing_flags.append("SameSite")
            cookies.append({"name": name, "missing_flags": missing_flags})

    tls = None
    if transport == "https":
        tls_host = final_parsed.hostname or parsed.hostname
        port = final_parsed.port or 443
        cert = check_tls(tls_host, port, timeout=timeout)
        if cert:
            tls = {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notAfter": cert.get("notAfter"),
            }

    findings_count = (
        len(missing)
        + len(disclosed)
        + sum(1 for c in cookies if c["missing_flags"])
        + (0 if transport == "https" else 1)
    )

    return {
        "tool": "secscan",
        "target": url,
        "final_url": final_url,
        "redirected": redirected,
        "upgraded_to_https": upgraded_to_https,
        "status": status,
        "response_headers": {k: v for k, v in headers.items() if k.lower() in {"content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "content-type"}},
        "missing_headers": missing,
        "disclosed_headers": disclosed,
        "cookies": cookies,
        "transport": transport,
        "tls": tls,
        "site_gate": site_gate,
        "findings_count": findings_count,
    }


def main():
    banner("SecScan")
    ap = argparse.ArgumentParser(description="web security config analyzer")
    ap.add_argument("url", help="target URL, e.g. https://example.com")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="request timeout in seconds (default: 10)")
    args = ap.parse_args()

    try:
        result = run(args.url, args.timeout)
    except RuntimeError as exc:
        print(f"[!] request failed: {exc}")
        return 1

    print(f"\n[=] HTTP status: {result['status']}")

    print("\n[=] Security headers")
    for m in result["missing_headers"]:
        print(f"  [MISSING] {m['header']}  ({m['why']})")

    print("\n[=] Information disclosure")
    if result["disclosed_headers"]:
        for d in result["disclosed_headers"]:
            print(f"  [DISCLOSED] {d['header']}: {d['value'][:70]}")
    else:
        print("  [OK] no server tech-disclosure headers")

    print("\n[=] Cookies")
    if not result["cookies"]:
        print("  [OK] no cookies set")
    else:
        for c in result["cookies"]:
            if c["missing_flags"]:
                print(f"  [WEAK] {c['name']}: missing {', '.join(c['missing_flags'])}")
            else:
                print(f"  [OK] {c['name']}")

    if result["transport"] == "https":
        print("\n[=] TLS certificate")
        if result["tls"]:
            print(f"  subject : {result['tls']['subject']}")
            print(f"  issuer  : {result['tls']['issuer']}")
            if result["tls"]["notAfter"]:
                print(f"  expires : {result['tls']['notAfter']}")
        else:
            print("  [!] could not retrieve certificate")
    else:
        print("\n[=] Transport")
        print("  [WARN] site is served over plain HTTP (no transport encryption)")

    if result.get("redirected"):
        print("\n[=] Redirect")
        print(f"  {result['target']} -> {result['final_url']}")
        if result.get("upgraded_to_https"):
            print("  [i] http was upgraded to https (effective transport is encrypted)")

    print(f"\n[=] Summary: {result['findings_count']} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
