#!/usr/bin/env python3
"""Tool 13 - Broken authentication & session management (detect-only).

Non-destructive: inspects cookie flags, JWT headers (alg), and whether a
password form is served over TLS. It does NOT attempt logins or brute force.
"""
import argparse
import base64
import json
import re
import sys

from common import banner, http_request_ex

JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*')


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwt_header(token):
    try:
        return json.loads(_b64url_decode(token.split(".")[0]).decode("utf-8", "replace"))
    except Exception:
        return None


def run(url, timeout=8.0):
    if "://" not in url:
        url = "http://" + url
    status, headers, body, final_url = http_request_ex(url, timeout=timeout)
    findings = []

    # 1) cookie flags
    cookies = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            name = v.split("=", 1)[0]
            missing = []
            if "secure" not in v.lower():
                missing.append("Secure")
            if "httponly" not in v.lower():
                missing.append("HttpOnly")
            if "samesite" not in v.lower():
                missing.append("SameSite")
            cookies.append({"name": name, "missing": missing})
            if missing:
                findings.append({"type": "Session cookie missing flags", "severity": "MEDIUM",
                                 "detail": f"{name}: missing {', '.join(missing)}"})

    # 2) JWT analysis (cookies / headers / body)
    blobs = [body[:300000]] + [v for _, v in headers.items()]
    jwts = set()
    for b in blobs:
        for m in JWT_RE.finditer(b):
            jwts.add(m.group())
    jwt_info = []
    for t in list(jwts)[:10]:
        hdr = _jwt_header(t)
        if not hdr:
            continue
        jwt_info.append({"alg": hdr.get("alg"), "typ": hdr.get("typ")})
        if str(hdr.get("alg", "")).lower() == "none":
            findings.append({"type": "JWT uses alg=none", "severity": "HIGH",
                             "detail": "token header declares alg 'none' (signature not verified)"})

    # 3) password form served over plaintext
    low = body.lower().replace("'", '"')
    password_form = ("<input" in low and 'type="password"' in low)
    if password_form:
        is_https = final_url.startswith("https://")
        if not is_https:
            findings.append({"type": "Login form served over HTTP", "severity": "HIGH",
                             "detail": "password field on a non-TLS page"})

    return {"tool": "auth_scanner", "target": url, "status": status,
            "final_url": final_url, "cookies": cookies, "jwt": jwt_info,
            "password_form": password_form, "findings": findings}


def main():
    banner("AuthScanner")
    ap = argparse.ArgumentParser(description="auth/session checks (detect-only)")
    ap.add_argument("url", help="target URL, e.g. https://host/login")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    result = run(args.url, args.timeout)
    print(f"[*] target : {result['target']}")
    print(f"[*] final  : {result['final_url']}")
    if result["cookies"]:
        print("[*] cookies:")
        for c in result["cookies"]:
            print(f"    - {c['name']}: missing {c['missing'] or 'none'}")
    if result["jwt"]:
        print(f"[*] JWT    : {result['jwt']}")
    if not result["findings"]:
        print("\n[-] no auth/session issues detected")
    else:
        print(f"\n[+] {len(result['findings'])} finding(s):")
        for f in result["findings"]:
            print(f"  [{f['severity']}] {f['type']} - {f['detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
