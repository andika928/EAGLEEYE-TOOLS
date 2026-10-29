#!/usr/bin/env python3
"""Tool 7/9 - CSRF protection detector.

Fetches a page, parses HTML forms, and reports state-changing (POST) forms
that lack a CSRF token. Also reports the SameSite posture of Set-Cookie
headers and whether a global anti-CSRF <meta> tag is present.

A "missing token" is a CANDIDATE: the endpoint may still be protected by
SameSite=Strict, custom request headers, or a double-submit cookie.
"""
import argparse
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin

from common import banner, http_request

TOKEN_KEYS = ("csrf", "token", "nonce", "xsrf", "authenticity")


def is_token_name(name):
    n = (name or "").lower()
    return any(k in n for k in TOKEN_KEYS)


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.meta_tokens = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").strip().lower(),
                "inputs": [],
                "has_csrf": False,
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            name = (a.get("name") or "").lower()
            itype = (a.get("type") or "text").strip().lower()
            if itype == "hidden":
                self._form["inputs"].append({"name": name, "type": itype})
                if is_token_name(name):
                    self._form["has_csrf"] = True
        elif tag == "meta":
            name = (a.get("name") or a.get("http-equiv") or "").lower()
            if is_token_name(name):
                self.meta_tokens.append(name)


def run(url, timeout=10.0):
    if "://" not in url:
        url = "http://" + url
    st, headers, body = http_request(url, timeout=timeout)

    parser = _FormParser()
    try:
        parser.feed(body)
    except Exception:
        pass

    post_forms = [f for f in parser.forms if f["method"] == "post"]
    findings = []
    for f in post_forms:
        if not f["has_csrf"]:
            findings.append({
                "action": urljoin(url, f["action"]) if f["action"] else url,
                "method": "post",
                "has_token": False,
            })

    cookies = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            name = v.split("=", 1)[0]
            low = v.lower()
            if "samesite=none" in low:
                samesite = "none"
            elif "samesite=strict" in low or "samesite=lax" in low:
                samesite = "set"
            else:
                samesite = "missing"
            cookies.append({"cookie": name, "samesite": samesite})

    return {
        "tool": "csrf_scanner",
        "target": url,
        "status": st,
        "forms_found": len(parser.forms),
        "post_forms": len(post_forms),
        "meta_csrf": bool(parser.meta_tokens),
        "findings": findings,
        "cookies": cookies,
    }


def main():
    banner("CSRFScanner")
    ap = argparse.ArgumentParser(description="detect missing CSRF protection")
    ap.add_argument("url", help="URL of a page with forms, e.g. https://host/login")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    try:
        result = run(args.url, args.timeout)
    except RuntimeError as exc:
        print(f"[!] request failed: {exc}")
        return 1

    print(f"[*] target      : {result['target']}")
    print(f"[*] HTTP status : {result['status']}")
    print(f"[*] forms       : {result['forms_found']} total, {result['post_forms']} POST")
    print(f"[*] meta CSRF   : {'present' if result['meta_csrf'] else 'absent'}")

    if result["cookies"]:
        print("[*] cookies:")
        for c in result["cookies"]:
            print(f"    - {c['cookie']}: SameSite={c['samesite']}")

    if not result["findings"]:
        print("\n[-] no POST forms missing a CSRF token")
    else:
        print(f"\n[+] {len(result['findings'])} POST form(s) missing a CSRF token:")
        for f in result["findings"]:
            print(f"  [CANDIDATE] {f['method'].upper()} {f['action']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
