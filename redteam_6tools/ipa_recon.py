#!/usr/bin/env python3
"""Tool 11 - iOS IPA static recon (authorized targets only).

Unzips a local .ipa, parses Payload/*.app/Info.plist (binary or XML, via the
standard-library plistlib), and reports:
  - bundle id / name / version / minimum OS
  - custom URL schemes (CFBundleURLTypes)
  - App Transport Security posture (NSAllowsArbitraryLoads)
  - embedded URLs and hardcoded-secret candidates from the main executable
"""
import argparse
import plistlib
import re
import sys
import zipfile
from pathlib import Path

URL_RE = re.compile(rb'https?://[^\s"\'<>\\]{5,}')
SECRET_RE = re.compile(
    rb'(?i)\b(api[_-]?key|secret|client[_-]?secret|token|password|access[_-]?key)\b'
    rb'[^A-Za-z0-9]{0,3}[A-Za-z0-9_\-./+=]{8,}'
)


def _strings(blob, min_len=4):
    out = []
    cur = bytearray()
    for b in blob:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(bytes(cur))
    return out


def run(ipa_path, max_urls=200, max_secrets=100):
    ipa = Path(ipa_path)
    if not ipa.is_file():
        return {"tool": "ipa_recon", "target": str(ipa),
                "error": f"file not found: {ipa_path}"}

    try:
        z = zipfile.ZipFile(ipa)
    except (zipfile.BadZipFile, OSError) as exc:
        return {"tool": "ipa_recon", "target": str(ipa),
                "error": f"not a valid IPA (zip): {exc}"}

    with z:
        names = z.namelist()
        plist_name = next((n for n in names
                           if n.startswith("Payload/") and n.endswith(".app/Info.plist")), None)
        if plist_name is None:
            plist_name = next((n for n in names if n.endswith("Info.plist")), None)

        plist = {}
        plist_error = None
        if plist_name:
            try:
                plist = plistlib.loads(z.read(plist_name))
                if not isinstance(plist, dict):
                    plist = {}
            except Exception as exc:
                plist = {}
                plist_error = str(exc)

        app_dir = plist_name.rsplit("/", 1)[0] if plist_name else None
        exe_name = plist.get("CFBundleExecutable") if plist else None
        exec_blob = b""
        if app_dir and exe_name:
            exe_path = f"{app_dir}/{exe_name}"
            if exe_path in names:
                exec_blob = z.read(exe_path)

    url_schemes = []
    for ut in (plist.get("CFBundleURLTypes") or []):
        if isinstance(ut, dict):
            for s in (ut.get("CFBundleURLSchemes") or []):
                url_schemes.append(s)
    ats = plist.get("NSAppTransportSecurity") or {}
    if not isinstance(ats, dict):
        ats = {}

    strs = _strings(exec_blob)
    urls = set()
    secrets = set()
    for s in strs:
        for m in URL_RE.finditer(s):
            urls.add(m.group().decode().rstrip('.,;)]}'))
        for m in SECRET_RE.finditer(s):
            secrets.add(m.group().decode())

    return {
        "tool": "ipa_recon",
        "target": str(ipa),
        "file_size": ipa.stat().st_size,
        "zip_entries": len(names),
        "bundle_id": plist.get("CFBundleIdentifier"),
        "name": plist.get("CFBundleDisplayName") or plist.get("CFBundleName"),
        "version": plist.get("CFBundleShortVersionString"),
        "build": plist.get("CFBundleVersion"),
        "min_os": plist.get("MinimumOSVersion"),
        "executable": exe_name,
        "url_schemes": url_schemes,
        "ats_allow_arbitrary_loads": ats.get("NSAllowsArbitraryLoads"),
        "urls": sorted(urls)[:max_urls],
        "secret_candidates": sorted(secrets)[:max_secrets],
        "plist_error": plist_error,
    }


def main():
    print("=" * 62)
    print("  IPA Recon  v1.0")
    print("=" * 62)

    ap = argparse.ArgumentParser(description="static recon of a local iOS IPA")
    ap.add_argument("ipa", help="path to the .ipa file")
    ap.add_argument("--max-urls", type=int, default=200)
    ap.add_argument("--max-secrets", type=int, default=100)
    args = ap.parse_args()

    result = run(args.ipa, args.max_urls, args.max_secrets)

    if result.get("error"):
        print(f"[!] {result['error']}")
        return 1

    print(f"[*] target : {result['target']}")
    print(f"[*] bundle : {result['bundle_id']}  ({result['name']})")
    print(f"[*] version: {result['version']} (build {result['build']})  minOS {result['min_os']}")
    print(f"[*] size   : {result['file_size']} bytes, {result['zip_entries']} entries")

    print(f"\n[=] URL schemes ({len(result['url_schemes'])})")
    for s in result["url_schemes"]:
        print(f"  - {s}")

    print(f"\n[=] ATS allow arbitrary loads: {result['ats_allow_arbitrary_loads']}")

    print(f"\n[=] Embedded URLs ({len(result['urls'])})")
    for u in result["urls"]:
        print(f"  - {u}")

    print(f"\n[=] Secret candidates ({len(result['secret_candidates'])})")
    for s in result["secret_candidates"]:
        print(f"  - {s}")

    if result.get("plist_error"):
        print(f"\n[!] Info.plist parse warning: {result['plist_error']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
