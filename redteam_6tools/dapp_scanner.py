#!/usr/bin/env python3
"""Tool 14 - Decentralized application (dApp) misconfiguration recon.

Detects web3 markers, exposed RPC/node-provider endpoints, and hardcoded
private-key / mnemonic material in the page and its JS bundles.
"""
import argparse
import re
import sys
from urllib.parse import urljoin

from common import banner, http_request_ex

WEB3_MARKERS = ["window.ethereum", "web3", "ethers", "walletconnect", "wagmi",
                "viem", "solana", "metamask", "web3modal", "rainbowkit"]
RPC_RE = re.compile(r'https://[a-z0-9.-]*(?:infura\.io|alchemy\.com|quiknode\.pro|'
                    r'ankr\.com|moralis|getblock\.io)[^\s"\'<>]*', re.I)
KEYWORD_RE = re.compile(r'(?i)(private[_-]?key|mnemonic|seed[_-]?phrase)["\']?\s*[:=]\s*'
                        r'["\']([A-Za-z0-9 _./+-]{16,})')
HEXKEY_RE = re.compile(r'\b0x[a-fA-F0-9]{64}\b')
JS_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)


def run(url, timeout=8.0, max_scripts=8):
    if "://" not in url:
        url = "http://" + url
    status, _headers, body, final_url = http_request_ex(url, timeout=timeout)

    blobs = {"(page)": body}
    for s in JS_RE.findall(body)[:max_scripts]:
        try:
            _, _, b, _ = http_request_ex(urljoin(url, s), timeout=timeout)
            blobs[s] = b
        except RuntimeError:
            continue

    markers = set()
    rpc, keywords, hexkeys = set(), set(), set()
    for b in blobs.values():
        low = b.lower()
        for m in WEB3_MARKERS:
            if m in low:
                markers.add(m)
        for m in RPC_RE.finditer(b):
            rpc.add(m.group())
        for m in KEYWORD_RE.finditer(b):
            keywords.add(m.group(0)[:90])
        for m in HEXKEY_RE.finditer(b):
            hexkeys.add(m.group())
    markers = sorted(markers)

    findings = []
    if keywords:
        findings.append({"type": "Hardcoded private key / mnemonic material",
                         "severity": "HIGH", "detail": "; ".join(sorted(keywords)[:3])})
    if hexkeys:
        findings.append({"type": "64-hex string (possible raw private key)",
                         "severity": "HIGH", "detail": "; ".join(sorted(hexkeys)[:3])})
    if rpc:
        findings.append({"type": "Exposed RPC/node-provider endpoints",
                         "severity": "MEDIUM", "detail": "; ".join(sorted(rpc)[:5])})

    return {"tool": "dapp_scanner", "target": url, "status": status,
            "is_dapp": bool(markers), "web3_markers": markers,
            "scripts_scanned": list(blobs.keys()),
            "rpc_endpoints": sorted(rpc), "findings": findings}


def main():
    banner("DAppScanner")
    ap = argparse.ArgumentParser(description="dApp misconfiguration recon")
    ap.add_argument("url", help="target URL, e.g. https://dapp.example")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    result = run(args.url, args.timeout)
    print(f"[*] target : {result['target']}")
    print(f"[*] is dApp: {result['is_dapp']}  markers={result['web3_markers']}")
    print(f"[*] scripts: {len(result['scripts_scanned'])} scanned")
    if not result["findings"]:
        print("\n[-] no dApp misconfigurations detected")
    else:
        print(f"\n[+] {len(result['findings'])} finding(s):")
        for f in result["findings"]:
            print(f"  [{f['severity']}] {f['type']} - {f['detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
