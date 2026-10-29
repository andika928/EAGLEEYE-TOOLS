#!/usr/bin/env python3
"""POC / reproduction builder.

Turns each scanner result into reproducible evidence, labelled either
CONFIRMED (objective, independent of heuristics) or CANDIDATE (heuristic —
manual verification required). This is what separates a reportable bug-bounty
finding from a guess.

Every item has: title, confidence, severity, poc (ready-to-run command),
evidence (what a successful reproduction looks like).
"""


def _item(title, confidence, severity, poc, evidence=""):
    return {"title": title, "confidence": confidence, "severity": severity,
            "poc": poc, "evidence": evidence}


def _curl(url, method="GET", extra=""):
    return f'curl -sS -i -X {method} "{url}"{extra}'


def _display_arg(value):
    """Return a non-breaking, single-line quoted argument for displayed PoCs."""
    cleaned = str(value or "").replace("\r", "").replace("\n", "").replace('"', "%22")
    return f'"{cleaned}"'


HEURISTIC = {
    "sqli_scanner": "Confirm with SLEEP(0) vs SLEEP(5) timing, then sqlmap --technique=T (authorized only).",
    "xss_scanner": "Open the URL in a browser; script execution proves it (check the HTML context).",
    "csrf_scanner": "Replay the POST from another origin without the token; if it succeeds, CSRF is real.",
    "idor_scanner": "Repeat with two accounts (A's session on B's object id); cross-account data = real IDOR.",
    "dapp_scanner": "Confirm the key/RPC is live and privileged before reporting.",
}


def build_pocs(tool, target, result):
    r = result or {}
    pocs = []

    if tool in ("injection_audit", "privilege_audit", "sensitive_data_audit"):
        target_arg = _display_arg(target)
        replay = {
            "injection_audit": f"python sqli_scanner.py {target_arg}\npython xss_scanner.py {target_arg}",
            "privilege_audit": f"python idor_scanner.py {target_arg}",
            "sensitive_data_audit": f"python misconfig_scanner.py {target_arg}",
        }[tool]
        for observation in r.get("observations", []):
            confidence = str(observation.get("confidence") or "candidate").lower()
            # Directly observed headers may be called observed. Injection and
            # authorization anomalies remain candidates until impact is proven.
            proof_state = "observed" if confidence == "observed" else "candidate"
            pocs.append({
                "title": observation.get("title") or observation.get("category") or "Evidence observation",
                "confidence": proof_state,
                "severity": str(observation.get("severity") or "info").lower(),
                "poc": replay,
                "evidence": observation.get("evidence") or "No normalized evidence was recorded.",
                "validation": observation.get("validation") or "Independent manual validation is required.",
                "evidence_only": True,
            })
        return pocs

    if tool == "portscanner":
        for o in r.get("open_ports", []):
            pocs.append(_item(f"Open port {o['port']}/tcp", "confirmed", "info",
                              f'nc -vz {target} {o["port"]}', "TCP connect succeeds"))

    elif tool == "subenum":
        for s in r.get("subdomains", []):
            pocs.append(_item(f"Subdomain {s['host']}", "confirmed", "info",
                              f'dig +short {s["host"]}',
                              f'resolves to {", ".join(s.get("ips", []))}'))

    elif tool == "dirbust":
        if r.get("site_gate"):
            sg = r["site_gate"]
            pocs.append(_item(
                f"Site Gate / Interception Active ({sg.get('type')})",
                "confirmed", "info",
                _curl(target, extra=" -I"),
                f"Traffic redirected to {sg.get('gate_host')} ({sg.get('gate_url')})"
            ))
        for p in r.get("paths", []):
            url = target.rstrip("/") + p["path"]
            pocs.append(_item(f"{p['status']} {p['path']}", "confirmed", "info",
                              _curl(url), f"HTTP {p['status']}, length {p['length']}"))

    elif tool == "secscan":
        for m in r.get("missing_headers", []):
            pocs.append(_item(f"Missing {m['header']}", "confirmed", "low",
                              f'{_curl(target, extra=" -I")} | grep -i "{m["header"]}"',
                              "empty output = header absent"))
        for d in r.get("disclosed_headers", []):
            pocs.append(_item(f"Discloses {d['header']}", "confirmed", "info",
                              f'{_curl(target, extra=" -I")} | grep -i "{d["header"]}"',
                              d.get("value", "")))
        if r.get("transport") and r["transport"] != "https":
            pocs.append(_item("No transport encryption", "confirmed", "medium",
                              _curl(target), "served over plain HTTP"))

    elif tool == "ssrf_scanner":
        for f in r.get("findings", []):
            pocs.append(_item(f"SSRF via '{f['param']}'", "confirmed", "high",
                              _curl(target),
                              f"target fetched the callback {f.get('callback', '')}"))

    elif tool == "misconfig_scanner":
        if r.get("checks", {}).get("site_gate"):
            sg = r["checks"]["site_gate"]
            pocs.append(_item(
                f"Site Gate / Interception Active ({sg.get('type')})",
                "confirmed", "info",
                _curl(target, extra=" -I"),
                f"Traffic redirected to {sg.get('gate_host')} ({sg.get('gate_url')}) · {sg.get('reason')}"
            ))
        for f in r.get("findings", []):
            t = f.get("type", "")
            if "Site Gate" in t:
                continue
            elif "Exposed sensitive files" in t:
                for e in (r.get("checks", {}).get("exposed_files") or []):
                    url = target.rstrip("/") + "/" + e["path"]
                    evidence = e.get("evidence") or f"HTTP {e['status']}, length {e['length']}"
                    pocs.append(_item(f"Exposed {e['path']}", "confirmed", "high",
                                      _curl(url), evidence))
            elif "CORS reflects" in t:
                pocs.append(_item("CORS reflects arbitrary Origin", "confirmed", "high",
                                  _curl(target, extra=' -H "Origin: https://evil.example.com"'),
                                  "Access-Control-Allow-Origin echoes the attacker origin"))
            elif "TRACE" in t:
                pocs.append(_item("HTTP TRACE enabled", "confirmed", "medium",
                                  _curl(target, method="TRACE"), "200 with the request echoed"))
            elif "Directory listing" in t:
                for d in (r.get("checks", {}).get("directory_listing") or []):
                    pocs.append(_item(f"Directory listing {d}", "confirmed", "medium",
                                      _curl(target.rstrip("/") + d), "'Index of /' in body"))
            else:
                pocs.append(_item(t, "confirmed", f.get("severity", "medium"),
                                  _curl(target), f.get("detail", "")))

    elif tool == "auth_scanner":
        for f in r.get("findings", []):
            pocs.append(_item(f.get("type", ""), "confirmed", f.get("severity", "medium"),
                              f'{_curl(target, extra=" -I")}   # inspect Set-Cookie / body',
                              f.get("detail", "")))

    elif tool in ("apk_recon", "ipa_recon"):
        script = "apk_recon.py" if tool == "apk_recon" else "ipa_recon.py"
        pocs.append(_item("Static artifact facts", "confirmed", "info",
                          f'python {script} "{target}"', "re-run the analyzer to reproduce"))

    else:
        conf = "candidate"
        verify = HEURISTIC.get(tool, "Verify manually before reporting.")
        for f in r.get("findings", []):
            label = (f.get("type") or f.get("param") or f.get("action")
                     or (f"id={f['id']}" if "id" in f else "finding"))
            pocs.append(_item(str(label), conf, f.get("severity", "medium"),
                              _curl(target), f.get("detail") or verify))

    return pocs
