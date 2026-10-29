#!/usr/bin/env python3
"""
Lightweight Red Team Security Dashboard Server.
Serves the web UI and exposes REST APIs for running real-time threat assessments.
Uses only Python standard library.
"""

import sys
import os
import re
import json
import socket
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse



# Ensure UTF-8 console output for Windows CLI
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Setup root path
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
sys.path.insert(0, str(BASE_DIR))

from redteam_tool.parser import PRDParser
from redteam_tool.engine import ThreatAnalysisEngine
from redteam_tool.reporter import ReportGenerator


# --- redteam_6tools active scanner integration (direct import, no subprocess) ---
TOOLS_DIR = BASE_DIR / "redteam_6tools"
sys.path.insert(0, str(TOOLS_DIR))

try:
    import runner as _rt_tools  # noqa: F401
    from common import http_request as _tools_http  # noqa: F401
    import poc as _rt_poc  # noqa: F401
    import nuclei_engine as _rt_nuclei  # noqa: F401
    _TOOLS_AVAILABLE = True
except Exception as _tools_err:
    _TOOLS_AVAILABLE = False
    print(f"[!] redteam_6tools integration unavailable: {_tools_err}")


def _pick_scheme(host: str) -> str:
    """Probe whether a host serves HTTPS or HTTP (prefer HTTPS)."""
    if not _TOOLS_AVAILABLE:
        return "http"
    for scheme in ("https", "http"):
        try:
            _tools_http(f"{scheme}://{host}/", timeout=5)
            return scheme
        except RuntimeError:
            continue
    return "http"


def _normalize_target(target: str):
    """Return (host, base_url) from a domain, host[:port], or full URL."""
    t = (target or "").strip()
    scheme = ""
    rest = t
    if "://" in t:
        scheme, rest = t.split("://", 1)
        scheme = scheme.lower()
    rest = rest.split("/")[0].split("?")[0].split("#")[0]
    host = rest.split(":")[0].strip().lower()
    if not scheme:
        scheme = _pick_scheme(host)
    base_url = f"{scheme}://{rest}"
    return host, base_url


# Fast top-ports list for UI-driven scans (keeps wall-time low).
FAST_PORTS = ("21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,"
              "3306,3389,5432,5900,6379,8000,8080,8443,8888,9090,9200,27017")

# Findings templates for missing security headers (used by /api/fullscan).
SECURITY_HEADER_FINDINGS = {
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy header",
        "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-693",
        "description": "No Content-Security-Policy header is returned, so the browser has no allowlist for script, style, and object sources.",
        "impact": "Reflected or stored XSS becomes significantly easier to exploit without CSP restrictions.",
        "remediation": "Set a strict Content-Security-Policy header (e.g. default-src 'self').",
    },
    "Strict-Transport-Security": {
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-319",
        "description": "The site does not send Strict-Transport-Security, so browsers may connect over plain HTTP on later visits.",
        "impact": "Downgrade and man-in-the-middle attacks are possible for returning visitors.",
        "remediation": "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    },
    "X-Content-Type-Options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": "LOW", "cvss": 4.3, "cwe": "CWE-693",
        "description": "The response lacks X-Content-Type-Options: nosniff, allowing the browser to MIME-sniff responses.",
        "impact": "MIME confusion can lead to script execution from attacker-controlled content types.",
        "remediation": "Send `X-Content-Type-Options: nosniff`.",
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options header",
        "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-1021",
        "description": "The response has no X-Frame-Options header, so the page can be framed by other sites.",
        "impact": "Clickjacking attacks can trick users into performing unintended actions.",
        "remediation": "Send `X-Frame-Options: DENY` (or SAMEORIGIN), or a frame-ancestors CSP directive.",
    },
    "Referrer-Policy": {
        "title": "Missing Referrer-Policy header",
        "severity": "LOW", "cvss": 3.7, "cwe": "CWE-200",
        "description": "No Referrer-Policy is set, so the browser may leak the full URL (including sensitive query parameters) in the Referer header.",
        "impact": "Sensitive tokens or paths can leak to third-party destinations via the Referer header.",
        "remediation": "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
    },
    "Permissions-Policy": {
        "title": "Missing Permissions-Policy header",
        "severity": "LOW", "cvss": 3.1, "cwe": "CWE-693",
        "description": "No Permissions-Policy header restricts which browser features (camera, mic, geolocation) the site may use.",
        "impact": "If an XSS or injected frame occurs, powerful browser APIs are unrestricted.",
        "remediation": "Send a Permissions-Policy header limiting features to needed origins.",
    },
}

_CDN_MARKERS = ("cloudflare", "cloudfront", "fastly", "akamai", "incapsula",
                "imperva", "sucuri", "stackpath")


def _run_full_scan(host: str):
    """Run subdomain enum + per-host security config scan + apex port scan,
    and assemble a real asset inventory, findings, and summary."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    subdomain_hosts = []
    try:
        sub = _rt_tools.run_tool("subenum", host, {"threads": 40, "timeout": 4.0})
        subdomain_hosts = [s["host"] for s in sub.get("subdomains", [])]
    except Exception:
        subdomain_hosts = []

    hosts = [host]
    for s in subdomain_hosts:
        if s not in hosts:
            hosts.append(s)
    hosts = hosts[:20]

    def scan_host(h):
        try:
            ip = socket.gethostbyname(h)
        except Exception:
            ip = ""
        url = f"{_pick_scheme(h)}://{h}"
        try:
            sc = _rt_tools.run_tool("secscan", url, {"timeout": 6.0})
        except Exception as exc:
            return {"host": h, "ip": ip, "status": None, "ports": "", "tech": [],
                    "ssl": False, "vulns": 0, "grade": "A", "tls": None,
                    "missing_headers": [], "disclosed": [], "error": str(exc)}

        missing = sc.get("missing_headers", [])
        disclosed = sc.get("disclosed_headers", [])
        tech = [d.get("value", "") for d in disclosed
                if d.get("header", "").lower() == "server"]
        transport = sc.get("transport")
        vulns = len(missing) + (0 if transport == "https" else 1)
        grade = "F" if vulns >= 3 else ("C" if vulns >= 1 else "A")
        tls = None
        if sc.get("tls"):
            tls = sc["tls"].get("notAfter")
        return {"host": h, "ip": ip, "status": sc.get("status"),
                "ports": "443 80" if transport == "https" else "80",
                "tech": tech, "ssl": transport == "https", "vulns": vulns,
                "grade": grade, "tls": tls,
                "missing_headers": [m.get("header") for m in missing],
                "disclosed": [f"{d.get('header')}: {d.get('value')}" for d in disclosed],
                "error": None}

    assets = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(scan_host, h): h for h in hosts}
        for fut in as_completed(futures):
            assets.append(fut.result())
    assets.sort(key=lambda a: (0 if a["host"] == host else 1, a["host"]))

    open_ports = []
    try:
        ps = _rt_tools.run_tool("portscanner", host,
                                {"ports": FAST_PORTS, "timeout": 1.0, "threads": 150})
        open_ports = [p["port"] for p in ps.get("open_ports", [])]
    except Exception:
        open_ports = []
    if open_ports and assets and assets[0]["host"] == host:
        assets[0]["ports"] = " ".join(str(p) for p in open_ports)

    findings = []
    fid = 1
    for a in assets:
        for mh in a.get("missing_headers", []):
            tpl = SECURITY_HEADER_FINDINGS.get(mh)
            if not tpl:
                continue
            findings.append({
                "id": f"VULN-{fid:03d}", "title": tpl["title"],
                "severity": tpl["severity"], "cvss_score": tpl["cvss"],
                "affected_component": a["host"], "cwe_id": tpl["cwe"],
                "description": tpl["description"], "impact": tpl["impact"],
                "remediation": tpl["remediation"],
                "attack_scenario": (f"An attacker exploits the missing {mh} control on "
                                    f"{a['host']} during an authorized assessment."),
            })
            fid += 1

    live = sum(1 for a in assets if a["status"] is not None and 200 <= a["status"] < 400)
    ssl_count = sum(1 for a in assets if a["ssl"])
    vuln_assets = sum(1 for a in assets if a["vulns"] > 0)
    cdn_assets = sum(1 for a in assets
                     if any(m in str(a.get("disclosed", "")).lower() for m in _CDN_MARKERS))
    techs = set()
    for a in assets:
        for t in a["tech"]:
            techs.add(t)

    return {
        "host": host,
        "open_ports": open_ports,
        "subdomains": subdomain_hosts,
        "assets": assets,
        "findings": findings,
        "summary": {
            "total_assets": len(assets),
            "ssl": ssl_count, "no_ssl": len(assets) - ssl_count,
            "live": live, "down": len(assets) - live,
            "with_vulns": vuln_assets, "clean": len(assets) - vuln_assets,
            "behind_cdn": cdn_assets, "direct": len(assets) - cdn_assets,
            "unique_tech": len(techs),
        },
    }


MAX_PAYLOAD_SIZE = 2 * 1024 * 1024  # 2MB Limit to prevent Denial of Service (OWASP A04)
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB for APK/IPA file uploads


def extract_clean_domain(text: str) -> str:
    """Extract clean domain/hostname from raw domain string, URL, or cURL command."""
    if not text or not isinstance(text, str):
        return ""
    text = text.strip()

    # 1. Search for full URL in curl commands or raw text
    url_match = re.search(r'https?://([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})', text, re.IGNORECASE)
    if url_match:
        cand = url_match.group(1).lower()
        if "curl" not in cand:
            return cand

    # 2. Strip leading curl or cli flags: e.g. curl -I -sS -k
    clean = re.sub(r'^(?:curl\s+)?(?:-[a-zA-Z0-9-]+\s+)*', '', text, flags=re.IGNORECASE).strip()
    clean = clean.strip('\'"')
    clean = re.sub(r'^(?:https?:\/\/)?(?:www\.)?', '', clean, flags=re.IGNORECASE)
    clean = clean.split('/')[0].split('?')[0].split('#')[0].split(':')[0].strip()

    # 3. Match valid domain pattern
    domain_match = re.search(r'^([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})$', clean)
    if domain_match:
        candidate = domain_match.group(1).lower()
        if 'curl' not in candidate:
            return candidate

    return ""


def check_domain_resolves(domain: str) -> bool:
    """Check if the target domain actually resolves in public DNS (prevents false positives)."""
    if not domain:
        return False
    clean = domain.split(":")[0].strip()
    if clean in ["localhost", "127.0.0.1"]:
        return True
    try:
        socket.getaddrinfo(clean, None, socket.AF_INET)
        return True
    except Exception:
        return False


class RedTeamHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def end_headers(self):
        # OWASP A05: Security Misconfiguration - Standard Defensive Headers
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        # Never cache assets so the UI always reflects the latest files
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        from rg_tools_api import handle
        if handle(self, BASE_DIR, "GET"):
            return
        url = urllib.parse.urlparse(self.path)
        path = url.path

        # OWASP A01: Path Traversal defense
        safe_path = os.path.normpath(path).replace("\\", "/")
        if ".." in safe_path or safe_path.startswith("../"):
            self.send_error(403, "Access denied: Path traversal detected")
            return

        if path == "/api/report":
            self._handle_get_report()
        elif path == "/api/report/markdown":
            self._handle_get_markdown()
        elif path == "/api/prd":
            self._handle_get_prd()
        elif path == "/api/fullscan/results":
            self._handle_get_full_scan_results()
        elif path == "/api/tools/results":
            self._handle_get_tools_results()
        elif path == "/api/enterprise/templates":
            self._handle_get_enterprise_templates()
        elif path == "/api/enterprise/results":
            self._handle_get_enterprise_results()
        elif path == "/api/reconguard/results":
            self._handle_get_reconguard_results()
        elif path == "/api/reconguard/report/markdown":
            self._handle_get_reconguard_markdown()
        elif path in ["/", "/index.html"]:
            self.path = "/index.html"
            super().do_GET()
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        else:
            target_file = (WEB_DIR / path.lstrip("/")).resolve()
            if not str(target_file).startswith(str(WEB_DIR.resolve())) or not target_file.is_file():
                self.send_error(404, "File not found")
                return
            super().do_GET()

    def do_POST(self):
        from rg_tools_api import handle
        if handle(self, BASE_DIR, "POST"):
            return
        url = urllib.parse.urlparse(self.path)
        if url.path == "/api/audit":
            self._handle_post_audit()
        elif url.path == "/api/fullscan":
            self._handle_post_full_scan()
        elif url.path == "/api/tools/scan":
            self._handle_post_tools_scan()
        elif url.path == "/api/reconguard/scan":
            self._handle_post_reconguard_scan()
        elif url.path == "/api/enterprise/recon":
            self._handle_post_enterprise_recon()
        elif url.path == "/api/enterprise/nuclei":
            self._handle_post_enterprise_nuclei()
        elif url.path == "/api/enterprise/templates":
            self._handle_post_enterprise_templates()
        elif url.path == "/api/mobile/scan":
            self._handle_post_mobile_scan()
        elif url.path == "/api/clear":
            self._handle_post_clear()
        elif url.path == "/api/reset":
            self._handle_post_reset()
        else:
            self.send_error(404, "Endpoint not found")

    def _handle_post_clear(self):
        from datetime import datetime
        empty_data = {
            "product_name": "taskflow.ai",
            "version": "1.0",
            "assessment_date": datetime.now().strftime("%Y-%m-%d"),
            "author_role": "Lead Security Pentester",
            "risk_rating": "INFO",
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "findings": [],
            "threat_model": {
                "trust_boundaries": [],
                "entry_points": {},
                "asset_inventory": [],
                "stride": []
            },
            "test_plan": []
        }
        json_content = json.dumps(empty_data, indent=2)
        (BASE_DIR / "redteam_assessment.json").write_text(json_content, encoding="utf-8")
        (BASE_DIR / "REDTEAM_SECURITY_ASSESSMENT.md").write_text("# Attack Surface & Security Assessment\n\n*All data cleared. No active findings.*\n", encoding="utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json_content.encode("utf-8"))

    def _handle_post_reset(self):
        self._regenerate_assessment(BASE_DIR / "PRD.MD")
        self._handle_get_report()

    def _send_json(self, status_code, obj):
        body = json.dumps(obj, indent=2)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _read_json_body(self):
        """Read and parse the JSON request body; returns dict or None (error sent)."""
        try:
            raw_len = self.headers.get("Content-Length")
            if not raw_len or not raw_len.isdigit():
                self.send_error(400, "Bad Request: invalid or missing Content-Length")
                return None
            content_length = int(raw_len)
            if content_length > MAX_PAYLOAD_SIZE:
                self.send_error(413, "Payload Too Large: Maximum allowed size is 2MB")
                return None
            if content_length <= 0:
                self.send_error(400, "Bad Request: empty payload")
                return None
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            data = json.loads(body)
            if not isinstance(data, dict):
                self.send_error(400, "Bad Request: JSON payload must be an object")
                return None
            return data
        except json.JSONDecodeError:
            self.send_error(400, "Bad Request: malformed JSON payload")
            return None
        except Exception:
            self.send_error(400, "Bad Request")
            return None

    def _handle_get_full_scan_results(self):
        f = BASE_DIR / "redteam_fullscan.json"
        if not f.exists():
            self._send_json(200, {"assets": [], "findings": [], "summary": {}})
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(f.read_bytes())
        except Exception as e:
            self.send_error(500, f"Error reading full scan results: {e}")

    def _handle_post_full_scan(self):
        if not _TOOLS_AVAILABLE:
            self._send_json(503, {"error": "redteam_6tools integration unavailable",
                                  "assets": [], "findings": [], "summary": {}})
            return

        data = self._read_json_body()
        if data is None:
            return

        target = str(data.get("target") or "").strip()
        if not target:
            self.send_error(400, "Bad Request: missing target")
            return

        host, base_url = _normalize_target(target)
        if not check_domain_resolves(host):
            self._send_json(200, {
                "target": target, "host": host,
                "error": f"DNS lookup failed for '{host}' (NXDOMAIN). Scan skipped to prevent false positives.",
                "assets": [], "findings": [], "summary": {},
            })
            return

        try:
            result = _run_full_scan(host)
        except Exception as exc:
            self._send_json(200, {
                "target": target, "host": host, "error": str(exc),
                "assets": [], "findings": [], "summary": {},
            })
            return

        result["target"] = target
        result["base_url"] = base_url
        try:
            (BASE_DIR / "redteam_fullscan.json").write_text(
                json.dumps(result, indent=2), encoding="utf-8")
        except Exception:
            pass
        self._send_json(200, result)

    def _handle_post_mobile_scan(self):
        if not _TOOLS_AVAILABLE:
            self._send_json(503, {"error": "redteam_6tools integration unavailable"})
            return

        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        kind = (q.get("kind") or ["apk"])[0].lower()
        if kind not in ("apk", "ipa"):
            self.send_error(400, "Bad Request: kind must be 'apk' or 'ipa'")
            return

        raw_len = self.headers.get("Content-Length")
        if not raw_len or not raw_len.isdigit():
            self.send_error(400, "Bad Request: invalid or missing Content-Length")
            return
        content_length = int(raw_len)
        if content_length > MAX_UPLOAD_SIZE:
            self.send_error(413, "Payload Too Large: maximum allowed size is 100MB")
            return
        if content_length <= 0:
            self.send_error(400, "Bad Request: empty file")
            return

        body = self.rfile.read(content_length)
        ext = ".apk" if kind == "apk" else ".ipa"
        tmp = BASE_DIR / f"_mobile_upload{ext}"
        tmp.write_bytes(body)
        try:
            tool_name = "apk_recon" if kind == "apk" else "ipa_recon"
            result = _rt_tools.run_tool(tool_name, str(tmp))
        except Exception as exc:
            result = {"error": str(exc)}
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        self._send_json(200, result)

    def _handle_get_tools_results(self):
        f = BASE_DIR / "redteam_6tools_results.json"
        if not f.exists():
            self._send_json(200, {"results": {}})
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(f.read_bytes())
        except Exception as e:
            self.send_error(500, f"Error reading tools results: {e}")

    def _handle_get_enterprise_templates(self):
        if not _TOOLS_AVAILABLE:
            self._send_json(503, {"error": "Enterprise Nuclei engine unavailable"})
            return
        try:
            templates = _rt_nuclei.get_all_templates()
            self._send_json(200, {"templates": templates, "count": len(templates)})
        except Exception as e:
            self.send_error(500, f"Error reading templates: {e}")

    def _handle_get_enterprise_results(self):
        f = BASE_DIR / "redteam_enterprise_results.json"
        if not f.exists():
            self._send_json(200, {"status": "EMPTY", "summary": {}, "assets": [], "findings": []})
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(f.read_bytes())
        except Exception as e:
            self.send_error(500, f"Error reading enterprise results: {e}")

    def _handle_get_reconguard_results(self):
        f = BASE_DIR / "reconguard_results.json"
        if not f.exists():
            self._send_json(200, {"status": "EMPTY", "target": "", "assets": [], "findings": [], "baselines": {}, "summary": {}})
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(f.read_bytes())
        except Exception as e:
            self.send_error(500, f"Error reading ReconGuard results: {e}")

    def _handle_get_reconguard_markdown(self):
        f = BASE_DIR / "RECONGUARD_SECURITY_REPORT.md"
        if not f.exists():
            self.send_error(404, "ReconGuard markdown report not found")
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(f.read_bytes())
        except Exception as e:
            self.send_error(500, f"Error reading report: {e}")

    def _handle_post_reconguard_scan(self):
        data = self._read_json_body()
        if data is None:
            return
        target = str(data.get("target") or "").strip()
        if not target:
            self.send_error(400, "Bad Request: missing target")
            return

        host, _ = _normalize_target(target)
        if not check_domain_resolves(host):
            self._send_json(200, {
                "target": target, "host": host,
                "error": f"DNS lookup failed for '{host}' (NXDOMAIN). Scan skipped to prevent false positives.",
                "summary": {}, "assets": [], "findings": []
            })
            return

        try:
            from reconguard import ScopeConfig, ReconGuardPipeline, EvidenceEngine
            in_scope = data.get("in_scope") or [host, f"*.{host}"]
            out_of_scope = data.get("out_of_scope") or []
            researcher = data.get("researcher") or "ReconGuard-Pentester"
            rate_limit = float(data.get("rate_limit") or 15.0)
            max_fuzz = int(data.get("max_fuzz") or 10)

            scope = ScopeConfig(
                in_scope_domains=in_scope,
                out_of_scope_regex=out_of_scope,
                max_rate_limit=rate_limit,
                researcher_header=f"X-Bug-Bounty-Researcher: {researcher}"
            )

            pipeline = ReconGuardPipeline(
                scope_config=scope,
                threads=25,
                max_assets_to_fuzz=max_fuzz
            )

            report = pipeline.execute(host)
            report_dict = report.to_dict()

            # Persist results
            (BASE_DIR / "reconguard_results.json").write_text(
                json.dumps(report_dict, indent=2), encoding="utf-8"
            )
            md_content = EvidenceEngine.generate_markdown_report(report)
            (BASE_DIR / "RECONGUARD_SECURITY_REPORT.md").write_text(
                md_content, encoding="utf-8"
            )

            self._send_json(200, report_dict)
        except Exception as exc:
            self.send_error(500, f"ReconGuard scan failed: {exc}")

    def _handle_post_enterprise_templates(self):
        if not _TOOLS_AVAILABLE:
            self._send_json(503, {"error": "Enterprise Nuclei engine unavailable"})
            return
        data = self._read_json_body()
        if data is None:
            return
        try:
            saved = _rt_nuclei.save_custom_template(data)
            self._send_json(200, {"status": "SUCCESS", "template": saved})
        except Exception as e:
            self.send_error(500, f"Error saving template: {e}")

    def _handle_post_enterprise_recon(self):
        if not _TOOLS_AVAILABLE:
            self._send_json(503, {"error": "Enterprise Recon engine unavailable"})
            return
        data = self._read_json_body()
        if data is None:
            return
        target = str(data.get("target") or "").strip()
        if not target:
            self.send_error(400, "Bad Request: missing target")
            return
        host, _ = _normalize_target(target)
        if not check_domain_resolves(host):
            self._send_json(200, {
                "target": target, "host": host,
                "error": f"DNS lookup failed for '{host}' (NXDOMAIN). Scan skipped to prevent false positives.",
                "summary": {}, "assets": [], "findings": []
            })
            return
        try:
            result = _rt_nuclei.run_automated_surface_recon(host, data.get("options") or {})
            (BASE_DIR / "redteam_enterprise_results.json").write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
            self._send_json(200, result)
        except Exception as exc:
            self.send_error(500, f"Enterprise recon failed: {exc}")

    def _handle_post_enterprise_nuclei(self):
        if not _TOOLS_AVAILABLE:
            self._send_json(503, {"error": "Enterprise Nuclei engine unavailable"})
            return
        data = self._read_json_body()
        if data is None:
            return
        target = str(data.get("target") or "").strip()
        if not target:
            self.send_error(400, "Bad Request: missing target")
            return
        host, _ = _normalize_target(target)
        if not check_domain_resolves(host):
            self._send_json(200, {
                "target": target, "host": host,
                "error": f"DNS lookup failed for '{host}' (NXDOMAIN). Scan skipped to prevent false positives.",
                "findings": []
            })
            return
        try:
            t_ids = data.get("template_ids")
            result = _rt_nuclei.run_nuclei_scan(host, template_ids=t_ids)
            self._send_json(200, result)
        except Exception as exc:
            self.send_error(500, f"Nuclei scan failed: {exc}")

    def _handle_post_tools_scan(self):
        if not _TOOLS_AVAILABLE:
            self._send_json(503, {"error": "redteam_6tools integration unavailable"})
            return

        try:
            raw_len = self.headers.get("Content-Length")
            if not raw_len or not raw_len.isdigit():
                self.send_error(400, "Bad Request: invalid or missing Content-Length")
                return
            content_length = int(raw_len)
            if content_length > MAX_PAYLOAD_SIZE:
                self.send_error(413, "Payload Too Large: Maximum allowed size is 2MB")
                return
            if content_length <= 0:
                self.send_error(400, "Bad Request: empty payload")
                return
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_error(400, "Bad Request: malformed JSON payload")
                return
        except Exception:
            self.send_error(400, "Bad Request")
            return

        target = str(data.get("target") or "").strip()
        if not target:
            self.send_error(400, "Bad Request: missing target")
            return

        host, base_url = _normalize_target(target)

        # DNS validation: suppress findings against dead targets (false-positive control)
        if not check_domain_resolves(host):
            self._send_json(200, {
                "target": target,
                "host": host,
                "error": f"DNS lookup failed for '{host}' (NXDOMAIN). Scan skipped to prevent false positives.",
                "results": {},
            })
            return

        requested = list(data.get("tools") or _rt_tools.TOOLS.keys())
        options = dict(data.get("options") or {})
        endpoint = str(data.get("endpoint") or "").strip() or base_url

        results = {}
        for name in requested:
            if name not in _rt_tools.TOOLS:
                continue
            try:
                if name in ("sqli_scanner", "xss_scanner", "csrf_scanner",
                            "ssrf_scanner", "idor_scanner", "misconfig_scanner",
                            "auth_scanner", "dapp_scanner"):
                    tgt = endpoint
                elif name in ("dirbust", "secscan"):
                    tgt = base_url
                else:
                    tgt = host
                res = _rt_tools.run_tool(name, tgt, options)
                try:
                    res["pocs"] = _rt_poc.build_pocs(name, str(tgt), res)
                except Exception:
                    res["pocs"] = []
                results[name] = res
            except Exception as exc:
                results[name] = {"tool": name, "target": target, "error": str(exc)}

        payload = {
            "target": target,
            "host": host,
            "base_url": base_url,
            "tools_ran": list(results.keys()),
            "results": results,
        }

        # Attach site_gate metadata if detected by any scanner tool
        for r_item in results.values():
            if isinstance(r_item, dict):
                if r_item.get("checks", {}).get("site_gate"):
                    payload["site_gate"] = r_item["checks"]["site_gate"]
                    break
                elif r_item.get("site_gate"):
                    payload["site_gate"] = r_item["site_gate"]
                    break
        try:
            (BASE_DIR / "redteam_6tools_results.json").write_text(
                json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

        self._send_json(200, payload)

    def _handle_get_report(self):
        json_file = BASE_DIR / "redteam_assessment.json"
        if not json_file.exists():
            self._regenerate_assessment(BASE_DIR / "PRD.MD")

        try:
            content = json_file.read_text(encoding="utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        except Exception as e:
            self.send_error(500, f"Error reading report: {e}")

    def _handle_get_markdown(self):
        md_file = BASE_DIR / "REDTEAM_SECURITY_ASSESSMENT.md"
        if not md_file.exists():
            self._regenerate_assessment(BASE_DIR / "PRD.MD")

        try:
            content = md_file.read_text(encoding="utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        except Exception as e:
            self.send_error(500, f"Error reading markdown: {e}")

    def _handle_get_prd(self):
        prd_file = BASE_DIR / "PRD.MD"
        try:
            content = prd_file.read_text(encoding="utf-8") if prd_file.exists() else ""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        except Exception as e:
            self.send_error(500, f"Error reading PRD: {e}")

    def _handle_post_audit(self):
        try:
            raw_len = self.headers.get("Content-Length")
            if not raw_len or not raw_len.isdigit():
                self.send_error(400, "Bad Request: Invalid or missing Content-Length")
                return

            content_length = int(raw_len)
            # OWASP A04: DoS Mitigation - Enforce strict payload ceiling
            if content_length > MAX_PAYLOAD_SIZE:
                try:
                    self.rfile.read(min(content_length, 65536))
                except Exception:
                    pass
                self.send_error(413, "Payload Too Large: Maximum allowed size is 2MB")
                return

            if content_length <= 0:
                self.send_error(400, "Bad Request: Empty payload")
                return

            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_error(400, "Bad Request: Malformed JSON payload")
                return

            prd_text = data.get("prd_text", "")
            target = data.get("target") or data.get("domain", "")
            clean_target = ""

            # If target domain is provided, validate it and prevent false positives
            if target and isinstance(target, str):
                clean_target = extract_clean_domain(target)
                if not clean_target:
                    self.send_error(400, "Bad Request: Invalid target domain or unparseable URL")
                    return

                # Strict DNS Check: If domain does not resolve in public DNS, reject findings as false positives
                if not check_domain_resolves(clean_target):
                    empty_unresolved = {
                        "product_name": clean_target,
                        "dns_resolved": False,
                        "error_message": f"Target domain '{clean_target}' failed DNS lookup (NXDOMAIN). Findings suppressed to prevent false positives.",
                        "risk_rating": "INFO",
                        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                        "findings": [],
                        "threat_model": {
                            "trust_boundaries": [],
                            "entry_points": {},
                            "asset_inventory": [],
                            "stride": []
                        },
                        "test_plan": []
                    }
                    json_str = json.dumps(empty_unresolved, indent=2)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(json_str.encode("utf-8"))
                    return

                if not prd_text:
                    default_prd = (BASE_DIR / "PRD.MD").read_text(encoding="utf-8") if (BASE_DIR / "PRD.MD").exists() else ""
                    prd_text = f"## {clean_target} — Attack Surface & Architecture Specification\n\n" + default_prd

            if not prd_text or not isinstance(prd_text, str):
                self.send_error(400, "Bad Request: Missing or invalid prd_text field")
                return

            # Execute Threat Assessment Engine with safe parsing
            parsed = PRDParser(prd_text).parse()
            engine = ThreatAnalysisEngine(parsed)
            report = engine.run_assessment()
            if clean_target:
                report.product_name = clean_target

            # Generate Report outputs
            reporter = ReportGenerator(report)
            md_content = reporter.to_markdown()
            json_content = reporter.to_json()

            # Save to disk
            (BASE_DIR / "REDTEAM_SECURITY_ASSESSMENT.md").write_text(md_content, encoding="utf-8")
            (BASE_DIR / "redteam_assessment.json").write_text(json_content, encoding="utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json_content.encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as e:
            try:
                self.send_error(500, f"Audit processing failed: {e}")
            except Exception:
                pass

    def _regenerate_assessment(self, prd_file: Path):
        content = prd_file.read_text(encoding="utf-8") if prd_file.exists() else ""
        parsed = PRDParser(content).parse()
        engine = ThreatAnalysisEngine(parsed)
        report = engine.run_assessment()
        reporter = ReportGenerator(report)
        (BASE_DIR / "REDTEAM_SECURITY_ASSESSMENT.md").write_text(reporter.to_markdown(), encoding="utf-8")
        (BASE_DIR / "redteam_assessment.json").write_text(reporter.to_json(), encoding="utf-8")


def find_free_port(start_port=8080, max_attempts=50):
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    return start_port


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def main():
    port = find_free_port(8080)
    server_address = ("127.0.0.1", port)
    httpd = ThreadedHTTPServer(server_address, RedTeamHTTPHandler)

    print("=" * 65)
    print("         [+] AEGIS // RED TEAM SECURITY DASHBOARD SERVER")
    print("=" * 65)
    print(f"[*] Dashboard UI available at: http://localhost:{port}")
    print(f"[*] API Endpoints: http://localhost:{port}/api/report")
    print(f"[*] Press Ctrl+C to terminate the server")
    print("=" * 65)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        httpd.server_close()


if __name__ == "__main__":
    main()
