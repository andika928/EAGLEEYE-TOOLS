# RedTeam 9-Tool Toolkit

A standalone set of **9 security assessment tools** for discovering
vulnerabilities in web applications and network targets. Written in pure
Python (standard library only — no dependencies required), with clear CLI
output and built-in false-positive controls.

> **Authorized use only.** Run these tools only against systems you own or
> have explicit written permission to test. Unauthorized scanning is illegal
> in most jurisdictions.

---

## Tools

| # | Tool | File | What it finds |
|---|------|------|---------------|
| 1 | PortScanner | `portscanner.py` | Open TCP ports + service banners |
| 2 | SubEnumerator | `subenum.py` | Live subdomains (with wildcard-DNS filtering) |
| 3 | DirBuster | `dirbust.py` | Hidden web directories/files (soft-404 aware) |
| 4 | SQLiScanner | `sqli_scanner.py` | SQL injection candidates (error/boolean/time-based) |
| 5 | XSSScanner | `xss_scanner.py` | Reflected XSS candidates (reflection + payload tiers) |
| 6 | SecScan | `secscan.py` | Missing security headers, weak cookies, TLS issues |
| 7 | CSRFScanner | `csrf_scanner.py` | POST forms missing a CSRF token + SameSite posture |
| 8 | SSRFScanner | `ssrf_scanner.py` | SSRF via out-of-band callback (OAST) |
| 9 | IDORScanner | `idor_scanner.py` | Object-reference enumeration (potential IDOR) |

Shared module: `common.py` (banner, port parsing, HTTP request helper).
Runner: `runner.py` (dispatches all tools programmatically for the dashboard).
Wordlists: `wordlists/subdomains.txt`, `wordlists/dirs.txt`.

---

## Requirements

- Python 3.8+ (tested on 3.14). No third-party packages are required.
- Optional: `pip install requests` for more robust HTTP handling.

---

## Usage

```bash
# 1. TCP port scan
python portscanner.py 192.168.1.10 -p 1-1024,8080 --grab -T 400

# 2. Subdomain enumeration
python subenum.py example.com -w wordlists/subdomains.txt -t 100

# 3. Web directory discovery
python dirbust.py http://target/ -w wordlists/dirs.txt -e php,html

# 4. SQL injection detection
python sqli_scanner.py "http://target/item?id=1" --sleep 5

# 5. Reflected XSS detection
python xss_scanner.py "http://target/search?q=test"

# 6. Web security config review
python secscan.py https://target

# 7. CSRF protection check
python csrf_scanner.py https://target/login

# 8. SSRF detection (out-of-band callback)
python ssrf_scanner.py "http://target/fetch?url=x"

# 9. IDOR / object enumeration
python idor_scanner.py "http://target/user?id=100"
```

Every tool also supports `--help` for the full option list.

---

## About "no false positives, no bugs"

These tools are engineered to be reliable and self-contained, and each one is
verified for syntax and against a local test server before delivery. However,
**no vulnerability scanner can honestly guarantee zero false positives** —
that is a property of how heuristics interact with real, messy applications:

- **PortScanner / SubEnumerator / SecScan** report only objective, verifiable
  facts (a connection succeeded, a DNS record resolves, a header is missing),
  so their output is effectively false-positive-free by construction.
- **DirBuster** reduces false positives with a *soft-404 baseline* (it learns
  the site's "not found" response and filters look-alikes).
- **SubEnumerator** detects and filters *wildcard DNS* responses.
- **SQLiScanner / XSSScanner** are deliberately labeled **CANDIDATES** because
  error/time/reflection heuristics can be influenced by the application's own
  behavior. Always confirm these manually (e.g., with `sqlmap` or a browser).
- **SSRFScanner** is the strongest of the new tools: it reports SSRF only when
  the target actually fetches your callback, so a confirmed hit has no false
  positive. It needs the target to reach your callback host (use a public IP /
  Burp Collaborator for external targets).
- **CSRFScanner / IDORScanner** report facts (a token is missing; adjacent IDs
  return distinct 200s) but are **CANDIDATES** — CSRF may still be blocked by
  SameSite/custom headers, and IDOR must be confirmed with two accounts.

The honest engineering stance: **facts are reported as facts; heuristics are
reported as candidates with a confidence tier.**

---

## File layout

```
redteam_6tools/
├── common.py            # shared helpers (stdlib only)
├── portscanner.py       # tool 1
├── subenum.py           # tool 2
├── dirbust.py           # tool 3
├── sqli_scanner.py      # tool 4
├── xss_scanner.py       # tool 5
├── secscan.py           # tool 6
├── csrf_scanner.py      # tool 7
├── ssrf_scanner.py      # tool 8
├── idor_scanner.py      # tool 9
├── runner.py            # programmatic dispatcher (used by dashboard)
├── requirements.txt     # optional requests dependency
└── wordlists/
    ├── subdomains.txt
    └── dirs.txt
```
