#!/usr/bin/env python3
"""Shared helpers for the RedTeam 6-Tool Toolkit.

Pure Python standard library only, so the toolkit runs with zero third-party
dependencies. If `requests` happens to be installed it is used automatically,
otherwise a stdlib fallback is used.
"""
from __future__ import annotations

import sys

USER_AGENT = "Mozilla/5.0 (RedTeam6Tools/1.0; security-assessment; authorized-use-only)"


def eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def setup_stdio() -> None:
    """Make stdout/stderr Unicode-safe.

    Windows consoles default to cp1252, which raises UnicodeEncodeError when
    a resolved hostname, banner, or body snippet contains non-Latin text.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def banner(name: str, version: str = "1.0") -> None:
    """Print a uniform tool banner."""
    setup_stdio()
    line = "=" * 62
    print(line)
    print(f"  {name}  v{version}")
    print(line)


def parse_ports(spec: str):
    """Parse a comma-separated port spec with ranges, e.g. '80,443,8000-9000'.

    Returns a sorted list of unique ports. Raises ValueError on bad input.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValueError(f"invalid port range: {part!r}")
            if start > end:
                start, end = end, start
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"port range out of bounds: {part!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"invalid port: {part!r}")
            if not (1 <= p <= 65535):
                raise ValueError(f"port out of bounds: {part!r}")
            ports.add(p)
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)


def read_wordlist(path: str):
    """Read a wordlist file into cleaned, non-empty entries.

    Reads with a UTF-8 BOM-tolerant encoding so files saved by Windows editors
    or PowerShell do not leak a leading BOM character into entries. Blank lines
    and `#` comments are dropped.
    """
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        return [ln.strip() for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")]


def http_request_ex(url, timeout=10.0, method="GET", data=None, headers=None,
                    allow_redirects=True):
    """Perform an HTTP request and return
    (status_code, headers_dict, body_text, final_url).

    `final_url` is the URL after any redirects, so callers can tell which
    scheme/host actually served the response. Raises RuntimeError on
    transport-level failure. Uses `requests` when available, otherwise the
    standard library.
    """
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)

    try:
        import requests  # noqa: F401
        _requests = True
    except Exception:
        _requests = False

    if _requests:
        import requests
        try:
            r = requests.request(method, url, timeout=timeout, data=data,
                                 headers=hdrs, allow_redirects=allow_redirects,
                                 verify=True)
            return r.status_code, dict(r.headers), (r.text or ""), str(r.url)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"request failed: {exc}")

    import urllib.request
    import urllib.error

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body, resp.geturl()
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        hdr_dict = dict(exc.headers) if exc.headers else {}
        try:
            final = exc.geturl() or url
        except Exception:
            final = url
        return exc.code, hdr_dict, body, final
    except Exception as exc:
        raise RuntimeError(f"request failed: {exc}")


def http_request(url, timeout=10.0, method="GET", data=None, headers=None,
                 allow_redirects=True):
    """Perform an HTTP request and return (status_code, headers_dict, body_text)."""
    status, hdrs, body, _final = http_request_ex(
        url, timeout=timeout, method=method, data=data, headers=headers,
        allow_redirects=allow_redirects)
    return status, hdrs, body
