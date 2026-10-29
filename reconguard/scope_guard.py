"""
Stage 1: Scope & Policy Guard.
Validates targets against strict in-scope domains and out-of-scope regex rules
before any network packets are transmitted.
"""

from __future__ import annotations
import re
from typing import Tuple, List, Optional
from urllib.parse import urlparse
from .models import ScopeConfig


class ScopeGuard:
    """Enforces strict scope boundaries and rules of engagement."""

    def __init__(self, config: Optional[ScopeConfig] = None):
        self.config = config or ScopeConfig()

    @staticmethod
    def normalize_host(target: str) -> str:
        """Extract clean hostname from URL, IP, or domain string."""
        raw = target.strip()
        if "://" in raw:
            parsed = urlparse(raw)
            host = parsed.netloc or parsed.path
        else:
            host = raw.split("/")[0]

        # Strip userinfo or port
        if "@" in host:
            host = host.split("@")[-1]
        if ":" in host:
            host = host.split(":")[0]

        return host.strip().lower().rstrip(".")

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Validate whether a given target (domain, host, or URL) is permitted.
        Returns: (is_allowed: bool, reason: str)
        """
        host = self.normalize_host(target)
        if not host:
            return False, "Target resolved to empty hostname"

        # Check Out-of-Scope Regexes first (highest precedence block)
        for pattern in self.config.out_of_scope_regex:
            try:
                if re.search(pattern, host, re.IGNORECASE):
                    return False, f"Blocked by out-of-scope regex pattern '{pattern}'"
            except re.error as e:
                # Malformed pattern safety
                continue

        # If no explicit in-scope list is provided, default to allowing if not blocked
        if not self.config.in_scope_domains:
            return True, "Implicitly allowed (no in-scope restriction set)"

        # Check In-Scope Domain patterns
        for scope_pattern in self.config.in_scope_domains:
            pat = scope_pattern.strip().lower().rstrip(".")
            if not pat:
                continue

            # Exact match
            if host == pat:
                return True, f"Matches in-scope domain '{pat}'"

            # Wildcard domain: *.example.com or .example.com
            if pat.startswith("*."):
                root = pat[2:]
                if host == root or host.endswith("." + root):
                    return True, f"Matches in-scope wildcard '*.{root}'"
            elif pat.startswith("."):
                root = pat[1:]
                if host == root or host.endswith("." + root):
                    return True, f"Matches in-scope domain '.{root}'"
            else:
                # Subdomain of specified domain
                if host.endswith("." + pat):
                    return True, f"Subdomain of in-scope '{pat}'"

        return False, f"Target '{host}' is NOT in configured in-scope domains list"

    def filter_targets(self, targets: List[str]) -> List[str]:
        """Filter a list of targets and return only permitted ones."""
        allowed = []
        for t in targets:
            ok, _ = self.is_in_scope(t)
            if ok:
                allowed.append(self.normalize_host(t))
        return sorted(set(allowed))
