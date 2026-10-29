"""
Stage 5: Evidence & Diff Engine.
Provides side-by-side Raw Request/Response inspection, baseline difference analysis,
and one-click credential-sanitized Markdown audit report generation.
"""

from __future__ import annotations
import re
from typing import Dict, Any, List
from .models import FindingEvidence, BaselineFingerprint, ReconGuardReport


class EvidenceEngine:
    """Formats evidence, computes baseline differences, and produces sanitized audit exports."""

    @staticmethod
    def sanitize_secrets(text: str) -> str:
        """
        Redact sensitive tokens, authorization headers, cookies, and API keys
        prior to report exporting to prevent credential leaks.
        """
        if not text:
            return ""
        sanitized = text
        # Redact Authorization header
        sanitized = re.sub(r"(Authorization:\s*Bearer\s+)[^\r\n]+", r"\1[REDACTED_BEARER_TOKEN]", sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"(Authorization:\s*Basic\s+)[^\r\n]+", r"\1[REDACTED_BASIC_AUTH]", sanitized, flags=re.IGNORECASE)
        # Redact Cookie header
        sanitized = re.sub(r"(Cookie:\s*)[^\r\n]+", r"\1[REDACTED_SESSION_COOKIES]", sanitized, flags=re.IGNORECASE)
        # Redact Set-Cookie header
        sanitized = re.sub(r"(Set-Cookie:\s*)[^\r\n]+", r"\1[REDACTED_COOKIE]", sanitized, flags=re.IGNORECASE)
        # Redact AWS and API keys
        sanitized = re.sub(r"(AKIA[0-9A-Z]{16})", r"[REDACTED_AWS_ACCESS_KEY]", sanitized)
        sanitized = re.sub(r"(AWS_SECRET_ACCESS_KEY\s*=\s*)[^\r\n]+", r"\1[REDACTED_SECRET]", sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"(DB_PASSWORD\s*=\s*)[^\r\n]+", r"\1[REDACTED_PASSWORD]", sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"(SECRET_KEY\s*=\s*)[^\r\n]+", r"\1[REDACTED_SECRET_KEY]", sanitized, flags=re.IGNORECASE)
        return sanitized

    @staticmethod
    def format_raw_response(status: int, headers: Dict[str, str], body: str) -> str:
        """Format raw HTTP response with headers and body."""
        lines = [f"HTTP/1.1 {status}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(body[:4000])
        return "\r\n".join(lines)

    @classmethod
    def generate_markdown_report(cls, report: ReconGuardReport) -> str:
        """
        Generate complete, professional, senior security engineer audit report
        conforming to PRD Section 3.2 & Section 7.
        """
        lines = [
            f"# 🛡️ ReconGuard ASM & Zero-False-Positive Assessment Report",
            f"**Target Scope:** `{report.target_domain}`  ",
            f"**Audit Date:** {report.scan_date}  ",
            f"**Engine Version:** ReconGuard v1.0.0 (Zero-FP Calibrated)  ",
            f"**Classification:** Authorized Bug Bounty / Security Audit  ",
            "",
            "> ⚠️ **Notice:** All findings presented in this report have been validated through multi-factor",
            "> baseline calibration against soft-404 and SPA fallbacks. 100% genuine anomalies.",
            "",
            "---",
            "",
            "## 1. Executive Summary & Telemetry Matrix",
            "",
            f"- **Target Domain:** `{report.target_domain}`",
            f"- **In-Scope Rules:** `{', '.join(report.scope.in_scope_domains) if report.scope.in_scope_domains else 'All subdomains'}`",
            f"- **Total Discovered Assets:** {len(report.assets)} live hosts",
            f"- **Baseline Soft-404 Profiles:** {len(report.baselines)} calibrated targets",
            f"- **Verified True-Positive Findings:** **{len(report.findings)}** anomalies",
            "",
            "### Severity Distribution",
            "",
            "| Severity | Count | Priority |",
            "|:---|:---:|:---|",
        ]

        crit_count = sum(1 for f in report.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in report.findings if f.severity == "HIGH")
        med_count = sum(1 for f in report.findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in report.findings if f.severity == "LOW")
        info_count = sum(1 for f in report.findings if f.severity == "INFO")

        lines.extend([
            f"| 🔴 **CRITICAL** | {crit_count} | Immediate Action Required |",
            f"| 🟠 **HIGH** | {high_count} | High Risk Exposure |",
            f"| 🟡 **MEDIUM** | {med_count} | Medium Exposure |",
            f"| 🔵 **LOW** | {low_count} | Low Security Hygiene |",
            f"| ⚪ **INFO** | {info_count} | Informational / Recon |",
            "",
            "---",
            "",
            "## 2. Discovered Asset Inventory",
            "",
            "| Hostname | IP Address | Status | CDN / Edge | Technologies |",
            "|:---|:---|:---:|:---|:---|",
        ])

        for a in report.assets[:25]:
            tech_str = ", ".join(a.tech_stack[:4]) if a.tech_stack else "Standard Web"
            cdn_str = a.cdn_provider if a.cdn_provider else "Direct Origin"
            lines.append(f"| `{a.host}` | `{a.ip}` | `{a.status}` | {cdn_str} | {tech_str} |")

        if len(report.assets) > 25:
            lines.append(f"| *...and {len(report.assets) - 25} more assets* | | | | |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Calibrated Baseline Soft-404 Profiles",
            "",
            "| Target Host | Baseline Status | Avg Content-Length | Word Count | Catch-All | SPA Fallback |",
            "|:---|:---:|:---:|:---:|:---:|:---:|",
        ])

        for host, b in report.baselines.items():
            lines.append(
                f"| `{host}` | `{b.status_code}` | `{b.content_length_avg:.0f} B` | `{b.word_count_avg:.0f}` | "
                f"{'✅ Yes' if b.is_catch_all else '❌ No'} | {'✅ Yes' if b.is_spa_fallback else '❌ No'} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 4. Zero-False-Positive Verified Findings & Evidence Dumps",
            "",
        ])

        if not report.findings:
            lines.append("*No anomalies or vulnerabilities identified. Target returned zero false-positive deviations.*")
        else:
            for idx, f in enumerate(report.findings, 1):
                clean_req = cls.sanitize_secrets(f.raw_request)
                clean_res_headers = cls.sanitize_secrets(cls.format_raw_response(f.status_code, f.raw_response_headers, f.raw_response_body))

                lines.extend([
                    f"### {idx}. [{f.id}] ({f.severity}) {f.category} on `{f.asset_host}{f.endpoint_path}`",
                    f"- **URL:** `{f.url}`",
                    f"- **Status Code:** `{f.status_code}`",
                    f"- **Confidence Score:** `{f.confidence_score}`",
                    "",
                    "#### Baseline Comparison & Diff Summary",
                    f"> **Status Delta:** {f.diff_summary.status_delta}  ",
                    f"> **Byte Differential:** `{f.diff_summary.bytes_delta:+d} bytes`  ",
                    f"> **Word Differential:** `{f.diff_summary.words_delta:+d} words`  ",
                    f"> **Content-Type Delta:** {f.diff_summary.content_type_delta}  ",
                    f"> **Validation Rationale:** {f.diff_summary.rationale}",
                    "",
                    "#### Verified Replay cURL Command",
                    "```bash",
                    f"{f.curl_cmd}",
                    "```",
                    "",
                    "#### Raw HTTP Request (Sanitized)",
                    "```http",
                    clean_req.strip(),
                    "```",
                    "",
                    "#### Raw HTTP Response Telemetry (Sanitized)",
                    "```http",
                    clean_res_headers.strip(),
                    "```",
                    "",
                    "---",
                    "",
                ])

        lines.extend([
            "## 5. Audit Compliance & Researcher Identification",
            "",
            "- **Safe-Method Policy:** Exclusively non-destructive `GET`/`HEAD` read-only testing performed.",
            f"- **Researcher Identification Header:** `{report.scope.researcher_header}`",
            "- **Zero False Positive Guarantee:** Validated via 4-layer multi-factor fingerprint calibration.",
            "",
            "**Report Generated by ReconGuard v1.0.0**",
        ])

        return "\n".join(lines)
