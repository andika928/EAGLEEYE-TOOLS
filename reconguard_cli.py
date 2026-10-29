#!/usr/bin/env python3
"""
ReconGuard ASM & Zero-False-Positive Recon CLI Tool.
Usage:
    python reconguard_cli.py --target infomaniak.com --in-scope infomaniak.com,*.infomaniak.com --output RECONGUARD_REPORT.md
"""

from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure UTF-8 console output for Windows CLI
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from reconguard import ScopeConfig, ReconGuardPipeline, EvidenceEngine


BANNER = r"""
  ____                     ____                  _ 
 |  _ \ ___  ___ ___  _ __ / ___|_   _  __ _ _ __| |
 | |_) / _ \/ __/ _ \| '_ \ |  _| | | |/ _` | '__| |
 |  _ <  __/ (_| (_) | | | | |_| | |_| | (_| | |  |_|
 |_| \_\___|\___\___/|_| |_|\____|\__,_|\__,_|_|  (_)
    [ Zero-False-Positive ASM & Calibrated Recon Engine ]
"""


def main():
    parser = argparse.ArgumentParser(
        description="ReconGuard: Zero-False-Positive Automated Recon & Evidence Validation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", "-t", type=str, required=True, help="Target domain (e.g. infomaniak.com)")
    parser.add_argument("--in-scope", "-s", type=str, default="", help="Comma-separated in-scope domains (e.g. 'example.com,*.example.com')")
    parser.add_argument("--out-of-scope", "-b", type=str, default="", help="Comma-separated out-of-scope regex patterns (e.g. '.*logout.*,.*admin.*')")
    parser.add_argument("--researcher", "-r", type=str, default="ReconGuard-Pentester", help="Researcher username / identifier for custom header")
    parser.add_argument("--output", "-o", type=str, default="RECONGUARD_REPORT.md", help="Path to write Markdown audit report")
    parser.add_argument("--json-output", "-j", type=str, default=None, help="Optional path to output structured JSON telemetry")
    parser.add_argument("--threads", type=int, default=30, help="Concurrency worker threads (default: 30)")
    parser.add_argument("--rate-limit", type=float, default=15.0, help="Maximum requests per second (default: 15.0)")
    parser.add_argument("--max-fuzz", type=int, default=10, help="Max active hosts to deep-fuzz (default: 10)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress console banner")

    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    in_scope = [x.strip() for x in args.in_scope.split(",") if x.strip()]
    if not in_scope:
        # Default in-scope is target and its subdomains
        in_scope = [args.target, f"*.{args.target}"]

    out_of_scope = [x.strip() for x in args.out_of_scope.split(",") if x.strip()]

    scope = ScopeConfig(
        in_scope_domains=in_scope,
        out_of_scope_regex=out_of_scope,
        max_rate_limit=args.rate_limit,
        researcher_header=f"X-Bug-Bounty-Researcher: {args.researcher}"
    )

    pipeline = ReconGuardPipeline(
        scope_config=scope,
        threads=args.threads,
        max_assets_to_fuzz=args.max_fuzz
    )

    def log_print(msg: str):
        if not args.quiet:
            print(msg)

    report = pipeline.execute(args.target, log_cb=log_print)

    # Export Markdown Report
    md_content = EvidenceEngine.generate_markdown_report(report)
    out_path = Path(args.output)
    out_path.write_text(md_content, encoding="utf-8")
    if not args.quiet:
        print(f"\n[+] Markdown Audit Report written to: {out_path.resolve()}")

    if args.json_output:
        json_path = Path(args.json_output)
        json_path.write_text(report.to_json(), encoding="utf-8")
        if not args.quiet:
            print(f"[+] Structured JSON Telemetry written to: {json_path.resolve()}")

    if not args.quiet:
        print("\n" + "=" * 65)
        print("               RECONGUARD ASSESSMENT SUMMARY")
        print("=" * 65)
        print(f"Target Domain: {report.target_domain}")
        print(f"Assets Discovered: {len(report.assets)} | Baselines: {len(report.baselines)}")
        print(f"Verified True-Positive Findings: {len(report.findings)}")
        for idx, f in enumerate(report.findings, 1):
            print(f"  {idx}. [{f.id}] ({f.severity}) {f.category} -> {f.url}")
        print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
