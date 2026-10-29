#!/usr/bin/env python3
"""
Red Team Security Assessment & Threat Modeling CLI Tool.
Usage:
    python redteam_sec_auditor.py --prd PRD.MD --output REDTEAM_SECURITY_ASSESSMENT.md
"""

import sys
import os
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure UTF-8 console output for Windows CLI
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from redteam_tool.parser import PRDParser
from redteam_tool.engine import ThreatAnalysisEngine
from redteam_tool.reporter import ReportGenerator
from redteam_tool.models import Severity


BANNER = r"""
  ____           _   _____                      ____               _   _ _             
 |  _ \ ___   __| | |_   _|__  __ _ _ __ ___   / ___|  ___  ___   / \ (_) | _____ _ __ 
 | |_) / _ \ / _` |   | |/ _ \/ _` | '_ ` _ \  \___ \ / _ \/ __| / _ \| | |/ / _ \ '__|
 |  _ <  __/| (_| |   | |  __/ (_| | | | | | |  ___) |  __/ (__ / ___ \ |   <  __/ |   
 |_| \_\___| \__,_|   |_|\___|\__,_|_| |_| |_| |____/ \___|\___/_/   \_\_|_|\_\___|_|   
                     [ Offensive PRD Threat Modeler & Security Auditor ]
"""


def main():
    parser = argparse.ArgumentParser(
        description="Red Team PRD Threat Modeling & Vulnerability Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--prd",
        "-p",
        type=str,
        default="PRD.MD",
        help="Path to the PRD / SRS / Technical Specification markdown file (default: PRD.MD)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="REDTEAM_SECURITY_ASSESSMENT.md",
        help="Output path for the generated markdown report (default: REDTEAM_SECURITY_ASSESSMENT.md)",
    )
    parser.add_argument(
        "--json-output",
        "-j",
        type=str,
        default=None,
        help="Optional path to output the report in structured JSON format",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress console output and banner",
    )

    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    prd_path = Path(args.prd)
    if not prd_path.exists():
        print(f"[!] Error: Specified PRD file not found: {prd_path}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"[*] Reading and parsing PRD specification: {prd_path}")

    try:
        content = prd_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[!] Error reading {prd_path}: {e}", file=sys.stderr)
        sys.exit(1)

    # 1. Parse PRD
    parser_obj = PRDParser(content)
    parsed_prd = parser_obj.parse()

    if not args.quiet:
        print(f"[+] Product Identified: {parsed_prd.title} (v{parsed_prd.version})")
        print(f"[+] Detected Tech Stack Categories: {list(parsed_prd.tech_stack.keys())}")
        print(f"[+] Security Indicators: AI/LLM={parsed_prd.has_ai_llm}, OAuth={parsed_prd.has_oauth}, MultiTenancy={parsed_prd.has_multi_tenancy}")
        print(f"[*] Running Offensive Threat Modeling & STRIDE Analysis...")

    # 2. Run Threat Engine
    engine = ThreatAnalysisEngine(parsed_prd)
    report = engine.run_assessment()

    # 3. Generate Reports
    reporter = ReportGenerator(report)
    md_content = reporter.to_markdown()

    output_path = Path(args.output)
    output_path.write_text(md_content, encoding="utf-8")

    if not args.quiet:
        print(f"[+] Markdown Security Assessment Report written to: {output_path.resolve()}")

    if args.json_output:
        json_path = Path(args.json_output)
        json_path.write_text(reporter.to_json(), encoding="utf-8")
        if not args.quiet:
            print(f"[+] JSON Report written to: {json_path.resolve()}")

    # 4. Summary Output
    if not args.quiet:
        print("\n" + "=" * 60)
        print("                RED TEAM ASSESSMENT SUMMARY")
        print("=" * 60)
        print(f"Overall Risk Rating: {report.risk_rating.value}")
        counts = report.get_severity_counts()
        print(f"Findings: Critical={counts['CRITICAL']} | High={counts['HIGH']} | Medium={counts['MEDIUM']} | Low={counts['LOW']} | Info={counts['INFO']}")
        print("\nTop Critical & High Risk Findings:")
        for idx, finding in enumerate(report.get_top_risks(5), 1):
            print(f"  {idx}. [{finding.id}] ({finding.severity.value} - CVSS {finding.cvss_score}) {finding.title}")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
