"""
Unit tests for Red Team Security Assessment Tool.
Verifies PRD parsing, threat modeling engine, STRIDE generation, and report generation.
"""

import unittest
from pathlib import Path
from redteam_tool.parser import PRDParser
from redteam_tool.engine import ThreatAnalysisEngine
from redteam_tool.reporter import ReportGenerator
from redteam_tool.models import Severity


SAMPLE_PRD = """
# Product Requirements Document (PRD)
## TaskFlow AI — Test System
**Versi:** 1.0

## 4. Fitur Utama
- Membuat tugas dengan AI Priority Scoring (OpenAI GPT-4o).
- Integrasi Google Calendar dan Slack.
- Kolaborasi tim (Team tier).

## 8. Arsitektur & Teknologi
Next.js 14, Tailwind CSS, FastAPI, PostgreSQL, Redis, OpenAI GPT-4o.
"""


class TestRedTeamTool(unittest.TestCase):

    def test_parser_extracts_metadata(self):
        parser = PRDParser(SAMPLE_PRD)
        parsed = parser.parse()
        self.assertIn("TaskFlow AI", parsed.title)
        self.assertEqual(parsed.version, "1.0")
        self.assertTrue(parsed.has_ai_llm)
        self.assertTrue(parsed.has_multi_tenancy)
        self.assertIn("openai", parsed.tech_stack.get("AI/LLM", []))

    def test_engine_generates_report(self):
        parser = PRDParser(SAMPLE_PRD)
        parsed = parser.parse()
        engine = ThreatAnalysisEngine(parsed)
        report = engine.run_assessment()

        self.assertIsNotNone(report)
        self.assertIn(report.risk_rating, [Severity.CRITICAL, Severity.HIGH])
        self.assertTrue(len(report.findings) >= 5)
        self.assertIsNotNone(report.threat_model)
        self.assertTrue(len(report.threat_model.stride_matrix) >= 5)
        self.assertTrue(len(report.test_plan) >= 5)

    def test_reporter_renders_all_sections(self):
        parser = PRDParser(SAMPLE_PRD)
        parsed = parser.parse()
        engine = ThreatAnalysisEngine(parsed)
        report = engine.run_assessment()

        reporter = ReportGenerator(report)
        md = reporter.to_markdown()

        # Check all 8 required sections from prompt.md.txt
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Threat Model", md)
        self.assertIn("## 3. Vulnerability Findings", md)
        self.assertIn("## 4. AI/LLM-Specific Risks", md)
        self.assertIn("## 5. API & Integration Risks", md)
        self.assertIn("## 6. Compliance & Privacy Gaps", md)
        self.assertIn("## 7. Red Team Test Plan", md)
        self.assertIn("## 8. Secure Development Recommendations", md)

        # Check JSON rendering
        json_output = reporter.to_json()
        self.assertIn("TaskFlow AI", json_output)
        self.assertIn("findings", json_output)


if __name__ == "__main__":
    unittest.main()
