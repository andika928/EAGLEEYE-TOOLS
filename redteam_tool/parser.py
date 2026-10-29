"""
PRD and Technical Specification Parser.
Extracts architectural components, data flows, feature sets, tech stack,
and security indicators from markdown PRD files.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass
class ParsedPRD:
    title: str = "Unknown System"
    version: str = "1.0"
    raw_text: str = ""
    sections: Dict[str, str] = field(default_factory=dict)
    tech_stack: Dict[str, List[str]] = field(default_factory=dict)
    features: List[str] = field(default_factory=list)
    integrations: List[str] = field(default_factory=list)
    user_roles_tiers: List[str] = field(default_factory=list)
    has_ai_llm: bool = False
    has_oauth: bool = False
    has_voice_input: bool = False
    has_multi_tenancy: bool = False
    has_webhooks: bool = False
    has_notifications: bool = False
    has_analytics: bool = False


class PRDParser:
    """Parser that scans a PRD markdown file and extracts key security markers."""

    def __init__(self, content: str):
        self.content = content
        self.parsed = ParsedPRD(raw_text=content)

    def parse(self) -> ParsedPRD:
        self._extract_title_and_version()
        self._extract_sections()
        self._extract_features()
        self._detect_tech_stack()
        self._detect_security_indicators()
        return self.parsed

    def _extract_title_and_version(self) -> None:
        # Match TaskFlow AI or main heading
        product_match = re.search(r"##\s*([A-Za-z0-9\s]+)\s*—\s*([^\n]+)", self.content)
        if product_match:
            self.parsed.title = product_match.group(1).strip()
        else:
            title_match = re.search(r"^#+\s*([^\n]+)", self.content, re.MULTILINE)
            if title_match:
                candidate = re.sub(r"[^\w\s\-\.]", "", title_match.group(1)).strip()
                if candidate and "Product Requirements" not in candidate:
                    self.parsed.title = candidate

        version_match = re.search(r"\*\*Versi:\*\*\s*([0-9.]+)", self.content, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r"Version:\s*([0-9.]+)", self.content, re.IGNORECASE)
        if version_match:
            self.parsed.version = version_match.group(1).strip()

    def _extract_sections(self) -> None:
        matches = list(re.finditer(r"^##\s+([0-9.]*\s*[^#\n]+)", self.content, re.MULTILINE))
        for i, match in enumerate(matches):
            section_title = match.group(1).strip()
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(self.content)
            self.parsed.sections[section_title] = self.content[start:end].strip()

    def _extract_features(self) -> None:
        feature_section = ""
        for name, text in self.parsed.sections.items():
            if re.search(r"fitur|feature|scope|user stories", name, re.IGNORECASE):
                feature_section += "\n" + text

        for line in feature_section.splitlines():
            line = line.strip()
            if line.startswith("- ") or line.startswith("* "):
                clean_feat = line[2:].strip()
                if clean_feat and len(clean_feat) > 3:
                    self.parsed.features.append(clean_feat)

    def _detect_tech_stack(self) -> None:
        content_lower = self.content.lower()

        tech_catalog = {
            "Frontend": ["next.js", "react", "vue", "angular", "tailwind", "flutter", "react native"],
            "Backend": ["nestjs", "node.js", "node", "fastapi", "python", "express", "go", "gin", "spring"],
            "Database": ["postgresql", "postgres", "redis", "mongodb", "mysql", "elasticsearch"],
            "AI/LLM": ["openai", "gpt-4o", "gpt-4", "anthropic", "claude", "gemini", "langchain", "llamaindex"],
            "Cloud/Hosting": ["aws", "gcp", "vercel", "cloudflare", "azure", "docker", "kubernetes"],
        }

        for category, keywords in tech_catalog.items():
            found = [kw for kw in keywords if kw in content_lower]
            if found:
                self.parsed.tech_stack[category] = found

    def _detect_security_indicators(self) -> None:
        content_lower = self.content.lower()

        self.parsed.has_ai_llm = any(
            k in content_lower for k in ["ai", "gpt", "claude", "llm", "openai", "model", "prompt"]
        )
        self.parsed.has_oauth = any(
            k in content_lower for k in ["oauth", "google", "apple sign-in", "login with", "sso"]
        )
        self.parsed.has_voice_input = any(
            k in content_lower for k in ["voice", "suara", "transcription", "audio"]
        )
        self.parsed.has_multi_tenancy = any(
            k in content_lower for k in ["team", "kolaborasi", "shared project", "organization", "multi-tenant"]
        )
        self.parsed.has_webhooks = any(
            k in content_lower for k in ["webhook", "callback", "slack", "calendar", "integration", "integrasi"]
        )
        self.parsed.has_notifications = any(
            k in content_lower for k in ["notifikasi", "notification", "push", "reminder", "pengingat"]
        )
        self.parsed.has_analytics = any(
            k in content_lower for k in ["analitik", "analytics", "laporan", "report", "completion rate"]
        )

        integrations = []
        for integ in ["google calendar", "slack", "gmail", "outlook", "email", "calendar"]:
            if integ in content_lower and integ not in integrations:
                integrations.append(integ)
        self.parsed.integrations = integrations

        tiers = []
        for tier in ["free", "pro", "team", "enterprise", "premium"]:
            if tier in content_lower and tier not in tiers:
                tiers.append(tier.capitalize())
        self.parsed.user_roles_tiers = tiers
