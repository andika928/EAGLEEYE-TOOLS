"""
Models for Red Team Security Assessment Tool.
Provides strongly typed dataclasses for findings, threat models, STRIDE elements,
and complete security audit reports.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass
class STRIDEItem:
    category: STRIDECategory
    component: str
    threat: str
    mitigation: str


@dataclass
class VulnerabilityFinding:
    id: str
    title: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    affected_component: str
    description: str
    attack_scenario: str
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None


@dataclass
class ThreatModel:
    trust_boundaries: List[str] = field(default_factory=list)
    entry_points: Dict[str, List[str]] = field(default_factory=dict)
    asset_inventory: List[str] = field(default_factory=list)
    stride_matrix: List[STRIDEItem] = field(default_factory=list)


@dataclass
class AIThreatAnalysis:
    prompt_injection_risks: List[str] = field(default_factory=list)
    insecure_output_risks: List[str] = field(default_factory=list)
    training_data_risks: List[str] = field(default_factory=list)
    model_dos_risks: List[str] = field(default_factory=list)
    sensitive_info_disclosure: List[str] = field(default_factory=list)
    excessive_agency: List[str] = field(default_factory=list)
    overreliance_risks: List[str] = field(default_factory=list)


@dataclass
class APIIntegrationRisk:
    oauth_misconfig: List[str] = field(default_factory=list)
    third_party_abuse: List[str] = field(default_factory=list)
    webhook_ssrf: List[str] = field(default_factory=list)
    api_key_exposure: List[str] = field(default_factory=list)
    rate_limiting_gaps: List[str] = field(default_factory=list)


@dataclass
class CompliancePrivacyGap:
    pii_handling: List[str] = field(default_factory=list)
    data_retention: List[str] = field(default_factory=list)
    consent_mechanisms: List[str] = field(default_factory=list)
    gdpr_ccpa_items: List[str] = field(default_factory=list)
    encryption_standards: List[str] = field(default_factory=list)


@dataclass
class TestCase:
    id: str
    name: str
    target_area: str
    severity: Severity
    tools: List[str]
    scenario: str
    success_criteria: str


@dataclass
class SecureDevRecommendations:
    secure_coding_checklist: List[str] = field(default_factory=list)
    security_controls: List[str] = field(default_factory=list)
    monitoring_rules: List[str] = field(default_factory=list)
    incident_response_triggers: List[str] = field(default_factory=list)


@dataclass
class SecurityAuditReport:
    product_name: str
    version: str
    assessment_date: str
    author_role: str
    risk_rating: Severity
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    threat_model: Optional[ThreatModel] = None
    ai_risks: Optional[AIThreatAnalysis] = None
    api_risks: Optional[APIIntegrationRisk] = None
    compliance_gaps: Optional[CompliancePrivacyGap] = None
    test_plan: List[TestCase] = field(default_factory=list)
    secure_dev: Optional[SecureDevRecommendations] = None

    def get_severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def get_top_risks(self, limit: int = 5) -> List[VulnerabilityFinding]:
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.cvss_score),
            reverse=True,
        )
        return sorted_findings[:limit]
