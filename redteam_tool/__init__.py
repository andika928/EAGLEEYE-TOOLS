"""
Red Team Security Assessment & Threat Modeling Tool.
Built according to the offensive security specification in prompt.md.txt.
"""

from redteam_tool.models import (
    SecurityAuditReport,
    VulnerabilityFinding,
    ThreatModel,
    Severity,
    STRIDECategory,
)
from redteam_tool.parser import PRDParser, ParsedPRD
from redteam_tool.engine import ThreatAnalysisEngine
from redteam_tool.reporter import ReportGenerator

__version__ = "1.0.0"
__all__ = [
    "SecurityAuditReport",
    "VulnerabilityFinding",
    "ThreatModel",
    "Severity",
    "STRIDECategory",
    "PRDParser",
    "ParsedPRD",
    "ThreatAnalysisEngine",
    "ReportGenerator",
]
