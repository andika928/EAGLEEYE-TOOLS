"""
ReconGuard evidence-led active reconnaissance platform.
Standardized Senior Security Engineer implementation conforming to prd.md2.

Modules:
- scope_guard: Stage 1 Scope & Policy Guard
- subfinder_core: Stage 2 Passive & Active Subdomain Enumeration with Wildcard Filtering
- httpx_core: Stage 3 HTTP Probing & DOM/Favicon Hash Clustering
- ffuf_core: Stage 4 Auto-Calibrated Fuzzing with Baseline Delta Engine
- evidence_engine: Stage 5 Raw HTTP Evidence & Baseline Diff Engine
- pipeline: End-to-end Orchestrator with Circuit Breaker & Safe-Method Enforcers
"""

from .models import (
    ScopeConfig,
    AssetRecord,
    BaselineFingerprint,
    FindingEvidence,
    DiffSummary,
    ReconGuardReport,
)
from .scope_guard import ScopeGuard
from .subfinder_core import SubfinderCore
from .httpx_core import HttpxCore
from .ffuf_core import FfufCore
from .evidence_engine import EvidenceEngine
from .pipeline import ReconGuardPipeline

__version__ = "1.0.0"
__all__ = [
    "ScopeConfig",
    "AssetRecord",
    "BaselineFingerprint",
    "FindingEvidence",
    "DiffSummary",
    "ReconGuardReport",
    "ScopeGuard",
    "SubfinderCore",
    "HttpxCore",
    "FfufCore",
    "EvidenceEngine",
    "ReconGuardPipeline",
]
