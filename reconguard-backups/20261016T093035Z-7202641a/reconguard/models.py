"""
Data models for ReconGuard ASM & Zero-False-Positive Validation Platform.
Maps to database schema and pipeline objects specified in prd.md2 Section 5.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import json


@dataclass
class ScopeConfig:
    """Stage 1: Scope & Policy rules."""
    in_scope_domains: List[str] = field(default_factory=list)
    out_of_scope_regex: List[str] = field(default_factory=list)
    max_rate_limit: float = 10.0  # requests per second
    researcher_header: str = "X-Bug-Bounty-Researcher: ReconGuard-Pentester"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AssetRecord:
    """Stage 2 & 3: Discovered & Probed Host Asset."""
    id: str
    host: str
    ip: str = ""
    status: int = 0
    title: str = ""
    tech_stack: List[str] = field(default_factory=list)
    cdn_provider: str = ""
    dom_hash: str = ""
    favicon_hash: str = ""
    cluster_id: str = ""
    is_alive: bool = False
    ports: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineFingerprint:
    """Stage 4: Auto-Calibrated Soft-404 / Catch-All Profile for an Asset."""
    asset_host: str
    probe_paths: List[str] = field(default_factory=list)
    status_code: int = 404
    content_length_avg: float = 0.0
    word_count_avg: float = 0.0
    line_count_avg: float = 0.0
    content_type: str = ""
    body_hash: str = ""
    redirect_location: str = ""
    is_catch_all: bool = False
    is_spa_fallback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiffSummary:
    """Stage 5: Baseline vs Finding Difference Metrics."""
    status_delta: str
    bytes_delta: int
    words_delta: int
    content_type_delta: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FindingEvidence:
    """Stage 5: Verified True-Positive Finding with Raw HTTP Proof."""
    id: str
    asset_host: str
    endpoint_path: str
    url: str
    status_code: int
    confidence_score: str
    severity: str
    category: str
    raw_request: str
    raw_response_headers: Dict[str, str]
    raw_response_body: str
    diff_summary: DiffSummary
    curl_cmd: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class ReconGuardReport:
    """Complete Pipeline Result & Telemetry Export."""
    program_name: str
    target_domain: str
    scan_date: str
    scope: ScopeConfig
    assets: List[AssetRecord] = field(default_factory=list)
    baselines: Dict[str, BaselineFingerprint] = field(default_factory=dict)
    findings: List[FindingEvidence] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    telemetry_logs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_name": self.program_name,
            "target_domain": self.target_domain,
            "scan_date": self.scan_date,
            "scope": self.scope.to_dict(),
            "assets": [a.to_dict() for a in self.assets],
            "baselines": {k: v.to_dict() for k, v in self.baselines.items()},
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "telemetry_logs": self.telemetry_logs,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
