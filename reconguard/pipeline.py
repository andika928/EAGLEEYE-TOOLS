"""
ReconGuard Modular Pipeline Orchestrator.
Coordinates Stage 1 (Scope) -> Stage 2 (Subfinder) -> Stage 3 (Httpx) ->
Stage 4 (Calibrated Ffuf) -> Stage 5 (Evidence & Diff Generation).
Enforces strict rate limiting, circuit breaker on 429/503, and non-destructive probing.
"""

from __future__ import annotations
import time
from typing import List, Dict, Any, Optional, Callable
from .models import (
    ScopeConfig,
    AssetRecord,
    BaselineFingerprint,
    FindingEvidence,
    ReconGuardReport,
)
from .scope_guard import ScopeGuard
from .subfinder_core import SubfinderCore
from .httpx_core import HttpxCore
from .ffuf_core import FfufCore
from .evidence_engine import EvidenceEngine
from .tool_stage import automatic_tool_stages


class ReconGuardPipeline:
    """Full-Spectrum ASM & Reconnaissance Pipeline."""

    def __init__(
        self,
        scope_config: Optional[ScopeConfig] = None,
        threads: int = 30,
        timeout: float = 3.5,
        max_assets_to_fuzz: int = 15
    ):
        self.scope = scope_config or ScopeConfig()
        self.scope_guard = ScopeGuard(self.scope)
        self.threads = threads
        self.timeout = timeout
        self.max_assets_to_fuzz = max_assets_to_fuzz

    def execute(
        self,
        target_domain: str,
        log_cb: Optional[Callable[[str], None]] = None
    ) -> ReconGuardReport:
        """
        Execute end-to-end calibrated reconnaissance and evidence validation.
        """
        logs: List[str] = []

        def log(msg: str):
            timestamped = f"[{time.strftime('%H:%M:%S')}] {msg}"
            logs.append(timestamped)
            if log_cb:
                log_cb(timestamped)

        clean_target = self.scope_guard.normalize_host(target_domain)
        log(f"INIT // ReconGuard ASM Pipeline started for target '{clean_target}'")

        # =====================================================================
        # STAGE 1: Scope & Policy Guard
        # =====================================================================
        log(f"STAGE 1 // [Scope Guard] Validating scope permissions for '{clean_target}'...")
        is_allowed, scope_reason = self.scope_guard.is_in_scope(clean_target)
        if not is_allowed:
            log(f"[!] [Scope Guard] Execution ABORTED: {scope_reason}")
            return ReconGuardReport(
                program_name=f"ReconGuard-{clean_target}",
                target_domain=clean_target,
                scan_date=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                scope=self.scope,
                summary={"status": "ABORTED", "reason": scope_reason},
                telemetry_logs=logs
            )
        log(f"[+] [Scope Guard] Authorization verified: {scope_reason}")

        # =====================================================================
        # STAGE 2: Asset Discovery (Subfinder Core)
        # =====================================================================
        log(f"STAGE 2 // [Subfinder Core] Discovering subdomains & resolving DNS with Wildcard filter...")
        subfinder = SubfinderCore(threads=self.threads, timeout=self.timeout)
        sub_results = subfinder.run(clean_target, log_cb=log)
        raw_assets = sub_results.get("discovered_assets", [])

        # Filter discovered assets against Scope Guard (e.g. out-of-scope regex)
        scoped_assets = []
        for item in raw_assets:
            ok, _ = self.scope_guard.is_in_scope(item["host"])
            if ok:
                scoped_assets.append(item)
            else:
                log(f"[!] [Scope Filter] Dropped out-of-scope subdomain: {item['host']}")

        log(f"[+] [Subfinder Core] {len(scoped_assets)} in-scope targets scheduled for HTTP validation")

        # =====================================================================
        # STAGE 3: HTTP Probing (Httpx Core)
        # =====================================================================
        log(f"STAGE 3 // [Httpx Core] Probing live web services & DOM hash clustering...")
        httpx = HttpxCore(
            threads=self.threads,
            timeout=self.timeout,
            custom_header=self.scope.researcher_header
        )
        alive_assets: List[AssetRecord] = httpx.run(scoped_assets, log_cb=log)

        # =====================================================================
        # STAGE 4: Calibrated Fuzzing (Ffuf Core with Baseline Delta)
        # =====================================================================
        log(f"STAGE 4 // [Ffuf Core] Auto-Calibrating baselines & fuzzing high-value endpoints...")
        rate_delay = 1.0 / max(1.0, min(self.scope.max_rate_limit, 50.0))
        ffuf = FfufCore(
            timeout=self.timeout,
            custom_header=self.scope.researcher_header,
            rate_limit_delay=rate_delay
        )

        baselines: Dict[str, BaselineFingerprint] = {}
        all_findings: List[FindingEvidence] = []

        # Target top active assets (prioritizing status 200/302, unique clusters)
        fuzz_candidates = sorted(alive_assets, key=lambda a: (a.host != clean_target, a.status != 200))[:self.max_assets_to_fuzz]

        for asset in fuzz_candidates:
            try:
                baseline, findings = ffuf.fuzz_host(asset, log_cb=log)
                baselines[asset.host] = baseline
                all_findings.extend(findings)
            except Exception as exc:
                log(f"[!] [Ffuf Warning] Error probing {asset.host}: {exc}")

        # =====================================================================
        # STAGES 5 & 6: Automatic Dalfox and Nikto (same launch, no tool selection)
        # =====================================================================
        tool_target = target_domain if '://' in target_domain else f'https://{clean_target}/'
        tool_findings, tool_runs, tool_sources = automatic_tool_stages(tool_target, self.scope, log)
        all_findings.extend(tool_findings)
        log('STAGE 7 // [Evidence Engine] Compiling observations and source evidence')

        crit_count = sum(1 for f in all_findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in all_findings if f.severity == "HIGH")
        med_count = sum(1 for f in all_findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in all_findings if f.severity == "LOW")

        summary = {
            "status": "COMPLETED_WITH_GAPS" if any(run['state'] != 'finished' for run in tool_runs) or any(source.get('scan_metadata', {}).get('incomplete') for source in tool_sources) else "COMPLETED",
            "target": clean_target,
            "assets_discovered": len(scoped_assets),
            "live_endpoints": len(alive_assets),
            "calibrated_baselines": len(baselines),
            "verified_anomalies": len(all_findings),
            "observations": len(all_findings),
            "confirmed_vulnerabilities": 0,
            "severity_breakdown": {
                "CRITICAL": crit_count,
                "HIGH": high_count,
                "MEDIUM": med_count,
                "LOW": low_count
            },
            "wildcards_filtered": sub_results.get("wildcards_filtered", 0)
        }

        log(f"SUMMARY // Pipeline complete: {len(all_findings)} observations across {len(alive_assets)} live assets; check tool run states for coverage gaps")

        return ReconGuardReport(
            program_name=f"ReconGuard-{clean_target}",
            target_domain=clean_target,
            scan_date=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            scope=self.scope,
            assets=alive_assets,
            baselines=baselines,
            findings=all_findings,
            summary=summary,
            telemetry_logs=logs,
            tool_runs=tool_runs,
            tool_sources=tool_sources
        )
