"""
Report Generator for Red Team Security Assessments.
Renders markdown and JSON outputs formatted strictly according to the PRD Red Team standard.
"""

import json
from typing import Dict, Any
from redteam_tool.models import SecurityAuditReport, Severity


class ReportGenerator:
    """Generates structured Markdown and JSON reports from a SecurityAuditReport."""

    def __init__(self, report: SecurityAuditReport):
        self.report = report

    def to_markdown(self) -> str:
        """Generates comprehensive markdown report conforming strictly to prompt specifications."""
        lines = []

        # Document Header
        lines.append(f"# 🛡️ Offensive Security & Red Team Assessment Report")
        lines.append(f"**Target Application:** {self.report.product_name} (v{self.report.version})  ")
        lines.append(f"**Assessment Date:** {self.report.assessment_date}  ")
        lines.append(f"**Lead Assessor:** {self.report.author_role}  ")
        lines.append(f"**Overall Risk Rating:** **{self.report.risk_rating.value}**  ")
        lines.append(f"**Scope & Classification:** Authorized Offensive Assessment / Pre-Implementation Security Review  ")
        lines.append("")
        lines.append("> ⚠️ **Confidentiality Notice:** This security assessment contains offensive threat models, vulnerability analysis, and conceptual attack scenarios designed for authorized product defense, bug bounty mitigation, and secure development.")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Section 1: Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(f"A comprehensive offensive security evaluation was conducted against the **{self.report.product_name}** Product Requirements Document (PRD). As an adversary and seasoned penetration tester with a decade of offensive security experience, the architecture exhibits promising functionality but harbors several critical and high-severity design vulnerabilities. These vulnerabilities center around **LLM prompt injection**, **insecure output handling (Stored XSS)**, **asymmetric resource exhaustion (Denial of Wallet)**, **broken multi-tenant object authorization (BOLA)**, and **unrestricted webhook SSRF**.")
        lines.append("")
        lines.append("### 1.1 Risk Rating & Severity Distribution")
        lines.append("")

        severity_counts = self.report.get_severity_counts()
        lines.append("| Severity | Count | Status |")
        lines.append("|---|:---:|---|")
        lines.append(f"| 🔴 **Critical** | {severity_counts.get(Severity.CRITICAL.value, 0)} | Immediate remediation required prior to MVP release |")
        lines.append(f"| 🟠 **High** | {severity_counts.get(Severity.HIGH.value, 0)} | High risk of compromise / exploitability |")
        lines.append(f"| 🟡 **Medium** | {severity_counts.get(Severity.MEDIUM.value, 0)} | Requires mitigation in Phase 1 |")
        lines.append(f"| 🟢 **Low** | {severity_counts.get(Severity.LOW.value, 0)} | Security hardening & hygiene |")
        lines.append(f"| ℹ️ **Info** | {severity_counts.get(Severity.INFO.value, 0)} | Informational & compliance observations |")
        lines.append(f"| **Total Findings** | **{len(self.report.findings)}** | — |")
        lines.append("")

        lines.append("### 1.2 Top 5 Risks Requiring Immediate Attention")
        lines.append("")
        top_risks = self.report.get_top_risks(5)
        lines.append("| ID | Risk / Vulnerability | Severity | CVSS 3.1 | Core Impact |")
        lines.append("|---|---|:---:|:---:|---|")
        for f in top_risks:
            lines.append(f"| **{f.id}** | {f.title} | `{f.severity.value}` | `{f.cvss_score}` | {f.affected_component} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Section 2: Threat Model
        lines.append("## 2. Threat Model")
        lines.append("")
        lines.append("### 2.1 Trust Boundaries")
        if self.report.threat_model:
            for tb in self.report.threat_model.trust_boundaries:
                lines.append(f"- 🔀 **Boundary:** {tb}")
        lines.append("")

        lines.append("### 2.2 Entry Points")
        if self.report.threat_model:
            for category, endpoints in self.report.threat_model.entry_points.items():
                lines.append(f"#### {category}")
                for ep in endpoints:
                    lines.append(f"- `{ep}`")
                lines.append("")

        lines.append("### 2.3 Asset Inventory Worth Protecting")
        if self.report.threat_model:
            for asset in self.report.threat_model.asset_inventory:
                lines.append(f"- 💎 {asset}")
        lines.append("")

        lines.append("### 2.4 STRIDE Threat Classification per Component")
        lines.append("")
        lines.append("| STRIDE Category | Component | Threat Description | Architectural Mitigation |")
        lines.append("|---|---|---|---|")
        if self.report.threat_model:
            for st in self.report.threat_model.stride_matrix:
                lines.append(f"| **{st.category.value}** | {st.component} | {st.threat} | {st.mitigation} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Section 3: Vulnerability Findings
        lines.append("## 3. Vulnerability Findings")
        lines.append("")
        for f in self.report.findings:
            lines.append(f"### {f.id}: {f.title}")
            lines.append(f"- **Severity:** `{f.severity.value}` | **CVSS 3.1 Score:** `{f.cvss_score}` (`{f.cvss_vector}`)")
            lines.append(f"- **Affected Component:** `{f.affected_component}`")
            if f.cwe_id:
                lines.append(f"- **CWE:** `{f.cwe_id}` | **OWASP Category:** `{f.owasp_id}`")
            lines.append("")
            lines.append(f"**Description:**  \n{f.description}")
            lines.append("")
            lines.append(f"**Conceptual Attack Scenario (Red Team PoC):**  \n> *For authorized testing only:*  \n{f.attack_scenario}")
            lines.append("")
            lines.append(f"**Impact:**  \n{f.impact}")
            lines.append("")
            lines.append(f"**Remediation & Countermeasures:**  \n{f.remediation}")
            lines.append("")
            lines.append("**References:**")
            for ref in f.references:
                lines.append(f"- {ref}")
            lines.append("")
            lines.append("---")
            lines.append("")

        # Section 4: AI/LLM-Specific Risks
        lines.append("## 4. AI/LLM-Specific Risks")
        lines.append("")
        lines.append("TaskFlow AI relies heavily on LLM integration (OpenAI GPT-4o / Anthropic Claude) for core business value. Red team analysis reveals severe exposure points:")
        lines.append("")
        if self.report.ai_risks:
            ai = self.report.ai_risks
            lines.append("### 4.1 Prompt Injection (Direct & Indirect)")
            for item in ai.prompt_injection_risks:
                lines.append(f"- ⚠️ {item}")
            lines.append("")

            lines.append("### 4.2 Insecure Output Handling")
            for item in ai.insecure_output_risks:
                lines.append(f"- ⚠️ {item}")
            lines.append("")

            lines.append("### 4.3 Training Data Poisoning & Feedback Loops")
            for item in ai.training_data_risks:
                lines.append(f"- ⚠️ {item}")
            lines.append("")

            lines.append("### 4.4 Model Denial of Service & Financial Exhaustion")
            for item in ai.model_dos_risks:
                lines.append(f"- ⚠️ {item}")
            lines.append("")

            lines.append("### 4.5 Sensitive Information Disclosure & System Prompt Leaks")
            for item in ai.sensitive_info_disclosure:
                lines.append(f"- ⚠️ {item}")
            lines.append("")

            lines.append("### 4.6 Excessive Agency & Unsafe External Tooling")
            for item in ai.excessive_agency:
                lines.append(f"- ⚠️ {item}")
            lines.append("")

            lines.append("### 4.7 Overreliance on AI Outputs")
            for item in ai.overreliance_risks:
                lines.append(f"- ⚠️ {item}")
            lines.append("")

        lines.append("---")
        lines.append("")

        # Section 5: API & Integration Risks
        lines.append("## 5. API & Integration Risks")
        lines.append("")
        if self.report.api_risks:
            api = self.report.api_risks
            lines.append("### 5.1 OAuth / OIDC Misconfigurations")
            for item in api.oauth_misconfig:
                lines.append(f"- 🔑 {item}")
            lines.append("")

            lines.append("### 5.2 Third-Party API Abuse & Token Leakage")
            for item in api.third_party_abuse:
                lines.append(f"- 🔌 {item}")
            lines.append("")

            lines.append("### 5.3 Webhook / Callback SSRF")
            for item in api.webhook_ssrf:
                lines.append(f"- 🌐 {item}")
            lines.append("")

            lines.append("### 5.4 API Key Leakage & Storage Flaws")
            for item in api.api_key_exposure:
                lines.append(f"- 🛡️ {item}")
            lines.append("")

            lines.append("### 5.5 Rate Limiting & Throttling Gaps")
            for item in api.rate_limiting_gaps:
                lines.append(f"- ⏱️ {item}")
            lines.append("")

        lines.append("---")
        lines.append("")

        # Section 6: Compliance & Privacy Gaps
        lines.append("## 6. Compliance & Privacy Gaps")
        lines.append("")
        if self.report.compliance_gaps:
            comp = self.report.compliance_gaps
            lines.append("### 6.1 PII Handling & Trans-Border Data Flows")
            for item in comp.pii_handling:
                lines.append(f"- 📋 {item}")
            lines.append("")

            lines.append("### 6.2 Data Retention & Inactive Account Purging")
            for item in comp.data_retention:
                lines.append(f"- ⏳ {item}")
            lines.append("")

            lines.append("### 6.3 Consent Mechanisms & Profiling Rights")
            for item in comp.consent_mechanisms:
                lines.append(f"- 📝 {item}")
            lines.append("")

            lines.append("### 6.4 GDPR & CCPA Compliance Gaps")
            for item in comp.gdpr_ccpa_items:
                lines.append(f"- ⚖️ {item}")
            lines.append("")

            lines.append("### 6.5 Encryption at Rest & In Transit")
            for item in comp.encryption_standards:
                lines.append(f"- 🔒 {item}")
            lines.append("")

        lines.append("---")
        lines.append("")

        # Section 7: Red Team Test Plan
        lines.append("## 7. Red Team Test Plan")
        lines.append("")
        lines.append("The following authorized penetration testing plan is prioritized by business risk and technical exploitability:")
        lines.append("")
        lines.append("| Test ID | Target Area | Risk | Primary Toolset | Test Scenario | Success Criteria |")
        lines.append("|---|---|:---:|---|---|---|")
        for tc in self.report.test_plan:
            tool_str = ", ".join(tc.tools)
            lines.append(f"| **{tc.id}** | {tc.target_area} | `{tc.severity.value}` | `{tool_str}` | {tc.scenario} | {tc.success_criteria} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Section 8: Secure Development Recommendations
        lines.append("## 8. Secure Development Recommendations")
        lines.append("")
        if self.report.secure_dev:
            sd = self.report.secure_dev
            lines.append("### 8.1 Secure Coding Checklist")
            for item in sd.secure_coding_checklist:
                lines.append(f"- [ ] {item}")
            lines.append("")

            lines.append("### 8.2 Security Controls to Implement")
            for item in sd.security_controls:
                lines.append(f"- 🛡️ {item}")
            lines.append("")

            lines.append("### 8.3 Monitoring & Detection Rules (SIEM / SOC)")
            for item in sd.monitoring_rules:
                lines.append(f"- 📡 {item}")
            lines.append("")

            lines.append("### 8.4 Incident Response Triggers")
            for item in sd.incident_response_triggers:
                lines.append(f"- 🚨 {item}")
            lines.append("")

        lines.append("---")
        lines.append("*Report generated autonomously by Red Team PRD Security Auditor.*")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Converts report to structured JSON representation."""
        data = {
            "product_name": self.report.product_name,
            "version": self.report.version,
            "assessment_date": self.report.assessment_date,
            "author_role": self.report.author_role,
            "risk_rating": self.report.risk_rating.value,
            "severity_counts": self.report.get_severity_counts(),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "affected_component": f.affected_component,
                    "description": f.description,
                    "attack_scenario": f.attack_scenario,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "references": f.references,
                    "cwe_id": f.cwe_id,
                    "owasp_id": f.owasp_id,
                }
                for f in self.report.findings
            ],
            "threat_model": {
                "trust_boundaries": self.report.threat_model.trust_boundaries if self.report.threat_model else [],
                "entry_points": self.report.threat_model.entry_points if self.report.threat_model else {},
                "asset_inventory": self.report.threat_model.asset_inventory if self.report.threat_model else [],
                "stride": [
                    {
                        "category": s.category.value,
                        "component": s.component,
                        "threat": s.threat,
                        "mitigation": s.mitigation,
                    }
                    for s in (self.report.threat_model.stride_matrix if self.report.threat_model else [])
                ],
            },
            "test_plan": [
                {
                    "id": tc.id,
                    "name": tc.name,
                    "target_area": tc.target_area,
                    "severity": tc.severity.value,
                    "tools": tc.tools,
                    "scenario": tc.scenario,
                    "success_criteria": tc.success_criteria,
                }
                for tc in self.report.test_plan
            ],
        }
        return json.dumps(data, indent=2)
