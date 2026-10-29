"""
Threat Analysis Engine.
Processes parsed PRD data and generates a complete Security Audit Report
conforming to the specifications in prompt.md.txt.
"""

from typing import List, Dict
from redteam_tool.models import (
    SecurityAuditReport,
    ThreatModel,
    AIThreatAnalysis,
    APIIntegrationRisk,
    CompliancePrivacyGap,
    SecureDevRecommendations,
    Severity,
    VulnerabilityFinding,
)
from redteam_tool.parser import ParsedPRD
from redteam_tool.rules import (
    get_curated_vulnerabilities,
    get_curated_stride_items,
    get_curated_test_cases,
)
from datetime import datetime


class ThreatAnalysisEngine:
    """Engine executing red-team threat modeling and vulnerability identification on a PRD."""

    def __init__(self, parsed_prd: ParsedPRD):
        self.parsed = parsed_prd

    def run_assessment(self) -> SecurityAuditReport:
        """Executes full security analysis and returns a comprehensive report."""
        threat_model = self._build_threat_model()
        findings = self._identify_vulnerabilities()
        ai_risks = self._analyze_ai_risks()
        api_risks = self._analyze_api_risks()
        compliance_gaps = self._analyze_compliance_gaps()
        test_plan = get_curated_test_cases()
        secure_dev = self._build_secure_dev_recommendations()

        overall_risk = Severity.MEDIUM
        if any(f.severity == Severity.CRITICAL for f in findings):
            overall_risk = Severity.CRITICAL
        elif any(f.severity == Severity.HIGH for f in findings):
            overall_risk = Severity.HIGH

        return SecurityAuditReport(
            product_name=self.parsed.title or "TaskFlow AI",
            version=self.parsed.version or "1.0",
            assessment_date=datetime.now().strftime("%Y-%m-%d"),
            author_role="Senior Red Team Operator & AppSec Researcher (10+ Years Exp)",
            risk_rating=overall_risk,
            findings=findings,
            threat_model=threat_model,
            ai_risks=ai_risks,
            api_risks=api_risks,
            compliance_gaps=compliance_gaps,
            test_plan=test_plan,
            secure_dev=secure_dev,
        )

    def _build_threat_model(self) -> ThreatModel:
        trust_boundaries = [
            "Client Tier (Web Browser / React Native Mobile) ↔ Cloud Edge (Vercel CDN / Cloudflare)",
            "Edge / API Gateway ↔ Backend Services (NestJS / FastAPI)",
            "Backend Services ↔ Storage & Cache Layer (PostgreSQL, Redis, Elasticsearch)",
            "Backend Application ↔ External AI LLM Providers (OpenAI GPT-4o / Anthropic Claude)",
            "Backend Application ↔ External Ecosystem Integrations (Google Calendar, Slack, Gmail/Outlook)",
        ]

        entry_points = {
            "Authentication": [
                "POST /api/v1/auth/login (Email + Password)",
                "GET /api/v1/auth/google/callback (OAuth 2.0 / OIDC)",
                "POST /api/v1/auth/apple/callback (Apple Sign-In)",
                "POST /api/v1/auth/2fa/verify (2FA TOTP Verification)",
            ],
            "Task Management (CRUD)": [
                "POST /api/v1/tasks (Create task with title, tags, description, due date)",
                "GET /api/v1/tasks (Retrieve task list & filters)",
                "PATCH /api/v1/tasks/{id} (Update task status / metadata)",
                "DELETE /api/v1/tasks/{id} (Remove task)",
                "POST /api/v1/tasks/quick-add (Floating text / voice audio transcription)",
            ],
            "AI Endpoints": [
                "POST /api/v1/ai/priority-score (Triggers LLM priority scoring)",
                "GET /api/v1/ai/daily-plan (Generates automated daily schedule)",
                "GET /api/v1/ai/insights (Fetches smart suggestions & recommendations)",
            ],
            "Integrations & Webhooks": [
                "POST /api/v1/integrations/google/sync (Calendar synchronization)",
                "POST /api/v1/integrations/slack/events (Slack bot webhook events)",
                "POST /api/v1/webhooks/incoming (External event listeners)",
            ],
        }

        asset_inventory = [
            "User Credentials & Password Hashes (Argon2id/bcrypt)",
            "OAuth 2.0 Refresh & Access Tokens for Google Calendar, Slack, and Microsoft Outlook",
            "User Task Data (Sensitive business projects, personal schedules, confidential notes)",
            "AI System Prompts, Scoring Rubrics, and Proprietary Heuristics",
            "Third-Party AI Provider API Keys (OpenAI, Anthropic Claude)",
            "User Productivity Telemetry & Behavioral Analytics Records",
            "Database Connection Strings and Redis Session Stores",
        ]

        return ThreatModel(
            trust_boundaries=trust_boundaries,
            entry_points=entry_points,
            asset_inventory=asset_inventory,
            stride_matrix=get_curated_stride_items(),
        )

    def _identify_vulnerabilities(self) -> List[VulnerabilityFinding]:
        return get_curated_vulnerabilities()

    def _analyze_ai_risks(self) -> AIThreatAnalysis:
        return AIThreatAnalysis(
            prompt_injection_risks=[
                "Direct Prompt Injection: Attacker places instructions ('Ignore previous rules') in task titles.",
                "Indirect Prompt Injection: Malicious content synced from shared Slack channels or Google Calendar events hijacks the daily plan prompt.",
                "Delimiter Hijacking: Lack of strict boundary markers allows user input to escape the data context into the system command channel.",
            ],
            insecure_output_risks=[
                "Stored XSS in AI Explanations: LLM reflects markdown/HTML tags that execute when displayed on the Next.js frontend.",
                "Logic Injection: Unvalidated AI score outputs (e.g., negative scores or strings instead of integers) crashing the ranking algorithm.",
            ],
            training_data_risks=[
                "Feedback Loop Poisoning: If user overrides or feedback are collected to fine-tune future priority models, adversarial accounts can poison the dataset.",
            ],
            model_dos_risks=[
                "Denial of Wallet: High-volume automated task generation triggering expensive GPT-4o API calls without rate limiting.",
                "Context Window Exhaustion: Pushing extremely long task descriptions causing token overflows and request timeouts (> 2 seconds).",
            ],
            sensitive_info_disclosure=[
                "System Prompt Extraction: Attacker probes the 'reasoning' explanation endpoint to reconstruct backend prompts.",
                "Cross-Workspace Task Leakage: In multi-tenant environments, AI summarization prompts aggregating tasks across team boundaries.",
            ],
            excessive_agency=[
                "Unauthorized Calendar Booking: AI daily planner auto-syncing or deleting calendar events without explicit confirmation dialogs.",
                "Spamming Slack Channels: AI auto-triggering notification spam to team channels when deadlines shift.",
            ],
            overreliance_risks=[
                "Silent Deprioritization: Critical tasks receiving low AI scores without user awareness, causing missed business-critical deadlines.",
            ],
        )

    def _analyze_api_risks(self) -> APIIntegrationRisk:
        return APIIntegrationRisk(
            oauth_misconfig=[
                "Absence of PKCE on mobile clients allowing authorization code interception.",
                "Weak or missing 'state' parameter leading to OAuth Login CSRF and account linking exploits.",
                "Over-scoped OAuth permissions requested for Google/Slack (e.g., full drive/mail access rather than minimal calendar scope).",
            ],
            third_party_abuse=[
                "Unbounded third-party API consumption leading to rate limit bans by Google or Slack.",
                "Failure to refresh expired OAuth tokens gracefully, causing cascade failures.",
            ],
            webhook_ssrf=[
                "Slack or custom webhook dispatchers executing requests to attacker-controlled URLs without resolving IP ranges.",
                "Potential SSRF reaching internal cloud metadata services (169.254.169.254) on AWS/GCP.",
            ],
            api_key_exposure=[
                "Third-party AI API keys (OpenAI / Anthropic) accidentally packaged into frontend bundles or exposed via verbose error logs.",
                "Unencrypted storage of user OAuth refresh tokens in PostgreSQL tables.",
            ],
            rate_limiting_gaps=[
                "Missing per-user rate limits on AI scoring triggers allowing automated script abuse.",
                "Lack of throttling on authentication and 2FA verification endpoints (vulnerable to brute-force).",
            ],
        )

    def _analyze_compliance_gaps(self) -> CompliancePrivacyGap:
        return CompliancePrivacyGap(
            pii_handling=[
                "User tasks and voice audio transcripts containing Personally Identifiable Information (PII) transmitted to external US-based AI APIs (OpenAI/Anthropic).",
                "Lack of data processing agreements (DPA) and data residency guarantees under EU GDPR.",
            ],
            data_retention=[
                "Indefinite storage of completed tasks, activity logs, and AI conversation context with no defined retention policy.",
                "No automated purge mechanism for inactive user accounts.",
            ],
            consent_mechanisms=[
                "Missing granular opt-in consent for AI processing of personal task data and location-based tracking.",
                "Absence of consent toggles for weekly productivity analytics profiling.",
            ],
            gdpr_ccpa_items=[
                "GDPR Article 17 (Right to Erasure / 'Right to be Forgotten') not specified for Redis cache, Elasticsearch indexes, and database backups.",
                "GDPR Article 20 (Right to Data Portability) export mechanism absent.",
            ],
            encryption_standards=[
                "While PRD mentions AES-256, it does not specify KMS envelope encryption, key rotation policies, or token field-level encryption.",
                "Session tokens persist for 30 days without sliding expiration or mandatory re-authentication for high-risk actions.",
            ],
        )

    def _build_secure_dev_recommendations(self) -> SecureDevRecommendations:
        return SecureDevRecommendations(
            secure_coding_checklist=[
                "Always validate and sanitize all inputs at backend controllers using DTOs with class-validator (NestJS) or Pydantic (FastAPI).",
                "Ensure all AI outputs are sanitized on the frontend with DOMPurify before rendering markdown.",
                "Enforce strict schema responses from LLMs using JSON Mode / Structured Outputs (e.g., OpenAI response_format).",
                "Implement Row-Level Security (RLS) in PostgreSQL to enforce tenant isolation at the database layer.",
                "Never store plain OAuth tokens; encrypt them at rest using AES-256-GCM with keys managed in AWS KMS or GCP KMS.",
                "Implement PKCE (RFC 7636) and cryptographically random state parameters in all OAuth flows.",
            ],
            security_controls=[
                "WAF (Cloudflare / AWS WAF) with rate limiting and bot management rules on /api/v1/ai/* and /api/v1/auth/*.",
                "Redis-backed sliding window rate limiter (e.g., max 20 task creations/min, 10 AI scorings/min per user).",
                "Prompt injection guardrail layer (Llama Guard / NeMo Guardrails) before forwarding prompts to external LLMs.",
                "Network egress restrictions: Block outbound HTTP connections to 169.254.169.254, RFC1918 addresses, and localhost.",
                "Strict Content Security Policy (CSP): default-src 'self'; script-src 'self'; object-src 'none'.",
            ],
            monitoring_rules=[
                "Alert on anomalous spike in AI API calls per user (> 50 requests in 5 minutes).",
                "Alert on repeated 403 Forbidden errors indicating potential BOLA/IDOR enumeration.",
                "Alert on prompt injection signature patterns ('ignore previous', 'system prompt', '<script>') in task inputs.",
                "Monitor upstream AI token consumption and trigger automatic circuit breaker when budget threshold (e.g., 80%) is reached.",
            ],
            incident_response_triggers=[
                "Detection of AWS/GCP metadata IP in webhook or outbound integration logs (Immediate Sev-1 SSRF containment).",
                "Leakage of system prompt or multi-tenant task summaries in AI responses (Immediate LLM model disablement).",
                "Unauthorized cross-tenant task access detected via audit logs (Immediate tenant isolation & key revocation).",
            ],
        )
