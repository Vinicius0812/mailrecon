"""Data models used across the application."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class DnsLookupResult:
    """Stores DNS and MX lookup data for a domain."""

    resolves: bool
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    spf_records: list[str] = field(default_factory=list)
    dmarc_records: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    domain_status: str = "unknown"
    email_acceptance_status: str = "unknown"
    spf_status: str = "unknown"
    dmarc_status: str = "unknown"
    dmarc_policy: str | None = None
    provider_family: str = "unknown_provider"
    null_mx: bool = False


@dataclass(slots=True)
class HibpResult:
    """Stores Have I Been Pwned query information."""

    queried: bool
    status: str
    breaches: list[dict] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class EmailTechnicalAssessment:
    """Stores non-intrusive technical email/domain assessment signals."""

    syntax_status: str = "unknown"
    domain_status: str = "unknown"
    mx_status: str = "unknown"
    spf_status: str = "unknown"
    dmarc_status: str = "unknown"
    provider_family: str = "unknown_provider"
    disposable_status: str = "unknown"
    role_account_status: str = "unknown"
    catch_all_status: str = "not_tested"
    review_priority_score: int = 0
    decision_reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReconResult:
    """Aggregates the full recon result for one email address."""

    email: str
    domain: str
    is_valid: bool
    dns: DnsLookupResult
    hibp: HibpResult
    technical_assessment: EmailTechnicalAssessment = field(
        default_factory=EmailTechnicalAssessment
    )
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Convert the result to a serializable dictionary."""
        return asdict(self)


@dataclass(slots=True)
class InvestigationInput:
    """Structured input for a reusable OSINT investigation."""

    names: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)
    candidate_emails: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EvidenceRecord:
    """Captures one OSINT evidence item and its provenance."""

    title: str
    category: str
    source: str
    reference: str
    collected_at: str
    method: str
    confidence: str
    confidence_score: int
    summary: str
    observations: str | None = None
    evidence_strength: str = "none"
    risk_level: str = "none"
    decision_reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EmailCandidate:
    """Represents one email candidate discovered during an investigation."""

    email: str
    masked_email: str
    domain: str
    source: str
    confidence: str
    confidence_score: int
    status: str
    notes: list[str] = field(default_factory=list)
    analysis: ReconResult | None = None
    evidence_strength: str = "none"
    risk_level: str = "none"
    review_priority_score: int = 0
    decision_reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    role_account_status: str = "not_role_account"
    disposable_status: str = "unknown"
    provider_family: str = "unknown_provider"


@dataclass(slots=True)
class ProfilePivot:
    """Represents a safe public-profile pivot suggestion."""

    platform: str
    handle: str
    profile_url: str
    search_url: str
    source: str
    confidence: str
    confidence_score: int
    status: str
    resolution_status: str = "not_checked"
    http_status_code: int | None = None
    final_url: str | None = None
    checked_at: str | None = None
    notes: list[str] = field(default_factory=list)
    evidence_strength: str = "weak_inferred"
    risk_level: str = "none"
    review_priority_score: int = 0
    ambiguity_reasons: list[str] = field(default_factory=list)
    matched_fields: list[str] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)
    conflicting_fields: list[str] = field(default_factory=list)
    decision_reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class InvestigationResult:
    """Aggregates reusable OSINT investigation data around email pivots."""

    query: InvestigationInput
    candidate_emails: list[EmailCandidate]
    profile_pivots: list[ProfilePivot]
    evidences: list[EvidenceRecord]
    findings: list[str]
    risks: list[str]
    pivot_suggestions: list[str]
    limitations: list[str]
    overall_confidence_score: int
    review_priority_score: int = 0
    confidence_breakdown: dict[str, int] = field(default_factory=dict)
    refinement_file_path: str | None = None
    refinement_excluded_links: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Convert the investigation result to a serializable dictionary."""
        return asdict(self)


@dataclass(slots=True)
class SafetyDecision:
    """Stores the safety gate decision for lab-only intrusive checks."""

    allowed: bool
    status: str
    reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SmtpLabCheckResult:
    """Stores the result of one lab-only SMTP interaction."""

    check: str
    status: str
    smtp_code: int | None = None
    message: str | None = None
    network_used: bool = False


@dataclass(slots=True)
class SmtpLabValidationResult:
    """Aggregates a lab-only SMTP validation run."""

    email: str
    lab_domain: str
    host: str
    port: int
    resolved_ips: list[str]
    transport: str
    checks_requested: list[str]
    checks_run: list[SmtpLabCheckResult]
    safety_decision: SafetyDecision
    network_used: bool
    limitations: list[str]
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Convert the SMTP lab result to a serializable dictionary."""
        return asdict(self)
