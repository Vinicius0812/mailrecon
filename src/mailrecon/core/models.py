"""Data models used across the application."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class DnsLookupResult:
    """Stores DNS and MX lookup data for a domain."""

    resolves: bool
    a_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HibpResult:
    """Stores Have I Been Pwned query information."""

    queried: bool
    status: str
    breaches: list[dict] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class ReconResult:
    """Aggregates the full recon result for one email address."""

    email: str
    domain: str
    is_valid: bool
    dns: DnsLookupResult
    hibp: HibpResult
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
    refinement_file_path: str | None = None
    refinement_excluded_links: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Convert the investigation result to a serializable dictionary."""
        return asdict(self)
