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
