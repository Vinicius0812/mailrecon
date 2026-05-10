"""Primary orchestration service."""

from mailrecon.core.models import ReconResult
from mailrecon.core.validators import validate_email_input
from mailrecon.services.dns_service import DnsService
from mailrecon.services.hibp_service import HibpService


class ReconService:
    """Coordinates the full email recon flow."""

    def __init__(self, dns_service: DnsService, hibp_service: HibpService) -> None:
        self.dns_service = dns_service
        self.hibp_service = hibp_service

    def analyze_email(self, email: str) -> ReconResult:
        """Run the main analysis flow for one email address."""
        is_valid, normalized_or_error, domain = validate_email_input(email)
        if not is_valid or domain is None:
            raise ValueError(normalized_or_error)

        dns_result = self.dns_service.lookup_domain(domain)
        hibp_result = self.hibp_service.query_breaches(normalized_or_error)

        return ReconResult(
            email=normalized_or_error,
            domain=domain,
            is_valid=True,
            dns=dns_result,
            hibp=hibp_result,
        )
