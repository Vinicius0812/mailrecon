"""Primary orchestration service."""

from typing import Callable

from mailrecon.core.models import ReconResult
from mailrecon.core.validators import validate_email_input
from mailrecon.services.dns_service import DnsService
from mailrecon.services.hibp_service import HibpService


class ReconService:
    """Coordinates the full email recon flow."""

    def __init__(self, dns_service: DnsService, hibp_service: HibpService) -> None:
        self.dns_service = dns_service
        self.hibp_service = hibp_service

    def analyze_email(
        self,
        email: str,
        progress_callback: Callable[[str], None] | None = None,
    ) -> ReconResult:
        """Run the main analysis flow for one email address."""
        self._notify(progress_callback, "Validating email format...")
        is_valid, normalized_or_error, domain = validate_email_input(email)
        if not is_valid or domain is None:
            raise ValueError(normalized_or_error)

        self._notify(progress_callback, f"Checking DNS and MX records for {domain}...")
        dns_result = self.dns_service.lookup_domain(domain)
        self._notify(progress_callback, f"Querying HIBP for {normalized_or_error}...")
        hibp_result = self.hibp_service.query_breaches(normalized_or_error)

        return ReconResult(
            email=normalized_or_error,
            domain=domain,
            is_valid=True,
            dns=dns_result,
            hibp=hibp_result,
        )

    def _notify(
        self,
        progress_callback: Callable[[str], None] | None,
        message: str,
    ) -> None:
        """Emit a progress update when requested by the CLI."""
        if progress_callback is not None:
            progress_callback(message)
