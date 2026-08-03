"""Primary orchestration service."""

from typing import Callable

from mailrecon.core.models import EmailTechnicalAssessment, ReconResult
from mailrecon.core.validators import validate_email_input
from mailrecon.services.dns_service import DnsService
from mailrecon.services.hibp_service import HibpService


class ReconService:
    """Coordinates the full email recon flow."""

    role_account_local_parts = {
        "abuse",
        "admin",
        "billing",
        "contact",
        "help",
        "info",
        "no-reply",
        "noreply",
        "postmaster",
        "sales",
        "security",
        "support",
    }

    disposable_domains = {
        "10minutemail.com",
        "guerrillamail.com",
        "mailinator.com",
        "tempmail.com",
        "throwawaymail.com",
        "yopmail.com",
    }

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
        technical_assessment = self._build_technical_assessment(
            email=normalized_or_error,
            dns_result=dns_result,
        )

        return ReconResult(
            email=normalized_or_error,
            domain=domain,
            is_valid=True,
            dns=dns_result,
            hibp=hibp_result,
            technical_assessment=technical_assessment,
        )

    def _build_technical_assessment(
        self,
        email: str,
        dns_result,
    ) -> EmailTechnicalAssessment:
        """Build a non-intrusive technical assessment for an email candidate."""
        local_part, _, domain = email.partition("@")
        base_local = local_part.partition("+")[0].lower()
        role_account_status = (
            "role_account" if base_local in self.role_account_local_parts else "not_role_account"
        )
        disposable_status = (
            "disposable" if domain.lower() in self.disposable_domains else "unknown"
        )
        score = self._score_technical_assessment(
            dns_result.email_acceptance_status,
            disposable_status,
            role_account_status,
        )
        decision_reasons = [
            "Email syntax is valid.",
            f"Domain status is {dns_result.domain_status}.",
            f"Email acceptance status is {dns_result.email_acceptance_status}.",
            f"Provider family is {dns_result.provider_family}.",
        ]
        if dns_result.spf_status == "present":
            decision_reasons.append("Domain publishes SPF.")
        if dns_result.dmarc_status == "present":
            decision_reasons.append("Domain publishes DMARC.")
        if disposable_status == "disposable":
            decision_reasons.append("Domain is on the local disposable-domain list.")
        if role_account_status == "role_account":
            decision_reasons.append("Local-part looks like a role or shared mailbox.")

        return EmailTechnicalAssessment(
            syntax_status="valid",
            domain_status=dns_result.domain_status,
            mx_status=dns_result.email_acceptance_status,
            spf_status=dns_result.spf_status,
            dmarc_status=dns_result.dmarc_status,
            provider_family=dns_result.provider_family,
            disposable_status=disposable_status,
            role_account_status=role_account_status,
            catch_all_status="not_tested",
            review_priority_score=score,
            decision_reasons=decision_reasons,
            limitations=[
                "Technical assessment does not confirm individual mailbox existence.",
                "Catch-all status is not tested because MailRecon avoids SMTP probing.",
            ],
        )

    def _score_technical_assessment(
        self,
        email_acceptance_status: str,
        disposable_status: str,
        role_account_status: str,
    ) -> int:
        """Score review priority for technical assessment signals."""
        mapping = {
            "mx_present": 65,
            "implicit_mail_possible": 30,
            "inconclusive": 25,
            "no_mail_signal": 10,
            "domain_unresolved": 0,
            "declares_no_mail": 0,
        }
        score = mapping.get(email_acceptance_status, 20)
        if disposable_status == "disposable":
            score = min(score, 25)
        if role_account_status == "role_account":
            score = min(score, 35)
        return score

    def _notify(
        self,
        progress_callback: Callable[[str], None] | None,
        message: str,
    ) -> None:
        """Emit a progress update when requested by the CLI."""
        if progress_callback is not None:
            progress_callback(message)
