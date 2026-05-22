from mailrecon.core.models import DnsLookupResult, HibpResult, InvestigationInput, ReconResult
from mailrecon.services.investigation_service import InvestigationService


class FakeReconService:
    def analyze_email(self, email: str) -> ReconResult:
        domain = email.rsplit("@", maxsplit=1)[1]
        hibp_status = "breaches_found" if email.startswith("alice") else "no_breaches"
        breaches = [{"Name": "ExampleBreach", "Title": "Example Breach"}] if hibp_status == "breaches_found" else []
        return ReconResult(
            email=email,
            domain=domain,
            is_valid=True,
            dns=DnsLookupResult(
                resolves=True,
                a_records=["93.184.216.34"],
                mx_records=["mx.example.com"],
            ),
            hibp=HibpResult(
                queried=True,
                status=hibp_status,
                breaches=breaches,
            ),
        )


class FakeDnsService:
    def lookup_domain(self, domain: str) -> DnsLookupResult:
        return DnsLookupResult(
            resolves=True,
            a_records=["93.184.216.34"],
            mx_records=["mx.example.com"],
        )


def test_investigation_service_builds_candidates_from_multiple_seeds() -> None:
    service = InvestigationService(
        recon_service=FakeReconService(),
        dns_service=FakeDnsService(),
    )
    query = InvestigationInput(
        names=["Alice Smith"],
        emails=["alice@example.com"],
        usernames=["asmith"],
        domains=["example.com"],
        organizations=["Example Org"],
        contexts=["osint triage"],
    )

    result = service.investigate(query)

    emails = {candidate.email for candidate in result.candidate_emails}
    assert "alice@example.com" in emails
    assert "asmith@example.com" in emails
    assert "alice.smith@example.com" in emails
    assert result.profile_pivots
    assert any(pivot.platform == "LinkedIn" for pivot in result.profile_pivots)
    assert result.findings
    assert result.evidences
    assert result.pivot_suggestions
    assert result.limitations


def test_investigation_service_requires_at_least_one_seed() -> None:
    service = InvestigationService(
        recon_service=FakeReconService(),
        dns_service=FakeDnsService(),
    )

    try:
        service.investigate(InvestigationInput())
    except ValueError as exc:
        assert "Provide at least one seed" in str(exc)
    else:
        raise AssertionError("Expected a ValueError for an empty investigation input.")


def test_investigation_service_masks_invalid_candidate_email() -> None:
    service = InvestigationService(
        recon_service=FakeReconService(),
        dns_service=FakeDnsService(),
    )
    query = InvestigationInput(candidate_emails=["bad email"])

    result = service.investigate(query)

    assert result.candidate_emails[0].status == "invalid"
    assert result.candidate_emails[0].notes
