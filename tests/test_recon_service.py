from mailrecon.core.models import DnsLookupResult, HibpResult
from mailrecon.services.recon_service import ReconService


class FakeDnsService:
    def lookup_domain(self, domain: str) -> DnsLookupResult:
        return DnsLookupResult(
            resolves=True,
            a_records=["93.184.216.34"],
            mx_records=["aspmx.l.google.com"],
            spf_records=["v=spf1 include:_spf.google.com -all"],
            dmarc_records=["v=DMARC1; p=reject"],
            domain_status="resolves",
            email_acceptance_status="mx_present",
            spf_status="present",
            dmarc_status="present",
            dmarc_policy="reject",
            provider_family="google_workspace",
        )


class FakeHibpService:
    def query_breaches(self, email: str) -> HibpResult:
        return HibpResult(queried=False, status="disabled")


def test_recon_service_builds_technical_assessment() -> None:
    service = ReconService(
        dns_service=FakeDnsService(),
        hibp_service=FakeHibpService(),
    )

    result = service.analyze_email("Admin@Example.com")

    assert result.technical_assessment.syntax_status == "valid"
    assert result.technical_assessment.mx_status == "mx_present"
    assert result.technical_assessment.spf_status == "present"
    assert result.technical_assessment.dmarc_status == "present"
    assert result.technical_assessment.provider_family == "google_workspace"
    assert result.technical_assessment.role_account_status == "role_account"
    assert result.technical_assessment.catch_all_status == "not_tested"
    assert result.technical_assessment.review_priority_score == 35
    assert result.technical_assessment.limitations
