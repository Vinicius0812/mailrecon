from dataclasses import replace

import pytest

from mailrecon.core.models import (
    DnsLookupResult,
    HibpResult,
    InvestigationInput,
    ReconResult,
)
from mailrecon.services.investigation_service import InvestigationService
from mailrecon.services.profile_check_service import ProfileCheckService


class StaticDnsService:
    def __init__(self, result: DnsLookupResult) -> None:
        self.result = result

    def lookup_domain(self, domain: str) -> DnsLookupResult:
        return self.result


class StaticReconService:
    def __init__(self, dns: DnsLookupResult, hibp_status: str) -> None:
        self.dns = dns
        self.hibp_status = hibp_status

    def analyze_email(self, email: str, progress_callback=None) -> ReconResult:
        return ReconResult(
            email=email,
            domain=email.rsplit("@", 1)[1],
            is_valid=True,
            dns=self.dns,
            hibp=HibpResult(
                queried=True,
                status=self.hibp_status,
                breaches=[{"Name": "ExampleBreach"}] if self.hibp_status == "breaches_found" else [],
            ),
        )


def make_service(dns: DnsLookupResult | None = None, hibp_status: str = "no_breaches") -> InvestigationService:
    if dns is None:
        dns = DnsLookupResult(
            resolves=True,
            mx_records=["mx.example.com"],
            domain_status="resolves",
            email_acceptance_status="mx_present",
            spf_status="present",
            dmarc_status="present",
        )
    return InvestigationService(StaticReconService(dns, hibp_status), StaticDnsService(dns))


@pytest.mark.parametrize(
    ("direct", "provided", "username", "expected_source", "confidence", "scope", "priority"),
    [
        (True, True, True, "seed_email", "medium", "input_seed", 70),
        (False, True, True, "provided_candidate", "medium", "provided_address", 60),
        (False, False, True, "username_domain_inference", "low", "generated_hypothesis", 45),
        (False, False, False, "name_domain_inference", "low", "generated_hypothesis", 30),
    ],
)
def test_dedup_preserves_authority_and_all_origins(
    direct, provided, username, expected_source, confidence, scope, priority
) -> None:
    query = InvestigationInput(
        emails=["alice@EXAMPLE.COM", "alice@example.com"] if direct else [],
        candidate_emails=["alice@example.com", "alice@example.com"] if provided else [],
        usernames=["alice", "@alice"] if username else [],
        names=["Alice", "Alice"],
        domains=["example.com", "EXAMPLE.COM."],
    )

    result = make_service().investigate(query)

    assert len(result.candidate_emails) == 1
    candidate = result.candidate_emails[0]
    expected_sources = (
        (["seed_email"] if direct else [])
        + (["provided_candidate"] if provided else [])
        + (["username_domain_inference"] if username else [])
        + ["name_domain_inference"]
    )
    assert candidate.source == expected_source
    assert candidate.sources == expected_sources
    assert candidate.confidence == confidence
    assert candidate.confidence_scope == scope
    assert candidate.review_priority_score == priority
    expected_strength = "strong_direct_seed" if direct else "moderate_third_party_status" if provided else "weak_inferred"
    assert candidate.evidence_strength == expected_strength
    evidence = next(item for item in result.evidences if item.category == "email_candidate")
    assert evidence.sources == candidate.sources
    assert evidence.sources is not candidate.sources
    assert evidence.confidence_scope == scope
    assert result.confidence_breakdown["identity_correlation_confidence"] == 0


def test_invalid_duplicates_keep_direct_provenance_but_low_confidence() -> None:
    result = make_service().investigate(
        InvestigationInput(emails=["bad email"], candidate_emails=["bad email", "bad email"])
    )

    assert len(result.candidate_emails) == 1
    candidate = result.candidate_emails[0]
    assert candidate.source == "seed_email"
    assert candidate.sources == ["seed_email", "provided_candidate"]
    assert candidate.confidence == "low"
    assert candidate.confidence_scope == "input_seed"
    assert candidate.review_priority_score == 0


@pytest.mark.parametrize(
    ("dns", "status", "cap", "confidence"),
    [
        (DnsLookupResult(resolves=False, domain_status="nxdomain"), "rejected_domain_unresolved", 0, "low"),
        (DnsLookupResult(resolves=True, null_mx=True, email_acceptance_status="declares_no_mail"),
         "rejected_domain_no_mail", 5, "low"),
        (DnsLookupResult(resolves=True, a_records=["192.0.2.1"],
                         email_acceptance_status="implicit_mail_possible"), "accepted_direct_seed", 30, "medium"),
        (DnsLookupResult(resolves=False, email_acceptance_status="inconclusive"),
         "accepted_direct_seed", 25, "medium"),
        (DnsLookupResult(resolves=False, email_acceptance_status="no_mail_signal"),
         "accepted_direct_seed", 25, "medium"),
    ],
)
def test_dns_caps_do_not_change_provenance_or_syntax(dns, status, cap, confidence) -> None:
    result = make_service(dns).investigate(InvestigationInput(emails=["alice@example.com"]))
    candidate = result.candidate_emails[0]

    assert candidate.status == status
    assert candidate.confidence == confidence
    assert candidate.review_priority_score == candidate.confidence_score == cap
    assert candidate.confidence_scope == "input_seed"
    assert candidate.sources == ["seed_email"]
    assert result.confidence_breakdown["email_format_confidence"] == 100
    assert result.confidence_breakdown["identity_correlation_confidence"] == 0


@pytest.mark.parametrize(
    "status",
    ["breaches_found", "no_breaches", "missing_api_key", "disabled", "timeout", "request_error",
     "unauthorized", "forbidden", "rate_limited", "http_error", "invalid_response", "unknown"],
)
def test_hibp_confidence_is_only_about_exposure(status) -> None:
    result = make_service(hibp_status=status).investigate(InvestigationInput(emails=["alice@example.com"]))
    evidence = next(item for item in result.evidences if item.category == "exposure")

    assert evidence.confidence == ("medium" if status == "breaches_found" else "low")
    assert evidence.confidence_scope == "breach_exposure"
    assert evidence.sources == ["Have I Been Pwned"]
    assert evidence.evidence_strength == ("moderate_third_party_status" if status == "breaches_found" else "none")
    assert evidence.decision_reasons
    assert evidence.limitations
    assert result.confidence_breakdown["identity_correlation_confidence"] == 0


@pytest.mark.parametrize(
    ("dns", "expected"),
    [
        (DnsLookupResult(resolves=True, mx_records=["mx.example.com"]), 80),
        (DnsLookupResult(resolves=True, a_records=["192.0.2.1"]), 80),
        (DnsLookupResult(resolves=True, aaaa_records=["2001:db8::1"]), 80),
        (DnsLookupResult(resolves=False, ns_records=["ns.example.com"]), 80),
        (DnsLookupResult(resolves=False, txt_records=["v=spf1 -all"]), 80),
        (DnsLookupResult(resolves=False, domain_status="nxdomain"), 80),
        (DnsLookupResult(resolves=False, null_mx=True, email_acceptance_status="declares_no_mail"), 80),
        (DnsLookupResult(resolves=False, domain_status="inconclusive", errors=["DNS timed out"]), 0),
        (DnsLookupResult(resolves=False), 0),
        (DnsLookupResult(resolves=True), 0),
    ],
)
def test_domain_breakdown_reflects_facts_not_candidate_priority(dns, expected) -> None:
    result = make_service(dns).investigate(InvestigationInput(domains=["example.com"]))
    evidence = next(item for item in result.evidences if item.category == "domain")

    assert evidence.confidence_scope == "dns_observation"
    assert evidence.confidence_score == expected
    assert result.confidence_breakdown["domain_confidence"] == expected
    assert result.confidence_breakdown["identity_correlation_confidence"] == 0


def test_syntax_breakdown_is_independent_of_review_priority_and_dns() -> None:
    service = make_service()
    candidates = service._build_candidate_emails(
        InvestigationInput(emails=["alice@example.com"], candidate_emails=["bad email"])
    )
    candidates[0].review_priority_score = 0
    candidates[0].status = "rejected_domain_unresolved"

    breakdown = service._build_confidence_breakdown(candidates, [], [])

    assert breakdown["email_format_confidence"] == 50
    assert breakdown["domain_confidence"] == 0
    assert breakdown["profile_existence_confidence"] == 0
    assert breakdown["identity_correlation_confidence"] == 0


def test_profile_breakdown_uses_only_performed_real_checks_including_after_fifth() -> None:
    service = make_service()
    pivots = service._platform_pivots_for_handle("alice")
    checked = replace(
        pivots[-1],
        checked_at="2026-09-30T00:00:00+00:00",
        confidence_scope="http_reachability",
        resolution_status="public_match_possible",
        confidence_score=0,
        review_priority_score=0,
    )
    synthetic, _ = ProfileCheckService().simulate_profile_check(pivots[-2], "found")

    breakdown = service._build_confidence_breakdown([], pivots[:5] + [synthetic, checked], [])

    assert breakdown["profile_existence_confidence"] == 45
    assert breakdown["identity_correlation_confidence"] == 0
    not_found = replace(checked, resolution_status="not_found")
    breakdown = service._build_confidence_breakdown([], pivots[:5] + [checked, not_found], [])
    assert breakdown["profile_existence_confidence"] == 22


def test_profile_breakdown_does_not_count_a_status_without_a_performed_check() -> None:
    service = make_service()
    pivot = replace(service._platform_pivots_for_handle("alice")[0],
                    resolution_status="public_match_possible", confidence_scope="http_reachability")

    assert service._build_confidence_breakdown([], [pivot], [])["profile_existence_confidence"] == 0


def test_zero_review_priorities_do_not_fall_back_to_legacy_confidence_scores() -> None:
    service = make_service()
    candidate = service._make_candidate("alice@example.com", "seed_email", "medium")
    candidate.review_priority_score = 0
    candidate.confidence_score = 95
    pivot = service._platform_pivots_for_handle("alice")[0]
    pivot.review_priority_score = 0
    pivot.confidence_score = 95

    assert service._build_review_priority_score([candidate], [pivot], []) == 0


@pytest.mark.parametrize(
    ("email", "cap"),
    [("admin@example.com", 35), ("alice@mailinator.com", 25), ("admin@mailinator.com", 25)],
)
def test_role_and_disposable_caps_survive_full_provenance_merge(email, cap) -> None:
    local_part, domain = email.split("@")
    result = make_service().investigate(InvestigationInput(
        emails=[email], candidate_emails=[email], usernames=[local_part], names=[local_part], domains=[domain],
    ))
    candidate = result.candidate_emails[0]

    assert candidate.sources == [
        "seed_email", "provided_candidate", "username_domain_inference", "name_domain_inference",
    ]
    assert candidate.review_priority_score == cap
    assert candidate.confidence == "medium"
    assert result.confidence_breakdown["identity_correlation_confidence"] == 0


def test_scopes_and_provenance_serialize_without_changing_to_dict() -> None:
    result = make_service().investigate(InvestigationInput(
        emails=["alice@example.com"], candidate_emails=["alice@example.com"],
        usernames=["alice"], domains=["example.com"],
    ))

    serialized = result.to_dict()

    assert serialized["candidate_emails"][0]["sources"] == [
        "seed_email", "provided_candidate", "username_domain_inference",
    ]
    assert serialized["candidate_emails"][0]["confidence_scope"] == "input_seed"
    assert serialized["profile_pivots"][0]["confidence_scope"] == "generated_hypothesis"
    assert {item["confidence_scope"] for item in serialized["evidences"]} == {
        "input_seed", "breach_exposure", "dns_observation",
    }
    assert all(item["confidence"] == "medium" for item in serialized["evidences"] if item["category"] == "seed")
