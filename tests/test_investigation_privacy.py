import json
import socket

import httpx
import pytest
from typer.testing import CliRunner

from mailrecon.cli.app import app
from mailrecon.core.models import DnsLookupResult, HibpResult, InvestigationInput
from mailrecon.services.investigation_service import InvestigationService
from mailrecon.services.recon_service import ReconService
from mailrecon.services.refinement_state_service import RefinementStateService
from tests.test_public_profile_apis import payload, service_for


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Real network is forbidden")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


class Dns:
    def lookup_domain(self, domain):
        return DnsLookupResult(resolves=True, mx_records=["mx.example.com"],
                               domain_status="resolves", email_acceptance_status="mx_present")


class Hibp:
    def __init__(self):
        self.calls = []
        self.enabled = True

    def query_breaches(self, email):
        self.calls.append(email)
        return HibpResult(queried=True, status="no_breaches")


def investigation(profile_service=None):
    dns, hibp = Dns(), Hibp()
    return InvestigationService(ReconService(dns, hibp), dns, profile_service), hibp


def test_inferred_candidates_never_reach_hibp_by_default_and_dedup_keeps_explicit_policy():
    service, hibp = investigation()
    result = service.investigate(InvestigationInput(
        emails=["alice@example.com"], candidate_emails=["bob@example.com"],
        usernames=["alice", "bob", "carol"], names=["Dora"], domains=["example.com"],
    ))
    assert hibp.calls == ["alice@example.com", "bob@example.com"]
    inferred = [candidate for candidate in result.candidate_emails if candidate.source.endswith("inference")]
    assert inferred
    assert all(not candidate.analysis.hibp.queried and candidate.analysis.hibp.status == "disabled" for candidate in inferred)
    assert all(candidate.analysis.dns.resolves for candidate in inferred)
    assert hibp.enabled is True
    service.recon_service.analyze_email("later@example.com")
    assert hibp.calls[-1] == "later@example.com"


def test_recon_per_call_omission_does_not_call_or_mutate_provider():
    service, hibp = investigation()
    omitted = service.recon_service.analyze_email("alice@example.com", use_hibp=False)
    assert not hibp.calls
    assert omitted.hibp.status == "disabled"
    assert not omitted.hibp.queried
    assert hibp.enabled
    service.recon_service.analyze_email("alice@example.com")
    assert hibp.calls == ["alice@example.com"]


def test_inferred_hibp_requires_explicit_service_opt_in_for_each_run():
    service, hibp = investigation()
    query = InvestigationInput(usernames=["alice"], domains=["example.com"])
    service.investigate(query, allow_inferred_hibp=True)
    assert hibp.calls == ["alice@example.com"]
    service.investigate(query)
    assert hibp.calls == ["alice@example.com"]


def api_response(request):
    if request.url.host == "api.github.com":
        return httpx.Response(200, json=payload("GitHub", request.url.path.rsplit("/", 1)[1]))
    return httpx.Response(200, json=payload("GitLab", request.url.params["username"]))


def test_exclusions_are_before_http_and_cache_and_cannot_add_arbitrary_targets():
    profiles, calls = service_for(api_response)
    service, _ = investigation(profiles)
    query = InvestigationInput(usernames=["alice"])
    first = service.investigate(query, check_public_profiles=True)
    assert len(calls) == 2
    exclusions = {"https://github.com/alice", "https://gitlab.com/alice", "https://evil.example/login"}
    original = profiles.check_public_profile
    def check(pivot):
        if pivot.platform in {"GitHub", "GitLab"}:
            pytest.fail("Exclusion must precede service/cache")
        return original(pivot)
    profiles.check_public_profile = check
    second = service.investigate(query, check_public_profiles=True, excluded_profile_urls=exclusions)
    assert len(calls) == 2
    assert len(second.profile_pivots) == len(first.profile_pivots) - 2
    assert all(pivot.profile_url not in exclusions for pivot in second.profile_pivots)
    assert second.confidence_breakdown["profile_existence_confidence"] == 0
    assert second.confidence_breakdown["identity_correlation_confidence"] == 0


def test_investigation_resets_budget_and_reuses_only_live_sanitized_cache():
    profiles, calls = service_for(api_response, total_budget=1, cache_ttl=0)
    service, _ = investigation(profiles)
    query = InvestigationInput(usernames=["alice"])
    service.investigate(query, check_public_profiles=True)
    service.investigate(query, check_public_profiles=True)
    assert len(calls) == 2
    profiles, calls = service_for(api_response)
    service.profile_check_service = profiles
    first = service.investigate(query, check_public_profiles=True)
    second = service.investigate(query, check_public_profiles=True)
    assert len(calls) == 2
    first_checked = [pivot for pivot in first.profile_pivots if pivot.checked_at]
    second_checked = [pivot for pivot in second.profile_pivots if pivot.checked_at]
    assert all(pivot.cache_hit for pivot in second_checked)
    assert [pivot.checked_at for pivot in first_checked] == [pivot.checked_at for pivot in second_checked]
    assert second.confidence_breakdown["profile_existence_confidence"] == 45
    assert second.confidence_breakdown["identity_correlation_confidence"] == 0


@pytest.mark.parametrize("locale", ["pt-br", "en"])
@pytest.mark.parametrize("saved_hibp,no_hibp,expected", [(True, True, False), (True, False, True),
                                                     (False, False, False), (False, True, False)])
def test_rerun_last_can_only_reduce_hibp_and_honors_old_exclusions_before_http(
    monkeypatch, tmp_path, locale, saved_hibp, no_hibp, expected,
):
    state = RefinementStateService(tmp_path / "state.json", language=locale)
    query = InvestigationInput(emails=["alice@example.com"], usernames=["alice"])
    state.state_path.write_text(json.dumps({
        "query_fingerprint": state._fingerprint_query(query),
        "query": {"emails": query.emails, "usernames": query.usernames},
        "run_options": {"use_hibp": saved_hibp, "check_public_profiles": True},
        "excluded_profile_urls": ["https://github.com/alice", "https://gitlab.com/alice", "https://evil.example"],
        "suggested_profile_urls": ["https://evil.example"],
    }), encoding="utf-8")
    profiles, calls = service_for(api_response)
    service, hibp = investigation(profiles)
    builder_flags = []
    def build(use_hibp):
        builder_flags.append(use_hibp)
        # A disabled HIBP provider would normally be built by the CLI.
        if not use_hibp:
            def disabled(email):
                return HibpResult(queried=False, status="disabled")
            hibp.query_breaches = disabled
        return service
    monkeypatch.setattr("mailrecon.cli.app._build_investigation_service", build)
    monkeypatch.setattr("mailrecon.cli.app._build_refinement_state_service", lambda: state)
    result = CliRunner().invoke(app, ["--language", locale, "rerun-last", *(["--no-hibp"] if no_hibp else [])])
    assert result.exit_code == 0, result.output
    assert builder_flags == [expected]
    assert hibp.calls == (["alice@example.com"] if expected else [])
    assert not calls
    assert "evil.example" not in result.output
    assert state.load_last_investigation()[1]["use_hibp"] is expected


def test_nonmatching_fingerprint_does_not_exclude_profiles(tmp_path):
    state = RefinementStateService(tmp_path / "state.json")
    state.state_path.write_text(json.dumps({"query_fingerprint": "wrong", "excluded_profile_urls": ["https://github.com/alice"]}), encoding="utf-8")
    assert state.excluded_links_for_query(InvestigationInput(usernames=["alice"])) == set()
