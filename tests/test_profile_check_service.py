import httpx
import pytest

from mailrecon.core.models import ProfilePivot
from mailrecon.services.profile_check_service import ProfileCheckService


def test_profile_check_service_simulates_found_status() -> None:
    service = ProfileCheckService()
    pivot = ProfilePivot(
        platform="LinkedIn",
        handle="user",
        profile_url="https://www.linkedin.com/in/user/",
        search_url="https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22user%22",
        source="public_profile_pivot",
        confidence="low",
        confidence_score=50,
        status="manual_review",
    )

    updated, evidence = service.simulate_profile_check(pivot, "found")

    assert updated.resolution_status == "public_match_possible"
    assert updated.http_status_code == 200
    assert evidence.category == "public_profile"
    assert updated.confidence == evidence.confidence == "medium"
    assert updated.confidence_scope == evidence.confidence_scope == "synthetic_http_reachability"
    assert "lab_simulation" in evidence.sources


def test_profile_check_service_simulates_blocked_status() -> None:
    service = ProfileCheckService()
    pivot = ProfilePivot(
        platform="X",
        handle="user",
        profile_url="https://x.com/user",
        search_url="https://www.google.com/search?q=site%3Ax.com+%22user%22",
        source="public_profile_pivot",
        confidence="low",
        confidence_score=50,
        status="manual_review",
    )

    updated, evidence = service.simulate_profile_check(pivot, "blocked")

    assert updated.resolution_status == "blocked_by_platform"
    assert updated.http_status_code == 403
    assert evidence.confidence == "low"
    assert updated.confidence == evidence.confidence


def test_profile_check_service_treats_login_redirect_as_ambiguous(monkeypatch) -> None:
    service = ProfileCheckService()
    pivot = ProfilePivot(
        platform="LinkedIn",
        handle="user",
        profile_url="https://www.linkedin.com/in/user/",
        search_url="https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22user%22",
        source="public_profile_pivot",
        confidence="low",
        confidence_score=50,
        status="manual_review",
    )

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def get(self, url):
            request = httpx.Request("GET", "https://www.linkedin.com/login")
            return httpx.Response(
                status_code=200,
                request=request,
            )

    monkeypatch.setattr("mailrecon.services.profile_check_service.httpx.Client", FakeClient)

    updated, evidence = service.check_public_profile(pivot)

    assert updated.resolution_status == "ambiguous"
    assert updated.status == "ambiguous_requires_review"
    assert "login_search_or_challenge_redirect" in updated.ambiguity_reasons
    assert "deterministic_profile_state" in updated.missing_fields
    assert evidence.confidence == "low"
    assert evidence.decision_reasons
    assert updated.confidence == evidence.confidence
    assert updated.confidence_scope == evidence.confidence_scope == "http_reachability"


def make_pivot(priority: int = 90) -> ProfilePivot:
    return ProfilePivot(
        platform="GitHub",
        handle="user",
        profile_url="https://github.com/user",
        search_url="https://www.google.com/search?q=user",
        source="public_profile_pivot",
        confidence="high",
        confidence_score=95,
        status="manual_review",
        review_priority_score=priority,
        sources=["public_profile_pivot"],
    )


def mock_http_client(monkeypatch, *, status_code=200, final_url=None, error=None) -> None:
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def get(self, url):
            if error is not None:
                raise error
            return httpx.Response(status_code, request=httpx.Request("GET", final_url or url))

    monkeypatch.setattr("mailrecon.services.profile_check_service.httpx.Client", FakeClient)


@pytest.mark.parametrize(
    ("status_code", "final_url", "resolution", "confidence", "cap"),
    [
        (200, None, "public_match_possible", "medium", 45),
        (301, None, "public_match_possible", "medium", 45),
        (200, "https://github.com/search?q=user", "ambiguous", "low", 25),
        (200, "https://github.com/login", "ambiguous", "low", 25),
        (404, None, "not_found", "low", 0),
        (401, None, "blocked_by_platform", "low", 25),
        (403, None, "blocked_by_platform", "low", 25),
        (429, None, "rate_limited", "low", 25),
        (500, None, "ambiguous", "low", 25),
    ],
)
def test_public_http_confidence_and_evidence_agree(
    monkeypatch, status_code, final_url, resolution, confidence, cap
) -> None:
    mock_http_client(monkeypatch, status_code=status_code, final_url=final_url)
    pivot = make_pivot()

    updated, evidence = ProfileCheckService().check_public_profile(pivot)

    assert updated.resolution_status == resolution
    assert updated.confidence == evidence.confidence == confidence
    assert updated.confidence_scope == evidence.confidence_scope == "http_reachability"
    assert updated.confidence_score == updated.review_priority_score == evidence.confidence_score == cap
    assert updated.evidence_strength == evidence.evidence_strength
    assert evidence.sources == ["public_profile_pivot", "GitHub"]
    if confidence == "medium":
        assert "independent_identity_correlation" in updated.missing_fields
    assert pivot.confidence == "high"


@pytest.mark.parametrize(
    ("error", "resolution"),
    [
        (httpx.TimeoutException("timed out"), "timeout"),
        (httpx.ConnectError("connection failed"), "request_error"),
    ],
)
def test_http_exception_resets_stale_confidence_and_observations(monkeypatch, error, resolution) -> None:
    mock_http_client(monkeypatch, error=error)
    pivot = make_pivot()
    pivot.http_status_code = 200
    pivot.final_url = pivot.profile_url
    pivot.matched_fields = ["profile_url_resolved"]

    updated, evidence = ProfileCheckService().check_public_profile(pivot)

    assert updated.resolution_status == resolution
    assert updated.confidence == evidence.confidence == "low"
    assert updated.confidence_scope == evidence.confidence_scope == "http_reachability"
    assert updated.confidence_score == updated.review_priority_score == evidence.confidence_score == 20
    assert updated.evidence_strength == evidence.evidence_strength == "weak_public_http"
    assert updated.http_status_code is None
    assert updated.final_url is None
    assert updated.matched_fields == []
    assert evidence.observations is None
    assert updated.decision_reasons
    assert updated.limitations


@pytest.mark.parametrize("scenario", ["found", "not-found", "ambiguous", "blocked", "rate-limited", "unknown"])
def test_simulations_are_explicitly_synthetic_and_consistent(scenario) -> None:
    updated, evidence = ProfileCheckService().simulate_profile_check(make_pivot(), scenario)

    assert updated.confidence == evidence.confidence == ("medium" if scenario == "found" else "low")
    assert updated.confidence_scope == evidence.confidence_scope == "synthetic_http_reachability"
    assert "lab_simulation" in updated.sources == evidence.sources
    assert evidence.method == "lab_public_profile_check"
    assert updated.confidence_score == updated.review_priority_score == evidence.confidence_score
    assert any("Synthetic" in limitation for limitation in evidence.limitations)


@pytest.mark.parametrize("exception", [None, httpx.TimeoutException("timed out"), httpx.ConnectError("failed")])
def test_profile_zero_priority_is_authoritative(monkeypatch, exception) -> None:
    mock_http_client(monkeypatch, error=exception)
    updated, evidence = ProfileCheckService().check_public_profile(make_pivot(priority=0))

    assert updated.review_priority_score == updated.confidence_score == evidence.confidence_score == 0


def test_simulated_zero_priority_is_authoritative() -> None:
    updated, evidence = ProfileCheckService().simulate_profile_check(make_pivot(priority=0), "found")

    assert updated.review_priority_score == updated.confidence_score == evidence.confidence_score == 0
