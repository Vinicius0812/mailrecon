import httpx

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
