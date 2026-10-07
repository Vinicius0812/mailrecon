from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
import socket

import httpx
import pytest

from mailrecon.core.i18n import serialize_localized, translate
from mailrecon.core.models import ProfilePivot
from mailrecon.core.platform_catalog import PLATFORMS, PLATFORM_BY_NAME, validate_catalog
from mailrecon.services.profile_check_service import ProfileCheckService


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Real network is forbidden")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def pivot(platform="GitHub", handle="alice", priority=70):
    spec = PLATFORM_BY_NAME[platform]
    return ProfilePivot(platform, handle, spec.profile_url(handle), spec.search_url(handle),
                        "public_profile_pivot", "low", priority, "manual_review",
                        review_priority_score=priority, sources=["public_profile_pivot"])


def payload(platform="GitHub", handle="alice"):
    if platform == "GitHub":
        return {"id": 42, "login": handle, "html_url": f"https://github.com/{handle}",
                "email": "private@example.com", "bio": "private response must not be retained"}
    return [{"id": 42, "username": handle, "web_url": f"https://gitlab.com/{handle}",
             "email": "private@example.com"}]


def service_for(response=None, **options):
    calls = []
    def handler(request):
        calls.append(request)
        if callable(response):
            result = response(request)
        else:
            result = httpx.Response(200, json=response if response is not None else payload())
        if result.is_stream_consumed:
            return httpx.Response(result.status_code, headers=result.headers,
                                  stream=httpx.ByteStream(result.content))
        return result
    return ProfileCheckService(transport=httpx.MockTransport(handler), **options), calls


@pytest.mark.parametrize("platform", ["GitHub", "GitLab"])
@pytest.mark.parametrize("locale", ["pt-br", "en"])
def test_exact_official_profile_is_consistent_and_private_fields_are_discarded(platform, locale):
    service, calls = service_for(payload(platform))
    original = pivot(platform)
    updated, evidence = service.check_public_profile(original)
    assert len(calls) == 1
    assert str(calls[0].url) == PLATFORM_BY_NAME[platform].api_url("alice")
    assert calls[0].method == "GET"
    assert calls[0].headers["user-agent"] == "MailRecon/0.1"
    assert "authorization" not in calls[0].headers
    assert "cookie" not in calls[0].headers
    assert "private-token" not in calls[0].headers
    assert calls[0].headers["accept-encoding"] == "identity"
    assert updated.resolution_status == "public_match_possible"
    assert updated.confidence == evidence.confidence == "medium"
    assert updated.confidence_scope == evidence.confidence_scope == "public_profile_existence"
    assert updated.check_method == evidence.method == "official_public_api"
    assert updated.rule_id == evidence.rule_id == PLATFORM_BY_NAME[platform].rule_id
    assert updated.rule_version == evidence.rule_version == "1"
    assert updated.checked_at == evidence.collected_at
    assert updated.final_url == updated.profile_url
    assert updated.review_priority_score == evidence.confidence_score == 45
    assert "independent_identity_correlation" in updated.missing_fields
    assert original.checked_at is None
    rendered = json.dumps(serialize_localized(updated, locale)) + repr(service._cache)
    assert "private@example.com" not in rendered
    assert "private response" not in rendered
    localized = translate(evidence, locale)
    assert ("API oficial" if locale == "pt-br" else "Official API") in localized.decision_reasons[-1]


@pytest.mark.parametrize("platform", ["GitHub", "GitLab"])
@pytest.mark.parametrize("mutation", [
    {"id": 0}, {"id": -1}, {"id": True}, {"id": "42"}, {"id": None},
    {"handle": "bob"}, {"handle": "alice/bob"}, {"url": "https://evil.example/alice"},
    {"url": "https://github.com/login"}, {"url": "https://gitlab.com/users/sign_in"},
    {"url": "http://github.com/alice"}, {"url": "https://github.com/alice?private=1"},
    {"url": "https://github.com/alice/"},
])
def test_200_divergent_ids_handles_or_urls_never_confirm_profile(platform, mutation):
    data = payload(platform)
    record = data if platform == "GitHub" else data[0]
    for key, value in mutation.items():
        actual_key = {"handle": "login" if platform == "GitHub" else "username",
                      "url": "html_url" if platform == "GitHub" else "web_url"}.get(key, key)
        record[actual_key] = value
    service, calls = service_for(data)
    updated, evidence = service.check_public_profile(pivot(platform))
    assert len(calls) == 1
    assert updated.resolution_status == "ambiguous"
    assert updated.confidence == evidence.confidence == "low"
    assert updated.matched_fields == []
    assert updated.final_url is None
    assert not service._cache


@pytest.mark.parametrize("platform", ["GitHub", "GitLab"])
@pytest.mark.parametrize("body,content_type", [
    (b"{}", "application/json"), (b"null", "application/json"),
    (b"true", "application/json"), (b"{broken", "application/json"),
    (b'{"message":"Not Found"}', "application/json"),
    (b"<html>login</html>", "text/html"), (b"<html>404</html>", "application/json"),
    (b"\xff", "application/json"),
])
def test_generic_200_soft404_login_or_malformed_body_is_ambiguous(platform, body, content_type):
    service, _ = service_for(lambda request: httpx.Response(200, content=body,
                            headers={"content-type": content_type}))
    result, evidence = service.check_public_profile(pivot(platform))
    assert result.resolution_status == "ambiguous"
    assert result.confidence == evidence.confidence == "low"


@pytest.mark.parametrize("data,status", [([], "not_found"), ([{}, {}], "ambiguous"),
    ([*payload("GitLab"), *payload("GitLab")], "ambiguous"),
    ({"id": 42, "username": "alice", "web_url": "https://gitlab.com/alice"}, "ambiguous")])
def test_gitlab_empty_multiple_and_wrong_shape(data, status):
    service, _ = service_for(data)
    result, evidence = service.check_public_profile(pivot("GitLab"))
    assert result.resolution_status == status
    assert result.confidence == evidence.confidence == "low"


@pytest.mark.parametrize("platform", ["GitHub", "GitLab"])
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308, 500, 204])
def test_redirects_and_unexpected_status_never_follow_or_confirm(platform, code):
    service, calls = service_for(lambda request: httpx.Response(code, headers={"location": "https://evil.example/login"}))
    result, evidence = service.check_public_profile(pivot(platform))
    assert len(calls) == 1
    assert result.resolution_status == "ambiguous"
    assert result.confidence == evidence.confidence == "low"


@pytest.mark.parametrize("platform,status", [("GitHub", "not_found"), ("GitLab", "ambiguous")])
def test_404_is_source_specific(platform, status):
    service, _ = service_for(lambda request: httpx.Response(404))
    assert service.check_public_profile(pivot(platform))[0].resolution_status == status


@pytest.mark.parametrize("change", [
    {"source": "imported"}, {"platform": "Unknown"}, {"handle": "alice/bob"},
    {"handle": "alice?email=private@example.com"}, {"handle": "../alice"},
    {"profile_url": "https://evil.example/alice"}, {"profile_url": "https://github.com@evil.example/alice"},
    {"profile_url": "https://github.com:443/alice"}, {"profile_url": "http://github.com/alice"},
    {"profile_url": "https://github.com/alice/repos"}, {"profile_url": "https://github.com/alice?x=1"},
    {"profile_url": "https://github.com/alice#x"}, {"profile_url": "https://github.com/%61lice"},
])
def test_pivot_tampering_is_rejected_before_network_even_with_cache(change):
    service, calls = service_for()
    service.check_public_profile(pivot())
    result, evidence = service.check_public_profile(replace(pivot(), **change))
    assert len(calls) == 1
    assert result.resolution_status == "ambiguous"
    assert result.checked_at is None
    assert not result.cache_hit
    assert result.confidence == evidence.confidence == "low"


@pytest.mark.parametrize("spec", [spec for spec in PLATFORMS if spec.rule_id == "manual_only"])
def test_manual_sources_never_make_requests(spec):
    service, calls = service_for()
    result, evidence = service.check_public_profile(pivot(spec.name))
    assert calls == []
    assert result.resolution_status == "not_checked"
    assert result.checked_at is None
    assert result.confidence == evidence.confidence == "low"
    assert result.check_method == evidence.method == "manual_only"


@pytest.mark.parametrize("platform", ["GitHub", "GitLab"])
@pytest.mark.parametrize("code,status", [(401, "blocked_by_platform"), (403, "blocked_by_platform"), (429, "rate_limited")])
def test_block_or_rate_limit_disables_only_its_source_until_next_execution(platform, code, status):
    service, calls = service_for(lambda request: httpx.Response(code))
    first, _ = service.check_public_profile(pivot(platform))
    skipped, _ = service.check_public_profile(pivot(platform, "bob"))
    assert first.resolution_status == skipped.resolution_status == status
    assert skipped.checked_at is None
    assert skipped.http_status_code is None
    assert not service._cache
    assert len(calls) == 1
    other = "GitLab" if platform == "GitHub" else "GitHub"
    service.check_public_profile(pivot(other))
    assert len(calls) == 2
    service.begin_execution()
    service.check_public_profile(pivot(platform))
    assert len(calls) == 3


@pytest.mark.parametrize("error,status", [(httpx.ReadTimeout("secret detail"), "timeout"),
                                         (httpx.ConnectError("secret detail"), "request_error")])
def test_errors_are_low_no_retries_and_no_raw_exception_retained(error, status):
    def response(request):
        raise error
    service, calls = service_for(response)
    result, evidence = service.check_public_profile(pivot())
    assert len(calls) == 1
    assert result.resolution_status == status
    assert result.confidence == evidence.confidence == "low"
    assert "secret detail" not in repr(asdict(result))
    assert not service._cache


def test_budgets_apply_per_source_and_execution_and_reset():
    service, calls = service_for(lambda request: httpx.Response(200, json={}), total_budget=3, source_budget=2)
    for handle in ("alice", "bob"):
        service.check_public_profile(pivot(handle=handle))
    skipped, _ = service.check_public_profile(pivot(handle="carol"))
    assert skipped.checked_at is None
    assert skipped.ambiguity_reasons == ["budget_exhausted"]
    service.check_public_profile(pivot("GitLab"))
    service.check_public_profile(pivot("GitLab", "bob"))
    assert len(calls) == 3
    service.begin_execution()
    service.check_public_profile(pivot())
    assert len(calls) == 4


@pytest.mark.parametrize("options", [{"total_budget": 0}, {"source_budget": 0}])
def test_zero_budget_makes_no_requests(options):
    service, calls = service_for(**options)
    result, _ = service.check_public_profile(pivot())
    assert not calls
    assert result.resolution_status == "not_checked"


def test_cache_ttl_timestamp_no_budget_charge_and_priority_not_cached():
    now = [0.0]
    base = datetime(2026, 10, 7, tzinfo=timezone.utc)
    service, calls = service_for(total_budget=1, cache_ttl=5, clock=lambda: now[0],
                                utcnow=lambda: base + timedelta(seconds=now[0]))
    first, _ = service.check_public_profile(pivot())
    now[0] = 4
    cached, evidence = service.check_public_profile(pivot(priority=0))
    assert len(calls) == 1
    assert cached.cache_hit and evidence.cache_hit
    assert cached.checked_at == first.checked_at == evidence.collected_at
    assert cached.review_priority_score == evidence.confidence_score == 0
    service.begin_execution()
    assert service.check_public_profile(pivot())[0].cache_hit
    now[0] = 5
    refreshed, _ = service.check_public_profile(pivot())
    assert not refreshed.cache_hit
    assert refreshed.checked_at != first.checked_at
    assert len(calls) == 2


def test_cache_has_bounded_entries_and_is_not_shared_or_persistent():
    def response(request):
        return httpx.Response(200, json=payload(handle=request.url.path.rsplit("/", 1)[1]))
    service, calls = service_for(response, cache_entries=1)
    service.check_public_profile(pivot())
    service.check_public_profile(pivot(handle="bob"))
    service.check_public_profile(pivot())
    assert len(calls) == 3
    assert len(service._cache) == 1
    fresh, other_calls = service_for(response)
    assert not fresh.check_public_profile(pivot())[0].cache_hit
    assert len(other_calls) == 1


@pytest.mark.parametrize("options", [{"cache_ttl": 0}, {"cache_entries": 0}])
def test_cache_can_be_disabled(options):
    service, calls = service_for(**options)
    service.check_public_profile(pivot())
    service.check_public_profile(pivot())
    assert len(calls) == 2
    assert not service._cache


@pytest.mark.parametrize("length", [None, "5000", "9" * 5000])
def test_response_size_limit_stops_stream_and_closes_it(length):
    events = []
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(5):
                events.append("read")
                yield b"x" * 1024
        def close(self):
            events.append("closed")
    headers = {"content-type": "application/json"}
    if length is not None:
        headers["content-length"] = length
    service, _ = service_for(lambda request: httpx.Response(200, headers=headers, stream=Stream()),
                            max_response_bytes=1024)
    result, evidence = service.check_public_profile(pivot())
    assert result.resolution_status == "ambiguous"
    assert result.ambiguity_reasons == ["response_too_large"]
    assert result.confidence == evidence.confidence == "low"
    assert events[-1] == "closed"
    assert events.count("read") <= 2


@pytest.mark.parametrize("headers", [{"x-next-page": "2"}, {"link": '<https://evil.example>; rel="next"'},
                                     {"content-encoding": "gzip"}])
def test_pagination_and_compressed_responses_are_inconclusive(headers):
    service, calls = service_for(lambda request: httpx.Response(200, stream=httpx.ByteStream(b"{}"),
                                    headers={"content-type": "application/json", **headers}))
    result, _ = service.check_public_profile(pivot())
    assert len(calls) == 1
    assert result.resolution_status == "ambiguous"


def test_environment_proxy_is_ignored_and_client_redirects_disabled(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://must-not-be-used.invalid:1234")
    original = httpx.Client
    settings = []
    def client(*args, **kwargs):
        settings.append(kwargs)
        return original(*args, **kwargs)
    monkeypatch.setattr(httpx, "Client", client)
    service, calls = service_for()
    service.check_public_profile(pivot())
    assert len(calls) == 1
    assert settings[0]["trust_env"] is False
    assert settings[0]["follow_redirects"] is False


@pytest.mark.parametrize("change", [
    {"api_template": "https://evil.example/{handle}"}, {"profile_template": "https://evil.example/{handle}"},
    {"rule_id": "other"}, {"rule_version": ""}, {"documentation_url": None},
])
def test_catalog_rejects_unsafe_or_unknown_api_rules(change):
    with pytest.raises(ValueError):
        validate_catalog((replace(PLATFORM_BY_NAME["GitHub"], **change),))


def test_catalog_is_own_validated_immutable_and_escapes_handles():
    validate_catalog(PLATFORMS)
    assert len(PLATFORMS) == 9
    with pytest.raises(ValueError):
        validate_catalog((PLATFORMS[0], PLATFORMS[0]))
    assert PLATFORM_BY_NAME["GitLab"].profile_url("a/b?x=1") == "https://gitlab.com/a%2Fb%3Fx%3D1"
    with pytest.raises(ValueError):
        PLATFORM_BY_NAME["GitLab"].api_url("alice&search=private@example.com")


@pytest.mark.parametrize("platform", ["GitHub", "GitLab"])
def test_mixed_case_exact_logical_handle_preserves_strict_canonical_url_and_cache(platform):
    service, calls = service_for(payload(platform, "ALIce"))
    first, first_evidence = service.check_public_profile(pivot(platform, "alice"))
    assert first.resolution_status == "public_match_possible"
    assert first.final_url == PLATFORM_BY_NAME[platform].profile_url("ALIce")
    assert first.confidence == first_evidence.confidence == "medium"
    cached, evidence = service.check_public_profile(pivot(platform, "alice", priority=0))
    assert len(calls) == 1
    assert cached.cache_hit and evidence.cache_hit
    assert cached.checked_at == first.checked_at == evidence.collected_at
    assert cached.review_priority_score == evidence.confidence_score == 0
    data = payload(platform, "ALIce")
    record = data if platform == "GitHub" else data[0]
    record["html_url" if platform == "GitHub" else "web_url"] = PLATFORM_BY_NAME[platform].profile_url("alice")
    other, _ = service_for(data)
    assert other.check_public_profile(pivot(platform))[0].resolution_status == "ambiguous"


@pytest.mark.parametrize("platform", ["GitHub", "GitLab"])
def test_cache_key_uses_logical_handle_case_and_negative_result_retains_observation(platform):
    service, calls = service_for(payload(platform, "Alice"))
    first, _ = service.check_public_profile(pivot(platform))
    reused, _ = service.check_public_profile(pivot(platform, "ALICE", priority=0))
    assert len(calls) == 1
    assert reused.cache_hit
    assert reused.checked_at == first.checked_at
    assert reused.final_url == first.final_url
    assert reused.review_priority_score == 0
    negative, calls = service_for(lambda request: httpx.Response(404) if platform == "GitHub" else httpx.Response(200, json=[]))
    first, _ = negative.check_public_profile(pivot(platform))
    reused, evidence = negative.check_public_profile(pivot(platform))
    assert len(calls) == 1
    assert reused.cache_hit and evidence.cache_hit
    assert reused.resolution_status == "not_found"
    assert reused.checked_at == first.checked_at == evidence.collected_at
    assert reused.review_priority_score == 0


def test_circuit_breaker_precedes_even_a_live_cache_entry():
    def response(request):
        return httpx.Response(200, json=payload()) if request.url.path.endswith("/alice") else httpx.Response(429)
    service, calls = service_for(response)
    service.check_public_profile(pivot())
    service.check_public_profile(pivot(handle="bob"))
    skipped, _ = service.check_public_profile(pivot())
    assert len(calls) == 2
    assert skipped.resolution_status == "rate_limited"
    assert skipped.checked_at is None
    assert not skipped.cache_hit
    service.begin_execution()
    assert service.check_public_profile(pivot())[0].cache_hit
    assert len(calls) == 2


@pytest.mark.parametrize("chunk_seconds", [0.25, 0.6])
def test_slow_drip_stream_obeys_whole_response_deadline_without_sleep(chunk_seconds):
    now = [0.0]
    events = []
    class SlowStream(httpx.SyncByteStream):
        def __iter__(self):
            for byte in json.dumps(payload()).encode():
                now[0] += chunk_seconds
                events.append("read")
                yield bytes([byte])
        def close(self):
            events.append("closed")
    service, calls = service_for(lambda request: httpx.Response(200,
                                headers={"content-type": "application/json"}, stream=SlowStream()),
                                timeout=1.0, clock=lambda: now[0])
    result, evidence = service.check_public_profile(pivot())
    assert len(calls) == 1
    assert result.resolution_status == "timeout"
    assert result.confidence == evidence.confidence == "low"
    assert events[-1] == "closed"
    assert events.count("read") <= 4
    assert not service._cache


def test_header_latency_counts_toward_whole_response_deadline():
    now = [0.0]
    def response(request):
        now[0] = 2.0
        return httpx.Response(200, json=payload())
    service, calls = service_for(response, timeout=1.0, clock=lambda: now[0])
    assert service.check_public_profile(pivot())[0].resolution_status == "timeout"
    assert len(calls) == 1
