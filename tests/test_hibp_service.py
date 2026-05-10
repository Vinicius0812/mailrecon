import httpx

from mailrecon.services.hibp_service import HibpService


def test_hibp_service_skips_when_disabled() -> None:
    service = HibpService(api_key="secret", enabled=False)

    result = service.query_breaches("user@example.com")

    assert result.queried is False
    assert result.status == "disabled"


def test_hibp_service_skips_without_api_key() -> None:
    service = HibpService(api_key=None, enabled=True)

    result = service.query_breaches("user@example.com")

    assert result.queried is False
    assert result.status == "missing_api_key"


def test_hibp_service_handles_404_with_no_breaches(monkeypatch) -> None:
    service = HibpService(api_key="secret", enabled=True)

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def get(self, url, params=None):
            request = httpx.Request("GET", url)
            return httpx.Response(status_code=404, request=request)

    monkeypatch.setattr("mailrecon.services.hibp_service.httpx.Client", FakeClient)

    result = service.query_breaches("user@example.com")

    assert result.queried is True
    assert result.status == "no_breaches"
    assert result.breaches == []
