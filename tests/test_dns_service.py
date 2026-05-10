from types import SimpleNamespace

import dns.resolver

from mailrecon.services.dns_service import DnsService


def test_dns_service_returns_a_and_mx_records(monkeypatch) -> None:
    service = DnsService(timeout=2.0)

    class FakeResolver:
        def resolve(self, domain: str, record_type: str):
            assert domain == "example.com"
            if record_type == "A":
                return ["93.184.216.34"]
            if record_type == "MX":
                return [SimpleNamespace(exchange="mx.example.com.")]
            raise AssertionError(f"Unexpected record type: {record_type}")

    monkeypatch.setattr(service, "_build_resolver", lambda: FakeResolver())

    result = service.lookup_domain("example.com")

    assert result.resolves is True
    assert result.a_records == ["93.184.216.34"]
    assert result.mx_records == ["mx.example.com"]
    assert result.errors == []


def test_dns_service_handles_missing_records(monkeypatch) -> None:
    service = DnsService(timeout=2.0)

    class FakeResolver:
        def resolve(self, domain: str, record_type: str):
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(service, "_build_resolver", lambda: FakeResolver())

    result = service.lookup_domain("example.com")

    assert result.resolves is False
    assert result.a_records == []
    assert result.mx_records == []
    assert "No A records found." in result.errors
    assert "No MX records found." in result.errors
