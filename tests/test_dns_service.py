from types import SimpleNamespace

import dns.resolver

from mailrecon.services.dns_service import DnsService


def test_dns_service_returns_a_and_mx_records(monkeypatch) -> None:
    service = DnsService(timeout=2.0)

    class FakeResolver:
        def resolve(self, domain: str, record_type: str):
            assert domain in {"example.com", "_dmarc.example.com"}
            if record_type == "A":
                return ["93.184.216.34"]
            if record_type == "AAAA":
                raise dns.resolver.NoAnswer
            if record_type == "MX":
                return [SimpleNamespace(exchange="mx.example.com.")]
            if record_type == "TXT" and domain == "example.com":
                return [SimpleNamespace(strings=[b"v=spf1 include:_spf.example.com -all"])]
            if record_type == "TXT" and domain == "_dmarc.example.com":
                return [SimpleNamespace(strings=[b"v=DMARC1; p=reject"])]
            if record_type == "NS":
                return ["ns1.example.com."]
            raise AssertionError(f"Unexpected record type: {record_type}")

    monkeypatch.setattr(service, "_build_resolver", lambda: FakeResolver())

    result = service.lookup_domain("example.com")

    assert result.resolves is True
    assert result.a_records == ["93.184.216.34"]
    assert result.mx_records == ["mx.example.com"]
    assert result.spf_status == "present"
    assert result.dmarc_status == "present"
    assert result.dmarc_policy == "reject"
    assert result.email_acceptance_status == "mx_present"
    assert result.errors == ["No AAAA records found."]


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
    assert result.email_acceptance_status == "no_mail_signal"


def test_dns_service_detects_null_mx(monkeypatch) -> None:
    service = DnsService(timeout=2.0)

    class FakeResolver:
        def resolve(self, domain: str, record_type: str):
            if record_type == "MX":
                return [SimpleNamespace(exchange=".")]
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(service, "_build_resolver", lambda: FakeResolver())

    result = service.lookup_domain("example.com")

    assert result.null_mx is True
    assert result.email_acceptance_status == "declares_no_mail"
    assert result.mx_records == []
    assert "Domain publishes Null MX and declares it does not accept email." in result.errors
