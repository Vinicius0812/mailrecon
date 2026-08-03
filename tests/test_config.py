from mailrecon.core.config import load_settings


def test_load_settings_ignores_non_positive_timeouts(monkeypatch) -> None:
    monkeypatch.setenv("MAILRECON_HTTP_TIMEOUT", "-1")
    monkeypatch.setenv("MAILRECON_DNS_TIMEOUT", "0")

    settings = load_settings()

    assert settings.http_timeout == 10.0
    assert settings.dns_timeout == 5.0


def test_load_settings_ignores_non_finite_timeouts(monkeypatch) -> None:
    monkeypatch.setenv("MAILRECON_HTTP_TIMEOUT", "nan")
    monkeypatch.setenv("MAILRECON_DNS_TIMEOUT", "inf")

    settings = load_settings()

    assert settings.http_timeout == 10.0
    assert settings.dns_timeout == 5.0


def test_load_settings_reads_lab_smtp_controls(monkeypatch) -> None:
    monkeypatch.setenv("MAILRECON_ENABLE_LAB_SMTP", "1")
    monkeypatch.setenv("MAILRECON_LAB_SMTP_ALLOW_HOSTS", "127.0.0.1, lab-smtp.local ")
    monkeypatch.setenv("MAILRECON_LAB_SMTP_TIMEOUT", "2.5")

    settings = load_settings()

    assert settings.enable_lab_smtp is True
    assert settings.lab_smtp_allow_hosts == ["127.0.0.1", "lab-smtp.local"]
    assert settings.lab_smtp_timeout == 2.5
