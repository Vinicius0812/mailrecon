from mailrecon.core.config import load_settings
import pytest


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


@pytest.mark.parametrize("name,field,default,maximum", [
    ("MAILRECON_PROFILE_TOTAL_BUDGET", "profile_total_budget", 20, 100),
    ("MAILRECON_PROFILE_SOURCE_BUDGET", "profile_source_budget", 10, 50),
    ("MAILRECON_PROFILE_MAX_RESPONSE_BYTES", "profile_max_response_bytes", 65536, 1048576),
    ("MAILRECON_PROFILE_CACHE_TTL", "profile_cache_ttl", 60, 300),
    ("MAILRECON_PROFILE_CACHE_ENTRIES", "profile_cache_entries", 128, 512),
])
@pytest.mark.parametrize("invalid", ["", "-1", "nan", "inf", "1.5", "9999999999"])
def test_profile_env_limits_use_safe_defaults(monkeypatch, name, field, default, maximum, invalid):
    monkeypatch.setenv(name, invalid)
    assert getattr(load_settings(), field) == default
    monkeypatch.setenv(name, str(maximum))
    assert getattr(load_settings(), field) == maximum
