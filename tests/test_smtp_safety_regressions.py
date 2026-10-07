import json
import socket

import pytest

from mailrecon.reporting.console import render_smtp_lab_summary
from mailrecon.reporting.exporters import export_json, export_smtp_lab_markdown
from mailrecon.services.smtp_lab_service import SmtpLabValidationService


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Real network or SMTP constructor was invoked")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr("mailrecon.services.smtp_lab_service.smtplib.SMTP", forbidden)


def validate(*, host="127.0.0.1", transport="localhost", allow_hosts=None, **options):
    service = SmtpLabValidationService(
        enable_lab_smtp=options.pop("enabled", True), allow_hosts=allow_hosts
    )
    arguments = dict(
        email="user@lab.local", lab_domain="lab.local", host=host,
        port=2525, transport=transport, checks=["vrfy"], confirm_lab_only=True,
    )
    arguments.update(options)
    return service.validate(**arguments)


@pytest.mark.parametrize("transport", [" MOCK ", "mock", "Mock"])
@pytest.mark.parametrize("no_network", [False, True])
def test_normalized_mock_never_constructs_smtp(transport, no_network):
    result = validate(transport=transport, no_network=no_network,
                      host=" LOCALHOST ", lab_domain=" @LAB.LOCAL ")
    assert result.safety_decision.allowed
    assert not result.network_used
    assert (result.transport, result.host, result.lab_domain) == ("mock", "localhost", "lab.local")


@pytest.mark.parametrize("host", [
    "8.8.8.8", "192.0.2.1", "198.51.100.1", "203.0.113.1",
    "169.254.1.1", "224.0.0.1", "0.0.0.0", "100.64.0.1", "198.18.0.1",
    "240.0.0.1", "::", "ff02::1", "fe80::1", "fe80::1%1",
    "2001:db8::1", "::ffff:192.168.1.1", "lab.local", "localhost",
])
def test_allowlist_never_authorizes_unsafe_or_ambiguous_hosts(host):
    result = validate(host=host, transport="private-lab", allow_hosts=[host])
    assert not result.safety_decision.allowed
    assert not result.network_used


@pytest.mark.parametrize("host", ["192.168.1.1", "10.0.0.1", "fd00::1", "8.8.8.8", "lab.local"])
def test_localhost_transport_cannot_be_bypassed_by_allowlist(host):
    result = validate(host=host, allow_hosts=[host])
    assert not result.safety_decision.allowed
    assert not result.network_used


@pytest.mark.parametrize("host", ["10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1", "::1"])
def test_private_lab_requires_exact_ip_allowlist(host):
    result = validate(host=host, transport="private-lab", allow_hosts=["10.9.9.9"])
    assert not result.safety_decision.allowed


@pytest.mark.parametrize("options", [
    {"enabled": False}, {"confirm_lab_only": False}, {"no_network": True},
    {"port": 0}, {"port": 65536}, {"max_probes": 0}, {"max_probes": 4},
    {"checks": []}, {"checks": ["unknown"]},
    {"checks": ["vrfy", "rcpt"], "max_probes": 1},
])
def test_network_gates_and_probe_rules_preserved(options):
    result = validate(**options)
    assert not result.safety_decision.allowed
    assert not result.network_used


@pytest.mark.parametrize("port", [25, 465, 587])
def test_private_nonloopback_blocks_mail_ports(port):
    assert not validate(host="10.0.0.1", transport="private-lab",
                        allow_hosts=["10.0.0.1"], port=port).safety_decision.allowed


def test_expn_stays_localhost_only():
    assert not validate(transport="private-lab", allow_hosts=["127.0.0.1"],
                        checks=["expn"]).safety_decision.allowed


@pytest.mark.parametrize("host,transport,allow_hosts,target", [
    (" LOCALHOST ", " LOCALHOST ", [], "127.0.0.1"),
    ("127.0.0.1", "localhost", [], "127.0.0.1"),
    ("::1", "localhost", [], "::1"),
    (" 10.0.0.1 ", " PRIVATE-LAB ", [" 10.0.0.1 "], "10.0.0.1"),
    ("172.16.0.1", "private-lab", ["172.16.0.1"], "172.16.0.1"),
    ("192.168.1.1", "private-lab", ["192.168.1.1"], "192.168.1.1"),
    ("FD00::1", "private-lab", ["fd00:0:0:0:0:0:0:1"], "fd00::1"),
    ("::1", "private-lab", ["::1"], "::1"),
])
def test_connection_uses_classified_literal(monkeypatch, host, transport, allow_hosts, target):
    connections = []

    class FakeSmtp:
        def __init__(self, host, port, timeout):
            connections.append((host, port))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def helo(self, name):
            return 250, b"hello"

        def verify(self, email):
            return 250, b"accepted"

    monkeypatch.setattr("mailrecon.services.smtp_lab_service.smtplib.SMTP", FakeSmtp)
    result = validate(host=host, transport=transport, allow_hosts=allow_hosts)
    assert result.safety_decision.allowed
    assert connections == [(target, 2525)]
    assert result.resolved_ips == [target]


@pytest.mark.parametrize("locale", ["pt-br", "en"])
@pytest.mark.parametrize("mask", [False, True])
def test_wire_controls_are_escaped_but_json_keeps_raw_reply(tmp_path, locale, mask):
    result = validate(transport="mock")
    raw = "\x1b[2J\x1b]0;title\x07user@lab.local\r\n\t\b\x7f\x9b\u202e"
    result.checks_run[0].message = raw
    terminal = render_smtp_lab_summary(result, language=locale, mask_sensitive=mask)
    markdown = export_smtp_lab_markdown(result, tmp_path / "smtp.md", language=locale,
                                       mask_sensitive=mask).read_text(encoding="utf-8")
    for output in (terminal, markdown):
        for control in ("\x1b", "\x07", "\r", "\b", "\x7f", "\x9b", "\u202e"):
            assert control not in output
        assert "\\x1b[2J" in output
        assert ("user@lab.local" in output) is not mask
    payload = json.loads(export_json(result, tmp_path / "smtp.json", language=locale).read_text(encoding="utf-8"))
    assert payload["checks_run"][0]["message"] == raw
    assert result.checks_run[0].message == raw
