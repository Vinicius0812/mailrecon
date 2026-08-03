from mailrecon.services.smtp_lab_service import SmtpLabValidationService


def test_smtp_lab_service_mock_uses_no_network() -> None:
    service = SmtpLabValidationService()

    result = service.validate(
        email="user@lab.local",
        lab_domain="lab.local",
        host="127.0.0.1",
        port=2525,
        transport="mock",
        checks=["vrfy", "rcpt"],
    )

    assert result.safety_decision.allowed is True
    assert result.network_used is False
    assert all(check.status == "mocked_accept" for check in result.checks_run)
    assert "do not prove real mailbox existence" in " ".join(result.limitations)


def test_smtp_lab_service_blocks_network_without_env_gate() -> None:
    service = SmtpLabValidationService(enable_lab_smtp=False)

    result = service.validate(
        email="user@lab.local",
        lab_domain="lab.local",
        host="127.0.0.1",
        port=2525,
        transport="localhost",
        checks=["vrfy"],
        confirm_lab_only=True,
    )

    assert result.safety_decision.allowed is False
    assert result.safety_decision.status == "blocked_by_safety_policy"
    assert result.network_used is False
    assert result.checks_run[0].status == "blocked_by_safety_policy"


def test_smtp_lab_service_blocks_domain_mismatch() -> None:
    service = SmtpLabValidationService()

    result = service.validate(
        email="user@example.com",
        lab_domain="lab.local",
        host="127.0.0.1",
        port=2525,
        transport="mock",
        checks=["vrfy"],
    )

    assert result.safety_decision.allowed is False
    assert any("Email domain must match" in reason for reason in result.safety_decision.reasons)


def test_smtp_lab_service_blocks_public_private_lab_host() -> None:
    service = SmtpLabValidationService(
        enable_lab_smtp=True,
        allow_hosts=[],
    )

    result = service.validate(
        email="user@lab.local",
        lab_domain="lab.local",
        host="8.8.8.8",
        port=2525,
        transport="private-lab",
        checks=["vrfy"],
        confirm_lab_only=True,
    )

    assert result.safety_decision.allowed is False
    assert any("private-lab transport only permits" in reason for reason in result.safety_decision.reasons)


def test_smtp_lab_service_runs_localhost_with_fake_smtp(monkeypatch) -> None:
    service = SmtpLabValidationService(enable_lab_smtp=True)

    class FakeSmtp:
        def __init__(self, host: str, port: int, timeout: float):
            self.host = host
            self.port = port
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def helo(self, name: str):
            return 250, b"hello"

        def verify(self, email: str):
            return 250, b"accepted in lab"

    monkeypatch.setattr("mailrecon.services.smtp_lab_service.smtplib.SMTP", FakeSmtp)

    result = service.validate(
        email="user@lab.local",
        lab_domain="lab.local",
        host="127.0.0.1",
        port=2525,
        transport="localhost",
        checks=["vrfy"],
        confirm_lab_only=True,
    )

    assert result.safety_decision.allowed is True
    assert result.network_used is True
    assert result.checks_run[0].status == "accepted_by_lab_server"
    assert result.checks_run[0].smtp_code == 250
