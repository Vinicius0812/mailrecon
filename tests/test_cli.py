from typer.testing import CliRunner

from mailrecon.cli.app import app
from mailrecon.core.models import DnsLookupResult, HibpResult, ReconResult


class FakeReconService:
    def analyze_email(self, email: str) -> ReconResult:
        return ReconResult(
            email=email,
            domain="example.com",
            is_valid=True,
            dns=DnsLookupResult(
                resolves=True,
                a_records=["93.184.216.34"],
                mx_records=["mx.example.com"],
            ),
            hibp=HibpResult(
                queried=False,
                status="missing_api_key",
            ),
        )


def test_cli_shows_help_without_args() -> None:
    runner = CliRunner()

    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "Educational CLI for email recon and validation." in result.stdout


def test_cli_analyze_renders_summary(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_recon_service",
        lambda use_hibp: FakeReconService(),
    )

    result = runner.invoke(app, ["analyze", "user@example.com", "--no-hibp"])

    assert result.exit_code == 0
    assert "Email: user@example.com" in result.stdout
    assert "Domain: example.com" in result.stdout
    assert "HIBP status: missing_api_key" in result.stdout


def test_cli_analyze_handles_invalid_input(monkeypatch) -> None:
    runner = CliRunner()

    class ErrorReconService:
        def analyze_email(self, email: str) -> ReconResult:
            raise ValueError("The email address is not valid.")

    monkeypatch.setattr(
        "mailrecon.cli.app._build_recon_service",
        lambda use_hibp: ErrorReconService(),
    )

    result = runner.invoke(app, ["analyze", "not-an-email"])

    assert result.exit_code == 1
    assert "Invalid input:" in result.stdout
