from typer.testing import CliRunner

from mailrecon.cli.app import app
from mailrecon.core.models import (
    DnsLookupResult,
    EmailCandidate,
    EvidenceRecord,
    HibpResult,
    InvestigationInput,
    InvestigationResult,
    ReconResult,
)


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


class FakeInvestigationService:
    def investigate(self, query: InvestigationInput) -> InvestigationResult:
        return InvestigationResult(
            query=query,
            candidate_emails=[
                EmailCandidate(
                    email="user@example.com",
                    masked_email="u**r@example.com",
                    domain="example.com",
                    source="seed_email",
                    confidence="high",
                    status="valid",
                )
            ],
            evidences=[
                EvidenceRecord(
                    title="Seed email",
                    category="seed",
                    source="investigator_input",
                    reference="CLI input",
                    collected_at="2026-05-21T12:00:00+00:00",
                    method="manual_input",
                    confidence="high",
                    summary="The investigation started with email: u**r@example.com",
                )
            ],
            findings=["The investigation organized 1 candidate email(s) for safe review."],
            risks=["Public breach exposure may increase phishing risk."],
            pivot_suggestions=["Review naming patterns."],
            limitations=["Results are OSINT indicators."],
        )


def test_cli_shows_help_without_args() -> None:
    runner = CliRunner()

    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "Educational CLI for email recon and validation." in result.stdout
    assert "Commands" in result.stdout
    assert "analyze" in result.stdout
    assert "investigate" in result.stdout


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
    assert "Invalid input:" in result.stderr


def test_cli_investigate_renders_summary(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: FakeInvestigationService(),
    )

    result = runner.invoke(
        app,
        [
            "investigate",
            "--email",
            "user@example.com",
            "--domain",
            "example.com",
            "--no-hibp",
        ],
    )

    assert result.exit_code == 0
    assert "Investigation summary:" in result.stdout
    assert "- Candidate emails: 1" in result.stdout
    assert "u**r@example.com" in result.stdout


def test_cli_investigate_can_reveal_emails(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: FakeInvestigationService(),
    )

    result = runner.invoke(
        app,
        [
            "investigate",
            "--email",
            "user@example.com",
            "--domain",
            "example.com",
            "--reveal-emails",
            "--no-hibp",
        ],
    )

    assert result.exit_code == 0
    assert "user@example.com" in result.stdout


def test_cli_investigate_handles_invalid_input(monkeypatch) -> None:
    runner = CliRunner()

    class ErrorInvestigationService:
        def investigate(self, query: InvestigationInput) -> InvestigationResult:
            raise ValueError("Provide at least one seed.")

    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: ErrorInvestigationService(),
    )

    result = runner.invoke(app, ["investigate"])

    assert result.exit_code == 1
    assert "Invalid investigation input:" in result.stderr
