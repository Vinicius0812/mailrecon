from dataclasses import replace

from typer.testing import CliRunner

from mailrecon.cli.app import app
from mailrecon.core.models import (
    DnsLookupResult,
    EmailCandidate,
    EvidenceRecord,
    HibpResult,
    InvestigationInput,
    InvestigationResult,
    ProfilePivot,
    ReconResult,
)


class FakeReconService:
    def analyze_email(self, email: str, progress_callback=None) -> ReconResult:
        if progress_callback is not None:
            progress_callback("Checking DNS and MX records for example.com...")
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
    def investigate(
        self,
        query: InvestigationInput,
        check_public_profiles: bool = False,
        lab_profile_scenario: str | None = None,
        progress_callback=None,
    ) -> InvestigationResult:
        if progress_callback is not None:
            progress_callback("Building candidate emails...")
        return InvestigationResult(
            query=query,
            candidate_emails=[
                EmailCandidate(
                    email="user@example.com",
                    masked_email="u**r@example.com",
                    domain="example.com",
                    source="seed_email",
                    confidence="high",
                    confidence_score=90,
                    status="valid",
                )
            ],
            profile_pivots=[
                ProfilePivot(
                    platform="LinkedIn",
                    handle="user",
                    profile_url="https://www.linkedin.com/in/user/",
                    search_url="https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22user%22",
                    source="public_profile_pivot",
                    confidence="low",
                    confidence_score=50,
                    status="manual_review",
                    resolution_status="public_match_possible",
                    http_status_code=200,
                    final_url="https://www.linkedin.com/in/user/",
                    checked_at="2026-05-21T12:00:00+00:00",
                    notes=["Public URL generated for safe manual review."],
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
                    confidence_score=80,
                    summary="The investigation started with email: u**r@example.com",
                )
            ],
            findings=["The investigation organized 1 candidate email(s) for safe review."],
            risks=["Public breach exposure may increase phishing risk."],
            pivot_suggestions=["Review naming patterns."],
            limitations=["Results are OSINT indicators."],
            overall_confidence_score=73,
        )


class FakeRefinementStateService:
    def apply_and_store(
        self,
        query: InvestigationInput,
        result: InvestigationResult,
        run_options: dict[str, object] | None = None,
    ) -> InvestigationResult:
        return replace(
            result,
            refinement_file_path=".mailrecon-temp/last-investigation-refinement.json",
        )

    def load_last_investigation(self) -> tuple[InvestigationInput, dict[str, object]]:
        return (
            InvestigationInput(
                emails=["saved@example.com"],
                usernames=["saveduser"],
                domains=["example.com"],
            ),
            {
                "use_hibp": False,
                "check_public_profiles": True,
                "lab_profile_scenario": None,
            },
        )


def test_cli_shows_help_without_args() -> None:
    runner = CliRunner()

    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "Educational CLI for email recon and validation." in result.stdout
    assert "Commands" in result.stdout
    assert "analyze" in result.stdout
    assert "investigate" in result.stdout
    assert "interactive" in result.stdout


def test_cli_analyze_renders_summary(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_recon_service",
        lambda use_hibp: FakeReconService(),
    )

    result = runner.invoke(app, ["analyze", "user@example.com", "--no-hibp"])

    assert result.exit_code == 0
    assert "[...] Checking DNS and MX records for example.com..." in result.stdout
    assert "=== MailRecon Analysis ===" in result.stdout
    assert "Email              : user@example.com" in result.stdout
    assert "Domain             : example.com" in result.stdout
    assert "HIBP status        : missing_api_key" in result.stdout


def test_cli_analyze_handles_invalid_input(monkeypatch) -> None:
    runner = CliRunner()

    class ErrorReconService:
        def analyze_email(self, email: str, progress_callback=None) -> ReconResult:
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
    monkeypatch.setattr(
        "mailrecon.cli.app._build_refinement_state_service",
        lambda: FakeRefinementStateService(),
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
    assert "[...] Building candidate emails..." in result.stdout
    assert "=== MailRecon Investigation ===" in result.stdout
    assert "Overall confidence : 73/100" in result.stdout
    assert "Candidate emails : 1" in result.stdout
    assert "Profile pivots   : 1" in result.stdout
    assert "u**r@example.com" in result.stdout
    assert "Most trusted platform links" in result.stdout
    assert "https://www.linkedin.com/in/user/" in result.stdout
    assert "status=public_match_possible" in result.stdout
    assert "Refinement file ready at:" in result.stdout
    assert ".mailrecon-temp/last-investigation-refinement.json" in result.stdout


def test_cli_investigate_can_reveal_emails(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: FakeInvestigationService(),
    )
    monkeypatch.setattr(
        "mailrecon.cli.app._build_refinement_state_service",
        lambda: FakeRefinementStateService(),
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


def test_cli_interactive_collects_inputs(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: FakeInvestigationService(),
    )
    monkeypatch.setattr(
        "mailrecon.cli.app._build_refinement_state_service",
        lambda: FakeRefinementStateService(),
    )

    answers = "\n".join(
        [
            "Alice Smith",
            "alice@example.com",
            "asmith",
            "example.com",
            "Example Org",
            "initial triage",
            "",
            "n",
            "n",
            "n",
        ]
    ) + "\n"

    result = runner.invoke(app, ["interactive", "--no-hibp"], input=answers)

    assert result.exit_code == 0
    assert "MailRecon interactive investigation" in result.stdout
    assert "Overall confidence : 73/100" in result.stdout


def test_cli_interactive_can_choose_exports(monkeypatch, tmp_path) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: FakeInvestigationService(),
    )
    monkeypatch.setattr(
        "mailrecon.cli.app._build_refinement_state_service",
        lambda: FakeRefinementStateService(),
    )

    json_path = tmp_path / "interactive.json"
    md_path = tmp_path / "interactive.md"
    answers = "\n".join(
        [
            "",
            "alice@example.com",
            "",
            "example.com",
            "",
            "",
            "",
            "y",
            str(json_path),
            "y",
            str(md_path),
            "pt-br",
            "n",
        ]
    ) + "\n"

    result = runner.invoke(app, ["interactive", "--no-hibp"], input=answers)

    assert result.exit_code == 0
    assert f"JSON report saved to: {json_path}" in result.stdout
    assert f"Markdown report saved to: {md_path}" in result.stdout
    assert json_path.exists()
    assert md_path.exists()


def test_cli_lab_admin_runs_simulation(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: FakeInvestigationService(),
    )
    monkeypatch.setattr(
        "mailrecon.cli.app._build_refinement_state_service",
        lambda: FakeRefinementStateService(),
    )

    result = runner.invoke(
        app,
        [
            "lab-admin",
            "--handle",
            "user",
            "--scenario",
            "found",
        ],
    )

    assert result.exit_code == 0
    assert "Overall confidence : 73/100" in result.stdout


def test_cli_rerun_last_reuses_saved_parameters(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: FakeInvestigationService(),
    )
    monkeypatch.setattr(
        "mailrecon.cli.app._build_refinement_state_service",
        lambda: FakeRefinementStateService(),
    )

    result = runner.invoke(app, ["rerun-last"])

    assert result.exit_code == 0
    assert "Reloading the latest saved investigation parameters..." in result.stdout
    assert "Overall confidence : 73/100" in result.stdout


def test_cli_investigate_handles_invalid_input(monkeypatch) -> None:
    runner = CliRunner()

    class ErrorInvestigationService:
        def investigate(
            self,
            query: InvestigationInput,
            check_public_profiles: bool = False,
            lab_profile_scenario: str | None = None,
            progress_callback=None,
        ) -> InvestigationResult:
            raise ValueError("Provide at least one seed.")

    monkeypatch.setattr(
        "mailrecon.cli.app._build_investigation_service",
        lambda use_hibp: ErrorInvestigationService(),
    )

    result = runner.invoke(app, ["investigate"])

    assert result.exit_code == 1
    assert "Invalid investigation input:" in result.stderr
