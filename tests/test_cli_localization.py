"""Offline acceptance tests for per-invocation languages and prompts."""

import json

import pytest
from typer.testing import CliRunner

from mailrecon.cli.app import app
from mailrecon.core.i18n import msg
from mailrecon.services.refinement_state_service import RefinementStateService
from tests.test_cli import FakeInvestigationService, FakeReconService, FakeRefinementStateService


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr("mailrecon.cli.app._build_recon_service", lambda use_hibp: FakeReconService())
    monkeypatch.setattr("mailrecon.cli.app._build_investigation_service", lambda use_hibp: FakeInvestigationService())
    monkeypatch.setattr("mailrecon.cli.app._build_refinement_state_service", lambda: FakeRefinementStateService())


@pytest.mark.parametrize("locale,heading,options", [("pt-br", "Uso:", "Opções:"), ("en", "Usage:", "Options:")])
@pytest.mark.parametrize("command", [None, "analyze", "investigate", "interactive", "rerun-last", "lab-admin", "lab-smtp-validate"])
def test_help_in_both_languages(locale, heading, options, command):
    arguments = ["--language", locale] + ([command] if command else []) + ["--help"]
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.exception
    assert heading in result.stdout
    assert options in result.stdout
    if locale == "pt-br":
        assert "Show this message" not in result.stdout
        assert "Email address" not in result.stdout
        assert "Install completion" not in result.stdout
    if command:
        assert "--markdown-language [pt-br|en]" in result.stdout


def test_language_does_not_leak_between_invocations(offline):
    runner = CliRunner()
    english = runner.invoke(app, ["--language", "en", "analyze", "person@example.com"])
    portuguese = runner.invoke(app, ["analyze", "person@example.com"])
    assert english.exit_code == portuguese.exit_code == 0
    assert "MailRecon Analysis" in english.stdout
    assert "Análise MailRecon" in portuguese.stdout


@pytest.mark.parametrize("locale,error", [("pt-br", "Erro:"), ("en", "Error:")])
@pytest.mark.parametrize("arguments", [["--language", "de", "analyze", "person@example.com"], ["analyze"], ["analyze", "person@example.com", "--markdown-language", "de"], ["unknown-command"]])
def test_parser_errors_are_localized(locale, error, arguments):
    result = CliRunner().invoke(app, ["--language", locale, *arguments])
    assert result.exit_code == 2
    assert error in result.stderr


@pytest.mark.parametrize("command,arguments", [
    ("analyze", ["person@example.com"]),
    ("investigate", ["--email", "person@example.com"]),
    ("lab-admin", ["--handle", "fictional"]),
    ("lab-smtp-validate", ["person@lab.local", "--lab-domain", "lab.local", "--no-network"]),
])
@pytest.mark.parametrize("locale,report_locale,title", [("pt-br", "en", "# MailRecon"), ("en", "pt-br", "# Relatório")])
def test_markdown_override_is_independent(offline, tmp_path, command, arguments, locale, report_locale, title):
    output = tmp_path / "report.md"
    result = CliRunner().invoke(app, ["--language", locale, command, *arguments, "--md-out", str(output), "--markdown-language", report_locale])
    assert result.exit_code == 0, result.exception
    if command == "lab-smtp-validate" and report_locale == "pt-br":
        title = "# Validação SMTP"
    assert output.read_text(encoding="utf-8").startswith(title)
    assert ("Relatório Markdown salvo" if locale == "pt-br" else "Markdown report saved") in result.stdout


def test_default_markdown_and_json_use_ptbr(offline, tmp_path):
    markdown = tmp_path / "report.md"
    output = tmp_path / "report.json"
    result = CliRunner().invoke(app, ["analyze", "person@example.com", "--md-out", str(markdown), "--json-out", str(output)])
    assert result.exit_code == 0, result.exception
    assert markdown.read_text(encoding="utf-8").startswith("# Relatório")
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["email"] == "person@example.com"
    assert payload["hibp"]["status"] == "missing_api_key"
    assert "technical_assessment" in payload


@pytest.mark.parametrize("positive", ["s", "sim", "S", "SIM"])
@pytest.mark.parametrize("negative", ["n", "não", "nao"])
def test_portuguese_confirmations(offline, tmp_path, positive, negative):
    output = tmp_path / "interactive.json"
    answers = ["Pessoa Exemplo", "person@example.com", "", "", "", "", "", positive, str(output), negative, negative]
    result = CliRunner().invoke(app, ["interactive", "--no-hibp"], input="\n".join(answers) + "\n")
    assert result.exit_code == 0, result.exception
    assert "Investigação interativa" in result.stdout
    assert "[s/N]" in result.stdout
    assert output.exists()


def test_enter_uses_announced_defaults_and_rejects_wrong_locale(offline, tmp_path):
    markdown = tmp_path / "interactive.md"
    answers = ["", "person@example.com", "", "", "", "", "", "yes", "", "", str(markdown), "", ""]
    result = CliRunner().invoke(app, ["interactive", "--no-hibp"], input="\n".join(answers) + "\n")
    assert result.exit_code == 0, result.exception
    assert "Responda sim ou não." in result.stdout
    assert "[S/n]" in result.stdout
    assert markdown.read_text(encoding="utf-8").startswith("# Relatório")


def test_progress_and_authored_error_preserve_message_metadata(monkeypatch):
    class Service:
        def analyze_email(self, email, progress_callback=None):
            progress_callback(msg("cli.reload"))
            raise ValueError(msg("cli.confirm_invalid"))

    monkeypatch.setattr("mailrecon.cli.app._build_recon_service", lambda use_hibp: Service())
    result = CliRunner().invoke(app, ["analyze", "person@example.com"])
    assert result.exit_code == 1
    assert "[...] Carregando os parâmetros" in result.stdout
    assert "Entrada inválida: Responda sim ou não." in result.stderr


def test_rerun_old_state_uses_selected_language(offline, monkeypatch, tmp_path):
    state = tmp_path / "old-state.json"
    state.write_text(json.dumps({"query": {"emails": ["person@example.com"]}, "run_options": {"use_hibp": False}, "instructions": "Legacy instructions"}), encoding="utf-8")
    monkeypatch.setattr("mailrecon.cli.app._build_refinement_state_service", lambda: RefinementStateService(state, language="pt-br"))
    result = CliRunner().invoke(app, ["--language", "en", "rerun-last"])
    assert result.exit_code == 0, result.exception
    assert "MailRecon Investigation" in result.stdout
    assert "Reloading the latest saved" in result.stdout


def test_utf8_entrypoint_reconfigures_streams(monkeypatch):
    from mailrecon import main

    class Stream:
        encoding = None
        def reconfigure(self, *, encoding):
            self.encoding = encoding

    output, error = Stream(), Stream()
    monkeypatch.setattr(main.sys, "stdout", output)
    monkeypatch.setattr(main.sys, "stderr", error)
    monkeypatch.setattr(main, "app", lambda: None)
    main.run()
    assert output.encoding == error.encoding == "utf-8"


@pytest.mark.parametrize("reveal", [False, True])
def test_progress_respects_email_masking(monkeypatch, reveal):
    class Service(FakeReconService):
        def analyze_email(self, email, progress_callback=None):
            progress_callback(msg("investigation.progress.analyze", email=email))
            return super().analyze_email(email)

    monkeypatch.setattr("mailrecon.cli.app._build_recon_service", lambda use_hibp: Service())
    arguments = ["analyze", "person@example.com"] + (["--reveal-emails"] if reveal else [])
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0
    if reveal:
        assert "[...] Analisando o e-mail candidato: person@example.com" in result.stdout
    else:
        assert "person@example.com" not in result.stdout
        assert "[...] Analisando o e-mail candidato: p****n@example.com" in result.stdout


def test_export_errors_use_selected_language(offline, monkeypatch, tmp_path):
    def failing(*args, **kwargs):
        raise PermissionError("External filesystem detail")

    monkeypatch.setattr("mailrecon.cli.app.export_json", failing)
    result = CliRunner().invoke(app, ["analyze", "person@example.com", "--json-out", str(tmp_path / "denied.json")])
    assert result.exit_code == 1
    assert "Não foi possível salvar o relatório" in result.stderr
    assert "External filesystem detail" in result.stderr


@pytest.mark.parametrize("arguments,expected", [
    (["--language"], "exige um argumento"),
    (["analyze", "person@example.com", "extra"], "Argumento extra inesperado (extra)"),
    (["lab-smtp-validate", "person@lab.local", "--lab-domain", "lab.local", "--port", "abc"], "não é um número inteiro válido"),
    (["lab-smtp-validate", "person@lab.local", "--lab-domain", "lab.local", "--port", "0"], "está fora do intervalo"),
])
def test_portuguese_parser_details(arguments, expected):
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 2
    assert expected in result.stderr


def test_english_interactive_abort_keeps_language():
    result = CliRunner().invoke(app, ["--language", "en", "interactive"], input="")
    assert result.exit_code == 1
    assert "Aborted." in result.stderr


@pytest.mark.parametrize("locale", ["pt-br", "en"])
@pytest.mark.parametrize("arguments,flag", [
    (["analyze", "person@example.com", "fictional@example.com"], None),
    (["lab-smtp-validate", "person@lab.local", "--lab-domain", "lab.local",
      "--port", "fictional@example.com"], "--port"),
    (["fictional@example.com"], None),
    (["analyze", "person@example.com", "--fictional@example.com"], "--"),
])
def test_parser_masks_addresses_without_hiding_flags(locale, arguments, flag):
    result = CliRunner().invoke(app, ["--language", locale, *arguments])
    assert result.exit_code == 2
    assert ("Erro:" if locale == "pt-br" else "Error:") in result.stderr
    assert "fictional@example.com" not in result.stderr
    assert "f*******l@example.com" in result.stderr
    if flag:
        assert flag in result.stderr


@pytest.mark.parametrize("reveal", [False, True])
def test_export_failure_masks_email_in_path_and_detail(offline, monkeypatch, tmp_path, reveal):
    output = tmp_path / "fictional@example.com" / "report.json"
    def failing(*args, **kwargs):
        raise PermissionError(13, "Permission denied", str(output))

    monkeypatch.setattr("mailrecon.cli.app.export_json", failing)
    arguments = ["analyze", "person@example.com", "--json-out", str(output)] + (["--reveal-emails"] if reveal else [])
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 1
    if reveal:
        assert "fictional@example.com" in result.stderr
    else:
        assert "fictional@example.com" not in result.stderr
        assert "f*******l@example.com" in result.stderr
