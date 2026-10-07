import json
import socket
from urllib.parse import parse_qs, urlsplit

import pytest
from typer.testing import CliRunner

from mailrecon.cli.app import app
from mailrecon.services.demo_service import generate_demo
from mailrecon.services.search_links_service import build_search_links
from tests.test_cli import FakeReconService, FakeInvestigationService, FakeRefinementStateService
from mailrecon.services.smtp_lab_service import SmtpLabValidationService


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Network forbidden')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)


def test_manual_query_encoding():
    links = build_search_links('Joao & Co + #?', organizations=['A/B'], domains=['EXAMPLE.com', 'example.org'],
                               contexts=['defesa'], after='2026-01-01', before='2026-10-07', file_type='pdf')
    assert len(links) == 2
    for domain, url in links:
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and parsed.netloc == 'www.google.com' and not parsed.fragment
        params = parse_qs(parsed.query)
        assert list(params) == ['q']
        assert params['q'] == [f'"Joao & Co + #?" "A/B" "defesa" after:2026-01-01 before:2026-10-07 filetype:pdf site:{domain}']


@pytest.mark.parametrize('options', [
    {'after': '2026-02-30'}, {'before': '20260101'}, {'after': '2026-2-01'},
    {'after': '2026-10-07', 'before': '2026-01-01'}, {'file_type': 'exe'},
    {'domains': ['https://example.com']}, {'domains': ['example.com OR evil.test']},
    {'domains': ['example.com:80']}, {'contexts': ['hello\x1b']},
])
def test_invalid_search_filters(options):
    with pytest.raises(ValueError):
        build_search_links('demo', **options)


@pytest.mark.parametrize('locale', ['pt-br', 'en'])
def test_demo_offline_no_state_and_all_formats(tmp_path, monkeypatch, locale):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ['--language', locale, 'demo', '--output-dir', str(tmp_path / 'reports')])
    assert result.exit_code == 0, result.output
    files = list((tmp_path / 'reports').iterdir())
    assert len(files) == 9
    assert not (tmp_path / '.mailrecon-temp').exists()
    for path in files:
        content = path.read_text(encoding='utf-8')
        if path.suffix != '.json':
            assert 'demo@example.com' not in content
        if path.suffix == '.html':
            assert 'data-kind="observed"' not in content and 'data-kind="hypothesis"' not in content
            assert 'SYNTHETIC DEMO' in content or 'DEMONSTRAÇÃO SINTÉTICA' in content
    data = json.loads((tmp_path / 'reports/demo-investigation.json').read_text(encoding='utf-8'))
    assert data['confidence_breakdown']['identity_correlation'] == 0
    assert data['refinement_file_path'] is None
    repeated = runner.invoke(app, ['demo', '--output-dir', str(tmp_path / 'reports')])
    assert repeated.exit_code == 1


@pytest.mark.parametrize('directory', ['.', '.git/demo', '.mailrecon-temp/demo', '.codex/demo'])
def test_demo_rejects_sensitive_paths(tmp_path, monkeypatch, directory):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        generate_demo(directory)


@pytest.mark.parametrize('locale', ['pt-br', 'en'])
def test_sources_and_manual_cli_offline(locale):
    runner = CliRunner()
    result = runner.invoke(app, ['--language', locale, 'sources'])
    assert result.exit_code == 0 and 'GitLab' in result.output and 'manual' in result.output.lower()
    result = runner.invoke(app, ['--language', locale, 'search-links', 'demo@example.com', '--after', '2026-01-01'])
    assert result.exit_code == 0 and 'demo%40example.com' not in result.output
    assert 'google.com/search' in result.output
    revealed = runner.invoke(app, ['search-links', 'demo@example.com', '--reveal-emails'])
    assert revealed.exit_code == 0 and 'demo%40example.com' in revealed.output


@pytest.mark.parametrize('command', ['analyze', 'investigate', 'interactive', 'rerun-last', 'lab-admin', 'lab-smtp-validate'])
def test_html_flag_available_on_all_report_commands(command):
    result = CliRunner().invoke(app, [command, '--help'])
    assert result.exit_code == 0 and '--html-out' in result.output


@pytest.mark.parametrize('locale', ['pt-br', 'en'])
@pytest.mark.parametrize('command,args', [
    ('analyze', ['user@example.com', '--no-hibp']),
    ('investigate', ['--username', 'demo', '--no-hibp']),
    ('interactive', ['--no-hibp']),
    ('rerun-last', ['--no-hibp']),
    ('lab-admin', ['--handle', 'demo']),
    ('lab-smtp-validate', ['user@example.com', '--lab-domain', 'example.com', '--no-network']),
])
def test_cli_html_written_offline_for_each_model(tmp_path, monkeypatch, locale, command, args):
    monkeypatch.setattr('mailrecon.cli.app._build_recon_service', lambda use_hibp: FakeReconService())
    monkeypatch.setattr('mailrecon.cli.app._build_investigation_service', lambda use_hibp: FakeInvestigationService())
    monkeypatch.setattr('mailrecon.cli.app._build_refinement_state_service', lambda: FakeRefinementStateService())
    monkeypatch.setattr('mailrecon.cli.app._build_smtp_lab_validation_service', lambda: SmtpLabValidationService(enable_lab_smtp=False))
    path = tmp_path / 'report.html'
    answers = '\n'.join(['', '', 'demo', '', '', '', '', 'n', 'n', 'n']) + '\n'
    result = CliRunner().invoke(app, ['--language', locale, command, *args, '--html-out', str(path)], input=answers)
    assert result.exit_code == 0, result.output
    content = path.read_text(encoding='utf-8')
    assert 'user@example.com' not in content
    assert 'Content-Security-Policy' in content
    assert ('lang="en"' if locale == 'en' else 'lang="pt-BR"') in content
