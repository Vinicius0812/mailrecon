import base64
import hashlib
from html import unescape
from html.parser import HTMLParser

import pytest

from tests.test_exporters import build_result, build_investigation_result
from mailrecon.reporting.html import export_html, _safe_url
from mailrecon.services.smtp_lab_service import SmtpLabValidationService
from mailrecon.reporting.html import _Report
from mailrecon.services.investigation_service import InvestigationService
from mailrecon.core.models import HibpResult


class Elements(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.elements = []
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


@pytest.mark.parametrize('locale', ['pt-br', 'en'])
@pytest.mark.parametrize('factory', [build_result, build_investigation_result])
def test_html_masking_hashes_and_local_resources(tmp_path, locale, factory):
    result = factory()
    content = export_html(result, tmp_path / 'report.html', language=locale).read_text(encoding='utf-8')
    assert 'user@example.com' not in unescape(content)
    elements = Elements(content).elements
    csp = next(attrs['content'] for tag, attrs in elements if attrs.get('http-equiv') == 'Content-Security-Policy')
    for tag in ['style', 'script']:
        block = content.split(f'<{tag}>')[1].split(f'</{tag}>')[0]
        digest = base64.b64encode(hashlib.sha256(block.encode()).digest()).decode()
        assert f"'sha256-{digest}'" in csp
    assert "default-src 'none'" in csp and "connect-src 'none'" in csp
    assert 'unsafe-inline' not in csp
    assert 'innerHTML' not in content and 'fetch(' not in content
    assert not any('src' in attrs or tag in {'img', 'iframe', 'link'} for tag, attrs in elements)
    assert all(attrs['rel'] == 'noopener noreferrer' for tag, attrs in elements if tag == 'a')
    assert 'html_identity' not in content
    revealed = export_html(result, tmp_path / 'reveal.html', mask_sensitive=False).read_text(encoding='utf-8')
    assert 'user@example.com' in revealed


@pytest.mark.parametrize('url', [
    'javascript:alert(1)', 'data:text/html,hi', '//example.com',
    'https://user:pass@example.com', 'https://example.com\\@evil.test',
    'https://example.com/?q=user%2540example.com',
    'https://example.com/?q=user&#64;example.com',
    'https://example.com/%0afoo', 'https://example.com:invalid',
])
def test_unsafe_or_email_links_are_not_clickable(url):
    assert _safe_url(url, True) is None


def test_upstream_payload_escaped_everywhere(tmp_path):
    result = build_investigation_result()
    attack = '</td><script>alert(1)</script><img src=x onerror=alert(2)>'
    result.query.contexts = [attack]
    result.profile_pivots[0].profile_url = 'https://example.com/?q=user%2540example.com'
    result.evidences[0].summary = attack
    result.evidences[0].reference = 'javascript:alert(2)'
    content = export_html(result, tmp_path / 'x.html').read_text(encoding='utf-8')
    assert attack not in content and '&lt;script&gt;' in content
    assert 'user%2540example.com' not in content and 'user@example.com' not in content
    assert not any(tag == 'img' or any(key.startswith('on') for key in attrs) for tag, attrs in Elements(content).elements)
    assert not any('@' in unescape(attrs['href']) or '%40' in attrs['href'] for tag, attrs in Elements(content).elements if tag == 'a')


def test_mock_smtp_report_controls_and_masking(tmp_path):
    result = SmtpLabValidationService(enable_lab_smtp=False).validate(
        'user@example.com', lab_domain='example.com', host='127.0.0.1', port=2525, transport='mock', checks=['vrfy'], no_network=True)
    result.checks_run[0].message = 'user@example.com\x1b[31m <script>bad</script>'
    content = export_html(result, tmp_path / 'smtp.html').read_text(encoding='utf-8')
    assert 'user@example.com' not in content and '\x1b' not in content
    assert '&lt;script&gt;bad&lt;/script&gt;' in content
    assert 'data-kind="synthetic"' in content


@pytest.mark.parametrize('status,queried,expected', [
    ('disabled', False, 'hypothesis'), ('missing_api_key', False, 'hypothesis'),
    ('no_breaches', True, 'observed'), ('breaches_found', True, 'observed'),
    ('timeout', True, 'observed'),
])
def test_hibp_collection_metadata_not_prose(status, queried, expected, tmp_path):
    result = build_investigation_result()
    candidate = result.candidate_emails[0]
    candidate.analysis = build_result()
    candidate.analysis.hibp = HibpResult(queried, status)
    service = InvestigationService(recon_service=None, dns_service=None)
    records = service._build_candidate_evidences(candidate)
    evidence = records[1]
    assert evidence.collection_performed is queried
    assert _Report('en', True).kind(evidence) == expected
    evidence.summary = 'Collection success claims in prose must not affect structured state'
    result.evidences = [evidence]
    result.profile_pivots = []
    candidate.analysis = None
    content = export_html(result, tmp_path / 'hibp.html', language='en').read_text(encoding='utf-8')
    assert f'Collection performed: {"yes" if queried else "no"}' in content
    assert (f'data-kind="{expected}"' in content)
    if not queried:
        assert 'data-kind="observed"' not in content


def test_legacy_hibp_collection_unknown_stays_hypothesis():
    evidence = build_investigation_result().evidences[0]
    evidence.confidence_scope = 'breach_exposure'
    assert evidence.collection_performed is None
    assert _Report('en', True).kind(evidence) == 'hypothesis'


@pytest.mark.parametrize('literal', ['A%2FB', 'R&amp;D', '100%25', '%2541', '<script>literal</script>'])
def test_non_sensitive_literals_preserved(literal):
    report = _Report('pt-br', True)
    assert unescape(report.s(literal)) == literal


@pytest.mark.parametrize('encoded', ['user%40example.com', 'user%2540example.com', 'user&#64;example.com', 'user&amp;#64;example.com'])
def test_hidden_email_redaction(encoded):
    rendered = unescape(_Report('pt-br', True).s(encoded))
    assert 'user@example.com' not in rendered and encoded not in rendered
    assert '@example.com' in rendered


def test_hidden_control_neutralized():
    assert '\x1b' not in unescape(_Report('pt-br', True).s('hello%251B[31m'))


def test_pt_br_enums_but_preserve_responses_and_literals(tmp_path):
    result = build_investigation_result()
    pivot = result.profile_pivots[0]
    pivot.matched_fields = ['exact_handle']
    pivot.missing_fields = ['independent_identity_correlation']
    pivot.ambiguity_reasons = ['invalid_payload']
    pivot.notes = ['mock', 'A%2FB', 'R&amp;D']
    content = export_html(result, tmp_path / 'fields.html').read_text(encoding='utf-8')
    assert 'usuário exato' in content and 'correlação independente de identidade' in content
    assert 'resposta de API inválida' in content
    assert '>mock<' in content and '>A%2FB<' in content and '>R&amp;amp;D<' in content
    smtp = SmtpLabValidationService(enable_lab_smtp=False).validate(
        'user@example.com', 'example.com', '127.0.0.1', 2525, 'mock', ['vrfy'], no_network=True)
    smtp.checks_run[0].message = 'mock'
    content = export_html(smtp, tmp_path / 'smtp.html').read_text(encoding='utf-8')
    assert '>simulado<' in content and 'permitido somente em laboratório' in content
    assert '>mock<' in content


@pytest.mark.parametrize('platform', ['GitHub', 'GitLab'])
def test_api_evidence_and_profile_have_same_observed_kind(platform):
    from tests.test_public_profile_apis import service_for, payload, pivot
    service, calls = service_for(payload(platform))
    original = pivot(platform)
    checked, evidence = service.check_public_profile(original)
    report = _Report('pt-br', True)
    assert evidence.collection_performed is True
    assert report.kind(checked) == report.kind(evidence) == 'observed'
    cached, cached_evidence = service.check_public_profile(original)
    assert len(calls) == 1
    assert cached_evidence.cache_hit and cached_evidence.collection_performed is True
    assert report.kind(cached) == report.kind(cached_evidence) == 'observed'


@pytest.mark.parametrize('locale', ['pt-br', 'en'])
@pytest.mark.parametrize('model_index', [0, 1, 2])
def test_compact_two_column_tables_and_single_brand_title(tmp_path, locale, model_index):
    from mailrecon.services.demo_service import synthetic_results
    result = synthetic_results()[model_index]
    content = export_html(result, tmp_path / 'demo.html', language=locale, synthetic=True).read_text(encoding='utf-8')
    title = content.split('<h1>')[1].split('</h1>')[0]
    assert title.count('MailRecon') == 1
    assert f'<title>{title}</title>' in content
    tables = [attrs for tag, attrs in Elements(content).elements if tag == 'table']
    assert any(attrs.get('class') == 'compact' for attrs in tables)
    assert any('class' not in attrs for attrs in tables)
    assert 'table.compact{min-width:0;table-layout:fixed}' in content
    assert '.compact th:first-child,.compact td:first-child{width:44%}' in content
    assert 'overflow-wrap:anywhere' in content
    assert 'table{width:100%;min-width:760px' in content
