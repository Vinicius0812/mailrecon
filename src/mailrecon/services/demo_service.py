"""Owned deterministic fixtures; no providers or saved investigation state."""

from pathlib import Path

from mailrecon.core.i18n import msg
from mailrecon.core.models import (
    DnsLookupResult, EmailCandidate, EvidenceRecord, HibpResult, InvestigationInput,
    InvestigationResult, ProfilePivot, ReconResult, SafetyDecision,
    SmtpLabCheckResult, SmtpLabValidationResult,
)
from mailrecon.core.platform_catalog import PLATFORM_BY_NAME
from mailrecon.reporting.exporters import export_json, export_markdown, export_investigation_markdown, export_smtp_lab_markdown
from mailrecon.reporting.html import export_html

STAMP = '2026-10-07T03:55:00+00:00'


def synthetic_results():
    notice = msg('cli.demo_notice')
    recon = ReconResult('demo@example.com', 'example.com', True,
                        DnsLookupResult(True, a_records=['192.0.2.10'], mx_records=['mx.example.com'], errors=[notice]),
                        HibpResult(False, 'disabled'), generated_at=STAMP)
    recon.technical_assessment.limitations = [notice]
    profiles, evidence = [], []
    for platform, handle, status in (
        ('GitHub', 'DemoExample', 'public_match_possible'),
        ('GitLab', 'demo_example', 'ambiguous'),
        ('LinkedIn', 'demo-example', 'not_checked'),
    ):
        spec = PLATFORM_BY_NAME[platform]
        profiles.append(ProfilePivot(platform, handle, spec.profile_url(handle), spec.search_url(handle),
                                     'synthetic_fixture', 'low', 0, 'manual_review', resolution_status=status,
                                     checked_at=STAMP if platform != 'LinkedIn' else None,
                                     notes=[notice], confidence_scope='synthetic_http_reachability',
                                     sources=['synthetic_fixture'], rule_id=spec.rule_id,
                                     rule_version=spec.rule_version, check_method='lab_simulation'))
        evidence.append(EvidenceRecord(platform, 'synthetic', 'synthetic_fixture', spec.profile_url(handle),
                                       STAMP, 'lab_simulation', 'low', 0, notice,
                                       observations=status, confidence_scope='synthetic_http_reachability',
                                       collection_performed=False,
                                       sources=['synthetic_fixture'], rule_id=spec.rule_id, rule_version=spec.rule_version))
    investigation = InvestigationResult(
        InvestigationInput(names=['Pessoa Ficticia'], emails=['demo@example.com'], usernames=['DemoExample'],
                           organizations=['Synthetic Example'], contexts=[notice]),
        [EmailCandidate('demo@example.com', 'd**o@example.com', 'example.com', 'synthetic_fixture', 'low', 0,
                        'not_checked', analysis=recon, notes=[notice], confidence_scope='generated_hypothesis')],
        profiles, evidence, [notice], [notice], [notice], [notice], 0,
        confidence_breakdown={'email_format': 0, 'domain_configuration': 0, 'profile_existence': 0, 'identity_correlation': 0},
        generated_at=STAMP)
    smtp = SmtpLabValidationResult('demo@example.com', 'example.com', '127.0.0.1', 2525, ['127.0.0.1'],
                                   'mock', ['vrfy', 'rcpt'],
                                   [SmtpLabCheckResult('vrfy', 'accepted', 250, notice),
                                    SmtpLabCheckResult('rcpt', 'inconclusive', 252, notice)],
                                   SafetyDecision(True, 'allowed_lab_only', reasons=[notice], limitations=[notice]),
                                   False, [notice], generated_at=STAMP)
    return recon, investigation, smtp


def generate_demo(output_dir: str | Path, language: str = 'pt-br') -> list[Path]:
    """Validate all destinations before writing; never overwrite existing files."""
    directory = Path(output_dir)
    if str(directory).startswith(('\\\\', '//')):
        raise ValueError(msg('cli.demo_directory_invalid'))
    if any(part.lower() in {'.git', '.env', '.agents', '.codex', '.mailrecon-temp'} for part in directory.parts):
        raise ValueError(msg('cli.demo_directory_invalid'))
    resolved = directory.resolve()
    if resolved == resolved.parent or resolved == Path.cwd().resolve() or (resolved.exists() and not resolved.is_dir()):
        raise ValueError(msg('cli.demo_directory_invalid'))
    if any(part.lower() in {'.git', '.env', '.agents', '.codex', '.mailrecon-temp'} for part in resolved.parts):
        raise ValueError(msg('cli.demo_directory_invalid'))
    names = ('demo-recon', 'demo-investigation', 'demo-smtp')
    paths = [resolved / (name + '.' + extension) for name in names for extension in ('json', 'md', 'html')]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise ValueError(msg('cli.demo_exists'))
    models = synthetic_results()
    markdown = (export_markdown, export_investigation_markdown, export_smtp_lab_markdown)
    resolved.mkdir(parents=True, exist_ok=True)
    for name, model, md in zip(names, models, markdown):
        export_json(model, resolved / (name + '.json'), language=language)
        md(model, resolved / (name + '.md'), language=language)
        export_html(model, resolved / (name + '.html'), language=language, synthetic=True)
    return paths
