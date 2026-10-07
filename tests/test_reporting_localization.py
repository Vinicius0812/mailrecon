"""Localization, authoritative scores and privacy at report boundaries."""

from dataclasses import replace
import json

import pytest

from mailrecon.core.catalog_reporting import CATALOG
from mailrecon.core.i18n import Message, msg, t, translate
from mailrecon.core.models import (
    DnsLookupResult,
    EmailCandidate,
    EmailTechnicalAssessment,
    EvidenceRecord,
    HibpResult,
    InvestigationInput,
    InvestigationResult,
    ProfilePivot,
    ReconResult,
    SafetyDecision,
    SmtpLabCheckResult,
    SmtpLabValidationResult,
)
from mailrecon.reporting.console import (
    _mask_text,
    render_investigation_summary,
    render_smtp_lab_summary,
    render_summary,
)
from mailrecon.reporting.exporters import (
    export_investigation_markdown,
    export_json,
    export_markdown,
    export_smtp_lab_markdown,
)


@pytest.fixture
def recon() -> ReconResult:
    return ReconResult(
        email="user@example.com",
        domain="example.com",
        is_valid=True,
        dns=DnsLookupResult(
            resolves=True,
            domain_status="resolves",
            email_acceptance_status="mx_present",
            errors=[msg("dns.error.no_records", record_type="AAAA"), "Raw upstream DNS detail."],
        ),
        hibp=HibpResult(queried=False, status="missing_api_key"),
    )


@pytest.fixture
def investigation() -> InvestigationResult:
    candidate = EmailCandidate(
        email="user@example.com",
        masked_email="u**r@example.com",
        domain="example.com",
        source="seed_email",
        confidence="medium",
        confidence_score=97,
        review_priority_score=0,
        status="accepted_direct_seed",
        confidence_scope="input_seed",
        sources=["investigator_input"],
    )
    pivot = ProfilePivot(
        platform="Zero",
        handle="user",
        profile_url="https://example.com/zero/",
        search_url="https://example.com/search?q=user",
        source="public_profile_pivot",
        confidence="low",
        confidence_score=99,
        review_priority_score=0,
        status="manual_review",
        confidence_scope="http_reachability",
        sources=["Public API"],
    )
    evidence = EvidenceRecord(
        title="External title remains unchanged",
        category="domain",
        source="public_dns",
        reference="raw reference",
        collected_at="2026-09-30T00:00:00+00:00",
        method="manual_input",
        confidence="medium",
        confidence_score=12,
        summary=msg("dns.error.no_records", record_type="MX"),
        confidence_scope="dns_observation",
        sources=["public_dns"],
    )
    return InvestigationResult(
        query=InvestigationInput(emails=["user@example.com"]),
        candidate_emails=[candidate],
        profile_pivots=[pivot],
        evidences=[evidence],
        findings=[msg("investigation.finding.breaches", email="user@example.com", count=2)],
        risks=["External risk remains in English."],
        pivot_suggestions=[],
        limitations=[],
        overall_confidence_score=98,
        review_priority_score=0,
        confidence_breakdown={"domain_confidence": 0},
    )


@pytest.fixture
def smtp() -> SmtpLabValidationResult:
    return SmtpLabValidationResult(
        email="user@example.test",
        lab_domain="example.test",
        host="localhost",
        port=1025,
        resolved_ips=["127.0.0.1"],
        transport="mock",
        checks_requested=["VRFY"],
        checks_run=[SmtpLabCheckResult(check="VRFY", status="mocked_accept", smtp_code=0, message="250 External server says: accepted")],
        safety_decision=SafetyDecision(
            allowed=True,
            status="allowed_lab_only",
            reasons=[msg("safety.reason.passed")],
            limitations=[msg("safety.limitation.mailbox")],
        ),
        network_used=False,
        limitations=[msg("safety.limitation.owned_lab")],
    )


def test_reporting_catalog_is_registered_and_complete() -> None:
    assert all(key.startswith("reporting.") for key in CATALOG)
    for key, entry in CATALOG.items():
        assert set(entry) == {"en", "pt-br"}
        assert t(key, "en") == entry["en"]
        assert t(key, "pt-br") == entry["pt-br"]


def test_recon_defaults_to_portuguese_and_keeps_mixed_prose(recon, tmp_path) -> None:
    summary = render_summary(recon)
    markdown = export_markdown(recon, tmp_path / "recon.md").read_text(encoding="utf-8")
    for content in (summary, markdown):
        assert "Formato válido" in content
        assert "chave de API ausente" in content
        assert "Nenhum registro AAAA encontrado." in content
        assert "Raw upstream DNS detail." in content
        assert "user@example.com" not in content
    assert "# Relatório MailRecon" in markdown
    assert "- HIBP consultado: não" in markdown
    assert isinstance(recon.dns.errors[0], Message)
    assert recon.dns.domain_status == "resolves"


@pytest.mark.parametrize("language", ["en", "pt-br"])
def test_investigation_zero_is_authoritative_everywhere(investigation, tmp_path, language) -> None:
    summary = render_investigation_summary(investigation, language=language)
    markdown = export_investigation_markdown(investigation, tmp_path / "investigation.md", language=language).read_text(encoding="utf-8")
    priority = t("reporting.review_priority", language)
    assert f"{priority}: 0/100" in markdown
    assert f"{priority:<19}: 0/100 [----------]" in summary
    assert markdown.count(f"{priority}=0/100") == 2
    assert summary.count(f"{priority}=0/100") == 3
    for content in (summary, markdown):
        for stale_score in (97, 98, 99):
            assert f"{stale_score}/100" not in content


def test_profile_link_order_uses_priority_even_when_zero(investigation) -> None:
    positive = replace(
        investigation.profile_pivots[0],
        platform="Positive",
        profile_url="https://example.com/positive/",
        confidence_score=1,
        review_priority_score=2,
    )
    investigation.profile_pivots.append(positive)
    summary = render_investigation_summary(investigation, language="en")
    review_links = summary.split("Profile links to review", 1)[1]
    assert review_links.index("/positive/") < review_links.index("/zero/")
    assert "status=manual_review" in review_links


def test_investigation_portuguese_confidence_and_provenance(investigation, tmp_path) -> None:
    summary = render_investigation_summary(investigation)
    markdown = export_investigation_markdown(investigation, tmp_path / "investigation.md").read_text(encoding="utf-8")
    for content in (summary, markdown):
        assert "Confiança=média" in content
        assert "Confiança=baixa" in content
        assert "Escopo da confiança" in content
        assert "acessibilidade HTTP" in content
        assert "Fontes" in content
        assert "Public API" in content
        assert "apareceu em 2 registro(s) público(s) de vazamento." in content
        assert "External risk remains in English." in content
    assert "Confiança=média" in markdown
    assert "Nenhum registro MX encontrado." in markdown
    assert "observação de DNS" in markdown
    assert "DNS público" in markdown
    assert "External title remains unchanged" in markdown
    assert isinstance(investigation.findings[0], Message)


@pytest.mark.parametrize("language", ["en", "pt-br"])
def test_plain_strings_matching_known_templates_are_not_translated(recon, tmp_path, language) -> None:
    canonical = "No MX records found."
    recon.dns.errors = [canonical]
    summary = render_summary(recon, language=language)
    markdown = export_markdown(recon, tmp_path / "raw.md", language=language).read_text(encoding="utf-8")
    assert canonical in summary
    assert canonical in markdown


@pytest.mark.parametrize("language", ["en", "pt-br"])
def test_every_investigation_free_text_field_is_masked(investigation, tmp_path, language) -> None:
    private = "secret@example.com"
    prose = f"Contact={private}; reference=mailto:{private}."
    investigation.query.names = [prose]
    investigation.query.organizations = [prose]
    investigation.query.contexts = [prose]
    investigation.findings = [prose]
    investigation.risks = [prose]
    investigation.pivot_suggestions = [prose]
    investigation.limitations = [prose]
    investigation.refinement_file_path = prose
    investigation.refinement_excluded_links = [f"https://example.com/?email={private}"]
    candidate = investigation.candidate_emails[0]
    candidate.source = prose
    candidate.notes = [prose]
    candidate.decision_reasons = [msg("hibp.error.request", error=prose)]
    candidate.limitations = [prose]
    candidate.sources = [prose]
    pivot = investigation.profile_pivots[0]
    pivot.platform = prose
    pivot.handle = prose
    pivot.profile_url = f"https://example.com/?email={private}"
    pivot.search_url = prose
    pivot.final_url = prose
    pivot.notes = [prose]
    pivot.decision_reasons = [prose]
    pivot.limitations = [prose]
    pivot.ambiguity_reasons = [prose]
    pivot.matched_fields = [prose]
    pivot.missing_fields = [prose]
    pivot.conflicting_fields = [prose]
    pivot.sources = [prose]
    evidence = investigation.evidences[0]
    evidence.title = prose
    evidence.reference = prose
    evidence.summary = prose
    evidence.observations = prose
    evidence.source = prose
    evidence.method = prose
    evidence.decision_reasons = [prose]
    evidence.limitations = [prose]
    evidence.sources = [prose]
    summary = render_investigation_summary(investigation, language=language)
    path = export_investigation_markdown(investigation, tmp_path / "masked.md", language=language)
    markdown = path.read_text(encoding="utf-8")
    assert private not in summary
    assert private not in markdown
    assert "s****t@example.com" in summary
    assert "s****t@example.com" in markdown
    revealed = export_investigation_markdown(investigation, path, mask_sensitive=False, language=language).read_text(encoding="utf-8")
    assert private in revealed
    assert pivot.notes == [prose]


def test_recon_reason_and_note_parameters_cannot_leak(recon, tmp_path) -> None:
    prose = "Contact=user@example.com."
    recon.dns.errors = [msg("dns.error.query", record_type="MX", error=prose)]
    recon.hibp.error = msg("hibp.error.request", error=prose)
    recon.technical_assessment.decision_reasons = [prose]
    recon.technical_assessment.limitations = [prose]
    recon.hibp.breaches = [{"Name": prose, "Title": prose}]
    summary = render_summary(recon)
    markdown = export_markdown(recon, tmp_path / "masked.md").read_text(encoding="utf-8")
    for content in (summary, markdown):
        assert "user@example.com" not in content
        assert "Contact=u**r@example.com." in content


@pytest.mark.parametrize("language", ["en", "pt-br"])
def test_json_localizes_only_messages_and_preserves_machine_values(investigation, tmp_path, language) -> None:
    investigation.evidences[0].observations = "No MX records found."
    output = export_json(investigation, tmp_path / "result.json", language=language)
    content = json.loads(output.read_text(encoding="utf-8"))
    assert content["query"]["emails"] == ["user@example.com"]
    assert content["review_priority_score"] == 0
    assert content["overall_confidence_score"] == 98
    candidate = content["candidate_emails"][0]
    assert candidate["review_priority_score"] == 0
    assert candidate["confidence"] == "medium"
    assert candidate["confidence_scope"] == "input_seed"
    assert candidate["status"] == "accepted_direct_seed"
    pivot = content["profile_pivots"][0]
    assert pivot["review_priority_score"] == 0
    assert pivot["status"] == "manual_review"
    assert pivot["confidence"] == "low"
    assert content["evidences"][0]["observations"] == "No MX records found."
    if language == "pt-br":
        assert "user@example.com apareceu" in content["findings"][0]
    else:
        assert "user@example.com appeared" in content["findings"][0]
    assert content["localization"]["/findings/0"]["key"] == "investigation.finding.breaches"
    assert content["localization"]["/findings/0"]["parameters"]["email"] == "user@example.com"


def test_json_defaults_to_portuguese_without_localizing_enums(investigation, tmp_path) -> None:
    output = export_json(investigation, tmp_path / "default.json")
    content = json.loads(output.read_text(encoding="utf-8"))
    assert "user@example.com apareceu" in content["findings"][0]
    assert content["candidate_emails"][0]["confidence"] == "medium"
    assert content["profile_pivots"][0]["status"] == "manual_review"
    assert content["review_priority_score"] == 0


def test_saved_json_can_be_rerendered_without_repeating_queries(recon, tmp_path) -> None:
    saved_path = export_json(recon, tmp_path / "saved.json")
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    assert saved["dns"]["errors"][0] == "Nenhum registro AAAA encontrado."
    english = translate(saved, "en")
    assert english["dns"]["errors"][0] == "No AAAA records found."
    assert english["dns"]["errors"][1] == "Raw upstream DNS detail."
    assert english["dns"]["domain_status"] == "resolves"
    restored = ReconResult(
        email=english["email"],
        domain=english["domain"],
        is_valid=english["is_valid"],
        dns=DnsLookupResult(**english["dns"]),
        hibp=HibpResult(**english["hibp"]),
        technical_assessment=EmailTechnicalAssessment(**english["technical_assessment"]),
        generated_at=english["generated_at"],
    )
    summary = render_summary(restored, language="en")
    markdown = export_markdown(restored, tmp_path / "saved.md", language="en").read_text(encoding="utf-8")
    assert "No AAAA records found." in summary
    assert "No AAAA records found." in markdown
    assert "Nenhum registro AAAA encontrado." in saved["dns"]["errors"][0]


@pytest.mark.parametrize("language", ["en", "pt-br"])
def test_smtp_language_and_raw_response_preservation(smtp, tmp_path, language) -> None:
    summary = render_smtp_lab_summary(smtp, language=language)
    markdown = export_smtp_lab_markdown(smtp, tmp_path / "smtp.md", language=language).read_text(encoding="utf-8")
    for content in (summary, markdown):
        assert smtp.checks_run[0].message in content
        assert t("reporting.smtp_title", language) in content
        assert t("reporting.lab_only", language) in content
        assert t("safety.reason.passed", language) in content
        assert t("safety.limitation.mailbox", language) in content
        assert t("safety.limitation.owned_lab", language) in content
        assert f"{t('reporting.smtp_code', language)}=0" in content
        assert "user@example.test" not in content


def test_smtp_defaults_to_portuguese_and_masks_all_free_prose(smtp, tmp_path) -> None:
    private = "secret@example.com"
    prose = f"Contact={private}."
    smtp.safety_decision.reasons = [prose]
    smtp.safety_decision.limitations = [prose]
    smtp.limitations = [prose]
    smtp.checks_run[0].message = f"550 Rejected {private}"
    summary = render_smtp_lab_summary(smtp)
    path = export_smtp_lab_markdown(smtp, tmp_path / "smtp.md")
    for content in (summary, path.read_text(encoding="utf-8")):
        assert "Validação SMTP em Laboratório" in content
        assert private not in content
        assert "550 Rejected s****t@example.com" in content
    assert private in render_smtp_lab_summary(smtp, mask_sensitive=False)
    export_smtp_lab_markdown(smtp, path, mask_sensitive=False)
    assert private in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("snippet", [
    "user@example.com.",
    "mailto:user@example.com",
    "Contact=user@example.com;",
    "https://example.com/?email=user@example.com&next=1",
    "(user@example.com), other@example.org!",
])
def test_mask_text_preserves_surrounding_punctuation(snippet) -> None:
    expected = snippet.replace("user@example.com", "u**r@example.com").replace("other@example.org", "o***r@example.org")
    assert _mask_text(snippet) == expected
    assert _mask_text(expected) == expected


@pytest.mark.parametrize("address", ["josé@example.com", "user@exemplo.com.br", '"name surname"@example.com', "user@localhost"])
def test_mask_text_handles_international_and_quoted_addresses(address) -> None:
    assert address not in _mask_text(f"Contact: {address};")


def test_invalid_candidate_email_field_is_masked(investigation, tmp_path) -> None:
    candidate = investigation.candidate_emails[0]
    candidate.email = "private@"
    candidate.status = "rejected_invalid_format"
    content = export_investigation_markdown(investigation, tmp_path / "invalid.md").read_text(encoding="utf-8")
    assert "private@" not in content
    assert "- *@ |" in content
