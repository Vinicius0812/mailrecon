import json

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
from mailrecon.reporting.exporters import (
    export_investigation_markdown,
    export_json,
    export_markdown,
)


def build_result() -> ReconResult:
    return ReconResult(
        email="user@example.com",
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


def build_investigation_result() -> InvestigationResult:
    return InvestigationResult(
        query=InvestigationInput(
            emails=["user@example.com"],
            usernames=["user"],
            domains=["example.com"],
            contexts=["training scenario"],
        ),
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
        refinement_file_path=".mailrecon-temp/last-investigation-refinement.json",
        refinement_excluded_links=["https://www.linkedin.com/in/other-user/"],
    )


def test_export_json_writes_file(tmp_path) -> None:
    output = tmp_path / "report.json"

    export_json(build_result(), output)

    content = json.loads(output.read_text(encoding="utf-8"))
    assert content["email"] == "user@example.com"
    assert content["dns"]["resolves"] is True


def test_export_markdown_writes_file(tmp_path) -> None:
    output = tmp_path / "report.md"

    export_markdown(build_result(), output)

    content = output.read_text(encoding="utf-8")
    assert "# MailRecon Report" in content
    assert "- Email: user@example.com" in content
    assert "- HIBP queried: no" in content


def test_export_investigation_markdown_writes_file(tmp_path) -> None:
    output = tmp_path / "investigation.md"

    export_investigation_markdown(build_investigation_result(), output)

    content = output.read_text(encoding="utf-8")
    assert "# MailRecon Investigation Report" in content
    assert "- Overall confidence: 73/100" in content
    assert "- refinement_excluded_links: 1" in content
    assert "## Candidate emails" in content
    assert "u**r@example.com" in content
    assert "## Public-profile pivots" in content
    assert "## Refinement" in content


def test_export_investigation_markdown_can_reveal_emails(tmp_path) -> None:
    output = tmp_path / "investigation-revealed.md"

    export_investigation_markdown(
        build_investigation_result(),
        output,
        mask_sensitive=False,
    )

    content = output.read_text(encoding="utf-8")
    assert "user@example.com" in content


def test_export_investigation_markdown_supports_pt_br(tmp_path) -> None:
    output = tmp_path / "investigation-ptbr.md"

    export_investigation_markdown(
        build_investigation_result(),
        output,
        language="pt-br",
    )

    content = output.read_text(encoding="utf-8")
    assert "# Relatório de Investigação MailRecon" in content
    assert "- Confiança geral: 73/100" in content
    assert "## Pivôs de perfis públicos" in content
