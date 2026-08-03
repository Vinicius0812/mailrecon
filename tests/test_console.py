from mailrecon.core.models import DnsLookupResult, HibpResult, InvestigationInput, InvestigationResult, ReconResult
from mailrecon.reporting.console import render_investigation_summary, render_summary


def build_recon_result() -> ReconResult:
    return ReconResult(
        email="user@example.com",
        domain="example.com",
        is_valid=True,
        dns=DnsLookupResult(resolves=True),
        hibp=HibpResult(queried=False, status="disabled"),
    )


def build_investigation_result() -> InvestigationResult:
    return InvestigationResult(
        query=InvestigationInput(emails=["user@example.com"]),
        candidate_emails=[],
        profile_pivots=[],
        evidences=[],
        findings=["user@example.com appeared in 2 public breach record(s)."],
        risks=["Public breach exposure may increase phishing risk for user@example.com."],
        pivot_suggestions=[],
        limitations=[],
        overall_confidence_score=50,
    )


def test_render_investigation_summary_masks_findings_and_risks_by_default() -> None:
    summary = render_investigation_summary(build_investigation_result())

    assert "user@example.com" not in summary
    assert "u**r@example.com" in summary


def test_render_investigation_summary_can_reveal_findings_and_risks() -> None:
    summary = render_investigation_summary(
        build_investigation_result(),
        mask_sensitive=False,
    )

    assert "user@example.com" in summary


def test_render_summary_masks_email_by_default() -> None:
    summary = render_summary(build_recon_result())

    assert "Email              : u**r@example.com" in summary
    assert "Email              : user@example.com" not in summary


def test_render_summary_can_reveal_email() -> None:
    summary = render_summary(build_recon_result(), mask_sensitive=False)

    assert "Email              : user@example.com" in summary
