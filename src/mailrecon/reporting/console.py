"""Terminal rendering helpers."""

from mailrecon.core.models import InvestigationResult, ReconResult
from mailrecon.core.validators import mask_email_address


def render_summary(result: ReconResult) -> str:
    """Build a friendly terminal summary for one recon result."""
    mx_found = "yes" if result.dns.mx_records else "no"
    resolves = "yes" if result.dns.resolves else "no"
    breach_count = len(result.hibp.breaches)

    lines = [
        f"Email: {result.email}",
        f"Domain: {result.domain}",
        f"Format valid: {'yes' if result.is_valid else 'no'}",
        f"Domain resolves: {resolves}",
        f"A records: {', '.join(result.dns.a_records) if result.dns.a_records else 'none'}",
        f"MX records found: {mx_found}",
        f"MX hosts: {', '.join(result.dns.mx_records) if result.dns.mx_records else 'none'}",
        f"HIBP status: {result.hibp.status}",
    ]

    if result.hibp.queried:
        lines.append(f"HIBP breaches found: {breach_count}")

    if result.dns.errors:
        lines.append(f"DNS notes: {'; '.join(result.dns.errors)}")

    if result.hibp.error:
        lines.append(f"HIBP notes: {result.hibp.error}")

    return "\n".join(lines)


def render_investigation_summary(
    result: InvestigationResult,
    mask_sensitive: bool = True,
) -> str:
    """Build a friendly terminal summary for one OSINT investigation."""
    valid_candidates = [item for item in result.candidate_emails if item.status == "valid"]
    exposed_candidates = [
        item
        for item in valid_candidates
        if item.analysis is not None and item.analysis.hibp.status == "breaches_found"
    ]

    lines = [
        "Investigation summary:",
        f"- Seed emails: {len(result.query.emails)}",
        f"- Seed usernames: {len(result.query.usernames)}",
        f"- Seed domains: {len(result.query.domains)}",
        f"- Candidate emails: {len(result.candidate_emails)}",
        f"- Valid candidates: {len(valid_candidates)}",
        f"- Exposure signals: {len(exposed_candidates)}",
        f"- Evidence records: {len(result.evidences)}",
    ]

    if valid_candidates:
        preview = ", ".join(
            (
                candidate.masked_email
                if mask_sensitive
                else candidate.email
            )
            for candidate in valid_candidates[:5]
        )
        lines.append(f"- Candidate preview: {preview}")

    if result.findings:
        lines.append(f"- Top finding: {result.findings[0]}")

    if result.risks:
        lines.append(f"- Primary risk: {result.risks[0]}")

    return "\n".join(lines)
