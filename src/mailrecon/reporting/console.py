"""Terminal rendering helpers."""

from mailrecon.core.models import InvestigationResult, ReconResult
from mailrecon.core.validators import mask_email_address


def render_summary(result: ReconResult) -> str:
    """Build a friendly terminal summary for one recon result."""
    mx_found = "yes" if result.dns.mx_records else "no"
    resolves = "yes" if result.dns.resolves else "no"
    breach_count = len(result.hibp.breaches)

    lines = [
        "=== MailRecon Analysis ===",
        f"Email              : {result.email}",
        f"Domain             : {result.domain}",
        f"Format valid       : {'yes' if result.is_valid else 'no'}",
        f"Domain resolves    : {resolves}",
        f"A records          : {', '.join(result.dns.a_records) if result.dns.a_records else 'none'}",
        f"MX records found   : {mx_found}",
        f"MX hosts           : {', '.join(result.dns.mx_records) if result.dns.mx_records else 'none'}",
        f"HIBP status        : {result.hibp.status}",
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
        "=== MailRecon Investigation ===",
        f"Overall confidence : {result.overall_confidence_score}/100 {_render_score_bar(result.overall_confidence_score)}",
        "",
        "Overview",
        f"  Seed emails      : {len(result.query.emails)}",
        f"  Seed usernames   : {len(result.query.usernames)}",
        f"  Seed domains     : {len(result.query.domains)}",
        f"  Candidate emails : {len(result.candidate_emails)}",
        f"  Profile pivots   : {len(result.profile_pivots)}",
        f"  Valid candidates : {len(valid_candidates)}",
        f"  Exposure signals : {len(exposed_candidates)}",
        f"  Evidence records : {len(result.evidences)}",
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
        lines.extend(["", "Candidate preview", f"  {preview}"])

    if result.findings:
        lines.extend(["", "Top finding", f"  {result.findings[0]}"])

    if result.risks:
        lines.extend(["", "Primary risk", f"  {result.risks[0]}"])

    if result.profile_pivots:
        lines.extend(["", "Platform preview"])
        for pivot in result.profile_pivots[:5]:
            lines.append(
                f"  {pivot.platform:<10} handle={pivot.handle} score={pivot.confidence_score}/100 status={pivot.resolution_status}"
            )

        strongest_links = sorted(
            result.profile_pivots,
            key=lambda pivot: (-pivot.confidence_score, pivot.platform, pivot.handle),
        )[:5]
        lines.extend(["", "Most trusted platform links"])
        for pivot in strongest_links:
            lines.append(
                f"  {pivot.platform:<10} {pivot.profile_url} (score={pivot.confidence_score}/100, status={pivot.resolution_status})"
            )

    if result.refinement_file_path:
        lines.extend(
            [
                "",
                "Refinement",
                f"  Excluded links   : {len(result.refinement_excluded_links)}",
                f"  State file       : {result.refinement_file_path}",
            ]
        )

    return "\n".join(lines)


def _render_score_bar(score: int) -> str:
    """Render a small ASCII score bar."""
    filled = max(0, min(10, round(score / 10)))
    return "[" + ("#" * filled) + ("-" * (10 - filled)) + "]"
