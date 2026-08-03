"""Terminal rendering helpers."""

from mailrecon.core.models import InvestigationResult, ReconResult, SmtpLabValidationResult
from mailrecon.core.validators import mask_email_address


def render_summary(result: ReconResult, mask_sensitive: bool = True) -> str:
    """Build a friendly terminal summary for one recon result."""
    mx_found = "yes" if result.dns.mx_records else "no"
    resolves = "yes" if result.dns.resolves else "no"
    breach_count = len(result.hibp.breaches)
    display_email = mask_email_address(result.email) if mask_sensitive else result.email

    lines = [
        "=== MailRecon Analysis ===",
        f"Email              : {display_email}",
        f"Domain             : {result.domain}",
        f"Format valid       : {'yes' if result.is_valid else 'no'}",
        f"Domain resolves    : {resolves}",
        f"Domain status      : {result.dns.domain_status}",
        f"Mail capability    : {result.dns.email_acceptance_status}",
        f"Provider family    : {result.dns.provider_family}",
        f"Technical priority : {result.technical_assessment.review_priority_score}/100",
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
    retained_candidates = [
        item
        for item in result.candidate_emails
        if not item.status.startswith("rejected_")
    ]
    exposed_candidates = [
        item
        for item in retained_candidates
        if item.analysis is not None and item.analysis.hibp.status == "breaches_found"
    ]

    lines = [
        "=== MailRecon Investigation ===",
        f"Review priority    : {result.review_priority_score or result.overall_confidence_score}/100 {_render_score_bar(result.review_priority_score or result.overall_confidence_score)}",
        "",
        "Overview",
        f"  Seed emails      : {len(result.query.emails)}",
        f"  Seed usernames   : {len(result.query.usernames)}",
        f"  Seed domains     : {len(result.query.domains)}",
        f"  Candidate emails : {len(result.candidate_emails)}",
        f"  Profile pivots   : {len(result.profile_pivots)}",
        f"  Retained leads   : {len(retained_candidates)}",
        f"  Exposure signals : {len(exposed_candidates)}",
        f"  Evidence records : {len(result.evidences)}",
    ]

    if result.confidence_breakdown:
        lines.extend(["", "Confidence breakdown"])
        for label, score in result.confidence_breakdown.items():
            lines.append(f"  {label:<31}: {score}/100")

    if retained_candidates:
        preview = ", ".join(
            (
                candidate.masked_email
                if mask_sensitive
                else candidate.email
            )
            for candidate in retained_candidates[:5]
        )
        lines.extend(["", "Candidate preview", f"  {preview}"])

    if result.findings:
        finding = _mask_text(result.findings[0]) if mask_sensitive else result.findings[0]
        lines.extend(["", "Top finding", f"  {finding}"])

    if result.risks:
        risk = _mask_text(result.risks[0]) if mask_sensitive else result.risks[0]
        lines.extend(["", "Primary risk", f"  {risk}"])

    if result.profile_pivots:
        lines.extend(["", "Platform preview"])
        for pivot in result.profile_pivots[:5]:
            lines.append(
                f"  {pivot.platform:<10} handle={pivot.handle} priority={pivot.review_priority_score or pivot.confidence_score}/100 status={pivot.status}"
            )

        review_links = sorted(
            result.profile_pivots,
            key=lambda pivot: (-(pivot.review_priority_score or pivot.confidence_score), pivot.platform, pivot.handle),
        )[:5]
        lines.extend(["", "Profile links to review"])
        for pivot in review_links:
            lines.append(
                f"  {pivot.platform:<10} {pivot.profile_url} (priority={pivot.review_priority_score or pivot.confidence_score}/100, status={pivot.status})"
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


def render_smtp_lab_summary(result: SmtpLabValidationResult) -> str:
    """Build a lab-only SMTP validation summary."""
    lines = [
        "=== MailRecon Lab SMTP Validation ===",
        "Mode               : LAB ONLY - not evidence of real mailbox existence",
        f"Email              : {result.email}",
        f"Lab domain         : {result.lab_domain}",
        f"Transport          : {result.transport}",
        f"Host               : {result.host}:{result.port}",
        f"Network used       : {'yes' if result.network_used else 'no'}",
        f"Safety status      : {result.safety_decision.status}",
    ]

    if result.resolved_ips:
        lines.append(f"Resolved IPs       : {', '.join(result.resolved_ips)}")

    if result.safety_decision.reasons:
        lines.extend(["", "Safety decision"])
        lines.extend(f"  {reason}" for reason in result.safety_decision.reasons)

    if result.checks_run:
        lines.extend(["", "Checks"])
        for check in result.checks_run:
            code = f" code={check.smtp_code}" if check.smtp_code is not None else ""
            lines.append(f"  {check.check:<5} status={check.status}{code}")
            if check.message:
                lines.append(f"        {check.message}")

    if result.limitations:
        lines.extend(["", "Limitations"])
        lines.extend(f"  {limitation}" for limitation in result.limitations)

    return "\n".join(lines)


def _render_score_bar(score: int) -> str:
    """Render a small ASCII score bar."""
    filled = max(0, min(10, round(score / 10)))
    return "[" + ("#" * filled) + ("-" * (10 - filled)) + "]"


def _mask_text(text: str) -> str:
    """Mask every email address found inside a free-form text snippet."""
    parts = []
    current = []
    separators = set(" \t\r\n,;:()[]{}<>\"'")

    def flush() -> None:
        if not current:
            return
        token = "".join(current)
        if "@" in token and "." in token.partition("@")[2]:
            parts.append(mask_email_address(token))
        else:
            parts.append(token)
        current.clear()

    for char in text:
        if char in separators:
            flush()
            parts.append(char)
        else:
            current.append(char)

    flush()
    return "".join(parts)
