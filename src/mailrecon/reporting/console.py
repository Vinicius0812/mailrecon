"""Terminal rendering helpers."""

from mailrecon.core.models import ReconResult


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
