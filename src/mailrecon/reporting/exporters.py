"""Report exporters."""

from __future__ import annotations

import json
from pathlib import Path

from mailrecon.core.models import InvestigationResult, ReconResult
from mailrecon.core.validators import mask_email_address


def export_json(result: ReconResult | InvestigationResult, output_path: str | Path) -> Path:
    """Export a result as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path


def export_markdown(result: ReconResult, output_path: str | Path) -> Path:
    """Export a recon result as Markdown."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# MailRecon Report",
        "",
        f"- Email: {result.email}",
        f"- Domain: {result.domain}",
        f"- Format valid: {'yes' if result.is_valid else 'no'}",
        f"- Domain resolves: {'yes' if result.dns.resolves else 'no'}",
        f"- MX records found: {'yes' if result.dns.mx_records else 'no'}",
        f"- HIBP status: {result.hibp.status}",
        f"- HIBP queried: {'yes' if result.hibp.queried else 'no'}",
        f"- Generated at: {result.generated_at}",
    ]

    if result.dns.a_records:
        lines.extend(["", "## A records", ""])
        lines.extend(f"- {record}" for record in result.dns.a_records)

    if result.dns.mx_records:
        lines.extend(["", "## MX records", ""])
        lines.extend(f"- {record}" for record in result.dns.mx_records)

    if result.dns.errors:
        lines.extend(["", "## DNS notes", ""])
        lines.extend(f"- {error}" for error in result.dns.errors)

    if result.hibp.breaches:
        lines.extend(["", "## HIBP breaches", ""])
        lines.extend(
            f"- {breach.get('Name', 'Unknown breach')}: {breach.get('Title', 'No title')}"
            for breach in result.hibp.breaches
        )

    if result.hibp.error:
        lines.extend(["", "## HIBP notes", "", f"- {result.hibp.error}"])

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def export_investigation_markdown(
    result: InvestigationResult,
    output_path: str | Path,
    mask_sensitive: bool = True,
) -> Path:
    """Export an investigation result as Markdown."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# MailRecon Investigation Report",
        "",
        f"- Generated at: {result.generated_at}",
        f"- Seed emails: {len(result.query.emails)}",
        f"- Seed usernames: {len(result.query.usernames)}",
        f"- Seed domains: {len(result.query.domains)}",
        f"- Candidate emails: {len(result.candidate_emails)}",
    ]

    if result.query.names:
        lines.extend(["", "## Names", ""])
        lines.extend(f"- {name}" for name in result.query.names)

    if result.query.organizations:
        lines.extend(["", "## Organizations", ""])
        lines.extend(f"- {organization}" for organization in result.query.organizations)

    if result.query.contexts:
        lines.extend(["", "## Context", ""])
        lines.extend(f"- {context}" for context in result.query.contexts)

    if result.candidate_emails:
        lines.extend(["", "## Candidate emails", ""])
        for candidate in result.candidate_emails:
            display_email = candidate.masked_email if mask_sensitive else candidate.email
            lines.append(
                f"- {display_email} | status={candidate.status} | source={candidate.source} | confidence={candidate.confidence}"
            )
            for note in candidate.notes:
                lines.append(f"  - note: {note}")

    if result.findings:
        lines.extend(["", "## Findings", ""])
        lines.extend(
            f"- {_mask_text(finding) if mask_sensitive else finding}"
            for finding in result.findings
        )

    if result.evidences:
        lines.extend(["", "## Evidence", ""])
        for evidence in result.evidences:
            lines.append(
                f"- {evidence.title} | source={evidence.source} | method={evidence.method} | confidence={evidence.confidence}"
            )
            summary = _mask_text(evidence.summary) if mask_sensitive else evidence.summary
            lines.append(f"  - summary: {summary}")
            lines.append(f"  - reference: {evidence.reference}")
            lines.append(f"  - collected_at: {evidence.collected_at}")
            if evidence.observations:
                lines.append(f"  - observations: {evidence.observations}")

    if result.risks:
        lines.extend(["", "## Risks", ""])
        lines.extend(
            f"- {_mask_text(risk) if mask_sensitive else risk}"
            for risk in result.risks
        )

    if result.pivot_suggestions:
        lines.extend(["", "## Pivot suggestions", ""])
        lines.extend(f"- {pivot}" for pivot in result.pivot_suggestions)

    if result.limitations:
        lines.extend(["", "## Limitations", ""])
        lines.extend(f"- {limitation}" for limitation in result.limitations)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


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
