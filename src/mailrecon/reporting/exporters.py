"""Report exporters."""

from __future__ import annotations

import json
from pathlib import Path

from mailrecon.core.models import ReconResult


def export_json(result: ReconResult, output_path: str | Path) -> Path:
    """Export a recon result as JSON."""
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
