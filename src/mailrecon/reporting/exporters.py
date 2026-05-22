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
    language: str = "en",
) -> Path:
    """Export an investigation result as Markdown."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    copy = _markdown_copy(language)

    lines = [
        copy["title"],
        "",
        f"- {copy['generated_at']}: {result.generated_at}",
        f"- {copy['overall_confidence']}: {result.overall_confidence_score}/100",
        f"- {copy['seed_emails']}: {len(result.query.emails)}",
        f"- {copy['seed_usernames']}: {len(result.query.usernames)}",
        f"- {copy['seed_domains']}: {len(result.query.domains)}",
        f"- {copy['candidate_emails']}: {len(result.candidate_emails)}",
        f"- {copy['profile_pivots']}: {len(result.profile_pivots)}",
        f"- {copy['refinement_excluded_links']}: {len(result.refinement_excluded_links)}",
    ]

    if result.query.names:
        lines.extend(["", copy["names_heading"], ""])
        lines.extend(f"- {name}" for name in result.query.names)

    if result.query.organizations:
        lines.extend(["", copy["organizations_heading"], ""])
        lines.extend(f"- {organization}" for organization in result.query.organizations)

    if result.query.contexts:
        lines.extend(["", copy["context_heading"], ""])
        lines.extend(f"- {context}" for context in result.query.contexts)

    if result.candidate_emails:
        lines.extend(["", copy["candidate_emails_heading"], ""])
        for candidate in result.candidate_emails:
            display_email = candidate.masked_email if mask_sensitive else candidate.email
            lines.append(
                f"- {display_email} | {copy['status']}={candidate.status} | {copy['source']}={candidate.source} | {copy['confidence']}={candidate.confidence} | {copy['score']}={candidate.confidence_score}/100"
            )
            for note in candidate.notes:
                lines.append(f"  - {copy['note']}: {note}")

    if result.profile_pivots:
        lines.extend(["", copy["profile_pivots_heading"], ""])
        for pivot in result.profile_pivots:
            lines.append(
                f"- {pivot.platform} | handle={pivot.handle} | {copy['status']}={pivot.status} | {copy['resolution_status']}={pivot.resolution_status} | {copy['confidence']}={pivot.confidence} | {copy['score']}={pivot.confidence_score}/100"
            )
            lines.append(f"  - {copy['profile_url']}: {pivot.profile_url}")
            lines.append(f"  - {copy['search_url']}: {pivot.search_url}")
            if pivot.final_url:
                lines.append(f"  - {copy['final_url']}: {pivot.final_url}")
            if pivot.http_status_code is not None:
                lines.append(f"  - {copy['http_status']}: {pivot.http_status_code}")
            for note in pivot.notes:
                lines.append(f"  - {copy['note']}: {note}")

    if result.findings:
        lines.extend(["", copy["findings_heading"], ""])
        lines.extend(
            f"- {_mask_text(finding) if mask_sensitive else finding}"
            for finding in result.findings
        )

    if result.evidences:
        lines.extend(["", copy["evidence_heading"], ""])
        for evidence in result.evidences:
            lines.append(
                f"- {evidence.title} | {copy['source']}={evidence.source} | {copy['method']}={evidence.method} | {copy['confidence']}={evidence.confidence} | {copy['score']}={evidence.confidence_score}/100"
            )
            summary = _mask_text(evidence.summary) if mask_sensitive else evidence.summary
            lines.append(f"  - {copy['summary']}: {summary}")
            lines.append(f"  - {copy['reference']}: {evidence.reference}")
            lines.append(f"  - {copy['collected_at']}: {evidence.collected_at}")
            if evidence.observations:
                lines.append(f"  - {copy['observations']}: {evidence.observations}")

    if result.risks:
        lines.extend(["", copy["risks_heading"], ""])
        lines.extend(
            f"- {_mask_text(risk) if mask_sensitive else risk}"
            for risk in result.risks
        )

    if result.pivot_suggestions:
        lines.extend(["", copy["pivot_suggestions_heading"], ""])
        lines.extend(f"- {pivot}" for pivot in result.pivot_suggestions)

    if result.limitations:
        lines.extend(["", copy["limitations_heading"], ""])
        lines.extend(f"- {limitation}" for limitation in result.limitations)

    if result.refinement_file_path:
        lines.extend(["", copy["refinement_heading"], ""])
        lines.append(f"- {copy['refinement_file_path']}: {result.refinement_file_path}")
        if result.refinement_excluded_links:
            lines.append(
                f"- {copy['refinement_excluded_links']}: {len(result.refinement_excluded_links)}"
            )
            for link in result.refinement_excluded_links:
                lines.append(f"  - {link}")

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


def _markdown_copy(language: str) -> dict[str, str]:
    """Return localized copy for investigation Markdown exports."""
    if language == "pt-br":
        return {
            "title": "# Relatório de Investigação MailRecon",
            "generated_at": "Gerado em",
            "overall_confidence": "Confiança geral",
            "seed_emails": "E-mails de origem",
            "seed_usernames": "Usernames de origem",
            "seed_domains": "Domínios de origem",
            "candidate_emails": "E-mails candidatos",
            "profile_pivots": "Pivôs de perfis públicos",
            "refinement_heading": "## Refinamento",
            "refinement_file_path": "arquivo_refinamento",
            "refinement_excluded_links": "links_excluidos_refinamento",
            "names_heading": "## Nomes",
            "organizations_heading": "## Organizações",
            "context_heading": "## Contexto",
            "candidate_emails_heading": "## E-mails candidatos",
            "profile_pivots_heading": "## Pivôs de perfis públicos",
            "findings_heading": "## Achados",
            "evidence_heading": "## Evidências",
            "risks_heading": "## Riscos",
            "pivot_suggestions_heading": "## Sugestões de pivô",
            "limitations_heading": "## Limitações",
            "status": "status",
            "resolution_status": "status_resolucao",
            "source": "fonte",
            "confidence": "confianca",
            "score": "score",
            "note": "nota",
            "profile_url": "url_perfil",
            "search_url": "url_busca",
            "final_url": "url_final",
            "http_status": "http_status",
            "method": "metodo",
            "summary": "resumo",
            "reference": "referencia",
            "collected_at": "coletado_em",
            "observations": "observacoes",
        }

    return {
        "title": "# MailRecon Investigation Report",
        "generated_at": "Generated at",
        "overall_confidence": "Overall confidence",
        "seed_emails": "Seed emails",
        "seed_usernames": "Seed usernames",
        "seed_domains": "Seed domains",
        "candidate_emails": "Candidate emails",
        "profile_pivots": "Public-profile pivots",
        "refinement_heading": "## Refinement",
        "refinement_file_path": "refinement_file_path",
        "refinement_excluded_links": "refinement_excluded_links",
        "names_heading": "## Names",
        "organizations_heading": "## Organizations",
        "context_heading": "## Context",
        "candidate_emails_heading": "## Candidate emails",
        "profile_pivots_heading": "## Public-profile pivots",
        "findings_heading": "## Findings",
        "evidence_heading": "## Evidence",
        "risks_heading": "## Risks",
        "pivot_suggestions_heading": "## Pivot suggestions",
        "limitations_heading": "## Limitations",
        "status": "status",
        "resolution_status": "resolution_status",
        "source": "source",
        "confidence": "confidence",
        "score": "score",
        "note": "note",
        "profile_url": "profile_url",
        "search_url": "search_url",
        "final_url": "final_url",
        "http_status": "http_status",
        "method": "method",
        "summary": "summary",
        "reference": "reference",
        "collected_at": "collected_at",
        "observations": "observations",
    }
