"""Report exporters."""

from __future__ import annotations

import json
from pathlib import Path

from mailrecon.core.i18n import serialize_localized, translate
from mailrecon.core.models import InvestigationResult, ReconResult, SmtpLabValidationResult
from mailrecon.reporting.console import _ReportText, _mask_text


def export_json(
    result: ReconResult | InvestigationResult | SmtpLabValidationResult,
    output_path: str | Path,
    language: str = "pt-br",
) -> Path:
    """Export localized prose with provenance, preserving machine keys and enums."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = serialize_localized(result, language)
    path.write_text(json.dumps(content, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _write_markdown(output_path: str | Path, lines: list[str]) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _prose_section(lines: list[str], text: _ReportText, heading: str, values: list[str]) -> None:
    if values:
        lines.extend(["", f"## {text.label(heading)}", ""])
        lines.extend(f"- {text.prose(value)}" for value in values)


def _item_details(lines: list[str], text: _ReportText, item: object) -> None:
    lines.extend(f"  - {label}: {value}" for label, value in text.confidence_details(item))
    for field, label in (
        ("decision_reasons", "decision_reason"),
        ("limitations", "limitation"),
        ("notes", "note"),
    ):
        for value in getattr(item, field, []):
            lines.append(f"  - {text.label(label)}: {text.prose(value)}")


def _quick_results(lines: list[str], text: _ReportText, results: list[str], actions: list[str]) -> None:
    """Keep the reading order consistent without hiding the supporting records."""
    lines.extend([f"## {text.label('quick_results')}", ""])
    lines.extend(f"- {value}" for value in results)
    lines.extend(["", f"## {text.label('next_steps')}", ""])
    lines.extend(f"- {value}" for value in actions)


def _technical_details(lines: list[str], text: _ReportText) -> None:
    lines.extend(["", "---", "", f"## {text.label('technical_details')}", ""])


def _recon_summary(result: ReconResult, text: _ReportText) -> tuple[list[str], list[str]]:
    label = text.label
    if result.dns.email_acceptance_status == "declares_no_mail":
        mail = "plain_mail_no"
    elif result.dns.domain_status == "nxdomain":
        mail = "plain_domain_missing"
    elif result.dns.email_acceptance_status == "mx_present" or result.dns.mx_records:
        mail = "plain_mail_yes"
    else:
        mail = "plain_mail_unknown"
    exposed = result.hibp.queried and result.hibp.status == "breaches_found"
    if exposed:
        breaches = label("plain_breaches")
    elif result.hibp.queried and result.hibp.status == "no_breaches":
        breaches = label("plain_no_breaches")
    else:
        breaches = label("plain_breaches_unknown")
    summary = [
        f"{label('email')}: **{text.email(result.email)}**",
        label("plain_format_ok" if result.is_valid else "plain_format_bad"),
        label(mail), breaches, label("plain_mailbox_limit"),
    ]
    actions = [label("plain_review_address")]
    if exposed:
        actions.append(label("plain_breach_action"))
    return summary, actions


def _investigation_summary(lines: list[str], result: InvestigationResult, text: _ReportText) -> None:
    label = text.label
    summary = [
        f"{label('plain_email_count')}: **{len(result.candidate_emails)}**.",
        f"{label('plain_profile_count')}: **{len(result.profile_pivots)}**.",
        label("plain_leads_limit"), label("plain_priority_limit"),
    ]
    summary.extend(f"{label('plain_finding')}: {text.prose(value)}" for value in result.findings[:3])
    summary.extend(f"{label('plain_attention')}: {text.prose(value)}" for value in result.risks[:2])
    if not result.candidate_emails and not result.profile_pivots:
        summary.append(label("plain_empty"))
    _quick_results(lines, text, summary, [label("plain_investigation_action")])
    if result.candidate_emails or result.profile_pivots:
        lines.extend(["", f"### {label('plain_shortlist')}", "", label("plain_shortlist_limit"), ""])
    for candidate in sorted(result.candidate_emails, key=lambda item: item.review_priority_score, reverse=True)[:5]:
        if candidate.status.startswith("rejected") or candidate.status == "invalid":
            meaning = "plain_email_rejected"
        elif candidate.source in {"seed_email", "provided_candidate", "seed_candidate"}:
            meaning = "plain_email_supplied"
        elif candidate.source in {"username_domain_inference", "name_domain_inference"} or candidate.status == "candidate_generated":
            meaning = "plain_email_generated"
        else:
            meaning = "plain_email_review"
        lines.append(f"- **{text.email(candidate.email)}** — {label(meaning)}.")
    for pivot in sorted(result.profile_pivots, key=lambda item: item.review_priority_score, reverse=True)[:5]:
        if pivot.status == "not_found" or pivot.resolution_status == "rejected_profile_not_found":
            meaning = "plain_profile_missing"
        elif pivot.status == "blocked_by_platform" or pivot.resolution_status == "blocked_cannot_determine":
            meaning = "plain_profile_blocked"
        elif pivot.status == "ambiguous" or pivot.resolution_status == "ambiguous_requires_review":
            meaning = "plain_profile_ambiguous"
        else:
            meaning = "plain_profile_review"
        lines.append(f"- **{text.prose(pivot.platform)} ({text.prose(pivot.handle)})** — {label(meaning)}.")
        if pivot.profile_url:
            lines.append(f"  - {text.prose(pivot.profile_url)}")


def export_markdown(
    result: ReconResult,
    output_path: str | Path,
    mask_sensitive: bool = True,
    language: str = "pt-br",
) -> Path:
    """Export a recon result as Markdown."""
    result = translate(result, language)
    text = _ReportText(language, mask_sensitive)
    label = text.label
    lines = [f"# {label('report_title')}", ""]
    summary, actions = _recon_summary(result, text)
    _quick_results(lines, text, summary, actions)
    _technical_details(lines, text)
    rows = [
        ("email", text.email(result.email)),
        ("domain", text.prose(result.domain)),
        ("format_valid", text.boolean(result.is_valid)),
        ("domain_resolves", text.boolean(result.dns.resolves)),
        ("domain_status", text.human(result.dns.domain_status)),
        ("mail_capability", text.human(result.dns.email_acceptance_status)),
        ("provider_family", text.human(result.dns.provider_family)),
        ("spf_status", text.human(result.dns.spf_status)),
        ("dmarc_status", text.human(result.dns.dmarc_status)),
        ("technical_review_priority", f"{result.technical_assessment.review_priority_score}/100"),
        ("role_account_status", text.human(result.technical_assessment.role_account_status)),
        ("disposable_status", text.human(result.technical_assessment.disposable_status)),
        ("catch_all_status", text.human(result.technical_assessment.catch_all_status)),
        ("mx_found", text.boolean(bool(result.dns.mx_records))),
        ("hibp_status", text.human(result.hibp.status)),
        ("hibp_queried", text.boolean(result.hibp.queried)),
        ("generated_at", result.generated_at),
    ]
    lines.extend(f"- {label(key)}: {value}" for key, value in rows)
    for heading, values in (
        ("a_records", result.dns.a_records),
        ("mx_records", result.dns.mx_records),
        ("dns_notes", result.dns.errors),
        ("technical_reasons", result.technical_assessment.decision_reasons),
        ("technical_limitations", result.technical_assessment.limitations),
    ):
        _prose_section(lines, text, heading, values)
    if result.hibp.breaches:
        lines.extend(["", f"## {label('hibp_breaches')}", ""])
        for breach in result.hibp.breaches:
            name = text.prose(breach.get("Name", label("unknown_breach")))
            title = text.prose(breach.get("Title", label("no_title")))
            lines.append(f"- {name}: {title}")
    if result.hibp.error:
        _prose_section(lines, text, "hibp_notes", [result.hibp.error])
    return _write_markdown(output_path, lines)


def export_smtp_lab_markdown(
    result: SmtpLabValidationResult,
    output_path: str | Path,
    language: str = "pt-br",
    mask_sensitive: bool = True,
) -> Path:
    """Export lab SMTP validation; wire replies are not translated."""
    result = translate(result, language)
    text = _ReportText(language, mask_sensitive)
    label = text.label
    lines = [f"# {label('smtp_title')}", ""]
    outcome = (f"{label('plain_lab_allowed')}: {len(result.checks_run)}."
               if result.safety_decision.allowed else label("plain_lab_blocked"))
    _quick_results(lines, text, [label("lab_only"), outcome], [label("plain_lab_action")])
    _technical_details(lines, text)
    rows = [
        ("mode", label("lab_only")),
        ("email", text.email(result.email)),
        ("lab_domain", text.prose(result.lab_domain)),
        ("transport", text.human(result.transport)),
        ("host", text.prose(f"{result.host}:{result.port}")),
        ("network_used", text.boolean(result.network_used)),
        ("safety_status", text.human(result.safety_decision.status)),
        ("generated_at", result.generated_at),
    ]
    lines.extend(f"- {label(key)}: {value}" for key, value in rows)
    _prose_section(lines, text, "resolved_ips", result.resolved_ips)
    _prose_section(lines, text, "safety_decision", result.safety_decision.reasons)
    if result.checks_run:
        lines.extend(["", f"## {label('checks')}", ""])
        for check in result.checks_run:
            code = f" | {label('smtp_code')}={check.smtp_code}" if check.smtp_code is not None else ""
            lines.append(f"- {check.check} | {label('status')}={text.human(check.status)}{code}")
            if check.message:
                reply = _mask_text(check.message) if mask_sensitive else check.message
                lines.append(f"  - {label('message')}: {reply}")
    _prose_section(lines, text, "limitations", result.safety_decision.limitations + result.limitations)
    return _write_markdown(output_path, lines)


def export_investigation_markdown(
    result: InvestigationResult,
    output_path: str | Path,
    mask_sensitive: bool = True,
    language: str = "pt-br",
) -> Path:
    """Export an investigation result as Markdown."""
    result = translate(result, language)
    text = _ReportText(language, mask_sensitive)
    label = text.label
    lines = [f"# {label('investigation_report_title')}", ""]
    _investigation_summary(lines, result, text)
    _technical_details(lines, text)
    rows = [
        ("generated_at", result.generated_at),
        ("review_priority", f"{result.review_priority_score}/100"),
        ("seed_emails", len(result.query.emails)),
        ("seed_usernames", len(result.query.usernames)),
        ("seed_domains", len(result.query.domains)),
        ("candidate_emails", len(result.candidate_emails)),
        ("public_profile_pivots", len(result.profile_pivots)),
        ("refinement_excluded_links", len(result.refinement_excluded_links)),
    ]
    lines.extend(f"- {label(key)}: {value}" for key, value in rows)
    lines.extend(f"- {name}: {value}" for name, value in text.confidence_details(result))
    if result.confidence_breakdown:
        lines.extend(["", f"## {label('confidence_breakdown')}", ""])
        lines.extend(f"- {text.human(key)}: {score}/100" for key, score in result.confidence_breakdown.items())
    for heading, values in (("names", result.query.names), ("organizations", result.query.organizations), ("context", result.query.contexts)):
        _prose_section(lines, text, heading, values)
    if result.candidate_emails:
        lines.extend(["", f"## {label('candidate_emails')}", ""])
        for candidate in result.candidate_emails:
            lines.append(
                f"- {text.email(candidate.email)} | {label('status')}={text.human(candidate.status)} "
                f"| {label('source')}={text.human(candidate.source)} "
                f"| {label('confidence')}={text.human(candidate.confidence)} "
                f"| {label('evidence_strength')}={text.human(candidate.evidence_strength)} "
                f"| {label('review_priority')}={candidate.review_priority_score}/100"
            )
            for key, value in (
                ("risk_level", candidate.risk_level),
                ("role_account_status", candidate.role_account_status),
                ("disposable_status", candidate.disposable_status),
                ("provider_family", candidate.provider_family),
            ):
                lines.append(f"  - {label(key)}: {text.human(value)}")
            _item_details(lines, text, candidate)
    if result.profile_pivots:
        lines.extend(["", f"## {label('public_profile_pivots')}", ""])
        for pivot in result.profile_pivots:
            lines.append(
                f"- {text.prose(pivot.platform)} | {label('handle')}={text.prose(pivot.handle)} "
                f"| {label('status')}={text.human(pivot.status)} "
                f"| {label('resolution_status')}={text.human(pivot.resolution_status)} "
                f"| {label('confidence')}={text.human(pivot.confidence)} "
                f"| {label('evidence_strength')}={text.human(pivot.evidence_strength)} "
                f"| {label('review_priority')}={pivot.review_priority_score}/100"
            )
            for key, value in (("profile_url", pivot.profile_url), ("search_url", pivot.search_url), ("final_url", pivot.final_url)):
                if value:
                    lines.append(f"  - {label(key)}: {text.prose(value)}")
            if pivot.http_status_code is not None:
                lines.append(f"  - {label('http_status')}: {pivot.http_status_code}")
            for key, values in (
                ("ambiguity_reason", pivot.ambiguity_reasons),
                ("matched_field", pivot.matched_fields),
                ("missing_field", pivot.missing_fields),
                ("conflicting_field", pivot.conflicting_fields),
            ):
                lines.extend(f"  - {label(key)}: {text.human(value)}" for value in values)
            _item_details(lines, text, pivot)
    _prose_section(lines, text, "findings", result.findings)
    if result.evidences:
        lines.extend(["", f"## {label('evidence')}", ""])
        for evidence in result.evidences:
            lines.append(
                f"- {text.prose(evidence.title)} | {label('source')}={text.human(evidence.source)} "
                f"| {label('method')}={text.human(evidence.method)} "
                f"| {label('confidence')}={text.human(evidence.confidence)} "
                f"| {label('evidence_strength')}={text.human(evidence.evidence_strength)} "
                f"| {label('score')}={evidence.confidence_score}/100"
            )
            for key, value in (("summary", evidence.summary), ("reference", evidence.reference), ("collected_at", evidence.collected_at), ("observations", evidence.observations)):
                if value is not None:
                    lines.append(f"  - {label(key)}: {text.prose(value)}")
            if evidence.risk_level != "none":
                lines.append(f"  - {label('risk_level')}: {text.human(evidence.risk_level)}")
            _item_details(lines, text, evidence)
    for heading, values in (("risks", result.risks), ("pivot_suggestions", result.pivot_suggestions), ("limitations", result.limitations)):
        _prose_section(lines, text, heading, values)
    if result.refinement_file_path:
        lines.extend(["", f"## {label('refinement')}", ""])
        lines.append(f"- {label('refinement_file_path')}: {text.prose(result.refinement_file_path)}")
        if result.refinement_excluded_links:
            lines.append(f"- {label('refinement_excluded_links')}: {len(result.refinement_excluded_links)}")
            lines.extend(f"  - {text.prose(link)}" for link in result.refinement_excluded_links)
    return _write_markdown(output_path, lines)
