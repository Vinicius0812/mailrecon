"""Terminal rendering helpers."""

import re

from mailrecon.core.catalog_reporting import CATALOG
from mailrecon.core.i18n import t, translate
from mailrecon.core.models import InvestigationResult, ReconResult, SmtpLabValidationResult
from mailrecon.core.validators import mask_email_address


class _ReportText:
    """Shared report copy, enum display and translate-before-mask handling."""

    def __init__(self, language: str, mask_sensitive: bool) -> None:
        self.language = language
        self.mask_sensitive = mask_sensitive

    def label(self, key: str) -> str:
        return t(f"reporting.{key}", language=self.language)

    def prose(self, value: str) -> str:
        rendered = str(translate(value, language=self.language))
        return _mask_text(rendered) if self.mask_sensitive else rendered

    def email(self, value: str) -> str:
        if not self.mask_sensitive:
            return value
        if value.endswith("@"):
            return "*@"
        return mask_email_address(value)

    def human(self, value: str) -> str:
        key = f"reporting.state.{value}"
        if self.language != "en" and key in CATALOG:
            return self.label(f"state.{value}")
        return self.prose(value)

    def boolean(self, value: bool) -> str:
        return self.label("yes" if value else "no")

    def confidence_details(self, item: object) -> list[tuple[str, str]]:
        details = []
        scope = getattr(item, "confidence_scope", None)
        if scope is not None:
            details.append((self.label("confidence_scope"), self.human(scope)))
        sources = getattr(item, "sources", None)
        if sources is not None:
            value = ", ".join(self.human(source) for source in sources)
            details.append((self.label("sources"), value or self.human("none")))
        return details


def _console_rows(rows: list[tuple[str, object]], indent: str = "") -> list[str]:
    width = max([19 - len(indent), *(len(label) for label, _ in rows)])
    return [f"{indent}{label:<{width}}: {value}" for label, value in rows]


def render_summary(
    result: ReconResult, mask_sensitive: bool = True, language: str = "pt-br"
) -> str:
    """Build a friendly terminal summary for one recon result."""
    result = translate(result, language)
    text = _ReportText(language, mask_sensitive)
    label = text.label
    lines = [f"=== {label('analysis_title')} ==="]
    lines.extend(_console_rows([
        (label("email"), text.email(result.email)),
        (label("domain"), text.prose(result.domain)),
        (label("format_valid"), text.boolean(result.is_valid)),
        (label("domain_resolves"), text.boolean(result.dns.resolves)),
        (label("domain_status"), text.human(result.dns.domain_status)),
        (label("mail_capability"), text.human(result.dns.email_acceptance_status)),
        (label("provider_family"), text.human(result.dns.provider_family)),
        (label("technical_priority"), f"{result.technical_assessment.review_priority_score}/100"),
        (label("a_records"), ", ".join(result.dns.a_records) or text.human("none")),
        (label("mx_found"), text.boolean(bool(result.dns.mx_records))),
        (label("mx_hosts"), ", ".join(result.dns.mx_records) or text.human("none")),
        (label("hibp_status"), text.human(result.hibp.status)),
    ]))
    if result.hibp.queried:
        lines.append(f"{label('hibp_breaches_found')}: {len(result.hibp.breaches)}")
    if result.dns.errors:
        notes = "; ".join(text.prose(error) for error in result.dns.errors)
        lines.append(f"{label('dns_notes')}: {notes}")
    if result.hibp.error:
        lines.append(f"{label('hibp_notes')}: {text.prose(result.hibp.error)}")
    return "\n".join(lines)


def render_investigation_summary(
    result: InvestigationResult,
    mask_sensitive: bool = True,
    language: str = "pt-br",
) -> str:
    """Build a friendly terminal summary for one OSINT investigation."""
    result = translate(result, language)
    text = _ReportText(language, mask_sensitive)
    label = text.label
    retained_candidates = [item for item in result.candidate_emails if not item.status.startswith("rejected_")]
    exposed_candidates = [item for item in retained_candidates if item.analysis is not None and item.analysis.hibp.status == "breaches_found"]
    score = result.review_priority_score
    lines = [
        f"=== {label('investigation_title')} ===",
        f"{label('review_priority'):<19}: {score}/100 {_render_score_bar(score)}",
        "", label("overview"),
    ]
    lines.extend(_console_rows([
        (label("seed_emails"), len(result.query.emails)),
        (label("seed_usernames"), len(result.query.usernames)),
        (label("seed_domains"), len(result.query.domains)),
        (label("candidate_emails"), len(result.candidate_emails)),
        (label("profile_pivots"), len(result.profile_pivots)),
        (label("retained_leads"), len(retained_candidates)),
        (label("exposure_signals"), len(exposed_candidates)),
        (label("evidence_records"), len(result.evidences)),
    ], indent="  "))
    details = text.confidence_details(result)
    if details:
        lines.extend(_console_rows(details, indent="  "))
    if result.confidence_breakdown:
        lines.extend(["", label("confidence_breakdown")])
        lines.extend(f"  {text.human(key):<31}: {score}/100" for key, score in result.confidence_breakdown.items())
    if retained_candidates:
        lines.extend(["", label("candidate_preview")])
        for candidate in retained_candidates[:5]:
            lines.append(
                f"  {text.email(candidate.email)} "
                f"{label('confidence')}={text.human(candidate.confidence)} "
                f"{label('review_priority')}={candidate.review_priority_score}/100"
            )
            lines.extend(_console_rows(text.confidence_details(candidate), indent="    "))
    for heading, values in (("top_finding", result.findings), ("primary_risk", result.risks)):
        if values:
            lines.extend(["", label(heading), f"  {text.prose(values[0])}"])
    if result.profile_pivots:
        lines.extend(["", label("platform_preview")])
        for pivot in result.profile_pivots[:5]:
            lines.append(
                f"  {text.prose(pivot.platform):<10} {label('handle')}={text.prose(pivot.handle)} "
                f"{label('review_priority')}={pivot.review_priority_score}/100 "
                f"{label('status')}={text.human(pivot.status)} "
                f"{label('confidence')}={text.human(pivot.confidence)}"
            )
            lines.extend(_console_rows(text.confidence_details(pivot), indent="    "))
        review_links = sorted(result.profile_pivots, key=lambda pivot: (-pivot.review_priority_score, pivot.platform, pivot.handle))[:5]
        lines.extend(["", label("review_links")])
        for pivot in review_links:
            lines.append(
                f"  {text.prose(pivot.platform):<10} {text.prose(pivot.profile_url)} "
                f"({label('review_priority')}={pivot.review_priority_score}/100, {label('status')}={text.human(pivot.status)})"
            )
    if result.refinement_file_path:
        lines.extend(["", label("refinement")])
        lines.extend(_console_rows([
            (label("excluded_links"), len(result.refinement_excluded_links)),
            (label("state_file"), text.prose(result.refinement_file_path)),
        ], indent="  "))
    return "\n".join(lines)


def render_smtp_lab_summary(
    result: SmtpLabValidationResult,
    language: str = "pt-br",
    mask_sensitive: bool = True,
) -> str:
    """Build a lab-only SMTP validation summary without translating wire replies."""
    result = translate(result, language)
    text = _ReportText(language, mask_sensitive)
    label = text.label
    lines = [f"=== {label('smtp_title')} ==="]
    lines.extend(_console_rows([
        (label("mode"), label("lab_only")),
        (label("email"), text.email(result.email)),
        (label("lab_domain"), text.prose(result.lab_domain)),
        (label("transport"), text.human(result.transport)),
        (label("host"), text.prose(f"{result.host}:{result.port}")),
        (label("network_used"), text.boolean(result.network_used)),
        (label("safety_status"), text.human(result.safety_decision.status)),
    ]))
    if result.resolved_ips:
        lines.append(f"{label('resolved_ips'):<19}: {', '.join(result.resolved_ips)}")
    if result.safety_decision.reasons:
        lines.extend(["", label("safety_decision")])
        lines.extend(f"  {text.prose(reason)}" for reason in result.safety_decision.reasons)
    if result.checks_run:
        lines.extend(["", label("checks")])
        for check in result.checks_run:
            code = f" {label('smtp_code')}={check.smtp_code}" if check.smtp_code is not None else ""
            lines.append(f"  {check.check:<5} {label('status')}={text.human(check.status)}{code}")
            if check.message:
                reply = _mask_text(check.message) if mask_sensitive else check.message
                lines.append(f"        {reply}")
    limitations = result.safety_decision.limitations + result.limitations
    if limitations:
        lines.extend(["", label("limitations")])
        lines.extend(f"  {text.prose(limitation)}" for limitation in limitations)
    return "\n".join(lines)


def _render_score_bar(score: int) -> str:
    """Render a small ASCII score bar."""
    filled = max(0, min(10, round(score / 10)))
    return "[" + ("#" * filled) + ("-" * (10 - filled)) + "]"


_EMAIL_IN_TEXT = re.compile(
    r'''(?:"[^"\r\n]+"|[\w.!#$%&'*+^_`{|}~-]+)@[\w](?:[\w.-]*[\w])?'''
)


def _mask_text(text: str) -> str:
    """Mask embedded addresses, including URL/query values, without eating punctuation."""
    return _EMAIL_IN_TEXT.sub(lambda match: mask_email_address(match.group()), text)
