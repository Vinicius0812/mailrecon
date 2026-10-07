"""Self-contained offline reports. Only fixed, hashed CSS/JS can execute."""

import base64
import hashlib
import unicodedata
from html import escape, unescape
from pathlib import Path
from urllib.parse import unquote, urlsplit

from mailrecon.core.i18n import translate
from mailrecon.core.models import EvidenceRecord, InvestigationResult, ReconResult, SmtpLabValidationResult
from mailrecon.reporting.console import _ReportText, _mask_text, _sanitize_terminal_text


_CSS = """
*{box-sizing:border-box}html{color-scheme:light}body{margin:0;background:#f5f7f8;color:#20272b;
font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;letter-spacing:0}
header{background:#fff;border-top:5px solid #176c66;border-bottom:1px solid #c9d2d5;padding:20px 24px}
header div,main{max-width:1440px;margin:auto}h1{font-size:24px;line-height:1.25;margin:0 0 8px}
h2{font-size:18px;margin:0 0 12px}p{margin:6px 0;overflow-wrap:anywhere}main{padding:20px 24px}
section{padding:20px 0;border-bottom:1px solid #c9d2d5;min-width:0}
.notice{border-left:4px solid #b56616;padding-left:12px;color:#583713}
.toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:end;padding:12px 0}
label{display:grid;gap:4px;font-weight:600;min-width:0}input,select,button{font:inherit;color:inherit;
border:1px solid #89999e;border-radius:4px;background:#fff;padding:8px;min-height:40px;max-width:100%}
input{width:320px}button{cursor:pointer}button:hover{background:#e4efed}
:focus-visible{outline:3px solid #b56616;outline-offset:2px}.scroll{overflow:auto;max-width:100%;border:1px solid #c9d2d5}
table{width:100%;min-width:760px;border-collapse:collapse;background:#fff;font-size:13px}
table.compact{min-width:0;table-layout:fixed}
.compact th:first-child,.compact td:first-child{width:40%}
.compact th,.compact td{max-width:none;white-space:normal;overflow-wrap:anywhere}
th,td{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid #dce2e4;
overflow-wrap:anywhere;max-width:360px}th{background:#e9eeef;font-weight:650;position:sticky;top:0}
tr:last-child td{border-bottom:0}tr[data-kind=observed] td:first-child{border-left:3px solid #176c66}
tr[data-kind=hypothesis] td:first-child{border-left:3px solid #b56616}
tr[data-kind=synthetic] td:first-child{border-left:3px solid #7c485f}a{color:#125e65;text-decoration:underline}
small{display:block;color:#526168}ul{padding-left:20px;margin:8px 0}li{overflow-wrap:anywhere}
.meta{display:flex;flex-wrap:wrap;gap:8px 24px;color:#526168}.empty{color:#526168}
[hidden]{display:none!important}output{color:#526168;font-variant-numeric:tabular-nums}
@media(max-width:600px){header{padding:16px}main{padding:8px 16px}h1{font-size:22px}
.toolbar label{width:100%}input,select{width:100%}.meta{gap:4px 12px}section{padding:16px 0}
.compact th:first-child,.compact td:first-child{width:44%}.compact th,.compact td{padding:8px}}
@media print{.toolbar{display:none}.scroll{overflow:visible}table{min-width:0}th{position:static}
body{background:#fff}header,main{padding:12px}a{color:inherit}}
"""

_JS = """
(() => {
  const form = document.getElementById('filters');
  const query = document.getElementById('query');
  const kind = document.getElementById('kind');
  const count = document.getElementById('count');
  const rows = Array.from(document.querySelectorAll('tbody tr[data-kind]'));
  const filter = () => {
    const needle = query.value.toLocaleLowerCase().trim();
    let shown = 0;
    for (const row of rows) {
      row.hidden = !(row.textContent.toLocaleLowerCase().includes(needle) &&
        (kind.value === 'all' || row.dataset.kind === kind.value));
      if (!row.hidden) shown += 1;
    }
    count.textContent = shown + ' / ' + rows.length;
  };
  query.addEventListener('input', filter);
  kind.addEventListener('change', filter);
  form.addEventListener('submit', event => event.preventDefault());
  form.addEventListener('reset', () => { query.value = ''; kind.value = 'all'; filter(); });
  filter();
})();
"""


_DECODE_MAX_CHARS = 65536
_DECODE_MAX_ROUNDS = 8


def _decoded(value: str) -> str | None:
    """Return a stable privacy view, or None when decoding cannot finish safely."""
    if '%' not in value and '&' not in value:
        return value
    if len(value) > _DECODE_MAX_CHARS:
        return None
    for _ in range(_DECODE_MAX_ROUNDS):
        entities = unescape(value)
        if len(entities) > _DECODE_MAX_CHARS:
            return None
        decoded = unquote(entities)
        if len(decoded) > _DECODE_MAX_CHARS:
            return None
        if decoded == value:
            return value
        value = decoded
    return None


def _safe_url(value: str, masked: bool) -> str | None:
    if len(value) > 8192 or any(char.isspace() or unicodedata.category(char) in {"Cc", "Cf"} for char in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or '%' in parsed.netloc or '&' in parsed.netloc
                or parsed.username is not None or parsed.password is not None):
            return None
        parsed.port
    except ValueError:
        return None
    decoded = _decoded(value)
    if decoded is None or any(unicodedata.category(char) in {"Cc", "Cf"} for char in decoded) or "\\" in decoded:
        return None
    if masked and "@" in decoded:
        return None
    return value


class _Report:
    def __init__(self, language: str, masked: bool, synthetic: bool = False):
        self.text = _ReportText(language, masked)
        self.language = language
        self.masked = masked
        self.synthetic = synthetic
        self.parts: list[str] = []

    def s(self, value: object) -> str:
        value = str(value) if value is not None else ""
        if self.masked:
            decoded = _decoded(value)
            if decoded is None:
                # Never expose the raw or partially decoded value after budget exhaustion.
                return ""
            masked = _mask_text(decoded)
            if masked != decoded or _sanitize_terminal_text(decoded) != decoded:
                value = masked
            else:
                value = _mask_text(value)
        return escape(_sanitize_terminal_text(value), quote=True)

    def label(self, key: str) -> str:
        return self.s(self.text.label(key))

    def human(self, value: object) -> str:
        return self.s(self.text.human(str(value)))

    def link(self, value: str) -> str:
        url = _safe_url(value, self.masked)
        if url is None:
            return self.s(value)
        return f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{self.s(value)}</a>'

    def table(self, heading: str, headers: list[str], rows: list[tuple[str, list[str]]]):
        self.parts.append(f'<section><h2>{self.label(heading)}</h2>')
        if not rows:
            self.parts.append(f'<p class="empty">{self.label("html_empty")}</p></section>')
            return
        table_class = ' class="compact"' if len(headers) == 2 else ''
        self.parts.append(f'<div class="scroll" role="region" tabindex="0" aria-label="{self.label(heading)}"><table{table_class}>')
        self.parts.append('<thead><tr>' + ''.join(f'<th scope="col">{self.label(key)}</th>' for key in headers) + '</tr></thead><tbody>')
        for kind, cells in rows:
            if self.synthetic:
                kind = "synthetic"
            self.parts.append(f'<tr data-kind="{kind}">' + ''.join(f'<td>{cell}</td>' for cell in cells) + '</tr>')
        self.parts.append('</tbody></table></div></section>')

    def prose(self, heading: str, values: list[str]):
        if values:
            self.parts.append(f'<section><h2>{self.label(heading)}</h2><ul>' + ''.join(f'<li>{self.s(value)}</li>' for value in values) + '</ul></section>')

    def provenance(self, item) -> str:
        sources = getattr(item, "sources", []) or [getattr(item, "source", "mailrecon")]
        rule = getattr(item, "rule_id", None)
        version = getattr(item, "rule_version", None)
        method = getattr(item, "check_method", None) or getattr(item, "method", None)
        lines = [self.s(', '.join(sources))]
        if method:
            lines.append(self.label("method") + ': ' + self.human(method))
        if rule:
            lines.append(self.label("html_rule") + ': ' + self.s(rule) + ' / ' + self.s(version))
        if getattr(item, "cache_hit", False):
            lines.append(self.label("html_cache"))
        if isinstance(item, EvidenceRecord):
            performed = item.collection_performed
            lines.append(self.label("html_collection") + ': ' + (self.label("state.unknown") if performed is None else self.s(self.text.boolean(performed))))
        return '<br>'.join(lines)

    def kind(self, item) -> str:
        if self.synthetic:
            return "synthetic"
        scope = getattr(item, "confidence_scope", "")
        if scope.startswith("synthetic") or getattr(item, "method", "").startswith("lab_"):
            return "synthetic"
        performed = getattr(item, "collection_performed", None)
        if scope == "breach_exposure":
            return "observed" if performed is True else "hypothesis"
        if performed is False:
            return "hypothesis"
        if (getattr(item, "checked_at", None) and getattr(item, "check_method", None) == "official_public_api") or scope == "dns_observation" or (getattr(item, "method", None) == "official_public_api" and performed is True):
            return "observed"
        return "hypothesis"

    def recon(self, result: ReconResult):
        fields = [("email", result.email), ("domain", result.domain), ("domain_status", result.dns.domain_status),
                  ("mail_capability", result.dns.email_acceptance_status), ("spf_status", result.dns.spf_status),
                  ("dmarc_status", result.dns.dmarc_status), ("provider_family", result.dns.provider_family),
                  ("hibp_status", result.hibp.status)]
        self.table("overview", ["html_field", "html_value"], [("hypothesis" if key in {"email", "domain"} or (key == "hibp_status" and not result.hibp.queried) else "observed", [self.label(key), self.human(value)]) for key, value in fields])
        records = [(key, value) for key in ("a_records", "aaaa_records", "mx_records", "ns_records", "txt_records", "spf_records", "dmarc_records") for value in getattr(result.dns, key)]
        self.table("html_dns", ["html_field", "html_value", "confidence_scope", "sources"], [("observed", [self.s(key), self.s(value), self.human("dns_observation"), self.human("public_dns")]) for key, value in records])
        self.prose("technical_reasons", result.technical_assessment.decision_reasons)
        self.prose("technical_limitations", result.technical_assessment.limitations)
        self.prose("dns_notes", result.dns.errors)
        self.table("hibp_breaches", ["name", "summary", "confidence_scope", "sources"], [("observed" if result.hibp.queried else "hypothesis", [self.s(breach.get("Name", "")), self.s(breach.get("Title", "")), self.human("breach_exposure"), self.s("Have I Been Pwned")]) for breach in result.hibp.breaches])
        if result.hibp.error:
            self.prose("hibp_notes", [result.hibp.error])

    def investigation(self, result: InvestigationResult):
        self.table("overview", ["html_field", "html_value"], [("hypothesis", [self.label(key), self.s(', '.join(values))]) for key, values in
                   (("names", result.query.names), ("seed_emails", result.query.emails), ("seed_usernames", result.query.usernames),
                    ("seed_domains", result.query.domains), ("organizations", result.query.organizations), ("context", result.query.contexts)) if values])
        self.table("confidence_breakdown", ["html_field", "score"], [("hypothesis", [self.human(key), self.s(f"{value}/100")]) for key, value in result.confidence_breakdown.items()])
        self.table("candidate_emails", ["email", "status", "confidence", "confidence_scope", "sources", "review_priority"],
                   [("hypothesis", [self.s(item.email), self.human(item.status), self.human(item.confidence), self.human(item.confidence_scope), self.provenance(item), self.s(f"{item.review_priority_score}/100")]) for item in result.candidate_emails])
        self.table("public_profile_pivots", ["html_kind", "platform", "handle", "resolution_status", "confidence", "confidence_scope", "sources", "profile_url", "collected_at"],
                   [(self.kind(item), [self.label("html_" + self.kind(item)), self.s(item.platform), self.s(item.handle), self.human(item.resolution_status), self.human(item.confidence), self.human(item.confidence_scope), self.provenance(item), self.link(item.profile_url) + ('<br>' + self.link(item.final_url) if item.final_url else ''), self.s(item.checked_at)]) for item in result.profile_pivots])
        self.table("evidence_records", ["html_kind", "summary", "reference", "confidence", "confidence_scope", "sources", "html_timestamp"],
                   [(self.kind(item), [self.label("html_" + self.kind(item)), self.s(item.summary), self.link(item.reference), self.human(item.confidence), self.human(item.confidence_scope), self.provenance(item), self.s(item.collected_at)]) for item in result.evidences])
        details = []
        for item in [*result.candidate_emails, *result.profile_pivots, *result.evidences]:
            reference = getattr(item, "email", None) or getattr(item, "profile_url", None) or getattr(item, "reference", "")
            for attribute, label in (("decision_reasons", "decision_reason"), ("limitations", "limitation"), ("notes", "note"), ("ambiguity_reasons", "ambiguity_reason"), ("matched_fields", "matched_field"), ("missing_fields", "missing_field"), ("conflicting_fields", "conflicting_field")):
                for value in getattr(item, attribute, []):
                    rendered = self.human(value) if attribute in {"ambiguity_reasons", "matched_fields", "missing_fields", "conflicting_fields"} else self.s(value)
                    details.append((self.kind(item), [self.s(reference), self.label(label), rendered]))
            if getattr(item, "observations", None):
                details.append((self.kind(item), [self.s(reference), self.label("observations"), self.s(item.observations)]))
            if getattr(item, "search_url", None):
                details.append(("hypothesis", [self.s(reference), self.label("search_url"), self.link(item.search_url)]))
            if getattr(item, "http_status_code", None) is not None:
                details.append((self.kind(item), [self.s(reference), self.label("http_status"), self.s(item.http_status_code)]))
        self.table("html_details", ["reference", "html_field", "html_value"], details)
        for candidate in result.candidate_emails:
            if candidate.analysis:
                self.prose("candidate_emails", [candidate.email])
                self.recon(candidate.analysis)
        for heading, values in (("findings", result.findings), ("risks", result.risks), ("limitations", result.limitations), ("pivot_suggestions", result.pivot_suggestions)):
            self.prose(heading, values)

    def smtp(self, result: SmtpLabValidationResult):
        self.prose("lab_only", [self.text.label("lab_only")])
        self.table("overview", ["html_field", "html_value"], [("observed" if result.network_used else "synthetic", [self.label(key), self.human(value) if key in {"transport", "safety_status"} else self.s(value)]) for key, value in
                   (("email", result.email), ("lab_domain", result.lab_domain), ("host", f"{result.host}:{result.port}"), ("transport", result.transport), ("resolved_ips", ', '.join(result.resolved_ips)), ("network_used", self.text.boolean(result.network_used)), ("safety_status", result.safety_decision.status))])
        self.table("checks", ["html_kind", "method", "status", "smtp_code", "message", "confidence_scope"],
                   [("synthetic" if not item.network_used else "observed", [self.label("html_synthetic" if not item.network_used else "html_observed"), self.s(item.check), self.human(item.status), self.s(item.smtp_code), self.s(item.message), self.label("lab_only")]) for item in result.checks_run])
        self.prose("safety_decision", result.safety_decision.reasons)
        self.prose("limitations", result.safety_decision.limitations + result.limitations)


def export_html(result: ReconResult | InvestigationResult | SmtpLabValidationResult,
                output_path: str | Path, language: str = "pt-br", mask_sensitive: bool = True,
                *, synthetic: bool = False) -> Path:
    """Export escaped, filtered tables with no data scripts or remote resources."""
    result = translate(result, language)
    report = _Report(language, mask_sensitive, synthetic)
    if isinstance(result, InvestigationResult):
        report.investigation(result)
        title = "investigation_report_title"
    elif isinstance(result, ReconResult):
        report.recon(result)
        title = "report_title"
    elif isinstance(result, SmtpLabValidationResult):
        report.smtp(result)
        title = "smtp_title"
    else:
        raise ValueError("Unsupported report model")
    digest = lambda value: base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")
    csp = (f"default-src 'none'; style-src 'sha256-{digest(_CSS)}'; script-src 'sha256-{digest(_JS)}'; "
           "connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; worker-src 'none'")
    labels = report.label
    options = ''.join(f'<option value="{key}">{labels("html_" + key)}</option>' for key in ("all", "hypothesis", "observed", "synthetic"))
    content = (f'<!doctype html><html lang="{"pt-BR" if language == "pt-br" else "en"}"><head><meta charset="utf-8">'
               f'<meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{escape(csp, quote=True)}">'
               f'<meta name="referrer" content="no-referrer"><title>{labels(title)}</title><style>{_CSS}</style></head><body>'
               f'<header><div><h1>{labels(title)}</h1><p class="notice">{labels("html_synthetic_notice") if synthetic else labels("html_identity")}</p>'
               f'<div class="meta"><span>{labels("generated_at")}: {report.s(result.generated_at)}</span><span>{labels("html_masked" if mask_sensitive else "html_revealed")}</span></div></div></header>'
               f'<main><form id="filters" class="toolbar"><label for="query">{labels("html_filter")}<input id="query" type="search" autocomplete="off"></label>'
               f'<label for="kind">{labels("html_kind")}<select id="kind">{options}</select></label><button type="reset">{labels("html_reset")}</button>'
               f'<output id="count" aria-live="polite"></output></form>{"".join(report.parts)}</main><script>{_JS}</script></body></html>')
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
