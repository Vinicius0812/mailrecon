"""Offline manual-query composition, unrelated to investigation fingerprints."""

from datetime import date
import re
import unicodedata
from urllib.parse import urlencode

from mailrecon.core.i18n import msg

FILE_TYPES = ("pdf", "docx", "xlsx", "pptx", "txt")


def _date(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            raise ValueError
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(msg("cli.search_date_invalid")) from exc


def _literal(value: str) -> str:
    if not value.strip() or len(value) > 500 or any(unicodedata.category(c) in {"Cc", "Cf"} for c in value):
        raise ValueError(msg("cli.search_text_invalid"))
    # Quotes and backslashes cannot escape the authored quoted term.
    return '"' + value.strip().replace('\\', ' ').replace('"', ' ') + '"'


def build_search_links(query: str, *, organizations: list[str] | None = None,
                       domains: list[str] | None = None, contexts: list[str] | None = None,
                       after: str | None = None, before: str | None = None,
                       file_type: str | None = None) -> list[tuple[str, str]]:
    """Generate links only. Search engine interpretation is not evidence."""
    start, end = _date(after), _date(before)
    if start and end and start > end:
        raise ValueError(msg("cli.search_date_order"))
    if file_type is not None and file_type not in FILE_TYPES:
        raise ValueError(msg("cli.search_file_invalid", choices=', '.join(FILE_TYPES)))
    seeds = [query, *(organizations or []), *(contexts or [])]
    if len(seeds) > 25 or len(domains or []) > 20:
        raise ValueError(msg("cli.search_text_invalid"))
    parts = [_literal(seed) for seed in seeds]
    validated_domains = []
    for domain in domains or []:
        try:
            ascii_domain = domain.encode('idna').decode('ascii').lower()
        except UnicodeError as exc:
            raise ValueError(msg("cli.search_domain_invalid")) from exc
        labels = ascii_domain.split('.')
        if (len(ascii_domain) > 253 or len(labels) < 2 or
                not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            raise ValueError(msg("cli.search_domain_invalid"))
        validated_domains.append(ascii_domain)
    if start:
        parts.append('after:' + start.isoformat())
    if end:
        parts.append('before:' + end.isoformat())
    if file_type:
        parts.append('filetype:' + file_type)
    expression = ' '.join(parts)
    return [(domain or '*', 'https://www.google.com/search?' + urlencode({'q': expression + (' site:' + domain if domain else '')}))
            for domain in (validated_domains or [''])]
