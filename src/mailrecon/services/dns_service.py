"""DNS-related service helpers."""

import dns.exception
import dns.resolver

from mailrecon.core.models import DnsLookupResult


class DnsService:
    """Resolves domain information from public DNS."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def _build_resolver(self) -> dns.resolver.Resolver:
        """Create a resolver configured with the service timeout."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    def _lookup_records(
        self,
        resolver: dns.resolver.Resolver,
        domain: str,
        record_type: str,
    ) -> tuple[list[str], str | None]:
        """Resolve one record type and return records plus an optional note."""
        try:
            answers = resolver.resolve(domain, record_type)
        except dns.resolver.NXDOMAIN:
            return [], "Domain does not exist in DNS."
        except dns.resolver.NoAnswer:
            return [], f"No {record_type} records found."
        except dns.resolver.NoNameservers:
            return [], "No nameservers responded to the DNS query."
        except dns.exception.Timeout:
            return [], f"DNS lookup for {record_type} timed out."
        except dns.resolver.LifetimeTimeout:
            return [], f"DNS lookup for {record_type} exceeded the configured timeout."
        except dns.exception.DNSException as exc:
            return [], f"DNS error while querying {record_type}: {exc}"

        if record_type == "MX":
            records = [str(answer.exchange).rstrip(".") for answer in answers]
        elif record_type == "TXT":
            records = [self._format_txt_answer(answer) for answer in answers]
        elif record_type == "NS":
            records = [str(answer).rstrip(".") for answer in answers]
        else:
            records = [str(answer) for answer in answers]

        return records, None

    def _format_txt_answer(self, answer: object) -> str:
        """Format TXT answers from dnspython or simple test doubles."""
        chunks = getattr(answer, "strings", None)
        if chunks:
            return "".join(
                chunk.decode("utf-8", errors="replace")
                if isinstance(chunk, bytes)
                else str(chunk)
                for chunk in chunks
            )
        return str(answer).strip('"')

    def lookup_domain(self, domain: str) -> DnsLookupResult:
        """Resolve public DNS information for a domain."""
        resolver = self._build_resolver()
        a_records, a_error = self._lookup_records(resolver, domain, "A")
        aaaa_records, aaaa_error = self._lookup_records(resolver, domain, "AAAA")
        mx_records, mx_error = self._lookup_records(resolver, domain, "MX")
        txt_records, txt_error = self._lookup_records(resolver, domain, "TXT")
        dmarc_records, dmarc_error = self._lookup_records(resolver, f"_dmarc.{domain}", "TXT")
        ns_records, ns_error = self._lookup_records(resolver, domain, "NS")

        if dmarc_error == "Domain does not exist in DNS.":
            dmarc_error = "No DMARC records found."

        null_mx = mx_records == [""]
        if null_mx:
            mx_records = []

        spf_records = [
            record for record in txt_records if record.lower().strip().startswith("v=spf1")
        ]
        dmarc_policy = self._extract_dmarc_policy(dmarc_records)

        errors: list[str] = []
        for error in (a_error, aaaa_error, mx_error, txt_error, dmarc_error, ns_error):
            if error and error not in errors:
                errors.append(error)

        if null_mx:
            errors.append("Domain publishes Null MX and declares it does not accept email.")

        return DnsLookupResult(
            resolves=bool(a_records or aaaa_records or mx_records),
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            ns_records=ns_records,
            txt_records=txt_records,
            spf_records=spf_records,
            dmarc_records=dmarc_records,
            errors=errors,
            domain_status=self._classify_domain_status(
                a_records=a_records,
                aaaa_records=aaaa_records,
                mx_records=mx_records,
                errors=errors,
            ),
            email_acceptance_status=self._classify_email_acceptance(
                a_records=a_records,
                aaaa_records=aaaa_records,
                mx_records=mx_records,
                null_mx=null_mx,
                errors=errors,
            ),
            spf_status=self._classify_spf_status(spf_records),
            dmarc_status="present" if dmarc_records else "absent",
            dmarc_policy=dmarc_policy,
            provider_family=self._classify_provider(mx_records, txt_records),
            null_mx=null_mx,
        )

    def _classify_domain_status(
        self,
        a_records: list[str],
        aaaa_records: list[str],
        mx_records: list[str],
        errors: list[str],
    ) -> str:
        """Classify domain resolution without implying mailbox existence."""
        if any("Domain does not exist" in error for error in errors):
            return "nxdomain"
        if mx_records or a_records or aaaa_records:
            return "resolves"
        if any("timed out" in error or "timeout" in error.lower() for error in errors):
            return "inconclusive"
        return "no_public_resolution"

    def _classify_email_acceptance(
        self,
        a_records: list[str],
        aaaa_records: list[str],
        mx_records: list[str],
        null_mx: bool,
        errors: list[str],
    ) -> str:
        """Classify whether the domain appears technically able to receive mail."""
        if null_mx:
            return "declares_no_mail"
        if any("Domain does not exist" in error for error in errors):
            return "domain_unresolved"
        if mx_records:
            return "mx_present"
        if a_records or aaaa_records:
            return "implicit_mail_possible"
        if any("timed out" in error or "timeout" in error.lower() for error in errors):
            return "inconclusive"
        return "no_mail_signal"

    def _classify_spf_status(self, spf_records: list[str]) -> str:
        """Classify SPF presence without treating it as mailbox proof."""
        if len(spf_records) > 1:
            return "multiple"
        if spf_records:
            return "present"
        return "absent"

    def _extract_dmarc_policy(self, dmarc_records: list[str]) -> str | None:
        """Extract a coarse DMARC policy value when present."""
        for record in dmarc_records:
            parts = [part.strip().lower() for part in record.split(";")]
            for part in parts:
                if part.startswith("p="):
                    return part.partition("=")[2] or None
        return None

    def _classify_provider(self, mx_records: list[str], txt_records: list[str]) -> str:
        """Classify common provider families from public MX/TXT signals."""
        haystack = " ".join(mx_records + txt_records).lower()
        provider_markers = {
            "google_workspace": ("aspmx.l.google.com", "google.com", "_spf.google.com"),
            "microsoft_365": ("mail.protection.outlook.com", "spf.protection.outlook.com"),
            "proton": ("protonmail", "proton.ch"),
            "zoho": ("zoho",),
            "fastmail": ("fastmail", "messagingengine.com"),
            "icloud": ("icloud.com", "me.com", "mac.com"),
            "yahoo": ("yahoodns.net", "yahoomail",),
            "mailgun": ("mailgun.org",),
            "sendgrid": ("sendgrid.net",),
            "amazon_ses": ("amazonses.com",),
            "cloudflare_email_routing": ("mx.cloudflare.net",),
            "improvmx": ("improvmx.com",),
        }
        for provider, markers in provider_markers.items():
            if any(marker in haystack for marker in markers):
                return provider
        return "unknown_provider"
