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
        else:
            records = [str(answer) for answer in answers]

        return records, None

    def lookup_domain(self, domain: str) -> DnsLookupResult:
        """Resolve public DNS information for a domain."""
        resolver = self._build_resolver()
        a_records, a_error = self._lookup_records(resolver, domain, "A")
        mx_records, mx_error = self._lookup_records(resolver, domain, "MX")

        errors: list[str] = []
        for error in (a_error, mx_error):
            if error and error not in errors:
                errors.append(error)

        return DnsLookupResult(
            resolves=bool(a_records or mx_records),
            a_records=a_records,
            mx_records=mx_records,
            errors=errors,
        )
