"""Have I Been Pwned integration scaffold."""

from urllib.parse import quote

import httpx

from mailrecon.core.i18n import msg
from mailrecon.core.models import HibpResult


class HibpService:
    """Prepares HIBP integration behind a small service boundary."""

    base_url = "https://haveibeenpwned.com/api/v3"

    def __init__(
        self,
        api_key: str | None,
        timeout: float = 10.0,
        enabled: bool = True,
    ) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.enabled = enabled

    def query_breaches(self, email: str) -> HibpResult:
        """Query HIBP for known breaches related to the email address."""
        if not self.enabled:
            return HibpResult(
                queried=False,
                status="disabled",
                breaches=[],
            )

        if not self.api_key:
            return HibpResult(
                queried=False,
                status="missing_api_key",
                breaches=[],
            )

        headers = {
            "hibp-api-key": self.api_key,
            "user-agent": "mailrecon/0.1.0",
        }
        encoded_email = quote(email, safe="")
        url = f"{self.base_url}/breachedaccount/{encoded_email}"
        params = {"truncateResponse": "false"}

        try:
            with httpx.Client(timeout=self.timeout, headers=headers) as client:
                response = client.get(url, params=params)
        except httpx.TimeoutException:
            return HibpResult(
                queried=True,
                status="timeout",
                breaches=[],
                error=msg("hibp.error.timeout"),
            )
        except httpx.HTTPError as exc:
            return HibpResult(
                queried=True,
                status="request_error",
                breaches=[],
                error=msg("hibp.error.request", error=str(exc)),
            )

        if response.status_code == 404:
            return HibpResult(
                queried=True,
                status="no_breaches",
                breaches=[],
            )

        if response.status_code == 401:
            return HibpResult(
                queried=True,
                status="unauthorized",
                breaches=[],
                error=msg("hibp.error.unauthorized"),
            )

        if response.status_code == 403:
            return HibpResult(
                queried=True,
                status="forbidden",
                breaches=[],
                error=msg("hibp.error.forbidden"),
            )

        if response.status_code == 429:
            return HibpResult(
                queried=True,
                status="rate_limited",
                breaches=[],
                error=msg("hibp.error.rate_limited"),
            )

        if response.is_error:
            return HibpResult(
                queried=True,
                status="http_error",
                breaches=[],
                error=msg("hibp.error.http", status_code=response.status_code),
            )

        try:
            breaches = response.json()
        except ValueError:
            return HibpResult(
                queried=True,
                status="invalid_response",
                breaches=[],
                error=msg("hibp.error.json"),
            )

        if not isinstance(breaches, list) or not all(
            isinstance(breach, dict) for breach in breaches
        ):
            return HibpResult(
                queried=True,
                status="invalid_response",
                breaches=[],
                error=msg("hibp.error.shape"),
            )

        return HibpResult(
            queried=True,
            status="breaches_found" if breaches else "no_breaches",
            breaches=breaches,
        )
