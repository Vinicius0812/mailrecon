"""Lab-only SMTP validation service with strict safety gates."""

from __future__ import annotations

from datetime import datetime, timezone
import re
import smtplib
import socket

from mailrecon.core.models import (
    SafetyDecision,
    SmtpLabCheckResult,
    SmtpLabValidationResult,
)
from mailrecon.core.safety import default_smtp_lab_limitations, evaluate_smtp_lab_safety


class SmtpLabValidationService:
    """Runs intrusive SMTP checks only inside explicit lab boundaries."""

    def __init__(
        self,
        enable_lab_smtp: bool = False,
        allow_hosts: list[str] | None = None,
        timeout: float = 3.0,
    ) -> None:
        self.enable_lab_smtp = enable_lab_smtp
        self.allow_hosts = allow_hosts or []
        self.timeout = timeout

    def validate(
        self,
        email: str,
        lab_domain: str,
        host: str,
        port: int,
        transport: str,
        checks: list[str],
        confirm_lab_only: bool = False,
        no_network: bool = False,
        max_probes: int = 3,
    ) -> SmtpLabValidationResult:
        """Run lab-only SMTP validation after all safety gates pass."""
        email = _normalize_lab_email(email)

        normalized_checks = [check.strip().lower() for check in checks if check.strip()]
        safety_decision, resolved_ips = evaluate_smtp_lab_safety(
            email=email,
            lab_domain=lab_domain,
            host=host,
            port=port,
            transport=transport,
            checks=normalized_checks,
            confirm_lab_only=confirm_lab_only,
            no_network=no_network,
            max_probes=max_probes,
            allow_hosts=self.allow_hosts,
            enable_lab_smtp=self.enable_lab_smtp,
        )

        if not safety_decision.allowed:
            return self._build_result(
                email=email,
                lab_domain=lab_domain,
                host=host,
                port=port,
                resolved_ips=resolved_ips,
                transport=transport,
                checks_requested=normalized_checks,
                checks_run=[
                    SmtpLabCheckResult(
                        check=check,
                        status="blocked_by_safety_policy",
                        message="Blocked before any SMTP interaction.",
                        network_used=False,
                    )
                    for check in normalized_checks
                ],
                safety_decision=safety_decision,
                network_used=False,
            )

        if transport == "mock":
            return self._run_mock(
                email=email,
                lab_domain=lab_domain,
                host=host,
                port=port,
                checks=normalized_checks,
                safety_decision=safety_decision,
            )

        return self._run_networked_lab(
            email=email,
            lab_domain=lab_domain,
            host=host,
            port=port,
            resolved_ips=resolved_ips,
            transport=transport,
            checks=normalized_checks,
            safety_decision=safety_decision,
        )

    def _run_mock(
        self,
        email: str,
        lab_domain: str,
        host: str,
        port: int,
        checks: list[str],
        safety_decision: SafetyDecision,
    ) -> SmtpLabValidationResult:
        """Return deterministic lab-only mock results without network."""
        local_part = email.partition("@")[0].lower()
        status = "mocked_reject" if local_part.startswith("reject") else "mocked_accept"
        checks_run = [
            SmtpLabCheckResult(
                check=check,
                status=status,
                smtp_code=250 if status == "mocked_accept" else 550,
                message="Mock lab transport result; no network used.",
                network_used=False,
            )
            for check in checks
        ]
        return self._build_result(
            email=email,
            lab_domain=lab_domain,
            host=host,
            port=port,
            resolved_ips=[],
            transport="mock",
            checks_requested=checks,
            checks_run=checks_run,
            safety_decision=safety_decision,
            network_used=False,
        )

    def _run_networked_lab(
        self,
        email: str,
        lab_domain: str,
        host: str,
        port: int,
        resolved_ips: list[str],
        transport: str,
        checks: list[str],
        safety_decision: SafetyDecision,
    ) -> SmtpLabValidationResult:
        """Run networked SMTP checks against a safety-approved lab host."""
        checks_run: list[SmtpLabCheckResult] = []
        try:
            with smtplib.SMTP(host=host, port=port, timeout=self.timeout) as smtp:
                smtp.helo("mailrecon.lab")
                for check in checks:
                    checks_run.append(self._run_networked_check(smtp, email, check))
        except (OSError, smtplib.SMTPException, socket.timeout) as exc:
            checks_run = [
                SmtpLabCheckResult(
                    check=check,
                    status="connection_failed",
                    message=f"Lab SMTP interaction failed: {exc}",
                    network_used=True,
                )
                for check in checks
            ]

        return self._build_result(
            email=email,
            lab_domain=lab_domain,
            host=host,
            port=port,
            resolved_ips=resolved_ips,
            transport=transport,
            checks_requested=checks,
            checks_run=checks_run,
            safety_decision=safety_decision,
            network_used=True,
        )

    def _run_networked_check(
        self,
        smtp: smtplib.SMTP,
        email: str,
        check: str,
    ) -> SmtpLabCheckResult:
        """Run one safety-approved lab SMTP command."""
        if check == "vrfy":
            code, message = smtp.verify(email)
        elif check == "expn":
            code, message = smtp.docmd("EXPN", email)
        elif check == "rcpt":
            smtp.mail("probe@mailrecon.lab")
            code, message = smtp.rcpt(email)
            smtp.rset()
        else:
            return SmtpLabCheckResult(
                check=check,
                status="check_not_supported",
                message="Unsupported lab SMTP check.",
                network_used=True,
            )

        text = _decode_smtp_message(message)
        return SmtpLabCheckResult(
            check=check,
            status=_map_smtp_code(code),
            smtp_code=code,
            message=text,
            network_used=True,
        )

    def _build_result(
        self,
        email: str,
        lab_domain: str,
        host: str,
        port: int,
        resolved_ips: list[str],
        transport: str,
        checks_requested: list[str],
        checks_run: list[SmtpLabCheckResult],
        safety_decision: SafetyDecision,
        network_used: bool,
    ) -> SmtpLabValidationResult:
        """Build a lab SMTP result with repeated safety limitations."""
        return SmtpLabValidationResult(
            email=email,
            lab_domain=lab_domain,
            host=host,
            port=port,
            resolved_ips=resolved_ips,
            transport=transport,
            checks_requested=checks_requested,
            checks_run=checks_run,
            safety_decision=safety_decision,
            network_used=network_used,
            limitations=list(default_smtp_lab_limitations),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )


def _map_smtp_code(code: int) -> str:
    """Map SMTP response codes to lab-only statuses."""
    if 200 <= code < 300:
        return "accepted_by_lab_server"
    if 400 <= code < 500:
        return "temporarily_unavailable"
    if 500 <= code < 600:
        return "rejected_by_lab_server"
    return "inconclusive"


def _decode_smtp_message(message: bytes | str) -> str:
    """Decode SMTP response text safely."""
    if isinstance(message, bytes):
        return message.decode("utf-8", errors="replace")
    return str(message)


def _normalize_lab_email(email: str) -> str:
    """Validate lab email syntax while allowing reserved lab domains."""
    value = email.strip()
    if value.count("@") != 1:
        raise ValueError("Lab SMTP email must contain exactly one @ sign.")

    local_part, domain = value.split("@", maxsplit=1)
    domain = domain.lower()
    if not local_part or not domain:
        raise ValueError("Lab SMTP email must include local-part and domain.")

    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local_part):
        raise ValueError("Lab SMTP email local-part contains unsupported characters.")

    labels = domain.split(".")
    if any(not label for label in labels):
        raise ValueError("Lab SMTP email domain contains an empty label.")

    for label in labels:
        if not re.fullmatch(r"[a-z0-9-]+", label):
            raise ValueError("Lab SMTP email domain contains unsupported characters.")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("Lab SMTP email domain labels cannot start or end with hyphen.")

    return f"{local_part}@{domain}"
