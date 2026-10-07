"""Safety gates for lab-only intrusive validation modes."""

from __future__ import annotations

import ipaddress

from mailrecon.core.i18n import msg
from mailrecon.core.models import SafetyDecision


allowed_smtp_lab_transports = {"mock", "localhost", "private-lab"}
allowed_smtp_lab_checks = {"vrfy", "rcpt", "expn"}
default_smtp_lab_limitations = [
    msg("safety.limitation.owned_lab"),
    msg("safety.limitation.mailbox"),
    msg("safety.limitation.no_mx"),
]


def evaluate_smtp_lab_safety(
    email: str,
    lab_domain: str,
    host: str,
    port: int,
    transport: str,
    checks: list[str],
    confirm_lab_only: bool,
    no_network: bool,
    max_probes: int,
    allow_hosts: list[str],
    enable_lab_smtp: bool,
) -> tuple[SafetyDecision, list[str]]:
    """Validate whether lab-only SMTP checks may run."""
    reasons: list[str] = []
    resolved_ips: list[str] = []

    normalized_transport = transport.strip().lower()
    normalized_checks = [check.strip().lower() for check in checks if check.strip()]
    normalized_host = host.strip().lower()
    normalized_lab_domain = lab_domain.strip().lower().lstrip("@")
    email_domain = email.rsplit("@", maxsplit=1)[-1].lower() if "@" in email else ""

    if normalized_transport not in allowed_smtp_lab_transports:
        reasons.append(msg("safety.reason.transport", transport=transport))

    unsupported_checks = [
        check for check in normalized_checks if check not in allowed_smtp_lab_checks
    ]
    if unsupported_checks:
        reasons.append(msg("safety.reason.checks", checks=', '.join(unsupported_checks)))

    if not normalized_checks:
        reasons.append(msg("safety.reason.no_checks"))

    if max_probes < 1 or max_probes > 3:
        reasons.append(msg("safety.reason.probe_range"))

    if len(normalized_checks) > max_probes:
        reasons.append(msg("safety.reason.probe_limit"))

    if not normalized_lab_domain:
        reasons.append(msg("safety.reason.domain_required"))
    elif email_domain != normalized_lab_domain:
        reasons.append(msg("safety.reason.domain_mismatch"))

    if no_network and normalized_transport != "mock":
        reasons.append(msg("safety.reason.no_network"))

    if normalized_transport == "mock":
        return _build_decision(reasons, resolved_ips)

    if not enable_lab_smtp:
        reasons.append(msg("safety.reason.env_gate"))

    if not confirm_lab_only:
        reasons.append(msg("safety.reason.confirmation"))

    if not normalized_host:
        reasons.append(msg("safety.reason.host_required"))

    if normalized_transport == "private-lab" and not allow_hosts:
        reasons.append(msg("safety.reason.allow_hosts"))

    host_ips, host_reasons = _classify_lab_host(
        host=normalized_host,
        transport=normalized_transport,
        allow_hosts=[item.lower() for item in allow_hosts],
    )
    resolved_ips.extend(host_ips)
    reasons.extend(host_reasons)

    if port <= 0 or port > 65535:
        reasons.append(msg("safety.reason.port_range"))

    if (
        normalized_transport != "localhost"
        and port in {25, 465, 587}
        and not _all_loopback(host_ips)
    ):
        reasons.append(msg("safety.reason.public_ports"))

    if "expn" in normalized_checks and normalized_transport != "localhost":
        reasons.append(msg("safety.reason.expn"))

    return _build_decision(reasons, resolved_ips)


def _build_decision(reasons: list[str], resolved_ips: list[str]) -> tuple[SafetyDecision, list[str]]:
    """Build a safety decision from collected reasons."""
    if reasons:
        return (
            SafetyDecision(
                allowed=False,
                status="blocked_by_safety_policy",
                reasons=reasons,
                limitations=default_smtp_lab_limitations,
            ),
            resolved_ips,
        )
    return (
        SafetyDecision(
            allowed=True,
            status="allowed_lab_only",
            reasons=[msg("safety.reason.passed")],
            limitations=default_smtp_lab_limitations,
        ),
        resolved_ips,
    )


def _classify_lab_host(
    host: str,
    transport: str,
    allow_hosts: list[str],
) -> tuple[list[str], list[str]]:
    """Classify a host without performing public DNS discovery."""
    if host in {"localhost"}:
        return ["127.0.0.1", "::1"], []

    if host in allow_hosts:
        return [host], []

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return [], [msg("safety.reason.host_type")]

    if transport == "localhost":
        if ip.is_loopback:
            return [str(ip)], []
        return [str(ip)], [msg("safety.reason.loopback")]

    if transport == "private-lab":
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return [str(ip)], []
        return [str(ip)], [msg("safety.reason.private_ip")]

    return [str(ip)], [msg("safety.reason.host_transport")]


def _all_loopback(ips: list[str]) -> bool:
    """Return whether every resolved IP is loopback."""
    if not ips:
        return False
    for value in ips:
        try:
            if not ipaddress.ip_address(value).is_loopback:
                return False
        except ValueError:
            return False
    return True
