"""Validation helpers."""

import re

from email_validator import EmailNotValidError, validate_email


def normalize_email_address(email: str) -> str:
    """Validate and normalize an email address."""
    result = validate_email(email, check_deliverability=False)
    return result.normalized


def extract_domain(email: str) -> str:
    """Extract the domain part from a validated email address."""
    normalized = normalize_email_address(email)
    return normalized.rsplit("@", maxsplit=1)[1]


def validate_email_input(email: str) -> tuple[bool, str, str | None]:
    """Validate user input and return a friendly result tuple."""
    try:
        normalized = normalize_email_address(email)
    except EmailNotValidError as exc:
        return False, str(exc), None

    domain = normalized.rsplit("@", maxsplit=1)[1]
    return True, normalized, domain


def mask_email_address(email: str) -> str:
    """Mask an email address for reports and terminal output."""
    local_part, _, domain = email.partition("@")
    if not domain:
        return email

    if len(local_part) <= 2:
        masked_local = local_part[0] + "*" if local_part else "*"
    else:
        masked_local = local_part[0] + ("*" * (len(local_part) - 2)) + local_part[-1]

    return f"{masked_local}@{domain}"


def normalize_domain_input(domain: str) -> str:
    """Normalize a user-provided domain value."""
    return domain.strip().lower().rstrip(".")


def split_name_tokens(name: str) -> list[str]:
    """Extract simple name tokens that can support safe email candidate generation."""
    tokens = re.findall(r"[a-z0-9]+", name.lower())
    return [token for token in tokens if token]
