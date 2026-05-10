"""Validation helpers."""

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
