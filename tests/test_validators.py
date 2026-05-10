from mailrecon.core.validators import validate_email_input


def test_validate_email_input_accepts_valid_email() -> None:
    is_valid, normalized, domain = validate_email_input("User@example.com")

    assert is_valid is True
    assert normalized == "User@example.com"
    assert domain == "example.com"


def test_validate_email_input_rejects_invalid_email() -> None:
    is_valid, message, domain = validate_email_input("invalid-email")

    assert is_valid is False
    assert domain is None
    assert message
