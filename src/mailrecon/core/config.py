"""Application configuration helpers."""

from dataclasses import dataclass
import os

from dotenv import load_dotenv

load_dotenv()


@dataclass(slots=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    hibp_api_key: str | None
    http_timeout: float = 10.0
    dns_timeout: float = 5.0


def _get_float_env(name: str, default: float) -> float:
    """Read a float environment variable with a safe fallback."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        return float(raw_value)
    except ValueError:
        return default


def load_settings() -> Settings:
    """Load environment settings with safe defaults."""
    hibp_api_key = os.getenv("HIBP_API_KEY") or None
    http_timeout = _get_float_env("MAILRECON_HTTP_TIMEOUT", 10.0)
    dns_timeout = _get_float_env("MAILRECON_DNS_TIMEOUT", 5.0)
    return Settings(
        hibp_api_key=hibp_api_key,
        http_timeout=http_timeout,
        dns_timeout=dns_timeout,
    )
