"""Application configuration helpers."""

from dataclasses import dataclass, field
import math
import os

from dotenv import load_dotenv

load_dotenv()


@dataclass(slots=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    hibp_api_key: str | None
    http_timeout: float = 10.0
    dns_timeout: float = 5.0
    enable_lab_smtp: bool = False
    lab_smtp_allow_hosts: list[str] = field(default_factory=list)
    lab_smtp_timeout: float = 3.0
    profile_total_budget: int = 20
    profile_source_budget: int = 10
    profile_max_response_bytes: int = 65536
    profile_cache_ttl: int = 60
    profile_cache_entries: int = 128


def _get_float_env(name: str, default: float) -> float:
    """Read a float environment variable with a safe fallback."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        value = float(raw_value)
    except ValueError:
        return default

    if not math.isfinite(value) or value <= 0:
        return default

    return value


def _get_bool_env(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable with a safe fallback."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    """Reject invalid limits rather than silently allowing unbounded work."""
    try:
        parsed = int(str(value))
    except (TypeError, ValueError, OverflowError):
        return default
    return parsed if minimum <= parsed <= maximum else default


def _get_csv_env(name: str) -> list[str]:
    """Read a comma-separated environment variable as a clean list."""
    raw_value = os.getenv(name)
    if not raw_value:
        return []
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def load_settings() -> Settings:
    """Load environment settings with safe defaults."""
    hibp_api_key = os.getenv("HIBP_API_KEY") or None
    http_timeout = _get_float_env("MAILRECON_HTTP_TIMEOUT", 10.0)
    dns_timeout = _get_float_env("MAILRECON_DNS_TIMEOUT", 5.0)
    enable_lab_smtp = _get_bool_env("MAILRECON_ENABLE_LAB_SMTP", False)
    lab_smtp_allow_hosts = _get_csv_env("MAILRECON_LAB_SMTP_ALLOW_HOSTS")
    lab_smtp_timeout = _get_float_env("MAILRECON_LAB_SMTP_TIMEOUT", 3.0)
    return Settings(
        hibp_api_key=hibp_api_key,
        http_timeout=http_timeout,
        dns_timeout=dns_timeout,
        enable_lab_smtp=enable_lab_smtp,
        lab_smtp_allow_hosts=lab_smtp_allow_hosts,
        lab_smtp_timeout=lab_smtp_timeout,
        profile_total_budget=bounded_int(os.getenv("MAILRECON_PROFILE_TOTAL_BUDGET"), 20, 0, 100),
        profile_source_budget=bounded_int(os.getenv("MAILRECON_PROFILE_SOURCE_BUDGET"), 10, 0, 50),
        profile_max_response_bytes=bounded_int(os.getenv("MAILRECON_PROFILE_MAX_RESPONSE_BYTES"), 65536, 1024, 1048576),
        profile_cache_ttl=bounded_int(os.getenv("MAILRECON_PROFILE_CACHE_TTL"), 60, 0, 300),
        profile_cache_entries=bounded_int(os.getenv("MAILRECON_PROFILE_CACHE_ENTRIES"), 128, 0, 512),
    )
