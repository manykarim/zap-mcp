"""Validation helpers for user supplied inputs."""

from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse


class ValidationError(ValueError):
    """Raised when user supplied input is invalid."""


_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWED_SCAN_TYPES = {"quick", "standard", "comprehensive"}


def validate_url(value: str) -> str:
    """Ensure a URL uses an allowed scheme and contains a host."""

    if not value:
        raise ValidationError("URL must not be empty")

    parsed = urlparse(value)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValidationError("Only HTTP and HTTPS URLs are supported")
    if not parsed.netloc:
        raise ValidationError("URL must contain a hostname")
    return value


def validate_scan_type(value: str) -> str:
    """Ensure a supplied scan type is supported."""

    scan_type = value.lower()
    if scan_type not in _ALLOWED_SCAN_TYPES:
        raise ValidationError(f"Unsupported scan type: {value}")
    return scan_type


def validate_max_depth(depth: int) -> int:
    """Validate spider depth options."""

    if depth < 0:
        raise ValidationError("Depth must be non negative")
    if depth > 50:
        raise ValidationError("Depth above 50 is not supported")
    return depth


def ensure_allowed_domain(url: str, allowed_domains: Iterable[str]) -> None:
    """Ensure the URL matches one of the configured allowed domains."""

    parsed = urlparse(url)
    host = parsed.hostname or ""
    for domain in allowed_domains:
        if domain == "*" or host.endswith(domain):
            return
    raise ValidationError(f"URL {url} is not part of the configured allow list")
