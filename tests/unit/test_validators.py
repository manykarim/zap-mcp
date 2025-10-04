"""Unit tests for validator helpers."""

from __future__ import annotations

import pytest

from zap_mcp.utils.validators import (
    ValidationError,
    ensure_allowed_domain,
    validate_max_depth,
    validate_scan_type,
    validate_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://localhost:8080/api",
        "https://sub.domain.test/path",
    ],
)
def test_validate_url_success(url: str) -> None:
    validate_url(url)


@pytest.mark.parametrize("url", ["", "ftp://example.com", "javascript:alert(1)"])
def test_validate_url_failure(url: str) -> None:
    with pytest.raises(ValidationError):
        validate_url(url)


@pytest.mark.parametrize("scan_type", ["quick", "standard", "comprehensive"])
def test_validate_scan_type_success(scan_type: str) -> None:
    assert validate_scan_type(scan_type) == scan_type


@pytest.mark.parametrize("scan_type", ["fast", "", "STANDARDPLUS"])
def test_validate_scan_type_failure(scan_type: str) -> None:
    with pytest.raises(ValidationError):
        validate_scan_type(scan_type)


@pytest.mark.parametrize("depth", [0, 10, 50])
def test_validate_depth_success(depth: int) -> None:
    assert validate_max_depth(depth) == depth


@pytest.mark.parametrize("depth", [-1, 51])
def test_validate_depth_failure(depth: int) -> None:
    with pytest.raises(ValidationError):
        validate_max_depth(depth)


def test_ensure_allowed_domain_wildcard() -> None:
    ensure_allowed_domain("https://example.com", ["*"])


def test_ensure_allowed_domain_specific() -> None:
    ensure_allowed_domain("https://api.example.com", ["example.com"])


def test_ensure_allowed_domain_failure() -> None:
    with pytest.raises(ValidationError):
        ensure_allowed_domain("https://evil.com", ["example.com"])
