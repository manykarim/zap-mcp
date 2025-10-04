"""Integration tests for tool orchestration using mocks."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from zap_mcp.tools.scanning import ScanUrlTool
from zap_mcp.ui.builder import UIBuilder


@pytest.mark.asyncio
async def test_scan_tool_invokes_zap_methods(monkeypatch: pytest.MonkeyPatch) -> None:
    zap = AsyncMock()
    zap.get_alerts.return_value = [
        {"id": "1", "risk": "High", "confidence": "Medium", "name": "Test"}
    ]
    zap.get_alert_summary.return_value = {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    tool = ScanUrlTool(zap_client=zap, ui_builder=UIBuilder())
    result = await tool.run("https://example.com", scan_type="quick", include_spider=False)
    assert result["alerts_found"] == 1
    zap.get_alerts.assert_awaited()
    zap.get_alert_summary.assert_awaited()
