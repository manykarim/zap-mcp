"""Reporting helpers exposed as MCP tools."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastmcp import Tool

from ..core.zap_client import ZAPClient
from ..utils.validators import validate_url


class GenerateReportTool(Tool):
    """Generate an HTML report using the ZAP daemon."""

    name = "generate_report"
    description = "Generate a ZAP HTML report"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def run(self, url: Optional[str] = None) -> Dict[str, Any]:
        if url:
            validate_url(url)
        report = await self._zap_client.generate_html_report(base_url=url)
        return {"report": report}
