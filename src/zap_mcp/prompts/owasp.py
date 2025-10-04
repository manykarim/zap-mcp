"""Prompt returning a lightweight OWASP Top 10 review."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastmcp import Prompt

from ..core.zap_client import ZAPClient
from ..ui.builder import UIBuilder


class OWASPCompliancePrompt(Prompt):
    """Summarise alert counts by OWASP Top 10 category."""

    name = "owasp_compliance"
    description = "Summarise findings in an OWASP Top 10 context"

    def __init__(self, zap_client: ZAPClient, ui_builder: Optional[UIBuilder] = None) -> None:
        self._zap_client = zap_client
        self._ui_builder = ui_builder

    async def run(self, url: Optional[str] = None) -> Dict[str, Any]:
        summary = await self._zap_client.get_alert_summary(base_url=url)
        ui_resources = []
        if self._ui_builder:
            ui_resources.append(
                await self._ui_builder.create_security_dashboard(
                    alerts=summary,
                    scan_status={"url": url or "all", "type": "summary", "progress": 100},
                )
            )
        return {"summary": summary, "ui_resources": ui_resources}
