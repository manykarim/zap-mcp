"""Guided security assessment prompt."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastmcp import Prompt

from ..core.scan_manager import ScanManager
from ..core.zap_client import ZAPClient
from ..ui.builder import UIBuilder
from ..utils.validators import validate_scan_type, validate_url


class SecurityAssessmentPrompt(Prompt):
    """Run a guided assessment workflow."""

    name = "security_assessment"
    description = "Run a guided security assessment using OWASP ZAP"

    def __init__(self, zap_client: ZAPClient, ui_builder: Optional[UIBuilder] = None) -> None:
        self._zap_client = zap_client
        self._scan_manager = ScanManager(zap_client)
        self._ui_builder = ui_builder

    async def run(
        self,
        target_url: str,
        assessment_type: str = "standard",
        include_spider: bool = True,
    ) -> Dict[str, Any]:
        validate_url(target_url)
        scan_type = validate_scan_type(assessment_type)
        steps: List[Dict[str, Any]] = []

        if include_spider:
            spider_id = await self._zap_client.spider_scan(target_url)
            await self._zap_client.wait_for_spider(spider_id)
            steps.append({"step": "spider", "status": "completed", "scan_id": spider_id})

        if scan_type != "quick":
            scan = await self._zap_client.active_scan(target_url)
            await self._zap_client.wait_for_active_scan(scan)
            steps.append({"step": "active_scan", "status": "completed", "scan_id": scan})

        alerts = await self._zap_client.get_alerts(base_url=target_url)
        summary = await self._zap_client.get_alert_summary(base_url=target_url)

        ui_resources = []
        if self._ui_builder:
            ui_resources.append(
                await self._ui_builder.create_assessment_dashboard(
                    target_url=target_url,
                    assessment_type=scan_type,
                    steps=steps,
                    alerts=summary,
                )
            )

        return {
            "target": target_url,
            "assessment_type": scan_type,
            "steps": steps,
            "alerts": alerts,
            "summary": summary,
            "ui_resources": ui_resources,
        }
