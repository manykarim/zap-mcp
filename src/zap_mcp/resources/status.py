"""Resources exposing real-time ZAP status."""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from fastmcp import Resource

from ..core.zap_client import ZAPClient


class ScanStatusResource(Resource):
    """Return combined information about current scans."""

    name = "scan_status"
    description = "Current status of ZAP scanning jobs"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def read(self) -> Dict[str, Any]:
        passive = await self._zap_client.get_passive_scan_status()
        loop = asyncio.get_running_loop()
        active = await loop.run_in_executor(None, self._zap_client._zap.ascan.scans)  # noqa: SLF001
        spider = await loop.run_in_executor(None, self._zap_client._zap.spider.scans)  # noqa: SLF001
        return {
            "passive": passive,
            "active": active or [],
            "spider": spider or [],
            "is_scanning": passive.get("scanning") or bool(active) or bool(spider),
        }


class AlertSummaryResource(Resource):
    """Provide a high-level summary of alerts."""

    name = "alert_summary"
    description = "Aggregated view of alert severities"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def read(self) -> Dict[str, Any]:
        summary = await self._zap_client.get_alert_summary()
        alerts = await self._zap_client.get_alerts()
        return {"summary": summary, "total": len(alerts)}
