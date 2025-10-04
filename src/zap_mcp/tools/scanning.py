"""MCP tools that expose scanning workflows."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastmcp import Tool

from ..config import server_allowed_domains, settings
from ..core.scan_manager import ScanManager
from ..core.zap_client import ZAPClient
from ..ui.builder import UIBuilder
from ..utils.validators import (
    ensure_allowed_domain,
    validate_max_depth,
    validate_scan_type,
    validate_url,
)

logger = logging.getLogger(__name__)


class ScanUrlTool(Tool):
    """Run a combined spider and active scan."""

    name = "scan_url"
    description = "Perform a security scan for a given URL"

    def __init__(self, zap_client: ZAPClient, ui_builder: Optional[UIBuilder] = None) -> None:
        self._scan_manager = ScanManager(zap_client)
        self._zap_client = zap_client
        self._ui_builder = ui_builder

    async def run(
        self,
        url: str,
        scan_type: str = "standard",
        include_spider: bool = True,
        max_depth: Optional[int] = None,
    ) -> Dict[str, Any]:
        validate_url(url)
        ensure_allowed_domain(url, server_allowed_domains())
        scan_mode = validate_scan_type(scan_type)
        if max_depth is not None:
            validate_max_depth(max_depth)

        logger.info("starting %s scan for %s", scan_mode, url)
        scan_result = await self._scan_manager.execute_scan(
            url=url,
            scan_type=scan_mode,
            include_spider=include_spider,
            max_depth=max_depth,
        )

        alerts = await self._zap_client.get_alerts(base_url=url)
        summary = await self._zap_client.get_alert_summary(base_url=url)
        ui_resources = []
        if self._ui_builder:
            ui_resources.append(
                await self._ui_builder.create_security_dashboard(
                    alerts=summary,
                    scan_status={
                        "url": url,
                        "type": scan_mode,
                        "progress": 100,
                    },
                )
            )
            for alert in alerts[:3]:
                ui_resources.append(await self._ui_builder.create_vulnerability_viewer(alert))

        return {
            "url": url,
            "scan_type": scan_mode,
            "scan_id": scan_result.get("scan_id"),
            "alerts_found": len(alerts),
            "alert_summary": summary,
            "ui_resources": ui_resources,
        }


class ActiveScanTool(Tool):
    """Expose the active scan helper directly."""

    name = "active_scan"
    description = "Run an active scan against the supplied URL"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def run(self, url: str, policy: Optional[str] = None) -> Dict[str, Any]:
        validate_url(url)
        ensure_allowed_domain(url, server_allowed_domains())
        scan_id = await self._zap_client.active_scan(url=url, policy=policy)
        await self._zap_client.wait_for_active_scan(scan_id)
        alerts = await self._zap_client.get_alerts(base_url=url)
        return {
            "scan_id": scan_id,
            "url": url,
            "alerts_found": len(alerts),
        }


class SpiderTool(Tool):
    """Discover content using the ZAP spider."""

    name = "spider_site"
    description = "Trigger a ZAP spider against the supplied URL"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def run(
        self,
        url: str,
        max_depth: Optional[int] = None,
        subtree_only: bool = True,
    ) -> Dict[str, Any]:
        validate_url(url)
        ensure_allowed_domain(url, server_allowed_domains())
        depth = validate_max_depth(max_depth or settings.zap.max_spider_depth)
        spider_id = await self._zap_client.spider_scan(
            url=url,
            max_depth=depth,
            subtree_only=subtree_only,
        )
        await self._zap_client.wait_for_spider(spider_id)
        return {
            "scan_id": spider_id,
            "url": url,
            "max_depth": depth,
            "subtree_only": subtree_only,
        }
