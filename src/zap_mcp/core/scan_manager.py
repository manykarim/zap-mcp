"""High level orchestration of ZAP scan workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .zap_client import ZAPClient


@dataclass(slots=True)
class ScanManager:
    """Coordinates spidering, passive, and active scans."""

    zap_client: ZAPClient

    async def execute_scan(
        self,
        url: str,
        scan_type: str,
        include_spider: bool = True,
        max_depth: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute a scan pipeline and return metadata."""

        urls_found = 0
        scan_id: Optional[str] = None

        if include_spider:
            spider_id = await self.zap_client.spider_scan(url=url, max_depth=max_depth)
            await self.zap_client.wait_for_spider(spider_id)
            scan_id = spider_id

        if scan_type in {"standard", "comprehensive"}:
            if scan_type == "standard":
                policy = "Default Policy"
            else:
                policy = "Aggressive"
            scan_id = await self.zap_client.active_scan(url=url, policy=policy)
            await self.zap_client.wait_for_active_scan(scan_id)

        return {
            "scan_id": scan_id,
            "urls_found": urls_found,
            "scan_type": scan_type,
        }
