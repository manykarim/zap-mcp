"""MCP tools providing access to ZAP alert data."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastmcp import Tool

from ..config import server_allowed_domains
from ..core.zap_client import ZAPClient
from ..utils.validators import ensure_allowed_domain, validate_url


class GetAlertsTool(Tool):
    """Return ZAP alerts for a specific site."""

    name = "get_alerts"
    description = "Retrieve vulnerability alerts from ZAP"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def run(self, url: Optional[str] = None, min_risk: Optional[str] = None) -> Dict[str, Any]:
        if url:
            validate_url(url)
            ensure_allowed_domain(url, server_allowed_domains())
        alerts = await self._zap_client.get_alerts(base_url=url, min_risk=min_risk)
        return {"alerts": alerts, "count": len(alerts)}


class MarkFalsePositiveTool(Tool):
    """Placeholder tool for flagging alerts."""

    name = "mark_false_positive"
    description = "Mark a ZAP alert as a false positive"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def run(self, alert_id: str) -> Dict[str, Any]:
        # python-owasp-zap-v2.4 does not expose an API for this directly; surface acknowledgement
        return {"alert_id": alert_id, "status": "acknowledged"}
