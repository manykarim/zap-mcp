"""Resources exposing detailed ZAP findings."""

from __future__ import annotations

from typing import Any, Dict

from fastmcp import Resource

from ..core.zap_client import ZAPClient


class VulnerabilityDetailsResource(Resource):
    """Return the raw ZAP alert payloads."""

    name = "vulnerability_details"
    description = "Detailed vulnerability information from ZAP"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def read(self) -> Dict[str, Any]:
        alerts = await self._zap_client.get_alerts()
        return {"alerts": alerts}
