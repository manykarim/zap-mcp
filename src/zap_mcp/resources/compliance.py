"""Simplified OWASP Top 10 compliance aggregation."""

from __future__ import annotations

from typing import Any, Dict

from fastmcp import Resource

from ..core.zap_client import ZAPClient


class ComplianceStatusResource(Resource):
    """Provide a coarse compliance indicator based on alert severities."""

    name = "compliance_status"
    description = "OWASP Top 10 style compliance summary"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def read(self) -> Dict[str, Any]:
        summary = await self._zap_client.get_alert_summary()
        status = "attention_required" if summary["high"] or summary["critical"] else "pass"
        return {"summary": summary, "status": status}
