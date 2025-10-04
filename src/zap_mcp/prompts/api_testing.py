"""Prompt offering helper actions for API focused tests."""

from __future__ import annotations

from typing import Any, Dict

from fastmcp import Prompt

from ..core.zap_client import ZAPClient


class APITestingPrompt(Prompt):
    """Provide minimal guidance for API security tests."""

    name = "api_testing"
    description = "Provide guidance for API security testing"

    def __init__(self, zap_client: ZAPClient) -> None:
        self._zap_client = zap_client

    async def run(self, target_url: str) -> Dict[str, Any]:
        await self._zap_client.spider_scan(target_url, subtree_only=True)
        summary = await self._zap_client.get_alert_summary(base_url=target_url)
        return {
            "target": target_url,
            "recommendations": [
                "Review authentication and authorisation flows",
                "Validate rate limiting and throttling",
                "Confirm sensitive data is not exposed",
            ],
            "summary": summary,
        }
