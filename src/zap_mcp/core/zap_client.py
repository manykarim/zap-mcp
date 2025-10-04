"""Asynchronous helper around the official ZAP Python client."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import httpx
from zapv2 import ZAPv2

from ..config import settings


class ZAPClientError(RuntimeError):
    """Raised when communication with ZAP fails."""


@dataclass(slots=True)
class ZAPClient:
    """Thin asynchronous wrapper for the python-owasp-zap-v2.4 client."""

    proxy_url: Optional[str] = None
    api_key: Optional[str] = None

    def __post_init__(self) -> None:
        proxy = self.proxy_url or settings.zap.proxy_url
        key = self.api_key or (settings.zap.api_key.get_secret_value() if settings.zap.api_key else None)
        proxies = {"http": proxy, "https": proxy}
        self._zap = ZAPv2(proxies=proxies, apikey=key)
        self._http_client = httpx.AsyncClient(timeout=settings.zap.timeout_seconds)
        self._connected = False

    async def connect(self) -> None:
        """Ensure the ZAP daemon is reachable."""

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._zap.core.version)
        except Exception as exc:  # noqa: BLE001 - propagate informative error
            raise ZAPClientError("Unable to communicate with the ZAP daemon") from exc
        self._connected = True

    async def ensure_connected(self) -> None:
        """Open a connection if one has not been established."""

        if not self._connected:
            await self.connect()

    # ------------------------------------------------------------------
    # Spider helpers

    async def spider_scan(
        self,
        url: str,
        max_depth: Optional[int] = None,
        subtree_only: bool = True,
        context_name: Optional[str] = None,
    ) -> str:
        await self.ensure_connected()
        loop = asyncio.get_running_loop()
        depth = max_depth or settings.zap.max_spider_depth
        params: Dict[str, Any] = {
            "url": url,
            "maxchildren": depth,
            "recurse": not subtree_only,
            "subtreeonly": subtree_only,
        }
        if context_name:
            params["contextname"] = context_name
        return await loop.run_in_executor(None, lambda: self._zap.spider.scan(**params))

    async def get_spider_status(self, scan_id: str) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        progress = await loop.run_in_executor(None, self._zap.spider.status, scan_id)
        value = int(progress)
        return {"scan_id": scan_id, "progress": value, "complete": value >= 100}

    async def wait_for_spider(self, scan_id: str, poll_interval: Optional[float] = None) -> None:
        interval = poll_interval or settings.zap.poll_interval_seconds
        while True:
            status = await self.get_spider_status(scan_id)
            if status["complete"]:
                return
            await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # Active scan helpers

    async def active_scan(
        self,
        url: str,
        policy: Optional[str] = None,
        context_id: Optional[str] = None,
    ) -> str:
        await self.ensure_connected()
        loop = asyncio.get_running_loop()
        params: Dict[str, Any] = {"url": url}
        if policy:
            params["scanpolicyname"] = policy
        if context_id:
            params["contextid"] = context_id
        return await loop.run_in_executor(None, lambda: self._zap.ascan.scan(**params))

    async def get_active_scan_status(self, scan_id: str) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        progress = await loop.run_in_executor(None, self._zap.ascan.status, scan_id)
        value = int(progress)
        return {"scan_id": scan_id, "progress": value, "complete": value >= 100}

    async def wait_for_active_scan(self, scan_id: str, poll_interval: Optional[float] = None) -> None:
        interval = poll_interval or settings.zap.poll_interval_seconds
        while True:
            status = await self.get_active_scan_status(scan_id)
            if status["complete"]:
                return
            await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # Alert helpers

    async def get_alerts(
        self,
        base_url: Optional[str] = None,
        min_risk: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        await self.ensure_connected()
        loop = asyncio.get_running_loop()
        params: Dict[str, Any] = {}
        if base_url:
            params["baseurl"] = base_url
        if min_risk:
            params["riskid"] = min_risk
        alerts: List[Dict[str, Any]] = await loop.run_in_executor(
            None, lambda: list(self._zap.core.alerts(**params))
        )
        return alerts

    async def get_alert_summary(self, base_url: Optional[str] = None) -> Dict[str, int]:
        alerts = await self.get_alerts(base_url=base_url)
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        mapping = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "informational",
        }
        for alert in alerts:
            risk = alert.get("risk", "Informational")
            bucket = mapping.get(risk, "informational")
            if risk == "High" and alert.get("confidence") == "Confirmed":
                summary["critical"] += 1
            else:
                summary[bucket] += 1
        return summary

    # ------------------------------------------------------------------
    # Passive scans

    async def get_passive_scan_status(self) -> Dict[str, Any]:
        await self.ensure_connected()
        loop = asyncio.get_running_loop()
        remaining = await loop.run_in_executor(None, self._zap.pscan.records_to_scan)
        count = int(remaining)
        return {"records_to_scan": count, "scanning": count > 0}

    # ------------------------------------------------------------------
    # Reports

    async def generate_html_report(self, base_url: Optional[str] = None) -> str:
        await self.ensure_connected()
        loop = asyncio.get_running_loop()
        params: Dict[str, Any] = {}
        if base_url:
            params["sites"] = base_url
        return await loop.run_in_executor(None, lambda: self._zap.core.htmlreport(**params))

    # ------------------------------------------------------------------
    # Context helpers

    async def create_context(self, name: str) -> str:
        await self.ensure_connected()
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._zap.context.new_context, name)

    async def include_in_context(self, context_name: str, regex: str) -> None:
        await self.ensure_connected()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._zap.context.include_in_context, context_name, regex)

    # ------------------------------------------------------------------

    async def close(self) -> None:
        await self._http_client.aclose()
        self._connected = False
